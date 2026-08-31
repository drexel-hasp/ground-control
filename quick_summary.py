"""Restart-decision summary derived from decoded downlink packets.

Only CRC-valid, correctly framed packets from the latest observed boot segment
are used.  Sequence numbers provide relative time when the payload RTC is zero.
"""

from __future__ import annotations

from collections.abc import Iterable
from time import time

from constants import TELEMETRY_MODULE_NAMES


PACKET_RATE_HZ = 5.0
WINDOWS_SECONDS = {"5m": 5 * 60, "10m": 10 * 60, "30m": 30 * 60, "1h": 60 * 60}
# Main and acquisition_handler are parent rollups: known-bad sensors can mark
# them degraded even when acquisition itself is still operating.  Leaf modules
# below are more actionable for a power-cycle decision.
CRITICAL_MODULE_IDS = (3, 8, 9, 10, 13, 18)
MAX_FORWARD_SEQUENCE_STEP = 32768


def _counter_delta(current: int, previous: int, bits: int = 32) -> int:
    return (current - previous) & ((1 << bits) - 1)


def _latest_status(rows: list[dict], status_type: int) -> dict | None:
    return next((row for row in reversed(rows) if int(row["status_type"]) == status_type), None)


def _status_samples(rows: list[dict], status_type: int, seconds: int) -> list[dict]:
    return [
        row for row in rows
        if float(row["_age_seconds"]) <= seconds and int(row["status_type"]) == status_type
    ]


def _counter_window(rows: list[dict], status_type: int, seconds: int, bits: int = 32) -> int | None:
    samples = _status_samples(rows, status_type, seconds)
    if len(samples) < 2:
        return None
    return _counter_delta(int(samples[-1]["status_data"]), int(samples[0]["status_data"]), bits)


def _packed_counter_window(rows: list[dict], status_type: int, seconds: int) -> tuple[int | None, int | None]:
    samples = _status_samples(rows, status_type, seconds)
    if len(samples) < 2:
        return None, None
    old = int(samples[0]["status_data"])
    new = int(samples[-1]["status_data"])
    return (
        _counter_delta((new >> 16) & 0xFFFF, (old >> 16) & 0xFFFF, 16),
        _counter_delta(new & 0xFFFF, old & 0xFFFF, 16),
    )


def _counter_progress_age(rows: list[dict], status_type: int) -> float | None:
    samples = [row for row in rows if int(row["status_type"]) == status_type]
    for older, newer in zip(reversed(samples[:-1]), reversed(samples[1:])):
        if int(older["status_data"]) != int(newer["status_data"]):
            return float(newer["_age_seconds"])
    return None


def _window_packets(rows: list[dict], seconds: int) -> list[dict]:
    return [row for row in rows if float(row["_age_seconds"]) <= seconds]


def _window_summary(rows: list[dict], seconds: int) -> dict:
    selected = _window_packets(rows, seconds)
    if not selected:
        return {
            "coverage_seconds": 0.0,
            "received_packets": 0,
            "expected_packets": 0,
            "missing_percent": None,
            "packet_rate_hz": None,
            "trigger_rates_hz": [None] * 16,
            "board_rates_hz": [None, None],
        }

    coverage = min(float(seconds), float(rows[-1]["_timeline_seconds"]) - float(selected[0]["_timeline_seconds"]) + 0.2)
    expected = max(1, round(coverage * PACKET_RATE_HZ))
    received = len(selected)
    duration = max(0.2, expected / PACKET_RATE_HZ)
    trigger_rates = [
        sum(int(row[f"sipm_{channel:02d}_trigger_count"]) for row in selected) / duration
        for channel in range(1, 17)
    ]
    return {
        "coverage_seconds": round(coverage, 1),
        "received_packets": received,
        "expected_packets": expected,
        "missing_percent": round(max(0.0, 100.0 * (1.0 - received / expected)), 2),
        "packet_rate_hz": round(received / duration, 3),
        "trigger_rates_hz": [round(rate, 4) for rate in trigger_rates],
        # Physical ownership: SiPM Teensy 2 owns channels 1-8; Teensy 1 owns 9-16.
        "board_rates_hz": [round(sum(trigger_rates[8:]), 4), round(sum(trigger_rates[:8]), 4)],
    }


def _latest_boot_rows(rows: Iterable[dict]) -> tuple[list[dict], float | None]:
    valid = [row for row in rows if bool(row.get("crc_ok")) and bool(row.get("frame_ok"))]
    if not valid:
        return [], None

    latest_desc: list[dict] = [valid[-1]]
    newer_sequence = int(valid[-1]["sequence_number"])
    elapsed_steps = 0
    restart_boundary = False

    for row in reversed(valid[:-1]):
        sequence = int(row["sequence_number"])
        step = (newer_sequence - sequence) & 0xFFFF
        if step > MAX_FORWARD_SEQUENCE_STEP:
            restart_boundary = True
            break
        elapsed_steps += step
        if elapsed_steps > int(max(WINDOWS_SECONDS.values()) * PACKET_RATE_HZ):
            break
        latest_desc.append(row)
        newer_sequence = sequence

    latest = list(reversed(latest_desc))
    timeline = 0.0
    previous_sequence = int(latest[0]["sequence_number"])
    for row in latest:
        sequence = int(row["sequence_number"])
        timeline += ((sequence - previous_sequence) & 0xFFFF) / PACKET_RATE_HZ
        row["_timeline_seconds"] = timeline
        previous_sequence = sequence
    end = timeline
    for row in latest:
        row["_age_seconds"] = end - float(row["_timeline_seconds"])
    return latest, (end + 0.2 if restart_boundary else None)


def build_quick_summary(
    source_rows: Iterable[dict], *, live: dict | None = None, generated_at: float | None = None
) -> dict:
    """Build the compact operational summary returned to the browser."""
    rows, sequence_restart_age = _latest_boot_rows(source_rows)
    now = time() if generated_at is None else generated_at
    if not rows:
        return {"available": False, "generated_at": now, "windows": {}}

    windows = {
        label: _window_summary(rows, seconds)
        for label, seconds in WINDOWS_SECONDS.items()
    }

    uptime = _latest_status(rows, 0x21)
    sd_records = _latest_status(rows, 0x31)
    sd_failures = _latest_status(rows, 0x32)
    sd_free = _latest_status(rows, 0x33)
    ring = _latest_status(rows, 0x35)
    overflows = _latest_status(rows, 0x36)
    degraded = _latest_status(rows, 0x2E)
    last_error = _latest_status(rows, 0x2B)
    uplink_accepted = _latest_status(rows, 0x53)
    uplink_rejected = _latest_status(rows, 0x54)

    current_mask = int(degraded["status_data"]) if degraded else None
    degraded_modules = []
    for module_id in CRITICAL_MODULE_IDS:
        window_percent = {}
        for label, seconds in WINDOWS_SECONDS.items():
            samples = _status_samples(rows, 0x2E, seconds)
            window_percent[label] = (
                round(100.0 * sum(bool(int(sample["status_data"]) & (1 << (module_id - 1))) for sample in samples) / len(samples), 1)
                if samples else None
            )
        if (current_mask is not None and current_mask & (1 << (module_id - 1))) or any(
            value for value in window_percent.values() if value is not None
        ):
            degraded_modules.append({
                "id": module_id,
                "name": TELEMETRY_MODULE_NAMES[module_id],
                "current": bool(current_mask is not None and current_mask & (1 << (module_id - 1))),
                "persistence_percent": window_percent,
            })

    error_value = int(last_error["status_data"]) if last_error else 0
    error_module_id = (error_value >> 16) & 0xFFFF
    error_code = error_value & 0xFFFF
    error_matches = [
        row for row in rows
        if int(row["status_type"]) == 0x2B and int(row["status_data"]) == error_value
    ] if error_value else []

    failure_current = int(sd_failures["status_data"]) if sd_failures else None
    ring_current = int(ring["status_data"]) if ring else None
    rejected_current = int(uplink_rejected["status_data"]) if uplink_rejected else None

    storage_windows = {}
    uplink_windows = {}
    for label, seconds in WINDOWS_SECONDS.items():
        recorder_delta, writer_delta = _packed_counter_window(rows, 0x32, seconds)
        rejected_delta, complement_delta = _packed_counter_window(rows, 0x54, seconds)
        storage_windows[label] = {
            "records_delta": _counter_window(rows, 0x31, seconds),
            "data_recorder_failures_delta": recorder_delta,
            "sd_writer_failures_delta": writer_delta,
            "overflows_delta": _counter_window(rows, 0x36, seconds),
        }
        uplink_windows[label] = {
            "accepted_delta": _counter_window(rows, 0x53, seconds),
            "rejected_delta": rejected_delta,
            "complement_failures_delta": complement_delta,
        }

    live = live or {}
    last_packet_at = live.get("last_packet_at")
    last_packet_age = max(0.0, now - float(last_packet_at)) if last_packet_at else None
    uptime_seconds = int(uptime["status_data"]) / 1000.0 if uptime else None
    recent_restart = (
        (sequence_restart_age is not None and sequence_restart_age < 300)
        or (uptime_seconds is not None and uptime_seconds < 300)
    )

    alerts = []
    if last_packet_age is not None and last_packet_age > 10:
        alerts.append({"level": "danger", "code": "DOWNLINK LOST", "detail": f"No new valid packet for {last_packet_age:.0f} s"})
    if recent_restart:
        alerts.append({"level": "warning", "code": "RECENT RESTART", "detail": "Sequence or uptime indicates a recent reboot"})

    five = windows["5m"]
    thirty = windows["30m"]
    for index, name in enumerate(("SiPM Teensy 1 (channels 9-16)", "SiPM Teensy 2 (channels 1-8)")):
        recent_rate = five["board_rates_hz"][index]
        earlier_rate = thirty["board_rates_hz"][index]
        if recent_rate == 0 and earlier_rate is not None and earlier_rate > 0:
            alerts.append({"level": "danger", "code": "TRIGGER ACTIVITY STOPPED", "detail": name})

    storage_five = storage_windows["5m"]
    if five["board_rates_hz"][0] + five["board_rates_hz"][1] > 0 and storage_five["records_delta"] == 0:
        alerts.append({"level": "danger", "code": "RECORDING STALLED", "detail": "Triggers continue but the SD record counter did not advance"})
    if (storage_five["data_recorder_failures_delta"] or 0) + (storage_five["sd_writer_failures_delta"] or 0) > 0:
        alerts.append({"level": "danger", "code": "SD FAILURES INCREASING", "detail": "New storage failures in the last 5 minutes"})
    if (storage_five["overflows_delta"] or 0) > 0:
        alerts.append({"level": "danger", "code": "BUFFER OVERFLOW", "detail": "New ring-buffer overflow in the last 5 minutes"})
    current_critical = [item["name"] for item in degraded_modules if item["current"]]
    if current_critical:
        alerts.append({"level": "warning", "code": "CRITICAL MODULE DEGRADED", "detail": ", ".join(current_critical)})
    if sd_free and int(sd_free["status_data"]) < 128:
        alerts.append({"level": "warning", "code": "SD NEARLY FULL — RESTART WILL NOT HELP", "detail": f"{int(sd_free['status_data'])} MB reported free"})
    if not alerts:
        alerts.append({"level": "ok", "code": "NO CRITICAL CONDITION DETECTED", "detail": "Based on the downlinked fields currently available"})

    return {
        "available": True,
        "generated_at": now,
        "latest_sequence": int(rows[-1]["sequence_number"]),
        "valid_packets_used": len(rows),
        "coverage_seconds": round(float(rows[-1]["_timeline_seconds"]) + 0.2, 1),
        "last_packet_age_seconds": round(last_packet_age, 1) if last_packet_age is not None else None,
        "uptime_seconds": uptime_seconds,
        "recent_restart": recent_restart,
        "sequence_restart_age_seconds": sequence_restart_age,
        "windows": windows,
        "storage": {
            "records_written": int(sd_records["status_data"]) if sd_records else None,
            "last_progress_age_seconds": _counter_progress_age(rows, 0x31),
            "data_recorder_failures": (failure_current >> 16) & 0xFFFF if failure_current is not None else None,
            "sd_writer_failures": failure_current & 0xFFFF if failure_current is not None else None,
            "free_mb": int(sd_free["status_data"]) if sd_free else None,
            "ring_depth": (ring_current >> 16) & 0xFFFF if ring_current is not None else None,
            "ring_high_water": ring_current & 0xFFFF if ring_current is not None else None,
            "overflows": int(overflows["status_data"]) if overflows else None,
            "windows": storage_windows,
        },
        "degraded_modules": degraded_modules,
        "last_error": {
            "module_id": error_module_id,
            "module_name": TELEMETRY_MODULE_NAMES.get(error_module_id, f"module_{error_module_id}"),
            "code": error_code,
            "first_seen_age_seconds": float(error_matches[0]["_age_seconds"]) if error_matches else None,
            "last_seen_age_seconds": float(error_matches[-1]["_age_seconds"]) if error_matches else None,
        } if error_value else None,
        "uplink": {
            "accepted": int(uplink_accepted["status_data"]) if uplink_accepted else None,
            "rejected": (rejected_current >> 16) & 0xFFFF if rejected_current is not None else None,
            "complement_failures": rejected_current & 0xFFFF if rejected_current is not None else None,
            "windows": uplink_windows,
        },
        "alerts": alerts,
    }
