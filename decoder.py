from __future__ import annotations

import csv
import re
from datetime import datetime, timezone
from pathlib import Path

from constants import (
    CSV_HEADER,
    END_MARKER,
    RECORD_SIZE,
    START_MARKER,
    STATUS_SCHEDULE,
    STATUS_TYPE_NAMES,
    TELEMETRY_MODULE_NAMES,
)


def crc16_ccitt_false(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


def u16_be(packet: bytes, offset: int) -> int:
    return int.from_bytes(packet[offset : offset + 2], "big", signed=False)


def s16_be(packet: bytes, offset: int) -> int:
    return int.from_bytes(packet[offset : offset + 2], "big", signed=True)


def u32_be(packet: bytes, offset: int) -> int:
    return int.from_bytes(packet[offset : offset + 4], "big", signed=False)


def temp_from_nibble(value: int) -> int:
    return (value * 10) - 60


def satellite_range(index: int) -> str:
    if index == 0:
        return "0"
    if index >= 15:
        return "43-99"
    low = (index - 1) * 3 + 1
    high = index * 3
    return f"{low}-{high}"


def utc_string(timestamp_s: int) -> str:
    if timestamp_s == 0:
        return "0"
    return datetime.fromtimestamp(timestamp_s, timezone.utc).isoformat()


def signed_from_unsigned(value: int, bits: int) -> int:
    sign_bit = 1 << (bits - 1)
    return value - (1 << bits) if value & sign_bit else value


def status_u8s(value: int) -> tuple[int, int, int, int]:
    return (
        (value >> 24) & 0xFF,
        (value >> 16) & 0xFF,
        (value >> 8) & 0xFF,
        value & 0xFF,
    )


def status_u16_pair(value: int) -> tuple[int, int]:
    return (value >> 16) & 0xFFFF, value & 0xFFFF


def duty_percent(raw: int) -> float:
    return round((raw * 100.0) / 255.0, 1)


def decoded_pairs(**items: object) -> str:
    return "; ".join(f"{key}={value}" for key, value in items.items())


def decode_module_mask(mask: int) -> str:
    if mask == 0:
        return "none"
    names = [
        TELEMETRY_MODULE_NAMES.get(module_id, f"module_{module_id}")
        for module_id in sorted(TELEMETRY_MODULE_NAMES)
        if mask & (1 << (module_id - 1))
    ]
    unknown = mask & ~sum(1 << (module_id - 1) for module_id in TELEMETRY_MODULE_NAMES)
    if unknown:
        names.append(f"unknown_bits=0x{unknown:X}")
    return ", ".join(names)


def decode_status(status_type: int, status_data: int, packet_number: int) -> dict[str, object]:
    b0, b1, b2, b3 = status_u8s(status_data)
    high, low = status_u16_pair(status_data)
    signed_high = signed_from_unsigned(high, 16)
    signed_low = signed_from_unsigned(low, 16)
    expected_index = (packet_number - 1) % len(STATUS_SCHEDULE)
    expected_type = STATUS_SCHEDULE[expected_index]
    name = STATUS_TYPE_NAMES.get(status_type, f"Unknown 0x{status_type:02X}")

    if status_type in {0x21, 0x22, 0x23, 0x31, 0x33, 0x36, 0x52, 0x53, 0x55}:
        decoded = decoded_pairs(value=status_data)
    elif status_type == 0x24:
        decoded = decoded_pairs(
            telemetry_mhz=b0 * 4,
            sipm1_mhz=(b1 * 4 if b1 else "unavailable"),
            sipm2_mhz=(b2 * 4 if b2 else "unavailable"),
        )
    elif status_type == 0x25:
        decoded = decoded_pairs(telemetry_core_temp_c=signed_from_unsigned(status_data, 32))
    elif status_type == 0x28:
        decoded = decoded_pairs(reset_cause=hex(status_data))
    elif status_type == 0x2B:
        decoded = decoded_pairs(last_error_code=hex(status_data))
    elif status_type == 0x2E:
        decoded = decoded_pairs(mask=f"0x{status_data:08X}", degraded_modules=decode_module_mask(status_data))
    elif status_type == 0x32:
        decoded = decoded_pairs(
            data_recorder_failures=high,
            sd_writer_failures=low,
        )
    elif status_type == 0x34:
        decoded = decoded_pairs(session_file_index=status_data)
    elif status_type == 0x35:
        decoded = decoded_pairs(
            current_depth=high,
            high_water_mark=low,
        )
    elif 0x3D <= status_type <= 0x40:
        start_channel = 1 + (status_type - 0x3D) * 4
        decoded = decoded_pairs(**{
            f"sipm_{start_channel + idx:02d}_threshold_mv": value * 4
            for idx, value in enumerate((b0, b1, b2, b3))
        })
    elif 0x41 <= status_type <= 0x48:
        start_channel = 1 + (status_type - 0x41) * 2
        decoded = decoded_pairs(**{
            f"sipm_{start_channel:02d}_adc_avg": high,
            f"sipm_{start_channel + 1:02d}_adc_avg": low,
        })
    elif status_type == 0x49:
        decoded = decoded_pairs(heading_degrees=round(high / 10.0, 1), pitch_degrees=round(signed_low / 10.0, 1))
    elif status_type == 0x4A:
        decoded = decoded_pairs(
            roll_degrees=round(signed_high / 10.0, 1),
            calibration_status=b2,
        )
    elif status_type == 0x4B:
        decoded = decoded_pairs(accel_x_mg=signed_high, accel_y_mg=signed_low)
    elif status_type == 0x4C:
        decoded = decoded_pairs(accel_z_mg=signed_high)
    elif status_type == 0x4D:
        decoded = decoded_pairs(
            top_temp_c=signed_high / 100.0,
            top_middle_temp_c=signed_low / 100.0,
        )
    elif status_type == 0x4E:
        decoded = decoded_pairs(
            middle_bottom_temp_c=signed_high / 100.0,
            bottom_temp_c=signed_low / 100.0,
        )
    elif status_type == 0x4F:
        decoded = decoded_pairs(
            gps_temp_c=signed_high / 100.0,
            mag_computation_temp_c=signed_low / 100.0,
        )
    elif status_type == 0x50:
        decoded = decoded_pairs(
            power_heater=f"{duty_percent(b0)}%",
            telemetry_heater=f"{duty_percent(b1)}%",
            signal_heater=f"{duty_percent(b2)}%",
            sipm_heater=f"{duty_percent(b3)}%",
        )
    elif status_type == 0x51:
        decoded = decoded_pairs(
            power_fan=f"{duty_percent(b0)}%",
            telemetry_fan=f"{duty_percent(b1)}%",
            signal_fan=f"{duty_percent(b2)}%",
            sipm_fan=f"{duty_percent(b3)}%",
        )
    elif status_type == 0x54:
        decoded = decoded_pairs(rejected_inputs=high, complement_failures=low)
    else:
        decoded = decoded_pairs(raw_unsigned=status_data)

    return {
        "status_type_hex": f"0x{status_type:02X}",
        "status_name": name,
        "status_data_signed": signed_from_unsigned(status_data, 32),
        "status_data_hex": f"0x{status_data:08X}",
        "status_decoded": decoded,
        "status_roll_index": expected_index + 1,
        "status_expected_type": expected_type,
        "status_expected_type_hex": f"0x{expected_type:02X}",
        "status_schedule_ok": status_type == expected_type,
    }


HEX_LINE_RE = re.compile(r"^(?:(?:0x)?[0-9A-Fa-f]{2})+$")


def extract_hex_bytes_from_line(line: str) -> bytes | None:
    """Pull raw bytes out of one input line, stripping any DOWNLINK_HEX marker.

    Returns None if the line isn't pure hex data (e.g. unrelated log text),
    so it can be excluded from the packet stream rather than corrupting it.
    Returns b"" for a blank line.
    """
    payload = line.strip()
    marker_idx = payload.find("DOWNLINK_HEX")
    if marker_idx >= 0:
        payload = payload[marker_idx + len("DOWNLINK_HEX"):].strip()

    compact = re.sub(r"\s+", "", payload)
    if not compact:
        return b""
    if not HEX_LINE_RE.match(compact):
        return None

    hex_tokens = re.findall(r"(?:0x)?([0-9A-Fa-f]{2})", compact)
    return bytes(int(token, 16) for token in hex_tokens)


def decode_packet(packet: bytes, packet_number: int) -> dict[str, object]:
    frame_ok = packet[0] == START_MARKER and packet[49] == END_MARKER
    received_crc = u16_be(packet, 47)
    calculated_crc = crc16_ccitt_false(packet[1:47])

    pressure_satellite = u16_be(packet, 28)
    pressure_mbar = pressure_satellite >> 4
    satellite_index = pressure_satellite & 0x0F

    sipm_power_temp = packet[38]
    sipm_teensy_temp = packet[40]
    telemetry_temp = packet[41]
    status_type = packet[42]
    status_data = u32_be(packet, 43)

    row: dict[str, object] = {
        "packet_number": packet_number,
        "sequence_number": u16_be(packet, 1),
        "payload_id": packet[3],
        "timestamp_unix": u32_be(packet, 4),
        "timestamp_utc": utc_string(u32_be(packet, 4)),
        "threshold_01_mv": packet[24] * 4,
        "threshold_02_mv": packet[25] * 4,
        "threshold_03_mv": packet[26] * 4,
        "threshold_04_mv": packet[27] * 4,
        "pressure_mbar": pressure_mbar,
        "satellite_index": satellite_index,
        "satellite_count_range": satellite_range(satellite_index),
        "altitude_m": u16_be(packet, 30),
        "magnetometer_x_uT": s16_be(packet, 32),
        "magnetometer_y_uT": s16_be(packet, 34),
        "magnetometer_z_uT": s16_be(packet, 36),
        "sipm_stack_temp_c": temp_from_nibble((sipm_power_temp >> 4) & 0x0F),
        "power_board_temp_c": temp_from_nibble(sipm_power_temp & 0x0F),
        "control_board_temp_c": int.from_bytes(packet[39:40], "big", signed=True),
        "sipm_teensy1_temp_c": temp_from_nibble((sipm_teensy_temp >> 4) & 0x0F),
        "sipm_teensy2_temp_c": temp_from_nibble(sipm_teensy_temp & 0x0F),
        "telemetry_teensy_temp_c": temp_from_nibble((telemetry_temp >> 4) & 0x0F),
        "telemetry_board_temp_c": temp_from_nibble(telemetry_temp & 0x0F),
        "status_type": status_type,
        "status_data": status_data,
        **decode_status(status_type, status_data, packet_number),
        "crc_received": f"0x{received_crc:04X}",
        "crc_calculated": f"0x{calculated_crc:04X}",
        "crc_ok": received_crc == calculated_crc,
        "frame_ok": frame_ok,
        "raw_hex": packet.hex(" ").upper(),
    }

    for idx in range(16):
        row[f"sipm_{idx + 1:02d}_trigger_count"] = packet[8 + idx]

    return row


def decode_text(text: str) -> tuple[list[dict], int, int]:
    """Decode all packets from a text string.

    Packets don't need to be one-per-line: hex bytes from every valid hex
    line are concatenated into a single stream and then sliced into fixed
    RECORD_SIZE chunks. This handles the usual one-record-per-line input as
    well as a continuous hex blob with no line breaks between records,
    both reduce to the same underlying byte stream. Returns
    (rows, decoded_count, ignored_count).
    """
    buffer = bytearray()
    ignored_lines = 0
    for line in text.splitlines():
        chunk = extract_hex_bytes_from_line(line)
        if chunk is None:
            ignored_lines += 1
            continue
        buffer.extend(chunk)

    full_records = len(buffer) // RECORD_SIZE
    rows = [
        decode_packet(bytes(buffer[i * RECORD_SIZE:(i + 1) * RECORD_SIZE]), i + 1)
        for i in range(full_records)
    ]

    leftover = len(buffer) - full_records * RECORD_SIZE
    ignored = ignored_lines + (1 if leftover else 0)
    return rows, len(rows), ignored


def decode_binary(data: bytes) -> tuple[list[dict], int, int]:
    """Decode fixed-size packets from a raw binary stream.

    The scan advances by a complete record after a framed packet and by one
    byte after a false start marker. This preserves CRC-failing packets for
    inspection while still allowing the decoder to resynchronize after
    unrelated or damaged bytes.
    """
    rows: list[dict] = []
    ignored_regions = 0
    cursor = 0

    while cursor < len(data):
        marker = data.find(bytes([START_MARKER]), cursor)
        if marker < 0:
            if cursor < len(data):
                ignored_regions += 1
            break
        if marker > cursor:
            ignored_regions += 1
        if len(data) - marker < RECORD_SIZE:
            ignored_regions += 1
            break

        candidate = data[marker:marker + RECORD_SIZE]
        if candidate[-1] != END_MARKER:
            ignored_regions += 1
            cursor = marker + 1
            continue

        rows.append(decode_packet(candidate, len(rows) + 1))
        cursor = marker + RECORD_SIZE

    return rows, len(rows), ignored_regions


def decode_bytes(data: bytes) -> tuple[list[dict], int, int]:
    """Decode either raw binary packets or the existing hexadecimal text."""
    rows, decoded, ignored = decode_binary(data)
    if decoded:
        return rows, decoded, ignored
    return decode_text(data.decode("utf-8", errors="replace"))


def decode_file(input_path: Path, output_path: Path) -> tuple[int, int]:
    """Decode binary or hex-text packets and write them to CSV."""
    rows, decoded, ignored = decode_bytes(input_path.read_bytes())

    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_HEADER)
        writer.writeheader()
        writer.writerows(rows)

    return decoded, ignored
