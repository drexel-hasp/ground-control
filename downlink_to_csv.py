#!/usr/bin/env python3
"""Decode telemetry downlink debug byte lines into CSV.

Expected input is a text capture from USB serial where each downlink packet is
printed by firmware as:

    DOWNLINK_HEX 7E000042...7F

Bare 50-byte hex lines are also accepted. The older spaced debug format is
accepted too. Other logger lines are ignored.
"""

from __future__ import annotations

import argparse
import csv
import re
import sys
from datetime import datetime, timezone
from pathlib import Path


RECORD_SIZE = 50
START_MARKER = 0x7E
END_MARKER = 0x7F


CSV_HEADER = [
    "line_number",
    "sequence_number",
    "payload_id",
    "timestamp_unix",
    "timestamp_utc",
    *[f"sipm_{idx:02d}_trigger_count" for idx in range(1, 17)],
    "threshold_01_mv",
    "threshold_02_mv",
    "threshold_03_mv",
    "threshold_04_mv",
    "pressure_mbar",
    "satellite_index",
    "satellite_count_range",
    "altitude_m",
    "magnetometer_x_uT",
    "magnetometer_y_uT",
    "magnetometer_z_uT",
    "sipm_stack_temp_c",
    "power_board_temp_c",
    "control_board_temp_c",
    "sipm_teensy1_temp_c",
    "sipm_teensy2_temp_c",
    "telemetry_teensy_temp_c",
    "telemetry_board_temp_c",
    "status_type",
    "status_data",
    "crc_received",
    "crc_calculated",
    "crc_ok",
    "frame_ok",
    "raw_hex",
]


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


def s32_be(packet: bytes, offset: int) -> int:
    return int.from_bytes(packet[offset : offset + 4], "big", signed=True)


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


def extract_packet_from_line(line: str) -> bytes | None:
    payload = line.strip()
    marker_idx = payload.find("DOWNLINK_HEX")
    if marker_idx >= 0:
        payload = payload[marker_idx + len("DOWNLINK_HEX") :]

    hex_tokens = re.findall(r"(?:0x)?([0-9A-Fa-f]{2})", payload)
    if len(hex_tokens) != RECORD_SIZE:
        return None
    return bytes(int(token, 16) for token in hex_tokens)


def decode_packet(packet: bytes, line_number: int) -> dict[str, object]:
    frame_ok = packet[0] == START_MARKER and packet[49] == END_MARKER
    received_crc = u16_be(packet, 47)
    calculated_crc = crc16_ccitt_false(packet[1:47])

    pressure_satellite = u16_be(packet, 28)
    pressure_mbar = pressure_satellite >> 4
    satellite_index = pressure_satellite & 0x0F

    sipm_power_temp = packet[38]
    sipm_teensy_temp = packet[40]
    telemetry_temp = packet[41]

    row: dict[str, object] = {
        "line_number": line_number,
        "sequence_number": u16_be(packet, 1),
        "payload_id": packet[3],
        "timestamp_unix": u32_be(packet, 4),
        "timestamp_utc": utc_string(u32_be(packet, 4)),
        "threshold_01_mv": packet[24],
        "threshold_02_mv": packet[25],
        "threshold_03_mv": packet[26],
        "threshold_04_mv": packet[27],
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
        "status_type": packet[42],
        "status_data": s32_be(packet, 43),
        "crc_received": f"0x{received_crc:04X}",
        "crc_calculated": f"0x{calculated_crc:04X}",
        "crc_ok": received_crc == calculated_crc,
        "frame_ok": frame_ok,
        "raw_hex": packet.hex(" ").upper(),
    }

    for idx in range(16):
        row[f"sipm_{idx + 1:02d}_trigger_count"] = packet[8 + idx]

    return row


def default_output_path(input_path: Path) -> Path:
    return input_path.with_suffix(".csv")


def decode_file(input_path: Path, output_path: Path) -> tuple[int, int]:
    decoded_count = 0
    ignored_count = 0

    with input_path.open("r", encoding="utf-8", errors="replace") as source, \
            output_path.open("w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(destination, fieldnames=CSV_HEADER)
        writer.writeheader()

        for line_number, line in enumerate(source, start=1):
            packet = extract_packet_from_line(line)
            if packet is None:
                ignored_count += 1
                continue

            writer.writerow(decode_packet(packet, line_number))
            decoded_count += 1

    return decoded_count, ignored_count


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Decode HASP downlink debug byte lines to CSV."
    )
    parser.add_argument("input", type=Path, help="Text file with packet lines")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Output CSV path; defaults to input path with .csv suffix",
    )
    args = parser.parse_args()

    input_path = args.input
    output_path = args.output or default_output_path(input_path)

    decoded_count, ignored_count = decode_file(input_path, output_path)
    print(
        f"Decoded {decoded_count} packet(s) to {output_path}; "
        f"ignored {ignored_count} non-packet line(s)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
