from __future__ import annotations

import unittest

from decoder import crc16_ccitt_false, decode_bytes


def make_packet(sequence: int, *, status_type: int = 0x21, status_data: int = 0) -> bytes:
    packet = bytearray(50)
    packet[0] = 0x7E
    packet[1:3] = sequence.to_bytes(2, "big")
    packet[3] = 0x42
    packet[24:28] = bytes([100, 100, 120, 120])
    packet[42] = status_type
    packet[43:47] = status_data.to_bytes(4, "big", signed=False)
    packet[47:49] = crc16_ccitt_false(packet[1:47]).to_bytes(2, "big")
    packet[49] = 0x7F
    return bytes(packet)


class DecodeBytesTests(unittest.TestCase):
    def test_decodes_raw_binary_packets(self) -> None:
        rows, decoded, ignored = decode_bytes(make_packet(7) + make_packet(8))

        self.assertEqual(decoded, 2)
        self.assertEqual(ignored, 0)
        self.assertEqual([row["sequence_number"] for row in rows], [7, 8])
        self.assertTrue(all(row["crc_ok"] for row in rows))

    def test_preserves_hex_text_support(self) -> None:
        text = "\n".join([make_packet(9).hex(), make_packet(10).hex()])
        rows, decoded, ignored = decode_bytes(text.encode("ascii"))

        self.assertEqual(decoded, 2)
        self.assertEqual(ignored, 0)
        self.assertEqual([row["sequence_number"] for row in rows], [9, 10])

    def test_resynchronizes_binary_after_noise(self) -> None:
        rows, decoded, ignored = decode_bytes(b"noise" + make_packet(11))

        self.assertEqual(decoded, 1)
        self.assertEqual(ignored, 1)
        self.assertEqual(rows[0]["sequence_number"], 11)

    def test_decodes_cpu_frequency_status_and_roll_slot(self) -> None:
        rows, decoded, ignored = decode_bytes(make_packet(7, status_type=0x24, status_data=0x96000000))

        self.assertEqual(decoded, 1)
        self.assertEqual(ignored, 0)
        row = rows[0]
        self.assertEqual(row["status_type_hex"], "0x24")
        self.assertEqual(row["status_name"], "CPU Frequency")
        self.assertEqual(row["status_data"], 0x96000000)
        self.assertLess(row["status_data_signed"], 0)
        self.assertEqual(row["status_roll_index"], 1)
        self.assertEqual(row["status_expected_type_hex"], "0x21")
        self.assertFalse(row["status_schedule_ok"])
        self.assertIn("telemetry_mhz=600", row["status_decoded"])

    def test_status_schedule_uses_packet_number(self) -> None:
        rows, _, _ = decode_bytes(make_packet(4, status_type=0x24, status_data=0x96000000))

        self.assertEqual(rows[0]["status_roll_index"], 1)
        self.assertEqual(rows[0]["status_expected_type_hex"], "0x21")
        self.assertFalse(rows[0]["status_schedule_ok"])

    def test_decodes_degraded_module_mask(self) -> None:
        rows, _, _ = decode_bytes(make_packet(1, status_type=0x2E, status_data=0x00020001))

        self.assertIn("main", rows[0]["status_decoded"])
        self.assertIn("sipm_status_receiver", rows[0]["status_decoded"])

    def test_decodes_threshold_status_bytes(self) -> None:
        rows, _, _ = decode_bytes(make_packet(1, status_type=0x3D, status_data=0x01020304))

        self.assertEqual(rows[0]["threshold_01_mv"], 400)
        self.assertEqual(rows[0]["threshold_02_mv"], 400)
        self.assertEqual(rows[0]["threshold_03_mv"], 480)
        self.assertEqual(rows[0]["threshold_04_mv"], 480)
        self.assertIn("sipm_01_threshold_mv=4", rows[0]["status_decoded"])
        self.assertIn("sipm_04_threshold_mv=16", rows[0]["status_decoded"])

    def test_decodes_packed_storage_and_ring_buffer_statuses(self) -> None:
        storage_rows, _, _ = decode_bytes(
            make_packet(1, status_type=0x32, status_data=0x00020003)
        )
        ring_rows, _, _ = decode_bytes(
            make_packet(1, status_type=0x35, status_data=0x00040009)
        )

        self.assertEqual(
            storage_rows[0]["status_decoded"],
            "data_recorder_failures=2; sd_writer_failures=3",
        )
        self.assertEqual(
            ring_rows[0]["status_decoded"],
            "current_depth=4; high_water_mark=9",
        )

    def test_decodes_session_file_index_as_u32(self) -> None:
        rows, _, _ = decode_bytes(
            make_packet(1, status_type=0x34, status_data=0x00010002)
        )

        self.assertEqual(
            rows[0]["status_decoded"], "session_file_index=65538"
        )
        self.assertNotIn("active_session_id", rows[0]["status_decoded"])

    def test_decodes_centi_celsius_temperature_statuses(self) -> None:
        rows, _, _ = decode_bytes(
            make_packet(1, status_type=0x4D, status_data=0x09C4FB2E)
        )

        self.assertEqual(
            rows[0]["status_decoded"],
            "top_temp_c=25.0; top_middle_temp_c=-12.34",
        )

    def test_decodes_rejected_uplink_status(self) -> None:
        rows, _, _ = decode_bytes(
            make_packet(1, status_type=0x54, status_data=0x00070002)
        )

        self.assertEqual(
            rows[0]["status_decoded"],
            "rejected_inputs=7; complement_failures=2",
        )


if __name__ == "__main__":
    unittest.main()
