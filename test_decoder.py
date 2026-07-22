from __future__ import annotations

import unittest

from decoder import crc16_ccitt_false, decode_bytes


def make_packet(sequence: int) -> bytes:
    packet = bytearray(50)
    packet[0] = 0x7E
    packet[1:3] = sequence.to_bytes(2, "big")
    packet[3] = 0x42
    packet[24:28] = bytes([100, 100, 120, 120])
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


if __name__ == "__main__":
    unittest.main()
