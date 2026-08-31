from __future__ import annotations

import unittest

from quick_summary import build_quick_summary


def row(sequence: int, *, status_type: int = 0x21, status_data: int = 0, triggers: int = 0) -> dict:
    result = {
        "sequence_number": sequence & 0xFFFF,
        "status_type": status_type,
        "status_data": status_data,
        "crc_ok": True,
        "frame_ok": True,
    }
    for channel in range(1, 17):
        result[f"sipm_{channel:02d}_trigger_count"] = triggers
    return result


class QuickSummaryTests(unittest.TestCase):
    def test_rates_use_sequence_time_and_report_missing_packets(self) -> None:
        rows = [row(sequence, triggers=1) for sequence in range(0, 1500, 2)]

        summary = build_quick_summary(rows, generated_at=1000)
        five = summary["windows"]["5m"]

        self.assertAlmostEqual(five["coverage_seconds"], 299.8, places=1)
        self.assertAlmostEqual(five["packet_rate_hz"], 2.5, places=2)
        self.assertAlmostEqual(five["missing_percent"], 50.0, places=1)
        self.assertAlmostEqual(five["trigger_rates_hz"][0], 2.5, places=2)

    def test_latest_boot_segment_does_not_mix_pre_restart_packets(self) -> None:
        rows = [row(100 + i, triggers=9) for i in range(20)]
        rows.extend(row(i, triggers=1) for i in range(10))

        summary = build_quick_summary(rows, generated_at=1000)

        self.assertTrue(summary["recent_restart"])
        self.assertEqual(summary["valid_packets_used"], 10)
        self.assertAlmostEqual(summary["windows"]["5m"]["trigger_rates_hz"][0], 5.0)

    def test_old_sequence_boundary_is_not_called_a_recent_restart(self) -> None:
        rows = [row(1000 + i, status_type=0x31) for i in range(10)]
        rows.extend(row(i, status_type=0x31) for i in range(4000))

        summary = build_quick_summary(rows, generated_at=1000)

        self.assertFalse(summary["recent_restart"])
        self.assertGreater(summary["sequence_restart_age_seconds"], 300)

    def test_storage_stall_and_critical_degradation_raise_focused_alerts(self) -> None:
        rows = []
        schedule = [
            (0x31, 120),
            (0x32, 0),
            (0x35, 0x00030008),
            (0x36, 0),
            (0x2E, 1 << (18 - 1)),
        ]
        for sequence in range(1600):
            status_type, status_data = schedule[sequence % len(schedule)]
            rows.append(row(sequence, status_type=status_type, status_data=status_data, triggers=1))

        summary = build_quick_summary(rows, generated_at=1000)
        codes = {alert["code"] for alert in summary["alerts"]}

        self.assertIn("RECORDING STALLED", codes)
        self.assertIn("CRITICAL MODULE DEGRADED", codes)
        self.assertEqual(summary["degraded_modules"][0]["name"], "sipm_status_receiver")

    def test_counter_deltas_and_live_packet_age(self) -> None:
        rows = []
        for sequence in range(1600):
            if sequence % 4 == 0:
                status_type, status_data = 0x31, 100 + sequence // 4
            elif sequence % 4 == 1:
                status_type, status_data = 0x32, ((sequence // 400) << 16) | (sequence // 800)
            elif sequence % 4 == 2:
                status_type, status_data = 0x36, sequence // 1000
            else:
                status_type, status_data = 0x53, sequence // 500
            rows.append(row(sequence, status_type=status_type, status_data=status_data))

        summary = build_quick_summary(rows, live={"last_packet_at": 990}, generated_at=1000)

        self.assertEqual(summary["last_packet_age_seconds"], 10)
        self.assertGreater(summary["storage"]["windows"]["5m"]["records_delta"], 0)
        self.assertGreater(summary["uplink"]["windows"]["5m"]["accepted_delta"], 0)

    def test_invalid_packets_are_excluded(self) -> None:
        bad = row(2, triggers=200)
        bad["crc_ok"] = False

        summary = build_quick_summary([row(1, triggers=1), bad, row(3, triggers=1)], generated_at=1000)

        self.assertEqual(summary["valid_packets_used"], 2)
        self.assertLess(summary["windows"]["5m"]["trigger_rates_hz"][0], 10)


if __name__ == "__main__":
    unittest.main()
