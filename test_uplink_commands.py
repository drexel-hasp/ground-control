from __future__ import annotations

from pathlib import Path
import unittest


TEMPLATE = (Path(__file__).parent / "templates" / "index.html").read_text(
    encoding="utf-8"
)


class UplinkCommandBuilderTests(unittest.TestCase):
    def test_only_implemented_threshold_commands_are_listed(self) -> None:
        self.assertIn("Enable Auto Threshold Control", TEMPLATE)
        self.assertIn("code: 0x1E, fixed2: 0xE1", TEMPLATE)
        self.assertIn("Disable Auto Threshold Control", TEMPLATE)
        self.assertIn("code: 0x1F, fixed2: 0xE0", TEMPLATE)
        self.assertIn("code: 0x20 + i", TEMPLATE)
        self.assertIn("code: 0x30 + i", TEMPLATE)
        self.assertIn("scale: 4", TEMPLATE)
        self.assertIn("maxValue: 1020", TEMPLATE)
        self.assertIn("scale: 8", TEMPLATE)
        self.assertIn("maxValue: 2040", TEMPLATE)
        self.assertIn("two raw binary bytes", TEMPLATE)

        for unavailable_command in (
            "Telemetry Teensy Reset",
            "Set Telemetry Teensy CPU Freq",
            "Disable Fault Protection",
            "Enable Watchdog Timer",
            "Set Power Layer Heating",
            "Set Power Layer Fan",
            "Force SD Flush",
            "Enable Flash Data Recording",
        ):
            self.assertNotIn(unavailable_command, TEMPLATE)


if __name__ == "__main__":
    unittest.main()
