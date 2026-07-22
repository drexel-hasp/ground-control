#!/usr/bin/env python3
"""CLI: decode a raw-binary or hex-text HASP downlink file to CSV.

Usage:
    python cli.py input.txt
    python cli.py input.txt -o output.csv
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from decoder import decode_file


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Decode HASP downlink debug byte lines to CSV."
    )
    parser.add_argument(
        "input", type=Path, help="Raw binary file or text file with hex packet lines"
    )
    parser.add_argument(
        "-o", "--output",
        type=Path,
        help="Output CSV path (default: input filename with .csv extension)",
    )
    args = parser.parse_args()

    input_path: Path = args.input
    if not input_path.exists():
        print(f"Error: file not found: {input_path}", file=sys.stderr)
        return 1

    output_path: Path = args.output or input_path.with_suffix(".csv")

    decoded, ignored = decode_file(input_path, output_path)
    print(
        f"Decoded {decoded} packet(s) to {output_path}  "
        f"({ignored} non-packet line(s) ignored)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
