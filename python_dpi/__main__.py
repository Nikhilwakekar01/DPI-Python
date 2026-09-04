"""Command-line entry point for the Python DPI engine."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .dpi_engine import DPIEngine


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m python_dpi",
        description="Process a PCAP through the Python DPI engine.",
    )
    parser.add_argument("input_pcap", type=Path)
    parser.add_argument("output_pcap", type=Path)
    args = parser.parse_args(argv)

    engine = DPIEngine()
    if not engine.process(args.input_pcap, args.output_pcap):
        print("DPI processing failed.", file=sys.stderr)
        return 1

    print(f"Processed packets: {engine.stats.total_packets}")
    print(f"Forwarded: {engine.stats.forwarded}")
    print(f"Dropped: {engine.stats.dropped}")
    print(f"Total bytes: {engine.stats.total_bytes}")
    if engine.stats.app_counts:
        print("Applications:")
        for app, count in sorted(engine.stats.app_counts.items(), key=lambda item: item[0].name):
            print(f"  {app.name}: {count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
