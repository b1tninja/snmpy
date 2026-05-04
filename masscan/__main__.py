"""Allow running masscan module directly: python -m masscan."""

from __future__ import annotations

import argparse
import logging

from masscan.readscan import BannerStatus, MasscanReader


def main() -> None:
    """CLI entry point for reading masscan scan files."""
    parser = argparse.ArgumentParser(description="Read masscan scan output files")
    parser.add_argument(
        "path",
        nargs="?",
        default="snmp.scan",
        help="Path to masscan output file (default: snmp.scan)",
    )
    parser.add_argument(
        "--readscan",
        action="store_true",
        help="Alias for the default behavior (read scan file)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase log level (use -vv for debug)",
    )
    args = parser.parse_args()

    # Configure logging
    if args.verbose >= 2:
        logging.basicConfig(level=logging.DEBUG)
    elif args.verbose >= 1:
        logging.basicConfig(level=logging.INFO)
    else:
        logging.basicConfig(level=logging.WARNING)

    path = args.path
    reader = MasscanReader(path)
    print(f"Reading: {reader.path}")
    print(f"Version: {reader.version}")
    print(f"Start time: {reader.start_time}")
    print(f"Record count: {sum(1 for _ in reader)}")
    print()

    for record in reader:
        if args.verbose > 0:
            print(f"  {record}")
        else:
            parts = [
                f"{record.ip.exploded}:{record.port}",
                f"status={record.status.name}",
                f"ttl={record.ttl}",
            ]
            if isinstance(record, BannerStatus):
                parts.append(f"banner={record.banner!r}")
            print(f"  {' '.join(parts)}")


if __name__ == "__main__":
    main()