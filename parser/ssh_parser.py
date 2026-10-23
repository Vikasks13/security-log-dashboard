"""
SSH Log Parser module.

Extracts structured authentication events (failed_password, invalid_user, accepted_password)
from raw OpenSSH syslog lines and counts/skips non-matching entries.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Canonical event type constants
EVENT_FAILED_PASSWORD = "failed_password"
EVENT_INVALID_USER = "invalid_user"
EVENT_ACCEPTED_PASSWORD = "accepted_password"

# Syslog header pattern: extracts timestamp, hostname, optional PID, and message
SYSLOG_HEADER_PATTERN = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$"
)

# Authentication event patterns
EVENT_PATTERNS = [
    (
        EVENT_FAILED_PASSWORD,
        re.compile(
            r"^Failed password for\s+(?:invalid user\s+)?(?P<username>\S+)\s+from\s+(?P<src_ip>\S+)\s+port\s+(?P<port>\d+)(?:\s+ssh2)?"
        ),
    ),
    (
        EVENT_INVALID_USER,
        re.compile(
            r"^Invalid user\s+(?P<username>\S+)\s+from\s+(?P<src_ip>\S+)(?:\s+port\s+(?P<port>\d+))?"
        ),
    ),
    (
        EVENT_ACCEPTED_PASSWORD,
        re.compile(
            r"^Accepted\s+(?:password|publickey)\s+for\s+(?P<username>\S+)\s+from\s+(?P<src_ip>\S+)\s+port\s+(?P<port>\d+)(?:\s+ssh2)?"
        ),
    ),
]


@dataclass
class SSHEvent:
    """Represents a structured SSH authentication event."""

    timestamp: str
    host: str
    event_type: str
    username: str
    src_ip: str
    port: Optional[int]

    def to_dict(self) -> Dict[str, Any]:
        """Convert the dataclass event to a dictionary."""
        return asdict(self)


class SSHLogParser:
    """Parser engine for OpenSSH log files."""

    def __init__(self) -> None:
        self.header_pattern = SYSLOG_HEADER_PATTERN
        self.event_patterns = EVENT_PATTERNS

    def parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        """
        Parse a single syslog line.

        Returns:
            Dictionary containing timestamp, host, event_type, username, src_ip, port
            if line matches one of the 3 target event types; otherwise None.
        """
        clean_line = line.strip()
        if not clean_line:
            return None

        header_match = self.header_pattern.match(clean_line)
        if not header_match:
            return None

        timestamp = header_match.group("timestamp")
        host = header_match.group("host")
        message = header_match.group("message")

        for event_type, pattern in self.event_patterns:
            m = pattern.search(message)
            if m:
                port_val = m.groupdict().get("port")
                port = int(port_val) if port_val is not None else None
                event = SSHEvent(
                    timestamp=timestamp,
                    host=host,
                    event_type=event_type,
                    username=m.group("username"),
                    src_ip=m.group("src_ip"),
                    port=port,
                )
                return event.to_dict()

        return None

    def parse_file(
        self, filepath: str | Path
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Parse an entire log file.

        Returns:
            Tuple of:
              - list of structured event dictionaries
              - summary dictionary with total_lines, parsed_lines, skipped_lines, and event_counts
        """
        path = Path(filepath)
        if not path.is_file():
            raise FileNotFoundError(f"Log file not found: {filepath}")

        records: List[Dict[str, Any]] = []
        skipped_count = 0
        total_lines = 0
        event_counts: Dict[str, int] = {
            EVENT_FAILED_PASSWORD: 0,
            EVENT_INVALID_USER: 0,
            EVENT_ACCEPTED_PASSWORD: 0,
        }

        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                total_lines += 1
                record = self.parse_line(line)
                if record:
                    records.append(record)
                    event_counts[record["event_type"]] += 1
                else:
                    skipped_count += 1

        summary = {
            "total_lines": total_lines,
            "parsed_lines": len(records),
            "skipped_lines": skipped_count,
            "event_counts": event_counts,
        }
        return records, summary


# Convenience functional APIs
_DEFAULT_PARSER = SSHLogParser()


def parse_line(line: str) -> Optional[Dict[str, Any]]:
    """Parse a single SSH log line."""
    return _DEFAULT_PARSER.parse_line(line)


def parse_file(filepath: str | Path) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Parse an SSH log file and return (records, summary)."""
    return _DEFAULT_PARSER.parse_file(filepath)


def print_cli_summary(
    filepath: Path, records: List[Dict[str, Any]], summary: Dict[str, Any]
) -> None:
    """Print formatted summary of parsing results to stdout."""
    total = summary["total_lines"]
    parsed = summary["parsed_lines"]
    skipped = summary["skipped_lines"]
    counts = summary["event_counts"]

    parsed_pct = (parsed / total * 100) if total else 0.0
    skipped_pct = (skipped / total * 100) if total else 0.0

    print("=" * 64)
    print("           SSH Log Parser - Execution Summary")
    print("=" * 64)
    print(f"  Target Log File : {filepath}")
    print(f"  Total Lines     : {total:,}")
    print(f"  Parsed Events   : {parsed:,} ({parsed_pct:.2f}%)")
    print(f"  Skipped Lines   : {skipped:,} ({skipped_pct:.2f}%)")
    print("-" * 64)
    print("  Event Breakdown:")
    for evt, count in counts.items():
        evt_pct = (count / parsed * 100) if parsed else 0.0
        print(f"    - {evt:<20}: {count:>5,}  ({evt_pct:>5.1f}%)")
    print("=" * 64)

    if records:
        print("\nSample Structured Records:")
        sample_count = min(len(records), 5)
        for i, r in enumerate(records[:sample_count], 1):
            print(
                f"  [{i}] {r['timestamp']} | Host: {r['host']} | Type: {r['event_type']} "
                f"| User: {r['username']} | IP: {r['src_ip']} | Port: {r['port']}"
            )
        print()


def main() -> None:
    """CLI entrypoint for ssh_parser."""
    parser = argparse.ArgumentParser(
        description="Parse SSH syslog files into structured authentication events."
    )
    parser.add_argument(
        "logfile",
        nargs="?",
        default="data/OpenSSH_2k.log",
        help="Path to OpenSSH log file (default: data/OpenSSH_2k.log)",
    )
    parser.add_argument(
        "--json",
        "-j",
        dest="json_output",
        help="Optional path to output parsed events as JSON.",
    )
    args = parser.parse_args()

    log_path = Path(args.logfile)
    if not log_path.exists():
        print(f"Error: Log file does not exist at '{log_path}'.", file=sys.stderr)
        sys.exit(1)

    records, summary = parse_file(log_path)
    print_cli_summary(log_path, records, summary)

    if args.json_output:
        out_path = Path(args.json_output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as jf:
            json.dump(records, jf, indent=2)
        print(f"Successfully exported {len(records)} records to {out_path}")


if __name__ == "__main__":
    main()
