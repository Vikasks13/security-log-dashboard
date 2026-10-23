"""
Unit tests for the SSH Log Parser module.

Tests coverage across:
- Failed password (both valid user and invalid user)
- Invalid user
- Accepted password
- Malformed and non-matching lines (disconnections, reverse DNS, garbage strings)
- Whole file parsing with parsed vs skipped summary validation
"""

import tempfile
from pathlib import Path

import pytest
from parser.ssh_parser import (
    EVENT_ACCEPTED_PASSWORD,
    EVENT_FAILED_PASSWORD,
    EVENT_INVALID_USER,
    SSHLogParser,
    parse_file,
    parse_line,
)

# Sample test lines
LINE_FAILED_PASSWORD_VALID_USER = (
    "Dec 10 07:13:43 LabSZ sshd[24227]: Failed password for root from 5.36.59.76 port 42393 ssh2"
)
LINE_FAILED_PASSWORD_INVALID_USER = (
    "Dec 10 06:55:48 LabSZ sshd[24200]: Failed password for invalid user webmaster from 173.234.31.186 port 38926 ssh2"
)
LINE_INVALID_USER = (
    "Dec 10 06:55:46 LabSZ sshd[24200]: Invalid user webmaster from 173.234.31.186"
)
LINE_ACCEPTED_PASSWORD = (
    "Dec 10 09:32:20 LabSZ sshd[24680]: Accepted password for fztu from 119.137.62.142 port 49116 ssh2"
)
LINE_NON_MATCHING_REVERSE_DNS = (
    "Dec 10 06:55:46 LabSZ sshd[24200]: reverse mapping checking getaddrinfo for ns.marryaldkfaczcz.com [173.234.31.186] failed - POSSIBLE BREAK-IN ATTEMPT!"
)
LINE_NON_MATCHING_CONNECTION_CLOSED = (
    "Dec 10 07:02:47 LabSZ sshd[24203]: Connection closed by 212.47.254.145 [preauth]"
)
LINE_MALFORMED_GARBAGE = "CRITICAL_KERNEL_PANIC: unexpected failure at 0xdeadbeef"


class TestSSHParser:
    """Test suite for SSH log parsing logic."""

    def test_parse_failed_password_valid_user(self) -> None:
        """Verify extraction of failed password attempt with known username."""
        record = parse_line(LINE_FAILED_PASSWORD_VALID_USER)
        assert record is not None
        assert record["timestamp"] == "Dec 10 07:13:43"
        assert record["host"] == "LabSZ"
        assert record["event_type"] == EVENT_FAILED_PASSWORD
        assert record["username"] == "root"
        assert record["src_ip"] == "5.36.59.76"
        assert record["port"] == 42393

    def test_parse_failed_password_invalid_user(self) -> None:
        """Verify extraction of failed password attempt with invalid user flag."""
        record = parse_line(LINE_FAILED_PASSWORD_INVALID_USER)
        assert record is not None
        assert record["timestamp"] == "Dec 10 06:55:48"
        assert record["host"] == "LabSZ"
        assert record["event_type"] == EVENT_FAILED_PASSWORD
        assert record["username"] == "webmaster"
        assert record["src_ip"] == "173.234.31.186"
        assert record["port"] == 38926

    def test_parse_invalid_user(self) -> None:
        """Verify extraction of invalid user dictionary scan attempt."""
        record = parse_line(LINE_INVALID_USER)
        assert record is not None
        assert record["timestamp"] == "Dec 10 06:55:46"
        assert record["host"] == "LabSZ"
        assert record["event_type"] == EVENT_INVALID_USER
        assert record["username"] == "webmaster"
        assert record["src_ip"] == "173.234.31.186"
        assert record["port"] is None

    def test_parse_accepted_password(self) -> None:
        """Verify extraction of successful authentication event."""
        record = parse_line(LINE_ACCEPTED_PASSWORD)
        assert record is not None
        assert record["timestamp"] == "Dec 10 09:32:20"
        assert record["host"] == "LabSZ"
        assert record["event_type"] == EVENT_ACCEPTED_PASSWORD
        assert record["username"] == "fztu"
        assert record["src_ip"] == "119.137.62.142"
        assert record["port"] == 49116

    @pytest.mark.parametrize(
        "non_matching_line",
        [
            LINE_NON_MATCHING_REVERSE_DNS,
            LINE_NON_MATCHING_CONNECTION_CLOSED,
            LINE_MALFORMED_GARBAGE,
            "",
            "   ",
        ],
    )
    def test_skip_non_matching_and_malformed_lines(self, non_matching_line: str) -> None:
        """Verify that irrelevant, malformed, or blank lines are skipped (return None)."""
        record = parse_line(non_matching_line)
        assert record is None

    def test_parse_file_summary_metrics(self) -> None:
        """Verify parse_file computes correct parsed vs skipped counts and breakdown."""
        test_content = "\n".join(
            [
                LINE_FAILED_PASSWORD_VALID_USER,
                LINE_NON_MATCHING_REVERSE_DNS,
                LINE_INVALID_USER,
                LINE_NON_MATCHING_CONNECTION_CLOSED,
                LINE_ACCEPTED_PASSWORD,
                LINE_MALFORMED_GARBAGE,
            ]
        )
        with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as tmp:
            tmp.write(test_content)
            tmp_path = Path(tmp.name)

        try:
            records, summary = parse_file(tmp_path)
            assert len(records) == 3
            assert summary["total_lines"] == 6
            assert summary["parsed_lines"] == 3
            assert summary["skipped_lines"] == 3
            assert summary["event_counts"][EVENT_FAILED_PASSWORD] == 1
            assert summary["event_counts"][EVENT_INVALID_USER] == 1
            assert summary["event_counts"][EVENT_ACCEPTED_PASSWORD] == 1
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

    def test_parse_real_sample_dataset(self) -> None:
        """Verify parser executes end-to-end against the OpenSSH_2k sample file."""
        dataset_path = Path("data/OpenSSH_2k.log")
        if not dataset_path.exists():
            pytest.skip("Sample dataset data/OpenSSH_2k.log not present.")

        records, summary = parse_file(dataset_path)
        assert summary["total_lines"] == 2000
        assert summary["parsed_lines"] == 632
        assert summary["skipped_lines"] == 1368
        assert summary["event_counts"][EVENT_FAILED_PASSWORD] == 518
        assert summary["event_counts"][EVENT_INVALID_USER] == 113
        assert summary["event_counts"][EVENT_ACCEPTED_PASSWORD] == 1
        assert len(records) == 632
