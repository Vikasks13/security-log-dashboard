"""
SQL Detection Rule Runner for Security Log Analytics Dashboard.

Clears existing rows in `alerts`, executes all SQL detection rules in
`sql/rules/*.sql` in alphabetical order, and prints a summary of generated
MITRE ATT&CK alerts by rule and severity.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

from sqlalchemy import text

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from parser.enrich_ips import enrich_unique_ips
from parser.load_events import bulk_load_events, get_engine, init_schema

RULES_DIR = PROJECT_ROOT / "sql" / "rules"

# Supplemental benchmark events representing post-compromise and off-hours logins
# (since the 2,000-line OpenSSH_2k.log slice only spans 06:55-11:04 with 1 benign login)
BENCHMARK_ATTACK_EVENTS = [
    (
        datetime(2025, 12, 10, 11, 4, 50),
        "accepted_password",
        "root",
        "183.62.140.253",
        20999,
        "openssh_benchmark",
    ),
    (
        datetime(2025, 12, 10, 23, 14, 5),
        "accepted_password",
        "admin",
        "185.190.58.151",
        51234,
        "openssh_benchmark",
    ),
    (
        datetime(2025, 12, 10, 3, 42, 10),
        "accepted_password",
        "fztu",
        "119.137.62.142",
        48112,
        "openssh_benchmark",
    ),
]


def ensure_events_populated(include_benchmark: bool = True) -> None:
    """Ensure `events` and `ip_enrichment` tables are populated prior to rule execution."""
    engine = get_engine()
    init_schema(engine)

    with engine.connect() as conn:
        openssh_cnt = conn.execute(
            text("SELECT COUNT(*) FROM events WHERE source = 'openssh'")
        ).scalar()

    if not openssh_cnt:
        bulk_load_events()

    with engine.begin() as conn:
        conn.execute(text("DELETE FROM events WHERE source = 'openssh_benchmark'"))
        if include_benchmark:
            for ts, evt_type, user, ip, port, src in BENCHMARK_ATTACK_EVENTS:
                conn.execute(
                    text(
                        """
                        INSERT INTO events (ts, event_type, username, src_ip, port, source)
                        VALUES (:ts, :evt_type, :user, :ip, :port, :src)
                        """
                    ),
                    {
                        "ts": ts,
                        "evt_type": evt_type,
                        "user": user,
                        "ip": ip,
                        "port": port,
                        "src": src,
                    },
                )

    enrich_unique_ips()


def run_all_rules(
    rules_dir: Path = RULES_DIR,
    include_benchmark: bool = True,
) -> List[Tuple[str, int]]:
    """
    Clear old alerts and execute all `.sql` rule files in `sql/rules/` in order.

    Returns:
        List of (rule_filename, alerts_inserted_count) tuples.
    """
    ensure_events_populated(include_benchmark=include_benchmark)
    engine = get_engine()

    rule_files = sorted(rules_dir.glob("*.sql"))
    if not rule_files:
        raise FileNotFoundError(f"No SQL rule files found in {rules_dir}")

    results: List[Tuple[str, int]] = []
    with engine.begin() as conn:
        conn.execute(text("TRUNCATE TABLE alerts RESTART IDENTITY"))
        for rule_file in rule_files:
            sql_query = rule_file.read_text(encoding="utf-8")
            res = conn.execute(text(sql_query))
            inserted = res.rowcount if res.rowcount is not None and res.rowcount >= 0 else 0
            results.append((rule_file.name, inserted))

    return results


def fetch_alerts_summary() -> Tuple[List[Tuple[Any, ...]], List[Tuple[Any, ...]]]:
    """Retrieve rule breakdown and top generated alerts for inspection."""
    engine = get_engine()
    with engine.connect() as conn:
        rule_summary = conn.execute(
            text(
                """
                SELECT rule, severity, mitre_id, COUNT(*) AS alert_count
                FROM alerts
                GROUP BY rule, severity, mitre_id
                ORDER BY
                    CASE severity
                        WHEN 'Critical' THEN 1
                        WHEN 'High' THEN 2
                        WHEN 'Medium' THEN 3
                        ELSE 4
                    END,
                    alert_count DESC
                """
            )
        ).fetchall()

        all_alerts = conn.execute(
            text(
                """
                SELECT
                    a.id,
                    a.ts,
                    a.src_ip,
                    COALESCE(i.country, 'Unknown') AS country,
                    a.rule,
                    a.severity,
                    a.mitre_id,
                    a.details
                FROM alerts a
                LEFT JOIN ip_enrichment i ON a.src_ip = i.ip
                ORDER BY
                    CASE a.severity
                        WHEN 'Critical' THEN 1
                        WHEN 'High' THEN 2
                        WHEN 'Medium' THEN 3
                        ELSE 4
                    END,
                    a.ts DESC
                """
            )
        ).fetchall()

    return [tuple(r) for r in rule_summary], [tuple(r) for r in all_alerts]


def main() -> None:
    """CLI entrypoint for executing all MITRE ATT&CK SQL detection rules."""
    parser = argparse.ArgumentParser(
        description="Clear old alerts and run all SQL detection rules in order."
    )
    parser.add_argument(
        "--no-benchmark",
        action="store_true",
        help="Run solely against raw OpenSSH_2k.log without benchmark post-compromise/off-hours events.",
    )
    args = parser.parse_args()

    file_results = run_all_rules(include_benchmark=not args.no_benchmark)
    rule_summary, all_alerts = fetch_alerts_summary()

    print("=" * 76)
    print("           MITRE ATT&CK Detection Engine - Execution Summary")
    print("=" * 76)
    print("  Executed SQL Rule Files:")
    for fname, cnt in file_results:
        print(f"    - {fname:<34} -> {cnt:>3} alert(s) triggered")
    print("-" * 76)
    print(
        f"  {'Rule Name':<24} | {'Severity':<10} | {'MITRE ID':<10} | {'Alerts':>6}"
    )
    print("  " + "-" * 60)
    total_alerts = 0
    for rule, sev, mitre, cnt in rule_summary:
        total_alerts += cnt
        print(f"  {rule:<24} | {sev:<10} | {mitre:<10} | {cnt:>6}")
    print("  " + "-" * 60)
    print(f"  {'Total Alerts Generated':<48} | {total_alerts:>6}")
    print("=" * 76)

    if all_alerts:
        print("\nTop Triggered Security Alerts (Spot-Check):")
        for alert_id, ts, ip, country, rule, sev, mitre, details in all_alerts:
            print(
                f"  [{sev.upper():<8}] ({mitre}) {rule} | {ts} | IP: {ip} ({country})\n"
                f"             Details: {details}"
            )
        print()


if __name__ == "__main__":
    main()
