"""
Bulk Event Loader for Security Log Analytics Dashboard.

Parses OpenSSH log records using `parser.ssh_parser` and bulk-inserts them
into the PostgreSQL `events` table. Automatically falls back to an embedded
PostgreSQL instance (`.pgdata`) if no external PostgreSQL server is running.
"""

from __future__ import annotations

import argparse
import os
import socket
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import psycopg2
from psycopg2.extras import execute_values
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

# Ensure project root is on sys.path when invoked as `python parser/load_events.py`
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from parser.ssh_parser import parse_file

_PG_SERVER_INSTANCE = None


def _is_port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    """Check if a TCP port is accepting connections."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def get_database_url() -> str:
    """
    Resolve the PostgreSQL connection URI.

    Priority:
    1. DATABASE_URL environment variable
    2. External PostgreSQL server on POSTGRES_HOST:POSTGRES_PORT (default localhost:5432)
    3. Local embedded PostgreSQL server via `pgserver` stored in `.pgdata/`
    """
    global _PG_SERVER_INSTANCE

    env_url = os.getenv("DATABASE_URL")
    if env_url:
        if env_url.startswith("postgresql://"):
            return env_url.replace("postgresql://", "postgresql+psycopg2://", 1)
        return env_url

    host = os.getenv("POSTGRES_HOST", "127.0.0.1")
    port = int(os.getenv("POSTGRES_PORT", "5432"))
    user = os.getenv("POSTGRES_USER", "postgres")
    password = os.getenv("POSTGRES_PASSWORD", "postgres")
    db = os.getenv("POSTGRES_DB", "security_logs")

    if _is_port_open(host, port):
        return f"postgresql+psycopg2://{user}:{password}@{host}:{port}/{db}"

    # Fallback to embedded PostgreSQL server (`pgserver`)
    import pgserver

    pgdata_dir = PROJECT_ROOT / ".pgdata"
    if _PG_SERVER_INSTANCE is None:
        _PG_SERVER_INSTANCE = pgserver.get_server(str(pgdata_dir))
    uri = _PG_SERVER_INSTANCE.get_uri()
    return uri.replace("postgresql://", "postgresql+psycopg2://", 1)


def get_engine() -> Engine:
    """Create and return a SQLAlchemy Engine connected to PostgreSQL."""
    db_url = get_database_url()
    return create_engine(db_url, future=True)


def init_schema(engine: Engine, schema_path: Optional[Path] = None) -> None:
    """Execute `sql/01_schema.sql` to ensure tables and indexes exist."""
    if schema_path is None:
        schema_path = PROJECT_ROOT / "sql" / "01_schema.sql"

    sql_content = schema_path.read_text(encoding="utf-8")
    with engine.begin() as conn:
        conn.execute(text(sql_content))


def parse_syslog_timestamp(ts_str: str, default_year: int = 2025) -> datetime:
    """
    Convert syslog timestamp (e.g. 'Dec 10 06:55:46') into a Python datetime.
    """
    normalized = " ".join(ts_str.split())
    return datetime.strptime(f"{default_year} {normalized}", "%Y %b %d %H:%M:%S")


def prepare_rows(
    records: List[Dict[str, Any]],
    source: str = "openssh",
    default_year: int = 2025,
) -> List[Tuple[datetime, str, Optional[str], str, Optional[int], str]]:
    """Transform parsed event dictionaries into tuples ready for PostgreSQL bulk insert."""
    rows: List[Tuple[datetime, str, Optional[str], str, Optional[int], str]] = []
    for r in records:
        dt = parse_syslog_timestamp(r["timestamp"], default_year=default_year)
        rows.append(
            (
                dt,
                r["event_type"],
                r["username"],
                r["src_ip"],
                r["port"],
                source,
            )
        )
    return rows


def bulk_load_events(
    log_path: str | Path = "data/OpenSSH_2k.log",
    source: str = "openssh",
    default_year: int = 2025,
    replace_source: bool = True,
) -> Tuple[int, Dict[str, Any]]:
    """
    Parse the SSH log file and bulk-insert structured events into PostgreSQL.

    Returns:
        Tuple of (inserted_count, parse_summary)
    """
    engine = get_engine()
    init_schema(engine)

    records, summary = parse_file(log_path)
    rows = prepare_rows(records, source=source, default_year=default_year)

    raw_conn = engine.raw_connection()
    try:
        with raw_conn.cursor() as cur:
            if replace_source:
                cur.execute("DELETE FROM events WHERE source = %s", (source,))
            if rows:
                insert_query = """
                    INSERT INTO events (ts, event_type, username, src_ip, port, source)
                    VALUES %s
                """
                execute_values(cur, insert_query, rows, page_size=1000)
        raw_conn.commit()
    finally:
        raw_conn.close()

    return len(rows), summary


def main() -> None:
    """CLI entrypoint for bulk loading SSH events into PostgreSQL."""
    parser = argparse.ArgumentParser(
        description="Bulk-load parsed OpenSSH log events into PostgreSQL."
    )
    parser.add_argument(
        "logfile",
        nargs="?",
        default=str(PROJECT_ROOT / "data" / "OpenSSH_2k.log"),
        help="Path to OpenSSH log file (default: data/OpenSSH_2k.log)",
    )
    parser.add_argument(
        "--source",
        default="openssh",
        help="Source label stored in events.source (default: openssh)",
    )
    parser.add_argument(
        "--year",
        type=int,
        default=2025,
        help="Year assigned to syslog timestamps lacking a year (default: 2025)",
    )
    args = parser.parse_args()

    inserted_count, summary = bulk_load_events(
        log_path=args.logfile,
        source=args.source,
        default_year=args.year,
        replace_source=True,
    )

    engine = get_engine()
    with engine.connect() as conn:
        total_in_db = conn.execute(text("SELECT COUNT(*) FROM events")).scalar()
        unique_ips = conn.execute(
            text("SELECT COUNT(DISTINCT src_ip) FROM events")
        ).scalar()
        type_rows = conn.execute(
            text(
                "SELECT event_type, COUNT(*) AS cnt "
                "FROM events GROUP BY event_type ORDER BY cnt DESC"
            )
        ).fetchall()

    print("=" * 64)
    print("        PostgreSQL Event Loader - Execution Summary")
    print("=" * 64)
    print(f"  Log File Processed : {args.logfile}")
    print(f"  Total Lines Read   : {summary['total_lines']:,}")
    print(f"  Skipped Lines      : {summary['skipped_lines']:,}")
    print(f"  Bulk Inserted Rows : {inserted_count:,}")
    print(f"  Total DB Events    : {total_in_db:,}")
    print(f"  Unique Source IPs  : {unique_ips:,}")
    print("-" * 64)
    print("  Database Breakdown by Event Type:")
    for evt_type, cnt in type_rows:
        print(f"    - {evt_type:<20}: {cnt:>5,}")
    print("=" * 64)


if __name__ == "__main__":
    main()
