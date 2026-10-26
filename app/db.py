"""
Database Connection and Cached Query Helpers for Streamlit Dashboard (`app/db.py`).

Provides cached SQLAlchemy engine access (`st.cache_resource`) and cached
DataFrame query helpers (`st.cache_data`) joining `events` and `alerts` with
`ip_enrichment`. Automatically initializes the schema, events, GeoIP data,
and MITRE ATT&CK alerts if the database is empty.
"""

from __future__ import annotations

import sys
from datetime import date
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pandas as pd
import streamlit as st
from sqlalchemy import text
from sqlalchemy.engine import Engine

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from parser.load_events import get_engine, init_schema
from sql.run_rules import run_all_rules


@st.cache_resource(show_spinner="Connecting to PostgreSQL security analytics database...")
def get_cached_engine() -> Engine:
    """Return a cached SQLAlchemy Engine and ensure the database is populated."""
    engine = get_engine()
    init_schema(engine)

    with engine.connect() as conn:
        event_cnt = conn.execute(text("SELECT COUNT(*) FROM events")).scalar() or 0
        alert_cnt = conn.execute(text("SELECT COUNT(*) FROM alerts")).scalar() or 0

    if event_cnt == 0 or alert_cnt == 0:
        run_all_rules(include_benchmark=True)

    return engine


@st.cache_data(ttl=60, show_spinner=False)
def load_events_df() -> pd.DataFrame:
    """
    Fetch all structured SSH authentication events joined with GeoIP enrichment.
    """
    engine = get_cached_engine()
    query = text(
        """
        SELECT
            e.id,
            e.ts,
            e.event_type,
            e.username,
            e.src_ip,
            e.port,
            e.source,
            COALESCE(i.country, 'Unknown') AS country,
            COALESCE(i.city, 'Unknown') AS city,
            i.lat,
            i.lon
        FROM events e
        LEFT JOIN ip_enrichment i ON e.src_ip = i.ip
        ORDER BY e.ts ASC
        """
    )
    with engine.connect() as conn:
        df = pd.read_sql(query, conn)

    if not df.empty:
        df["ts"] = pd.to_datetime(df["ts"])
        df["date"] = df["ts"].dt.date
        df["hour"] = df["ts"].dt.floor("h")
    return df


@st.cache_data(ttl=60, show_spinner=False)
def load_alerts_df() -> pd.DataFrame:
    """
    Fetch all MITRE ATT&CK security alerts joined with GeoIP enrichment.
    """
    engine = get_cached_engine()
    query = text(
        """
        SELECT
            a.id,
            a.ts,
            a.src_ip,
            COALESCE(i.country, 'Unknown') AS country,
            COALESCE(i.city, 'Unknown') AS city,
            i.lat,
            i.lon,
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
    with engine.connect() as conn:
        df = pd.read_sql(query, conn)

    if not df.empty:
        df["ts"] = pd.to_datetime(df["ts"])
        df["date"] = df["ts"].dt.date
    return df


def apply_filters(
    events_df: pd.DataFrame,
    alerts_df: pd.DataFrame,
    date_range: Optional[Tuple[date, date]] = None,
    countries: Optional[List[str]] = None,
    severities: Optional[List[str]] = None,
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Filter both `events_df` and `alerts_df` using the sidebar selections.
    """
    f_events = events_df.copy()
    f_alerts = alerts_df.copy()

    if date_range and len(date_range) == 2:
        start_d, end_d = date_range
        if not f_events.empty:
            f_events = f_events[
                (f_events["date"] >= start_d) & (f_events["date"] <= end_d)
            ]
        if not f_alerts.empty:
            f_alerts = f_alerts[
                (f_alerts["date"] >= start_d) & (f_alerts["date"] <= end_d)
            ]

    if countries:
        if not f_events.empty:
            f_events = f_events[f_events["country"].isin(countries)]
        if not f_alerts.empty:
            f_alerts = f_alerts[f_alerts["country"].isin(countries)]

    if severities:
        if not f_alerts.empty:
            f_alerts = f_alerts[f_alerts["severity"].isin(severities)]

    return f_events, f_alerts


def compute_kpis(events_df: pd.DataFrame, alerts_df: pd.DataFrame) -> Dict[str, int]:
    """Compute the top-level KPI metrics from filtered DataFrames."""
    total_events = int(len(events_df))
    unique_ips = (
        int(events_df["src_ip"].nunique()) if not events_df.empty else 0
    )
    total_alerts = int(len(alerts_df))
    critical_alerts = (
        int((alerts_df["severity"] == "Critical").sum())
        if not alerts_df.empty
        else 0
    )
    return {
        "total_events": total_events,
        "unique_ips": unique_ips,
        "total_alerts": total_alerts,
        "critical_alerts": critical_alerts,
    }
