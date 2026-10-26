"""
Security Log Analytics Dashboard - Streamlit Application (`app/main.py`).
"""

from __future__ import annotations

import sys
from pathlib import Path

import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.db import compute_kpis, load_alerts_df, load_events_df

st.set_page_config(
    page_title="Security Log Analytics Dashboard | MITRE ATT&CK",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


def render_kpi_row(kpis: dict[str, int]) -> None:
    """Render the top-level security metrics KPI row."""
    col1, col2, col3, col4 = st.columns(4)
    col1.metric(
        label="📊 Total Auth Events",
        value=f"{kpis['total_events']:,}",
        delta="OpenSSH Syslog Stream",
        delta_color="off",
    )
    col2.metric(
        label="🌐 Unique Attacker IPs",
        value=f"{kpis['unique_ips']:,}",
        delta="GeoIP Enriched",
        delta_color="off",
    )
    col3.metric(
        label="🚨 Total Security Alerts",
        value=f"{kpis['total_alerts']:,}",
        delta="4 MITRE ATT&CK Rules",
        delta_color="off",
    )
    col4.metric(
        label="🔥 Critical Alerts (T1078)",
        value=f"{kpis['critical_alerts']:,}",
        delta="Post-Compromise Logins",
        delta_color="inverse" if kpis["critical_alerts"] > 0 else "off",
    )


def main() -> None:
    """Main Streamlit entrypoint."""
    st.title("🛡️ Security Log Analytics & MITRE ATT&CK Detection Dashboard")
    st.caption(
        "Real-time OpenSSH authentication telemetry, GeoLite2 IP intelligence, "
        "and SQL window-function detections mapped to MITRE ATT&CK."
    )

    events_df = load_events_df()
    alerts_df = load_alerts_df()
    kpis = compute_kpis(events_df, alerts_df)

    render_kpi_row(kpis)


if __name__ == "__main__":
    main()
