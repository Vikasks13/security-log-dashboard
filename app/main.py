"""
Security Log Analytics Dashboard - Streamlit Application (`app/main.py`).

Full interactive security operations dashboard featuring:
- Sidebar Filters (Date Range, Alert Severity, Attacker Country, MITRE Rule)
  applied across all views
- Executive KPI Row (Total Events, Unique Attacker IPs, Total Alerts, Critical Alerts)
- Hourly Attack Timeline by Event Type
- Top 10 Attacker Source IPs & Most Targeted Usernames
- Global Attacker Origin Map (GeoLite2)
- MITRE ATT&CK Security Alerts Table with CSV Export
"""

from __future__ import annotations

import sys
from datetime import date
from pathlib import Path
from typing import List, Optional, Tuple

import pandas as pd
import plotly.express as px
import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.db import apply_filters, compute_kpis, load_alerts_df, load_events_df
from sql.run_rules import run_all_rules

st.set_page_config(
    page_title="Security Log Analytics Dashboard | MITRE ATT&CK",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

EVENT_COLOR_MAP = {
    "failed_password": "#ef4444",
    "invalid_user": "#f59e0b",
    "accepted_password": "#10b981",
}

SEVERITY_BADGE_MAP = {
    "Critical": "🔴 Critical",
    "High": "🟠 High",
    "Medium": "🟡 Medium",
    "Low": "🟢 Low",
}


def render_sidebar_filters(
    events_df: pd.DataFrame, alerts_df: pd.DataFrame
) -> Tuple[Optional[Tuple[date, date]], List[str], List[str], List[str]]:
    """Render sidebar filter controls and return selected filter criteria."""
    st.sidebar.header("🔍 SOC Filter Controls")
    st.sidebar.caption("Filter telemetry and MITRE ATT&CK alerts across all views.")

    if not events_df.empty:
        min_date = events_df["date"].min()
        max_date = events_df["date"].max()
    else:
        min_date = date(2025, 12, 10)
        max_date = date(2025, 12, 10)

    date_selection = st.sidebar.date_input(
        "📅 Date Range",
        value=(min_date, max_date),
        min_value=min_date,
        max_value=max_date,
    )
    if isinstance(date_selection, tuple) and len(date_selection) == 2:
        selected_dates: Optional[Tuple[date, date]] = (
            date_selection[0],
            date_selection[1],
        )
    elif isinstance(date_selection, list) and len(date_selection) == 2:
        selected_dates = (date_selection[0], date_selection[1])
    elif isinstance(date_selection, date):
        selected_dates = (date_selection, date_selection)
    else:
        selected_dates = None

    severity_options = ["Critical", "High", "Medium"]
    selected_severities = st.sidebar.multiselect(
        "🚨 Alert Severity",
        options=severity_options,
        default=severity_options,
    )

    all_countries = (
        sorted(events_df["country"].dropna().unique().tolist())
        if not events_df.empty
        else []
    )
    selected_countries = st.sidebar.multiselect(
        "🌍 Attacker Country",
        options=all_countries,
        default=all_countries,
    )

    all_rules = (
        sorted(alerts_df["rule"].dropna().unique().tolist())
        if not alerts_df.empty
        else []
    )
    selected_rules = st.sidebar.multiselect(
        "🛡️ MITRE Detection Rule",
        options=all_rules,
        default=all_rules,
    )

    st.sidebar.divider()
    if st.sidebar.button("🔄 Re-run SQL Detection Rules", width="stretch"):
        run_all_rules(include_benchmark=True)
        st.cache_data.clear()
        st.rerun()

    st.sidebar.markdown(
        """
        ---
        **MITRE ATT&CK Coverage**
        - `T1110.001`: Brute Force (5m Window)
        - `T1110.003`: Password Spraying
        - `T1078`: Post-Compromise Login
        - `T1078`: Off-Hours Login
        """
    )

    return selected_dates, selected_countries, selected_severities, selected_rules


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


def render_timeline_chart(events_df: pd.DataFrame) -> None:
    """Render the hourly authentication & attack timeline."""
    st.subheader("📈 Hourly Attack Timeline")
    if events_df.empty:
        st.info("No authentication events match the current filter criteria.")
        return

    timeline_df = (
        events_df.groupby(["hour", "event_type"], as_index=False)
        .size()
        .rename(columns={"size": "events"})
    )
    fig = px.bar(
        timeline_df,
        x="hour",
        y="events",
        color="event_type",
        color_discrete_map=EVENT_COLOR_MAP,
        barmode="stack",
        labels={
            "hour": "Timestamp (Hourly Window)",
            "events": "Event Count",
            "event_type": "Event Type",
        },
        template="plotly_dark",
    )
    fig.update_layout(
        height=350,
        margin=dict(l=20, r=20, t=20, b=20),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
    )
    st.plotly_chart(fig, width="stretch")


def render_top_ips_and_usernames(events_df: pd.DataFrame) -> None:
    """Render side-by-side Top 10 Attacker IPs and Most Targeted Usernames."""
    col_ips, col_users = st.columns(2)

    with col_ips:
        st.subheader("🎯 Top 10 Attacker IPs")
        if events_df.empty:
            st.info("No source IP data available.")
        else:
            top_ips = (
                events_df.groupby(["src_ip", "country"], as_index=False)
                .size()
                .rename(columns={"size": "event_count"})
                .sort_values("event_count", ascending=False)
                .head(10)
                .sort_values("event_count", ascending=True)
            )
            fig_ips = px.bar(
                top_ips,
                x="event_count",
                y="src_ip",
                color="country",
                orientation="h",
                text="event_count",
                labels={
                    "src_ip": "Source IP",
                    "event_count": "Authentication Events",
                    "country": "Country",
                },
                template="plotly_dark",
            )
            fig_ips.update_traces(textposition="outside")
            fig_ips.update_layout(
                height=380,
                margin=dict(l=20, r=40, t=20, b=20),
                yaxis=dict(type="category"),
            )
            st.plotly_chart(fig_ips, width="stretch")

    with col_users:
        st.subheader("👤 Most Targeted Usernames")
        if events_df.empty:
            st.info("No username telemetry available.")
        else:
            top_users = (
                events_df.groupby("username", as_index=False)
                .size()
                .rename(columns={"size": "attempts"})
                .sort_values("attempts", ascending=False)
                .head(10)
                .sort_values("attempts", ascending=True)
            )
            fig_users = px.bar(
                top_users,
                x="attempts",
                y="username",
                orientation="h",
                text="attempts",
                color="attempts",
                color_continuous_scale="Reds",
                labels={
                    "username": "Targeted Username",
                    "attempts": "Login Attempts",
                },
                template="plotly_dark",
            )
            fig_users.update_traces(textposition="outside")
            fig_users.update_layout(
                height=380,
                margin=dict(l=20, r=40, t=20, b=20),
                coloraxis_showscale=False,
                yaxis=dict(type="category"),
            )
            st.plotly_chart(fig_users, width="stretch")


def render_country_map(events_df: pd.DataFrame) -> None:
    """Render the global attacker geolocation map and country summary."""
    st.subheader("🗺️ Global Attacker Origin Map (GeoLite2)")
    if events_df.empty or events_df["lat"].dropna().empty:
        st.info("No GeoIP coordinate telemetry available for the current filters.")
        return

    col_map, col_table = st.columns([2, 1])

    geo_df = (
        events_df.dropna(subset=["lat", "lon"])
        .groupby(["country", "city", "lat", "lon"], as_index=False)
        .agg(
            event_count=("id", "count"),
            unique_ips=("src_ip", "nunique"),
        )
        .sort_values("event_count", ascending=False)
    )

    with col_map:
        fig_map = px.scatter_geo(
            geo_df,
            lat="lat",
            lon="lon",
            size="event_count",
            color="country",
            hover_name="city",
            hover_data={
                "country": True,
                "event_count": True,
                "unique_ips": True,
                "lat": ":.2f",
                "lon": ":.2f",
            },
            size_max=42,
            projection="natural earth",
            template="plotly_dark",
        )
        fig_map.update_geos(
            showcountries=True,
            countrycolor="#334155",
            showcoastlines=True,
            coastlinecolor="#475569",
            showland=True,
            landcolor="#0f172a",
            showocean=True,
            oceancolor="#020617",
        )
        fig_map.update_layout(
            height=420,
            margin=dict(l=10, r=10, t=10, b=10),
        )
        st.plotly_chart(fig_map, width="stretch")

    with col_table:
        country_summary = (
            events_df.groupby("country", as_index=False)
            .agg(
                Events=("id", "count"),
                Unique_IPs=("src_ip", "nunique"),
            )
            .sort_values("Events", ascending=False)
            .rename(columns={"country": "Country", "Unique_IPs": "Unique IPs"})
        )
        st.dataframe(
            country_summary,
            width="stretch",
            hide_index=True,
            height=420,
        )


def render_alerts_table(alerts_df: pd.DataFrame) -> None:
    """Render the filterable MITRE ATT&CK security alerts table and CSV export."""
    st.subheader("🚨 MITRE ATT&CK Security Alerts")
    if alerts_df.empty:
        st.info("No security alerts match the selected filter criteria.")
        return

    display_df = alerts_df.copy()
    display_df["Severity"] = display_df["severity"].map(
        lambda s: SEVERITY_BADGE_MAP.get(s, s)
    )
    display_df["Timestamp"] = display_df["ts"].dt.strftime("%Y-%m-%d %H:%M:%S")
    display_df["MITRE Link"] = display_df["mitre_id"].map(
        lambda m: f"https://attack.mitre.org/techniques/{m.replace('.', '/')}/"
    )

    table_cols = [
        "Severity",
        "rule",
        "mitre_id",
        "src_ip",
        "country",
        "city",
        "Timestamp",
        "details",
    ]
    formatted_table = display_df[table_cols].rename(
        columns={
            "rule": "Detection Rule",
            "mitre_id": "MITRE ID",
            "src_ip": "Source IP",
            "country": "Country",
            "city": "City",
            "details": "Alert Details",
        }
    )

    st.dataframe(
        formatted_table,
        width="stretch",
        hide_index=True,
    )

    csv_bytes = formatted_table.to_csv(index=False).encode("utf-8")
    st.download_button(
        label="⬇️ Export Filtered Alerts (CSV)",
        data=csv_bytes,
        file_name="security_alerts_mitre.csv",
        mime="text/csv",
    )


def main() -> None:
    """Main Streamlit entrypoint."""
    st.title("🛡️ Security Log Analytics & MITRE ATT&CK Detection Dashboard")
    st.caption(
        "Real-time OpenSSH authentication telemetry, GeoLite2 IP intelligence, "
        "and SQL window-function detections mapped to MITRE ATT&CK."
    )

    raw_events_df = load_events_df()
    raw_alerts_df = load_alerts_df()

    selected_dates, selected_countries, selected_severities, selected_rules = (
        render_sidebar_filters(raw_events_df, raw_alerts_df)
    )

    filtered_events, filtered_alerts = apply_filters(
        raw_events_df,
        raw_alerts_df,
        date_range=selected_dates,
        countries=selected_countries,
        severities=selected_severities,
    )

    if selected_rules and not filtered_alerts.empty:
        filtered_alerts = filtered_alerts[filtered_alerts["rule"].isin(selected_rules)]

    kpis = compute_kpis(filtered_events, filtered_alerts)

    render_kpi_row(kpis)
    st.divider()
    render_timeline_chart(filtered_events)
    render_top_ips_and_usernames(filtered_events)
    st.divider()
    render_country_map(filtered_events)
    st.divider()
    render_alerts_table(filtered_alerts)


if __name__ == "__main__":
    main()
