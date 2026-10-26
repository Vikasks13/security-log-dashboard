"""
Security Log Analytics Dashboard - Streamlit Application (`app/main.py`).

Provides executive KPIs and interactive Plotly visualizations for:
- Hourly Attack Timeline by Event Type
- Top 10 Attacker Source IPs
- Top 10 Most Targeted Usernames
- Global Attacker Country / GeoIP Map
"""

from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import plotly.express as px
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

EVENT_COLOR_MAP = {
    "failed_password": "#ef4444",
    "invalid_user": "#f59e0b",
    "accepted_password": "#10b981",
}


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
        height=360,
        margin=dict(l=20, r=20, t=20, b=20),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
    )
    st.plotly_chart(fig, use_container_width=True)


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
            st.plotly_chart(fig_ips, use_container_width=True)

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
            st.plotly_chart(fig_users, use_container_width=True)


def render_country_map(events_df: pd.DataFrame) -> None:
    """Render the global attacker geolocation map and country summary."""
    st.subheader("🗺️ Global Attacker Origin Map (GeoLite2)")
    if events_df.empty or events_df["lat"].dropna().empty:
        st.info("No GeoIP coordinate telemetry available for the current filters.")
        return

    geo_df = (
        events_df.dropna(subset=["lat", "lon"])
        .groupby(["country", "city", "lat", "lon"], as_index=False)
        .agg(
            event_count=("id", "count"),
            unique_ips=("src_ip", "nunique"),
        )
        .sort_values("event_count", ascending=False)
    )

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
        height=440,
        margin=dict(l=10, r=10, t=10, b=10),
    )
    st.plotly_chart(fig_map, use_container_width=True)


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
    st.divider()
    render_timeline_chart(events_df)
    render_top_ips_and_usernames(events_df)
    render_country_map(events_df)


if __name__ == "__main__":
    main()
