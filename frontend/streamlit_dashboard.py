# Network Security Monitor Dashboard
# Fully integrated with real FastAPI endpoints

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import requests
from datetime import datetime
import time

# ============================================================================

st.set_page_config(
    page_title="Network Security Monitor",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================================================

st.markdown("""
<style>
.kpi-card {
    background-color: #ffffff;
    border-radius: 12px;
    padding: 16px;
    box-shadow: 0 1px 6px rgba(0,0,0,0.08);
    text-align: left;
    height: 110px;
}
.kpi-icon {
    font-size: 22px;
    margin-bottom: 6px;
}
.kpi-value {
    font-size: 26px;
    font-weight: 700;
    line-height: 1.2;
}
.kpi-label {
    font-size: 13px;
    color: #6b7280;
}            
.card {
    background: #ffffff;
    border-radius: 16px;
    padding: 18px 20px;
    box-shadow: 0 8px 24px rgba(0,0,0,0.06);
    margin-bottom: 18px;
}
            
.card-title { 
    font-size: 1.05rem;
    font-weight: 600;
    color: #2b2f38;
    margin-bottom: 12px;
}
h4 { 
    margin-top: 0;
    margin-bottom: 10px;
    font-weight: 600;
    color: #2b2f38; }
.badge { display: inline-block; margin-top: 8px; padding: 4px 10px; border-radius: 999px; font-size: 0.85rem; font-weight: 600; background: #e8f5e9; color: #2e7d32; }            
.block-container { padding-top: 1.1rem !important; padding-bottom: 2rem; }
h1 { margin-top: 0 !important; padding-top: 0 !important; margin-bottom: 0.4rem !important; }
h1 + div { margin-top: 0.2rem !important; }
hr { margin-top: 0.7rem !important; margin-bottom: 0.7rem !important; }
h3 { margin-top: 0.8rem !important; margin-bottom: 0.6rem !important; }
</style>
""", unsafe_allow_html=True)

# ============================================================================

API_BASE_URL = st.secrets.get("API_URL", "http://localhost:8000")

# ============================================================================

def fetch_overview():
    """Fetch overview statistics from dashboard.py"""
    try:
        r = requests.get(f"{API_BASE_URL}/dashboard/overview", timeout=5)
        if r.status_code == 200:
            data = r.json()
            return {
                "total_flows": data.get("total_flows", 0),
                "total_attacks": data.get("total_attacks", 0),
                "detection_rate": round(data.get("detection_rate", 0.0) * 100, 2),
                "avg_anomaly_index": data.get("average_anomaly_index", 0.0)
            }
    except Exception as e:
        st.error(f"Failed to fetch overview: {e}")
    return {"total_flows": 0, "total_attacks": 0, "detection_rate": 0, "avg_anomaly_index": 0}

def fetch_live_traffic(limit=10):
    """Fetch latest flows"""
    try:
        r = requests.get(f"{API_BASE_URL}/dashboard/live-traffic?limit={limit}", timeout=5)
        if r.status_code == 200:
            rows = []
            for row in r.json():
                rows.append({
                    "Time": row.get("timestamp", "-").split("T")[-1],
                    "Source IP": row.get("src_ip", "-"),
                    "Destination IP": row.get("dst_ip", "-"),
                    "Protocol": row.get("protocol", "-"),
                    "Attack Type": row.get("attack_type", "Normal") if row.get("is_confirmed_attack") else "Normal",
                    "Score": round(row.get("attack_score_unsupervised", 0), 2)
                })
            return rows
    except Exception as e:
        st.error(f"Failed to fetch live traffic: {e}")
    return []

def fetch_flow_summary():
    """Fetch flow summary / attack distribution"""
    try:
        r = requests.get(f"{API_BASE_URL}/dashboard/flow-summary", timeout=5)
        if r.status_code == 200:
            data = r.json()
            # Return distribution for charts
            distribution = {k: v for k, v in data.get("flow_class_counts", {}).items()}
            return distribution
    except Exception as e:
        st.error(f"Failed to fetch flow summary: {e}")
    return {"Normal": 0, "Attack": 0}

# ============================================================================

def fetch_time_trends():
    """Fetch packet rate trends over time from real API"""
    try:
        r = requests.get(f"{API_BASE_URL}/dashboard/time-trends", timeout=5)
        if r.status_code == 200:
            data = r.json()
            # Expecting: {"timestamps": [...], "packet_rate": [...]} from API
            timestamps = data.get("timestamps", [])
            packet_rates = data.get("packet_rate", [])
            return timestamps, packet_rates
    except Exception as e:
        st.error(f"Failed to fetch time trends: {e}")
    # fallback dummy
    now = time.time()
    timestamps = [now - i*60 for i in range(10)][::-1]
    packet_rates = [12000 + i*500 for i in range(10)]
    return timestamps, packet_rates


# ============================================================================

# Auto-refresh logic
if "last_refresh" not in st.session_state:
    st.session_state.last_refresh = time.time()
if "refresh_interval" not in st.session_state:
    st.session_state.refresh_interval = 5

if time.time() - st.session_state.last_refresh > st.session_state.refresh_interval:
    st.session_state.last_refresh = time.time()
    st.rerun()

# ============================================================================

# Fetch overview and live traffic
overview = fetch_overview()
traffic_df = pd.DataFrame(fetch_live_traffic(10))
attack_dist = fetch_flow_summary()

# ============================================================================

# Header
header_l, header_r = st.columns([4, 1])
with header_l:
    st.markdown("<h1>🔒 Network Security Monitor</h1>", unsafe_allow_html=True)

with header_r:
    if st.button("🔄 Refresh"):
        st.session_state.last_refresh = time.time()
        st.rerun()
    st.caption(datetime.now().strftime("%H:%M:%S"))

st.markdown("<hr style='margin: 14px 0;'>", unsafe_allow_html=True)

# ============================================================================

# KPI ROW
st.markdown("<h3>📊 Overview</h3>", unsafe_allow_html=True)
k1, k2, k3, k4, k5, k6 = st.columns(6)

with k1:
    st.markdown(f"""
    <div class="kpi-card">
        <div class="kpi-icon">📊</div>
        <div class="kpi-value">{overview['total_flows']:,}</div>
        <div class="kpi-label">Total Flows</div>
    </div>""", unsafe_allow_html=True)

with k2:
    st.markdown(f"""
    <div class="kpi-card">
        <div class="kpi-icon">🚨</div>
        <div class="kpi-value">{overview['total_attacks']:,}</div>
        <div class="kpi-label">Attack Count</div>
    </div>""", unsafe_allow_html=True)

with k3:
    st.markdown(f"""
    <div class="kpi-card">
        <div class="kpi-icon">🛡️</div>
        <div class="kpi-value">{overview['detection_rate']}%</div>
        <div class="kpi-label">Detection Rate</div>
    </div>""", unsafe_allow_html=True)

with k4:
    st.markdown(f"""
    <div class="kpi-card">
        <div class="kpi-icon">📈</div>
        <div class="kpi-value">{overview['avg_anomaly_index']:.2f}</div>
        <div class="kpi-label">Avg Anomaly Index</div>
    </div>""", unsafe_allow_html=True)

# ============================================================================

# Live Traffic Table with pagination
flows_per_page = 10
total_flows = overview.get("total_flows", 0)
total_pages = max(1, (total_flows + flows_per_page - 1) // flows_per_page)

if "page" not in st.session_state:
    st.session_state.page = 1

nav_l, nav_r = st.columns([4, 1])
with nav_r:
    prev, page, next_ = st.columns([1, 1, 1])
    if prev.button("◀"):
        if st.session_state.page > 1:
            st.session_state.page -= 1
            st.rerun()
    page.markdown(f"<div style='text-align:center;padding-top:8px'>{st.session_state.page}/{total_pages}</div>", unsafe_allow_html=True)
    if next_.button("▶"):
        if st.session_state.page < total_pages:
            st.session_state.page += 1
            st.rerun()

st.subheader("📡 Live Network Traffic")
st.dataframe(
    traffic_df,
    use_container_width=True,
    hide_index=True,
    height=360
)
st.caption(f"Showing {(st.session_state.page-1)*flows_per_page+1:,}–{min(st.session_state.page*flows_per_page, total_flows):,} of {total_flows:,} flows")
st.markdown("<hr style='margin: 14px 0;'>", unsafe_allow_html=True)

# ============================================================================

# Threat Analysis
st.markdown("<h3>📊 Threat Analysis</h3>", unsafe_allow_html=True)
c1, c2, c3 = st.columns([1.2, 1.6, 1.2])

with c1:
    st.markdown("#### Attack Summary")
    total = sum(attack_dist.values())
    for label, value in attack_dist.items():
        pct = (value / total) * 100 if total > 0 else 0
        st.markdown(f"""
        <div class="card">
            <h4>{label}</h4>
            <div class="card-value">{value:,}</div>
            <div class="badge">↑ {pct:.1f}%</div>
        </div>
        """, unsafe_allow_html=True)

with c2:
    st.markdown("#### Attack Type Distribution")
    fig = go.Figure(go.Bar(x=list(attack_dist.keys()), y=list(attack_dist.values()), marker_color=["#66BB6A", "#EF5350"]))
    fig.update_layout(height=320, margin=dict(l=20, r=20, t=30, b=20), showlegend=False)
    st.plotly_chart(fig, use_container_width=True)

with c3:
    st.markdown("#### Flow Anomaly Index")
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=overview['avg_anomaly_index'],
        gauge={
            "axis": {"range": [0, 1]},
            "bar": {"color": "#1E88E5"},
            "steps": [
                {"range": [0, 0.25], "color": "#C8E6C9"},
                {"range": [0.25, 0.5], "color": "#FFF9C4"},
                {"range": [0.5, 0.75], "color": "#FFE0B2"},
                {"range": [0.75, 1], "color": "#FFCDD2"},
            ],
        }
    ))
    fig.update_layout(height=320, margin=dict(t=20, b=10))
    st.plotly_chart(fig, use_container_width=True)


# ============================================================================

st.markdown("<h3>📈 Packet Rate Over Time</h3>", unsafe_allow_html=True)
st.markdown('<div class="card">', unsafe_allow_html=True)

timestamps, packet_rates = fetch_time_trends()

if timestamps and packet_rates:
    timestamps_fmt = [datetime.fromtimestamp(ts).strftime("%H:%M") for ts in timestamps]

    fig_trend = go.Figure(
        go.Scatter(
            x=timestamps_fmt,
            y=[rate / 1000 for rate in packet_rates],  # kpps
            mode="lines+markers",
            line=dict(color="#1E88E5", width=3),
            fill="tozeroy",
        )
    )

    fig_trend.update_layout(
        height=360,
        margin=dict(l=40, r=40, t=20, b=40),
        xaxis_title="Time",
        yaxis_title="Rate (kpps)",
        showlegend=False,
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
    )

    st.plotly_chart(fig_trend, use_container_width=True)
else:
    st.info("📭 No packet rate trend data available")

st.markdown('</div>', unsafe_allow_html=True)
# Sidebar
with st.sidebar:
    st.header("⚙️ Settings")
    st.selectbox("Time Range", ["5 min", "15 min", "1 hour", "24 hours"])
    st.slider("Anomaly Threshold", 0.0, 1.0, 0.5)
    st.select_slider("Auto refresh (sec)", [3, 5, 10, 15, 30], value=5)
    st.info(f"Total Flows: {total_flows:,}")

# Footer
st.markdown(
    "<div style='text-align:center;color:#888;font-size:12px'>"
    "© 2024 Network Security Monitor | Streamlit + FastAPI"
    "</div>",
    unsafe_allow_html=True
)
