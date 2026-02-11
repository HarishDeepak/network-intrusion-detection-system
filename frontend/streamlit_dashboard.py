# Network Security Monitor Dashboard
# Clean, working version with improved layout

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import requests
from datetime import datetime
import time

# ============================================================================
# PAGE CONFIG
# ============================================================================
st.set_page_config(
    page_title="Network Security Monitor",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)


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

/* Generic card container */

/* Card look for each column block */
.card {
    background: #ffffff;
    border-radius: 16px;
    padding: 18px 20px;
    box-shadow: 0 8px 24px rgba(0,0,0,0.06);
    margin-bottom: 18px;
}

/* Card titles */
.card-title {
    font-size: 1.05rem;
    font-weight: 600;
    color: #2b2f38;
    margin-bottom: 12px;
}

/* Section titles inside cards */
h4 {
    margin-top: 0;
    margin-bottom: 10px;
    font-weight: 600;
    color: #2b2f38;
}



/* Percentage badge */
.badge {
    display: inline-block;
    margin-top: 8px;
    padding: 4px 10px;
    border-radius: 999px;
    font-size: 0.85rem;
    font-weight: 600;
    background: #e8f5e9;
    color: #2e7d32;
}            
            
</style>
""", unsafe_allow_html=True)

st.markdown("""
<style>

/* Main page container: remove Streamlit's extra top space */
.block-container {
    padding-top: 1.1rem !important;   /* was too large before */
    padding-bottom: 2rem;
}

/* Title (Network Security Monitor) */
h1 {
    margin-top: 0 !important;
    padding-top: 0 !important;
    margin-bottom: 0.4rem !important;
}

/* Subtitle (SOC Dashboard - Student Edition) */
h1 + div {
    margin-top: 0.2rem !important;
}

/* Divider spacing (THIS was the main issue) */
hr {
    margin-top: 0.7rem !important;
    margin-bottom: 0.7rem !important;
}

/* Section headers like "Overview", "Live Network Traffic" */
h3 {
    margin-top: 0.8rem !important;
    margin-bottom: 0.6rem !important;
}

</style>
""", unsafe_allow_html=True)



# ============================================================================
# CONFIG
# ============================================================================
API_BASE_URL = st.secrets["API_URL"] if "API_URL" in st.secrets else "http://localhost:8000"

# ============================================================================
# API HELPERS
# ============================================================================
def fetch_stats():
    try:
        r = requests.get(f"{API_BASE_URL}/api/stats", timeout=5)
        if r.status_code == 200:
            return r.json()
    except:
        pass
    return {"packet_count": 2847324, "byte_count": 8700000000, "detection_rate": 94.3}

def fetch_packets(count=10):
    try:
        r = requests.get(f"{API_BASE_URL}/api/packets?count={count}", timeout=5)
        if r.status_code == 200:
            rows = []
            for item in r.json():
                p = item.get("packet", {})
                pred = item.get("prediction", {})
                rows.append({
                    "Time": datetime.fromtimestamp(p.get("timestamp", 0)).strftime("%H:%M:%S"),
                    "Source IP": p.get("src_ip", "-"),
                    "Destination IP": p.get("dest_ip", "-"),
                    "Protocol": p.get("protocol", "-").upper(),
                    "Bytes": f"{p.get('length', 0):,}",
                    "Attack Type": pred.get("label", "Unknown"),
                    "Score": round(pred.get("confidence", 0), 2)
                })
            return rows
    except:
        pass
    return []

def fetch_time_trends():
    """Fetch time trends from /api/analytics/time_trends"""
    try:
        response = requests.get(
            f"{API_BASE_URL}/api/analytics/time_trends",
            timeout=5
        )
        if response.status_code == 200:
            return response.json()
    except Exception:
        pass

    # Safe fallback (demo data)
    return {
        "timestamps": [time.time() - i * 60 for i in range(10)][::-1],
        "packet_rate": [12000, 13500, 14000, 13200, 14800, 15000, 14200, 13800, 14500, 15200],
        "flow_rate": [],
        "bytes_per_sec": []
    }


def fetch_attack_distribution():
    try:
        r = requests.get(f"{API_BASE_URL}/api/analytics/attack_distribution", timeout=5)
        if r.status_code == 200:
            return r.json().get("distribution", {})
    except:
        pass
    return {}

# ============================================================================
# AUTO REFRESH
# ============================================================================
if "last_refresh" not in st.session_state:
    st.session_state.last_refresh = time.time()
if "refresh_interval" not in st.session_state:
    st.session_state.refresh_interval = 5

if time.time() - st.session_state.last_refresh > st.session_state.refresh_interval:
    st.session_state.last_refresh = time.time()
    st.rerun()

# ============================================================================
# DATA
# ============================================================================
stats = fetch_stats()
packet_count = stats.get("packet_count", 0)
byte_count = stats.get("byte_count", 0)
detection_rate = stats.get("detection_rate", 0)

if "page" not in st.session_state:
    st.session_state.page = 1

flows_per_page = 10
total_flows = packet_count
total_pages = max(1, (total_flows + flows_per_page - 1) // flows_per_page)

traffic_df = pd.DataFrame(fetch_packets(flows_per_page))

# ============================================================================
# HEADER
# ============================================================================
header_l, header_r = st.columns([4, 1])
with header_l:
    st.markdown("""
<h1 style="
    font-size: 38px;
    font-weight: 700;
    margin-bottom: 4px;
">
🔒 Network Security Monitor
</h1>
""", unsafe_allow_html=True)




with header_r:
    if st.button("🔄 Refresh"):
        st.session_state.last_refresh = time.time()
        st.rerun()
    st.caption(datetime.now().strftime("%H:%M:%S"))

st.markdown("<hr style='margin: 14px 0;'>", unsafe_allow_html=True)


# ============================================================================
# KPI ROW
# ============================================================================
st.markdown("""
<h3 style="margin-top:16px;">
📊 Overview
</h3>
""", unsafe_allow_html=True)


k1, k2, k3, k4, k5, k6 = st.columns(6)

with k1:
    st.markdown("""
    <div class="kpi-card">
        <div class="kpi-icon">📊</div>
        <div class="kpi-value">2,847,324</div>
        <div class="kpi-label">Total Flows</div>
    </div>
    """, unsafe_allow_html=True)

with k2:
    st.markdown("""
    <div class="kpi-card">
        <div class="kpi-icon">🧩</div>
        <div class="kpi-value">15.2M</div>
        <div class="kpi-label">Total Packets</div>
    </div>
    """, unsafe_allow_html=True)

with k3:
    st.markdown("""
    <div class="kpi-card">
        <div class="kpi-icon">💾</div>
        <div class="kpi-value">8.7GB</div>
        <div class="kpi-label">Total Bytes</div>
    </div>
    """, unsafe_allow_html=True)

with k4:
    st.markdown("""
    <div class="kpi-card">
        <div class="kpi-icon">🚨</div>
        <div class="kpi-value">1,247</div>
        <div class="kpi-label">Attack Count</div>
    </div>
    """, unsafe_allow_html=True)

with k5:
    st.markdown("""
    <div class="kpi-card">
        <div class="kpi-icon">🛡️</div>
        <div class="kpi-value">94.3%</div>
        <div class="kpi-label">Detection Rate</div>
    </div>
    """, unsafe_allow_html=True)

with k6:
    st.markdown("""
    <div class="kpi-card">
        <div class="kpi-icon">📈</div>
        <div class="kpi-value">0.34</div>
        <div class="kpi-label">Avg Anomaly Index</div>
    </div>
    """, unsafe_allow_html=True)


# ============================================================================
# TABLE + PAGINATION
# ============================================================================
st.subheader("📡 Live Network Traffic")

nav_l, nav_r = st.columns([4, 1])
with nav_r:
    prev, page, next_ = st.columns([1, 1, 1])

    if prev.button("◀"):
        if st.session_state.page > 1:
            st.session_state.page -= 1
            st.rerun()

    page.markdown(
        f"<div style='text-align:center;padding-top:8px'>{st.session_state.page}/{total_pages}</div>",
        unsafe_allow_html=True
    )

    if next_.button("▶"):
        if st.session_state.page < total_pages:
            st.session_state.page += 1
            st.rerun()

st.dataframe(
    traffic_df,
    use_container_width=True,
    hide_index=True,
    height=360
)

st.caption(
    f"Showing {(st.session_state.page-1)*flows_per_page+1:,}–"
    f"{min(st.session_state.page*flows_per_page, total_flows):,} "
    f"of {total_flows:,} flows"
)

st.markdown("<hr style='margin: 14px 0;'>", unsafe_allow_html=True)


# ============================================================================
# THREAT ANALYSIS (3 COLUMN LAYOUT)
# ============================================================================
st.markdown("""
<h3 style="margin-top:16px;">
📊 Threat Analysis
</h3>
""", unsafe_allow_html=True)

dist = fetch_attack_distribution()
c1, c2, c3 = st.columns([1.2, 1.6, 1.2])

# ----------------------------------------------------------------------------
# LEFT CARD – ATTACK SUMMARY (2 PER ROW)
# ----------------------------------------------------------------------------
with c1:
    st.markdown("#### Attack Summary")

    if dist:
        total = sum(dist.values())
        items = list(dist.items())[:4]

        # First row
        col_a, col_b = st.columns(2)
        for (label, value), col in zip(items[:2], [col_a, col_b]):
            pct = (value / total) * 100
            col.markdown(f"""
            <div class="card">
                <h4>{label}</h4>
                <div class="card-value">{value:,}</div>
                <div class="badge">↑ {pct:.1f}%</div>
            </div>
            """, unsafe_allow_html=True)

        # Second row
        col_c, col_d = st.columns(2)
        for (label, value), col in zip(items[2:4], [col_c, col_d]):
            pct = (value / total) * 100
            col.markdown(f"""
            <div class="card">
                <h4>{label}</h4>
                <div class="card-value">{value:,}</div>
                <div class="badge">↑ {pct:.1f}%</div>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.info("No attack summary data")



# ----------------------------------------------------------------------------
# MIDDLE CARD – ATTACK DISTRIBUTION
# ----------------------------------------------------------------------------
with c2:
    st.markdown("#### Attack Type Distribution")

    if dist:
        fig = go.Figure(go.Bar(
            x=list(dist.keys()),
            y=list(dist.values()),
            marker_color=["#66BB6A", "#EF5350", "#FFA726", "#AB47BC"]
        ))

        fig.update_layout(
            height=320,
            margin=dict(l=20, r=20, t=30, b=20),
            showlegend=False
        )

        
        st.plotly_chart(fig, use_container_width=True)
        


# ----------------------------------------------------------------------------
# RIGHT CARD – FLOW ANOMALY INDEX
# ----------------------------------------------------------------------------
with c3:
    
    st.markdown("#### Flow Anomaly Index")

    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=0.34,
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
    


st.markdown("<hr style='margin: 14px 0;'>", unsafe_allow_html=True)

with st.container():

    # Section title (inside container)
    st.markdown(
        """
        <h3 style="margin-top:16px;">
            📈 Packet Rate Over Time
        </h3>
        """,
        unsafe_allow_html=True
    )

    # Card wrapper (visual only)
    st.markdown('<div class="card">', unsafe_allow_html=True)

    # Fetch data
    trends = fetch_time_trends()
    timestamps = trends.get("timestamps", [])
    packet_rates = trends.get("packet_rate", [])

    if timestamps and packet_rates:
        timestamps = [
            datetime.fromtimestamp(ts).strftime("%H:%M")
            for ts in timestamps
        ]

        fig_trend = go.Figure(
            go.Scatter(
                x=timestamps,
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

    # Close card
    st.markdown('</div>', unsafe_allow_html=True)





# ============================================================================
# SIDEBAR
# ============================================================================
with st.sidebar:
    st.header("⚙️ Settings")
    st.selectbox("Time Range", ["5 min", "15 min", "1 hour", "24 hours"])
    st.slider("Anomaly Threshold", 0.0, 1.0, 0.5)
    st.select_slider("Auto refresh (sec)", [3, 5, 10, 15, 30], value=5)
    st.info(f"Total Flows: {total_flows:,}")

# ============================================================================
# FOOTER
# ============================================================================
st.markdown(
    "<div style='text-align:center;color:#888;font-size:12px'>"
    "© 2024 Network Security Monitor | Streamlit + FastAPI"
    "</div>",
    unsafe_allow_html=True
)
