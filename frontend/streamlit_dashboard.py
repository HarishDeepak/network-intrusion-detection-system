import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import requests
from datetime import datetime
from streamlit_autorefresh import st_autorefresh
import requests
import time
# =====================================================
# PAGE CONFIG
# =====================================================
st.set_page_config(page_title="Network Security Monitor", layout="wide")

# =====================================================
# AUTO REFRESH
# =====================================================
REFRESH_SECONDS = 10
st_autorefresh(interval=REFRESH_SECONDS * 1000, key="auto_refresh")

# =====================================================
# GLOBAL CSS (FIXED SPACING + KPI BOXES)
# =====================================================
st.markdown("""
<style>
.block-container {
    padding: 1.5rem 2rem !important;
    max-width: 100% !important;
}

/* Section titles */
.section-title {
    font-size: 20px;
    font-weight: 700;
    margin: 2rem 0 1rem 0;
}

/* KPI overview cards */
.kpi-grid {
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 16px;
    margin-bottom: 1.5rem;
}

.kpi-box {
    background: #f6f6f6;
    border-radius: 10px;
    padding: 18px 20px;
}

.kpi-label {
    font-size: 13px;
    color: #666;
    margin-bottom: 6px;
}

.kpi-value {
    font-size: 30px;
    font-weight: 700;
    color: #1a1a1a;
}

/* Cards */
.card {
    background: #f6f6f6;
    border-radius: 12px;
    padding: 20px;
}

/* Threat summary */
.attack-grid {
    display: grid;
    grid-template-columns: 1fr;
    gap: 14px;
}

.attack-item {
    background: white;
    border-radius: 8px;
    padding: 14px;
    border: 1px solid #e8e8e8;
}

.attack-value {
    font-size: 24px;
    font-weight: 700;
}

.attack-label {
    font-size: 12px;
    color: #666;
}
</style>
""", unsafe_allow_html=True)

# =====================================================
# API HELPERS
# =====================================================
API = "http://127.0.0.1:8000"


@st.cache_data(ttl=REFRESH_SECONDS)
def fetch(endpoint, params=None):
    try:
        r = requests.get(f"{API}{endpoint}", params=params, timeout=5)
        return r.json() if r.status_code == 200 else {}
    except Exception:
        return {}

def fmt_datetime(ts):
    ts = ts.replace("Z", "+00:00")
    return datetime.fromisoformat(ts).strftime("%b %d, %Y • %I:%M %p")

# =====================================================
# FETCH DATA
# =====================================================
overview = fetch("/dashboard/overview")
flow_summary = fetch("/dashboard/flow-summary")
attack_stats = fetch("/api/db/attacks/stats")

attack_types = attack_stats.get("by_type", {})
total_attacks = attack_stats.get("total_attacks", 0)

# =====================================================
# HEADER
# =====================================================
st.markdown("## 🔒 Network Security Monitor")



# =====================================================
# CSV UPLOAD SECTION
# =====================================================
st.markdown('<div class="section-title">📂 Upload CSV for Analysis</div>', unsafe_allow_html=True)

if "pipeline_started" not in st.session_state:
    st.session_state.pipeline_started = False

uploaded_file = st.file_uploader("Upload Network Flow CSV", type=["csv"])

# Placeholder for pipeline completion message
status_placeholder = st.empty()



if uploaded_file is not None:
    if st.button("Run Detection Pipeline"):
        files = {"file": (uploaded_file.name, uploaded_file, "text/csv")}
        response = requests.post(f"{API}/upload-and-run/", files=files)

        if response.status_code == 200:
            st.success("CSV uploaded. Pipeline started ✅")
            st.session_state.pipeline_started = True   # ✅ mark started
        else:
            st.error("Failed to upload CSV ❌")

if st.session_state.pipeline_started:

    status_placeholder = st.empty()
    status = fetch("/pipeline-status/")

    if status.get("prediction") == "completed" and status.get("fusion") == "completed":
        status_placeholder.success("✅ Pipeline completed! You can now view results below.")
    elif status.get("prediction") == "failed" or status.get("fusion") == "failed":
        status_placeholder.error("❌ Pipeline failed. Check logs.")
    elif status.get("prediction") == "running" or status.get("fusion") == "running":
        status_placeholder.info("Pipeline running... please wait ⏳")


# =====================================================
# OVERVIEW KPI BOXES (ONLY HERE)
# =====================================================
st.markdown("""
<div class="kpi-grid">
    <div class="kpi-box">
        <div class="kpi-label">Total Flows</div>
        <div class="kpi-value">{}</div>
    </div>
    <div class="kpi-box">
        <div class="kpi-label">Current Attacks</div>
        <div class="kpi-value">{}</div>
    </div>
    <div class="kpi-box">
        <div class="kpi-label">Total Attacks</div>
        <div class="kpi-value">{}</div>
    </div>
    <div class="kpi-box">
        <div class="kpi-label">Detection Rate</div>
        <div class="kpi-value">{}</div>
    </div>
    <div class="kpi-box">
        <div class="kpi-label">Avg Anomaly Index</div>
        <div class="kpi-value">{}</div>
    </div>
</div>
""".format(
    overview.get("total_flows", 0),
    overview.get("current_attacks", 0),
    overview.get("total_attacks", 0),
    f"{overview.get('detection_rate', 0)*100:.1f}%",
    f"{overview.get('average_anomaly_index', 0):.2f}"
), unsafe_allow_html=True)

# =====================================================
# ATTACK INVESTIGATION
# =====================================================
st.markdown('<div class="section-title">🔍 Attack Investigation</div>', unsafe_allow_html=True)

f1, f2, f3 = st.columns(3)
with f1:
    severity = st.selectbox("Severity", ["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
with f2:
    attack_type = st.selectbox("Attack Type", ["ALL"] + list(attack_types.keys()))
with f3:
    limit = st.selectbox("Rows", [10, 20, 50], index=1)

params = {"limit": limit}
if severity != "ALL":
    params["severity"] = severity
if attack_type != "ALL":
    params["attack_type"] = attack_type

attacks = fetch("/api/db/attacks", params=params) or []

if attacks:
    df = pd.DataFrame(attacks)
    st.dataframe(pd.DataFrame({
        "Date & Time": df["timestamp"].apply(fmt_datetime),
        "Attack Type": df["attack_type"],
        "Source IP": df["src_ip"],
        "Destination IP": df["dest_ip"],
        "Protocol": df["protocol"],
        # "Confidence (%)": (df["confidence"] * 100).round(2),
        "Severity": df["severity"]
    }), width="stretch", height=420, hide_index=True)
else:
    st.info("No attack records found.")

# =====================================================
# THREAT ANALYSIS
# =====================================================
st.markdown('<div class="section-title">📊 Threat Analysis</div>', unsafe_allow_html=True)

c1, c2, c3 = st.columns(3)

with c1:
    st.markdown('<div class="card"><b>Attack Summary</b><div class="attack-grid">', unsafe_allow_html=True)
    for name, count in attack_types.items():
        pct = (count / total_attacks * 100) if total_attacks else 0
        st.markdown(f"""
        <div class="attack-item">
            <div class="attack-value">{count}</div>
            <div class="attack-label">{name} • {pct:.1f}%</div>
        </div>
        """, unsafe_allow_html=True)
    st.markdown('</div></div>', unsafe_allow_html=True)

with c2:
    st.markdown('<div class="card"><b>Attack Distribution</b>', unsafe_allow_html=True)
    fig = go.Figure(go.Bar(
        x=list(attack_types.keys()),
        y=list(attack_types.values()),
        marker_color="#5b8def"
    ))
    fig.update_layout(height=280, margin=dict(l=20, r=20, t=20, b=40))
    st.plotly_chart(fig, width="stretch", config={"displayModeBar": False})
    st.markdown('</div>', unsafe_allow_html=True)

with c3:
    st.markdown('<div class="card"><b>Anomaly Index</b>', unsafe_allow_html=True)

    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=overview.get("average_anomaly_index", 0),
        number={
            "font": {"size": 48}
        },
        domain={"x": [0, 1], "y": [0, 1]},
        gauge={
            "axis": {"range": [0, 1], "tickwidth": 1},
            "bar": {"color": "#5b8def", "thickness": 0.35},
            "bgcolor": "white"
        }
    ))

    fig.update_layout(
        height=280,                 # ⬅ increase height
        margin=dict(l=10, r=10, t=40, b=10),  # ⬅ remove padding
        paper_bgcolor="white"
    )

    st.plotly_chart(fig, width="stretch", config={"displayModeBar": False})
    st.markdown('</div>', unsafe_allow_html=True)


# =====================================================
# ATTACK TREND OVER TIME
# =====================================================
st.markdown('<div class="section-title">📈 Attack Trend Over Time</div>', unsafe_allow_html=True)

trend = flow_summary.get("attacks_over_time", [])
if trend:
    df_trend = pd.DataFrame(trend)
    fig = go.Figure(go.Scatter(
        x=df_trend["date"],
        y=df_trend["count"],
        mode="lines+markers",
        line=dict(color="#5b8def", width=2.5),
        fill="tozeroy",
        fillcolor="rgba(91,141,239,0.15)"
    ))
    fig.update_layout(height=300, margin=dict(l=40, r=20, t=20, b=40))
    st.plotly_chart(fig, width="stretch", config={"displayModeBar": False})
