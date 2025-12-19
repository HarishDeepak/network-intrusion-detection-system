# Network Security Monitor Dashboard - Streamlit Frontend
# This is your starting template. Customize as needed!

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
import requests
from datetime import datetime, timedelta
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

# ============================================================================
# CONFIGURATION
# ============================================================================
# TODO: Change this to your FastAPI backend URL
API_BASE_URL = st.secrets.get("API_URL", "http://localhost:8000")

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

@st.cache_data(ttl=60)  # Cache for 60 seconds
def fetch_metrics():
    """Fetch KPI metrics from backend"""
    try:
        response = requests.get(f"{API_BASE_URL}/api/metrics/summary")
        if response.status_code == 200:
            return response.json()
    except Exception as e:
        st.error(f"Failed to fetch metrics: {e}")
    
    # Return dummy data for development
    return {
        "total_flows": 2847324,
        "total_packets": "15.2M",
        "total_bytes": "8.7GB",
        "attack_count": 1247,
        "detection_rate": 94.3,
        "anomaly_index": 0.34
    }

def fetch_live_traffic():
    """Fetch live network traffic from backend"""
    try:
        response = requests.get(f"{API_BASE_URL}/api/traffic/live", timeout=5)
        if response.status_code == 200:
            return response.json()
    except Exception as e:
        pass
    
    # Return dummy data for development
    return pd.DataFrame({
        "TIMESTAMP": ["14:32:35", "14:32:18", "14:32:22"],
        "SOURCE_IP": ["192.168.1.105", "172.15.0.45", "203.0.113.42"],
        "DESTINATION_IP": ["10.0.0.1", "192.168.1.200", "192.168.1.200"],
        "PROTOCOL": ["TCP", "UDP", "TCP"],
        "PACKETS": [1247, 2891, 15432],
        "BYTES": ["89.2KB", "156.7KB", "2.3MB"],
        "ATTACK_TYPE": ["Benign", "PortScan", "DDoS"],
        "ANOMALY_SCORE": [0.12, 0.67, 0.89]
    })

def fetch_attack_summary():
    """Fetch attack summary statistics"""
    try:
        response = requests.get(f"{API_BASE_URL}/api/attacks/summary")
        if response.status_code == 200:
            return response.json()
    except Exception as e:
        pass
    
    # Return dummy data for development
    return {
        "benign": {"count": 2456891, "change": 3.2},
        "ddos": {"count": 128453, "change": -4.5},
        "port_scan": {"count": 89234, "change": 5.1},
        "bruteforce": {"count": 45123, "change": 1.8},
        "infiltration": {"count": 15234, "change": 0.5},
        "web_attack": {"count": 9031, "change": 0.3}
    }

def create_attack_distribution_chart(attack_data):
    """Create bar chart for attack type distribution"""
    attack_types = ["DDoS", "Port Scan", "Brute Force", "Infiltration", "Web Attack", "Botnet"]
    counts = [128453, 89234, 45123, 15234, 9031, 5000]
    
    fig = go.Figure(data=[
        go.Bar(x=attack_types, y=counts, marker_color=['#FF6B6B', '#FFA500', '#FFD700', '#4CAF50', '#2196F3', '#9C27B0'])
    ])
    
    fig.update_layout(
        title="Attack Type Distribution",
        xaxis_title="Attack Type",
        yaxis_title="Count",
        hovermode='x unified',
        height=400,
        template="plotly_white"
    )
    
    return fig

def create_packet_rate_chart():
    """Create line chart for packet rate over time"""
    times = ["14:30", "14:31", "14:32", "14:33", "14:34", "14:35", "14:36", "14:37", "14:38", "14:39"]
    rates = [12, 13.5, 14, 13.2, 14.8, 15, 14.5, 13, 12.5, 11.8]
    
    fig = go.Figure(data=[
        go.Scatter(x=times, y=rates, mode='lines+markers', name='Packet Rate (kpps)',
                  line=dict(color='#2196F3', width=3),
                  fill='tozeroy')
    ])
    
    fig.update_layout(
        title="Packet Rate Over Time",
        xaxis_title="Time",
        yaxis_title="Rate (kpps)",
        height=400,
        template="plotly_white"
    )
    
    return fig

def create_flow_anomaly_gauge():
    """Create gauge chart for flow anomaly index"""
    fig = go.Figure(data=[go.Indicator(
        mode="gauge+number+delta",
        value=0.34,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': "Flow Anomaly Index"},
        delta={'reference': 0.35},
        gauge={
            'axis': {'range': [0, 1]},
            'bar': {'color': "darkblue"},
            'steps': [
                {'range': [0, 0.25], 'color': "lightgreen"},
                {'range': [0.25, 0.5], 'color': "lightyellow"},
                {'range': [0.5, 0.75], 'color': "lightcoral"},
                {'range': [0.75, 1], 'color': "red"}
            ],
            'threshold': {
                'line': {'color': "red", 'width': 4},
                'thickness': 0.75,
                'value': 0.9
            }
        }
    )])
    
    fig.update_layout(height=400)
    return fig

# ============================================================================
# MAIN DASHBOARD
# ============================================================================

# Header
st.markdown("""
    <style>
    .header-container {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 20px;
    }
    </style>
""", unsafe_allow_html=True)

col1, col2, col3 = st.columns([3, 1, 1])
with col1:
    st.title("🔒 Network Security Monitor")
    st.markdown("**SOC Dashboard - Student Edition**")

with col3:
    if st.button("🔄 Live Monitoring", use_container_width=True):
        st.rerun()
    
    # Last updated time
    st.caption(f"Last updated: {datetime.now().strftime('%H:%M:%S')}")

st.divider()

# ============================================================================
# KPI METRICS ROW
# ============================================================================
st.subheader("📊 Key Performance Indicators")

metrics = fetch_metrics()

col1, col2, col3, col4, col5, col6 = st.columns(6)

with col1:
    st.metric(
        label="Total Flows",
        value=f"{metrics.get('total_flows', 0):,}",
        delta="+5.2%",
        delta_color="normal"
    )

with col2:
    st.metric(
        label="Total Packets",
        value=metrics.get('total_packets', '15.2M'),
        delta="-2.1%",
        delta_color="inverse"
    )

with col3:
    st.metric(
        label="Total Bytes",
        value=metrics.get('total_bytes', '8.7GB'),
        delta="+1.3%",
        delta_color="normal"
    )

with col4:
    st.metric(
        label="Attacks Detected",
        value=f"{metrics.get('attack_count', 0):,}",
        delta="+8.5%",
        delta_color="off"
    )

with col5:
    st.metric(
        label="Detection Rate",
        value=f"{metrics.get('detection_rate', 94.3)}%",
        delta="+2.1%",
        delta_color="normal"
    )

with col6:
    st.metric(
        label="Anomaly Index",
        value=f"{metrics.get('anomaly_index', 0.34):.2f}",
        delta="-0.01",
        delta_color="inverse"
    )

st.divider()

# ============================================================================
# LIVE NETWORK TRAFFIC TABLE
# ============================================================================
st.subheader("📡 Live Network Traffic")

# Fetch and display live traffic
traffic_df = fetch_live_traffic()
if isinstance(traffic_df, dict):
    traffic_df = pd.DataFrame(traffic_df)

# Color-code the anomaly scores
def color_code_anomaly(val):
    if val < 0.3:
        return 'background-color: #C8E6C9'  # Green
    elif val < 0.6:
        return 'background-color: #FFF9C4'  # Yellow
    else:
        return 'background-color: #FFCDD2'  # Red

# Display traffic table
st.dataframe(
    traffic_df,
    use_container_width=True,
    hide_index=True,
    column_config={
        "ANOMALY_SCORE": st.column_config.NumberColumn(
            "Anomaly Score",
            format="%.2f"
        )
    }
)

# Pagination info
st.caption("Showing 1-20 of 2,847,324 flows")

st.divider()

# ============================================================================
# ATTACK ANALYSIS SECTION
# ============================================================================
st.subheader("🎯 Attack Analysis")

col1, col2, col3 = st.columns(3)

# Attack Summary Cards
attack_summary = fetch_attack_summary()

with col1:
    benign = attack_summary.get("benign", {})
    st.metric(
        label="Benign Traffic",
        value=f"{benign.get('count', 0):,}",
        delta=f"+{benign.get('change', 0)}%",
        delta_color="normal"
    )

with col2:
    ddos = attack_summary.get("ddos", {})
    st.metric(
        label="DDoS Attacks",
        value=f"{ddos.get('count', 0):,}",
        delta=f"{ddos.get('change', 0)}%",
        delta_color="off"
    )

with col3:
    port_scan = attack_summary.get("port_scan", {})
    st.metric(
        label="Port Scans",
        value=f"{port_scan.get('count', 0):,}",
        delta=f"+{port_scan.get('change', 0)}%",
        delta_color="off"
    )

st.divider()

# ============================================================================
# CHARTS SECTION
# ============================================================================
st.subheader("📈 Network Analysis")

col1, col2 = st.columns(2)

with col1:
    attack_dist_chart = create_attack_distribution_chart(attack_summary)
    st.plotly_chart(attack_dist_chart, use_container_width=True)

with col2:
    packet_rate_chart = create_packet_rate_chart()
    st.plotly_chart(packet_rate_chart, use_container_width=True)

st.divider()

# Anomaly Index Gauge
col1, col2, col3 = st.columns([1, 2, 1])
with col2:
    anomaly_gauge = create_flow_anomaly_gauge()
    st.plotly_chart(anomaly_gauge, use_container_width=True)

st.divider()

# ============================================================================
# SIDEBAR - FILTERS & SETTINGS
# ============================================================================
with st.sidebar:
    st.header("⚙️ Dashboard Settings")
    
    # Time Range Filter
    st.subheader("Time Range")
    time_range = st.selectbox(
        "Select time range:",
        ["Last 5 minutes", "Last 15 minutes", "Last Hour", "Last 24 hours", "Custom"]
    )
    
    # Attack Type Filter
    st.subheader("Attack Type Filter")
    attack_types = st.multiselect(
        "Select attack types to display:",
        ["Benign", "DDoS", "PortScan", "Brute Force", "Infiltration", "Web Attack"],
        default=["DDoS", "PortScan"]
    )
    
    # Anomaly Score Threshold
    st.subheader("Anomaly Score Threshold")
    threshold = st.slider("Show flows with score >", 0.0, 1.0, 0.5, 0.05)
    
    st.divider()
    
    # Export Options
    st.subheader("📥 Export Data")
    if st.button("Download CSV"):
        st.success("✅ Data exported successfully!")
    
    if st.button("Export Report"):
        st.info("📄 Report generation in progress...")
    
    st.divider()
    
    # About Section
    st.subheader("ℹ️ About")
    st.markdown("""
    **Network Security Monitor**
    
    Real-time threat detection dashboard powered by:
    - Machine Learning models
    - Network packet analysis
    - Anomaly detection
    
    **Version**: 1.0.0
    **Last Updated**: Dec 19, 2024
    """)

# ============================================================================
# FOOTER
# ============================================================================
st.divider()
st.markdown("""
<div style='text-align: center; color: #888; font-size: 12px; padding: 20px;'>
    © 2024 Network Security Monitor - Student Project | Powered by Streamlit & FastAPI
</div>
""", unsafe_allow_html=True)
