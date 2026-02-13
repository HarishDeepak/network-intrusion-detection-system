import streamlit as st
import requests
from datetime import datetime
import pandas as pd

# ==================================================
# CONFIG
# ==================================================
API_BASE = "http://localhost:8000/api"

st.set_page_config(
    page_title="Security Logs",
    layout="wide",
    page_icon="🛡️"
)

# ==================================================
# COMPACT PROFESSIONAL CSS
# ==================================================
st.markdown("""
<style>
.block-container {
    padding: 1.5rem 2rem !important;
    max-width: 100% !important;
}

h1, h2, h3 {
    margin-bottom: 0.3rem !important;
}

.card {
    background: #f6f6f6;
    border-radius: 10px;
    padding: 14px 18px;
    box-shadow: 0 3px 10px rgba(0,0,0,0.04);
    margin-bottom: 10px;
}

.metric-title {
    font-size: 13px;
    color: #777;
}

.metric-value {
    font-size: 26px;
    font-weight: 600;
}

.section-divider {
    margin-top: 15px;
    margin-bottom: 10px;
}

.badge {
    padding: 3px 8px;
    border-radius: 999px;
    font-size: 11px;
    font-weight: 600;
}

.badge-low { background: #E8F5E9; color: #2E7D32; }
.badge-medium { background: #FFF8E1; color: #F9A825; }
.badge-high { background: #FDECEA; color: #C62828; }
.badge-critical { background: #B71C1C; color: white; }
</style>
""", unsafe_allow_html=True)

# ==================================================
# HELPERS
# ==================================================
def fetch(endpoint, params=None):
    try:
        r = requests.get(f"{API_BASE}{endpoint}", params=params, timeout=5)
        if r.status_code == 200:
            return r.json()
    except:
        pass
    return None


def severity_badge(sev):
    sev = sev.upper()
    return {
        "LOW": "badge badge-low",
        "MEDIUM": "badge badge-medium",
        "HIGH": "badge badge-high",
        "CRITICAL": "badge badge-critical",
    }.get(sev, "badge badge-low")


def fmt_datetime(ts):
    dt = datetime.fromisoformat(ts)
    return dt.strftime("%d %b %Y  |  %H:%M:%S")


# ==================================================
# HEADER
# ==================================================
st.markdown("# 🛡️ Security Logs Dashboard")
st.caption("Email alerts, attack detections and explainable AI insights")

# ==================================================
# TOP STATS (REAL API)
# ==================================================
stats = fetch("/alerts/stats")

if stats:
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.markdown(f"""
        <div class="card">
            <div class="metric-title">Total Attacks</div>
            <div class="metric-value">{stats["total_attacks_detected"]}</div>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown(f"""
        <div class="card">
            <div class="metric-title">Alerts Sent</div>
            <div class="metric-value">{stats["total_alerts_sent"]}</div>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        st.markdown(f"""
        <div class="card">
            <div class="metric-title">Success Rate</div>
            <div class="metric-value">{stats["alert_success_rate"]:.1f}%</div>
        </div>
        """, unsafe_allow_html=True)

    with col4:
        high = stats["attacks_by_severity"].get("HIGH", 0)
        st.markdown(f"""
        <div class="card">
            <div class="metric-title">High Severity</div>
            <div class="metric-value">{high}</div>
        </div>
        """, unsafe_allow_html=True)

st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

# ==================================================
# 📧 EMAIL LOGS (FIRST)
# ==================================================
st.markdown("## 📧 Email Notification Logs")

email_logs = fetch("/alerts/alert_logs", params={"limit": 20})

if email_logs:
    df_email = pd.DataFrame(email_logs)

    df_email["timestamp"] = df_email["timestamp"].apply(fmt_datetime)
    df_email["recipients"] = df_email["recipients"].apply(lambda x: ", ".join(x))

    df_email = df_email[[
        "timestamp",
        "attack_type",
        "severity",
        "status",
        "recipients"
    ]]

    df_email.columns = [
        "Date & Time",
        "Attack Type",
        "Severity",
        "Status",
        "Recipients"
    ]

    st.dataframe(df_email, use_container_width=True)
else:
    st.info("No email logs available")

st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)


st.markdown("## 🧠 Attack Explanations")
attack_logs = fetch("/alerts/attack_logs", params={"limit": 50})

if attack_logs:
    unique_explanations = {}

    for log in attack_logs:
        attack_type = log["attack_type"]
        explanation = log.get("explanation")

        if attack_type not in unique_explanations and explanation:
            unique_explanations[attack_type] = explanation

    for attack_type, explanation in unique_explanations.items():
        with st.expander(f"{attack_type} Explanation"):
            st.write(explanation)
else:
    st.info("No explanations available.")
