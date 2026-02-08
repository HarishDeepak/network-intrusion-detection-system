import streamlit as st
import requests
from datetime import datetime

# ==================================================
# CONFIG
# ==================================================
API_BASE = "http://localhost:8000/api"

st.set_page_config(
    page_title="Logs Viewer",
    layout="wide",
    page_icon="📜"
)

# ==================================================
# CSS
# ==================================================
st.markdown("""
<style>
.card {
    background: #ffffff;
    border-radius: 14px;
    padding: 16px 18px;
    box-shadow: 0 6px 18px rgba(0,0,0,0.06);
    margin-bottom: 16px;
}

.metric-box {
    text-align: center;
}

.badge {
    padding: 4px 10px;
    border-radius: 999px;
    font-size: 12px;
    font-weight: 600;
}

.badge-low { background: #E8F5E9; color: #2E7D32; }
.badge-medium { background: #FFF8E1; color: #F9A825; }
.badge-high { background: #FDECEA; color: #C62828; }
.badge-critical { background: #B71C1C; color: white; }

.log-row {
    display: flex;
    justify-content: space-between;
    margin-bottom: 10px;
}
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


def fmt_time(ts):
    return datetime.fromisoformat(ts).strftime("%H:%M:%S")


# ==================================================
# HEADER
# ==================================================
st.markdown("## 📜 Logs Viewer")
st.caption("Security alerts, email notifications, and ML explanations")

# ==================================================
# SUMMARY PANEL
# ==================================================
stats = fetch("/alerts/stats")

if stats:
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.metric("Total Attacks", stats["total_attacks_detected"])
    with c2:
        st.metric("Alerts Sent", stats["total_alerts_sent"])
    with c3:
        st.metric("Success Rate", f"{stats['alert_success_rate']:.1f}%")
    with c4:
        high = stats["attacks_by_severity"].get("HIGH", 0)
        st.metric("High Severity", high)

st.markdown("<hr>", unsafe_allow_html=True)

# ==================================================
# 🚨 ALERT FEED
# ==================================================
st.markdown("### 🚨 Attack Detection Logs")

attack_logs = fetch("/alerts/attack_logs", params={"limit": 20})

with st.container():
    st.markdown('<div class="card">', unsafe_allow_html=True)

    if attack_logs:
        for log in attack_logs:
            st.markdown(f"""
            <div class="log-row">
                <div>
                    <b>{log['attack_type']}</b>  
                    <br>
                    <small>
                        {log['src_ip']} → {log['dest_ip']} |
                        {fmt_time(log['timestamp'])}
                    </small>
                </div>
                <div>
                    <span class="{severity_badge(log['severity'])}">
                        {log['severity']}
                    </span>
                    <br>
                    <small>{log['confidence']:.2f}</small>
                </div>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.info("No recent attacks")

    st.markdown('</div>', unsafe_allow_html=True)

# ==================================================
# 📧 EMAIL LOGS
# ==================================================
st.markdown("### 📧 Email Notification Logs")

email_logs = fetch("/alerts/alert_logs", params={"limit": 15})

with st.container():
    st.markdown('<div class="card">', unsafe_allow_html=True)

    if email_logs:
        st.dataframe(
            [{
                "Time": fmt_time(l["timestamp"]),
                "Recipients": ", ".join(l["recipients"]),
                "Attack": l["attack_type"],
                "Severity": l["severity"],
                "Status": l["status"],
            } for l in email_logs],
            use_container_width=True
        )
    else:
        st.info("No email alerts logged")

    st.markdown('</div>', unsafe_allow_html=True)

# ==================================================
# 🧠 EXPLANATIONS
# ==================================================
st.markdown("### 🧠 Alert Explanations")

if attack_logs:
    for log in attack_logs[:5]:
        with st.expander(f"{log['attack_type']} — {log['severity']}"):
            st.markdown(f"""
            **Confidence:** {log['confidence']:.2f}  
            **Protocol:** {log['protocol']}  
            **Packet Length:** {log['packet_length']} bytes  

            **Why this alert?**  
            This traffic pattern deviated significantly from normal behavior
            based on learned statistical and ML-based baselines.

            **Recommended Action:**  
            - Inspect source IP  
            - Apply rate limiting or blocking  
            - Monitor recurrence
            """)
