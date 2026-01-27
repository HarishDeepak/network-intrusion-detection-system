# api/alerts.py

from fastapi import APIRouter, Query
from typing import List, Dict
from services.email_services import get_attack_logs, get_alert_logs

router = APIRouter(tags=["Alerts & Logs"])

@router.get("/alerts/attack_logs", response_model=List[Dict])
async def get_attack_logs_endpoint(limit: int = Query(100, description="Number of recent attack logs to retrieve")):
    """
    Retrieve recent attack detection logs.
    """
    return get_attack_logs(limit)

@router.get("/alerts/alert_logs", response_model=List[Dict])
async def get_alert_logs_endpoint(limit: int = Query(100, description="Number of recent alert logs to retrieve")):
    """
    Retrieve recent alert system logs (emails sent, failures, etc.).
    """
    return get_alert_logs(limit)

@router.get("/alerts/stats")
async def get_alert_stats():
    """
    Get statistics about alerts and attacks.
    """
    attack_logs = get_attack_logs(1000)  # Get more logs for stats
    alert_logs = get_alert_logs(1000)

    # Calculate stats
    total_attacks = len(attack_logs)
    total_alerts = len(alert_logs)

    # Count by severity
    severity_count = {}
    attack_types = {}

    for attack in attack_logs:
        severity = attack.get("severity", "UNKNOWN")
        attack_type = attack.get("attack_type", "UNKNOWN")

        severity_count[severity] = severity_count.get(severity, 0) + 1
        attack_types[attack_type] = attack_types.get(attack_type, 0) + 1

    # Alert success rate
    successful_alerts = len([a for a in alert_logs if a.get("status") == "SENT"])
    alert_success_rate = (successful_alerts / total_alerts * 100) if total_alerts > 0 else 0

    return {
        "total_attacks_detected": total_attacks,
        "total_alerts_sent": total_alerts,
        "alert_success_rate": round(alert_success_rate, 2),
        "attacks_by_severity": severity_count,
        "attacks_by_type": attack_types,
        "recent_attacks": attack_logs[-10:] if attack_logs else [],  # Last 10 attacks
        "recent_alerts": alert_logs[-10:] if alert_logs else []   # Last 10 alerts
    }