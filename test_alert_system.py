#!/usr/bin/env python3
"""
Test script for Email Alert System
Run this to test the email alert functionality
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'backend'))

from models.packet import PacketData, PredictionResult, PacketWithPrediction
from services.email_services import send_attack_alert, get_attack_logs, get_alert_logs
import time

def test_email_alert_system():
    """Test the email alert system with sample attack data"""

    print("🧪 Testing Email Alert System")
    print("=" * 50)

    # Create a sample attack packet
    attack_packet = PacketData(
        id=1,
        src_ip="192.168.1.100",
        dest_ip="10.0.0.1",
        length=1200,  # Large packet to trigger DDoS detection
        protocol="TCP",
        timestamp=time.time()
    )

    attack_prediction = PredictionResult(
        label="attack",
        confidence=0.95,
        attack_type="DDoS"
    )

    packet_with_prediction = PacketWithPrediction(
        packet=attack_packet,
        prediction=attack_prediction
    )

    print("📧 Sending test alert email...")
    success = send_attack_alert(packet_with_prediction)

    if success:
        print("✅ Alert email sent successfully!")
    else:
        print("❌ Failed to send alert email (check email configuration)")

    print("\n📊 Checking logs...")

    # Check attack logs
    attack_logs = get_attack_logs()
    print(f"📋 Attack logs: {len(attack_logs)} entries")
    if attack_logs:
        latest_attack = attack_logs[-1]
        print(f"   Latest attack: {latest_attack['attack_type']} from {latest_attack['src_ip']}")

    # Check alert logs
    alert_logs = get_alert_logs()
    print(f"📬 Alert logs: {len(alert_logs)} entries")
    if alert_logs:
        latest_alert = alert_logs[-1]
        print(f"   Latest alert status: {latest_alert['status']}")

    print("\n🔍 Log file locations:")
    print("   Attack logs: logs/attack_log.json")
    print("   Alert logs: logs/alert_log.json")

    print("\n📡 API Endpoints available:")
    print("   GET /api/alerts/attack_logs - Retrieve attack detection logs")
    print("   GET /api/alerts/alert_logs - Retrieve alert system logs")
    print("   GET /api/alerts/stats - Get alert and attack statistics")

    print("\n⚙️  Configuration:")
    print("   Set environment variables:")
    print("   - ALERT_EMAIL: Your email address")
    print("   - ALERT_EMAIL_PASSWORD: Your email password")
    print("   - ALERT_RECIPIENTS: Comma-separated list of recipient emails")

if __name__ == "__main__":
    test_email_alert_system()