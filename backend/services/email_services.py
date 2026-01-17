# backend/services/email_services.py

import smtplib
import json
import os
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Optional
from models.packet import PacketWithPrediction

class EmailAlertSystem:
    def __init__(self, smtp_server: str = "smtp.gmail.com", smtp_port: int = 587):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.sender_email = os.getenv("ALERT_EMAIL", "alerts@networksecurity.com")
        self.sender_password = os.getenv("ALERT_EMAIL_PASSWORD", "")
        self.recipient_emails = os.getenv("ALERT_RECIPIENTS", "admin@company.com").split(",")

        # Create logs directory if it doesn't exist
        self.logs_dir = os.path.join(os.path.dirname(__file__), "..", "..", "logs")
        os.makedirs(self.logs_dir, exist_ok=True)

        # Log file paths
        self.attack_log_path = os.path.join(self.logs_dir, "attack_log.json")
        self.alert_log_path = os.path.join(self.logs_dir, "alert_log.json")

        # Initialize log files if they don't exist
        self._initialize_log_files()

    def _initialize_log_files(self):
        """Initialize log files with empty arrays if they don't exist"""
        for log_path in [self.attack_log_path, self.alert_log_path]:
            if not os.path.exists(log_path):
                with open(log_path, 'w') as f:
                    json.dump([], f, indent=2)

    def _get_severity_level(self, attack_type: str, confidence: float) -> str:
        """Determine severity level based on attack type and confidence"""
        severity_map = {
            "DDoS": "HIGH" if confidence > 0.8 else "MEDIUM",
            "PortScan": "MEDIUM" if confidence > 0.7 else "LOW",
            "Malware": "CRITICAL" if confidence > 0.9 else "HIGH",
            "BruteForce": "HIGH" if confidence > 0.8 else "MEDIUM",
            "SQLInjection": "CRITICAL" if confidence > 0.85 else "HIGH"
        }
        return severity_map.get(attack_type, "MEDIUM")

    def _get_attack_explanation(self, attack_type: str) -> str:
        """Get explanation summary for different attack types"""
        explanations = {
            "DDoS": "Distributed Denial of Service attack detected. Multiple packets flooding the target IP, potentially causing service disruption.",
            "PortScan": "Port scanning activity detected. Attacker is probing multiple ports to identify open services and vulnerabilities.",
            "Malware": "Malicious traffic pattern detected. Potential malware communication or command and control activity.",
            "BruteForce": "Brute force attack detected. Multiple authentication attempts from the same source IP.",
            "SQLInjection": "SQL injection attempt detected. Malicious SQL code injection in network traffic."
        }
        return explanations.get(attack_type, "Suspicious network activity detected requiring immediate attention.")

    def log_attack(self, packet_data: PacketWithPrediction) -> Dict:
        """Log attack information to attack_log.json"""
        attack_entry = {
            "timestamp": datetime.now().isoformat(),
            "attack_type": packet_data.prediction.attack_type,
            "src_ip": packet_data.packet.src_ip,
            "dest_ip": packet_data.packet.dest_ip,
            "protocol": packet_data.packet.protocol,
            "packet_length": packet_data.packet.length,
            "confidence": packet_data.prediction.confidence,
            "severity": self._get_severity_level(
                packet_data.prediction.attack_type,
                packet_data.prediction.confidence
            )
        }

        # Read existing attacks
        with open(self.attack_log_path, 'r') as f:
            attacks = json.load(f)

        # Add new attack
        attacks.append(attack_entry)

        # Write back to file
        with open(self.attack_log_path, 'w') as f:
            json.dump(attacks, f, indent=2)

        return attack_entry

    def log_alert(self, alert_data: Dict) -> Dict:
        """Log alert information to alert_log.json"""
        alert_entry = {
            "timestamp": datetime.now().isoformat(),
            "alert_type": "EMAIL_ALERT",
            "recipients": self.recipient_emails,
            "status": alert_data.get("status", "SENT"),
            **alert_data
        }

        # Read existing alerts
        with open(self.alert_log_path, 'r') as f:
            alerts = json.load(f)

        # Add new alert
        alerts.append(alert_entry)

        # Write back to file
        with open(self.alert_log_path, 'w') as f:
            json.dump(alerts, f, indent=2)

        return alert_entry

    def send_alert_email(self, packet_data: PacketWithPrediction) -> bool:
        """Send alert email for detected attack"""
        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = self.sender_email
            msg['To'] = ", ".join(self.recipient_emails)
            msg['Subject'] = f"🚨 SECURITY ALERT: {packet_data.prediction.attack_type} Attack Detected"

            # Log the attack first
            attack_info = self.log_attack(packet_data)

            # Create email body
            severity = self._get_severity_level(
                packet_data.prediction.attack_type,
                packet_data.prediction.confidence
            )
            explanation = self._get_attack_explanation(packet_data.prediction.attack_type)

            body = f"""
SECURITY ALERT - Network Anomaly Detection System

🚨 ATTACK DETECTED 🚨

Attack Details:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
• Attack Type: {packet_data.prediction.attack_type}
• Severity: {severity}
• Source IP: {packet_data.packet.src_ip}
• Destination IP: {packet_data.packet.dest_ip}
• Protocol: {packet_data.packet.protocol}
• Packet Size: {packet_data.packet.length} bytes
• Detection Time: {datetime.fromtimestamp(packet_data.packet.timestamp).strftime('%Y-%m-%d %H:%M:%S')}
• Confidence: {packet_data.prediction.confidence:.2%}

Explanation:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{explanation}

Recommended Actions:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
• Review firewall rules
• Monitor affected systems
• Check for additional indicators of compromise
• Consider blocking the source IP if appropriate

This alert has been logged and is available in the attack_log.json file.

Network Security Team
Automated Alert System
"""

            msg.attach(MIMEText(body, 'plain'))

            # Send email
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()
            server.login(self.sender_email, self.sender_password)
            text = msg.as_string()
            server.sendmail(self.sender_email, self.recipient_emails, text)
            server.quit()

            # Log successful alert
            self.log_alert({
                "attack_type": packet_data.prediction.attack_type,
                "severity": severity,
                "src_ip": packet_data.packet.src_ip,
                "dest_ip": packet_data.packet.dest_ip,
                "status": "SENT",
                "email_subject": msg['Subject']
            })

            return True

        except Exception as e:
            # Log failed alert
            self.log_alert({
                "attack_type": packet_data.prediction.attack_type,
                "severity": self._get_severity_level(
                    packet_data.prediction.attack_type,
                    packet_data.prediction.confidence
                ),
                "src_ip": packet_data.packet.src_ip,
                "dest_ip": packet_data.packet.dest_ip,
                "status": "FAILED",
                "error": str(e)
            })
            return False

    def get_attack_logs(self, limit: int = 100) -> List[Dict]:
        """Retrieve recent attack logs"""
        try:
            with open(self.attack_log_path, 'r') as f:
                attacks = json.load(f)
            return attacks[-limit:] if attacks else []
        except:
            return []

    def get_alert_logs(self, limit: int = 100) -> List[Dict]:
        """Retrieve recent alert logs"""
        try:
            with open(self.alert_log_path, 'r') as f:
                alerts = json.load(f)
            return alerts[-limit:] if alerts else []
        except:
            return []

# Global instance
alert_system = EmailAlertSystem()

def send_attack_alert(packet_data: PacketWithPrediction) -> bool:
    """Convenience function to send attack alert"""
    return alert_system.send_alert_email(packet_data)

def get_attack_logs(limit: int = 100) -> List[Dict]:
    """Convenience function to get attack logs"""
    return alert_system.get_attack_logs(limit)

def get_alert_logs(limit: int = 100) -> List[Dict]:
    """Convenience function to get alert logs"""
    return alert_system.get_alert_logs(limit)
