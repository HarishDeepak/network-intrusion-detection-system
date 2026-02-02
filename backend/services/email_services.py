# backend/services/email_services.py

import smtplib
import json
import os
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Optional
from models.packet import PacketWithPrediction
from models.database import SessionLocal, AttackLog, AlertLog

class EmailAlertSystem:
    def __init__(self, smtp_server: str = "smtp.gmail.com", smtp_port: int = 587):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.sender_email = os.getenv("ALERT_EMAIL", "nidsteamsharp@gmail.com")
        self.sender_password = os.getenv("ALERT_EMAIL_PASSWORD", "ergu amfi flxc vony")
        self.recipient_emails = os.getenv("ALERT_RECIPIENTS", "romiyaraju98@gmail.com,1ms17ec032@gmail.com").split(",")

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

    def _get_severity_level(self, attack_type: str, confidence: float, provided_severity: Optional[str] = None) -> str:
        """Determine severity: prefer provided severity from fusion; otherwise infer from type+confidence."""
        if provided_severity:
            # Normalize decision engine format (High/Medium/Low/None -> HIGH/MEDIUM/LOW/NONE)
            return provided_severity.upper() if provided_severity != "None" else "LOW"

        # fallback inference map (keeps behavior but covers actual labels)
        severity_map = {
            "DDoS": "HIGH" if confidence > 0.8 else "MEDIUM",
            "DoS": "HIGH" if confidence > 0.8 else "MEDIUM",
            "PortScan": "MEDIUM" if confidence > 0.7 else "LOW",
            "Scan": "MEDIUM" if confidence > 0.7 else "LOW",
            "Malware": "CRITICAL" if confidence > 0.9 else "HIGH",
            "BruteForce": "HIGH" if confidence > 0.8 else "MEDIUM",
            "SQLInjection": "CRITICAL" if confidence > 0.85 else "HIGH",
            "Web": "MEDIUM",
            "Benign": "LOW"
        }
        return severity_map.get(attack_type, "MEDIUM")

    def _get_attack_explanation(self, attack_type: str) -> str:
        """Get explanation summary for different attack types"""
        explanations = {
            "DDoS": "Distributed Denial of Service attack detected. Multiple packets flooding the target IP, potentially causing service disruption.",
            "DoS": "Denial of Service behavior detected. High resource usage or abnormal traffic to a host.",
            "PortScan": "Port scanning activity detected. Attacker is probing multiple ports to identify open services and vulnerabilities.",
            "Scan": "Port scanning / discovery activity detected. Attacker is probing services and ports.",
            "Malware": "Malicious traffic pattern detected. Potential malware communication or command and control activity.",
            "BruteForce": "Brute force attack detected. Multiple authentication attempts from the same source IP.",
            "SQLInjection": "SQL injection attempt detected. Malicious SQL code injection in network traffic.",
            "Web": "Suspicious web traffic detected. Potential web application abuse or exploitation attempts."
        }
        return explanations.get(attack_type, "Suspicious network activity detected requiring immediate attention.")

    def log_attack(self, packet_data: PacketWithPrediction, provided_severity: Optional[str] = None) -> Dict:
        """Log attack information to both JSON file and database"""
        severity = self._get_severity_level(
            packet_data.prediction.attack_type,
            packet_data.prediction.confidence,
            provided_severity,
        )

        # Include explanation if available
        explanation_payload = None
        if packet_data.prediction.explanation:
            explanation_payload = packet_data.prediction.explanation

        attack_entry = {
            "timestamp": datetime.now().isoformat(),
            "attack_type": packet_data.prediction.attack_type,
            "src_ip": getattr(packet_data.packet, 'src_ip', 'unknown'),
            "dest_ip": getattr(packet_data.packet, 'dest_ip', 'unknown'),
            "protocol": getattr(packet_data.packet, 'protocol', 'unknown'),
            "packet_length": getattr(packet_data.packet, 'length', 0),
            "confidence": packet_data.prediction.confidence,
            "severity": severity,
            "explanation": packet_data.prediction.explanation["text"] if packet_data.prediction.explanation else None
        }

        # Log to JSON file (backward compatibility)
        try:
            with open(self.attack_log_path, 'r') as f:
                attacks = json.load(f)
            attacks.append(attack_entry)
            with open(self.attack_log_path, 'w') as f:
                json.dump(attacks, f, indent=2)
        except Exception as e:
            print(f"[Warning] Failed to log to JSON: {e}")

        # Log to database
        try:
            db = SessionLocal()
            attack_log = AttackLog(
                timestamp=datetime.now(),
                attack_type=attack_entry["attack_type"],
                src_ip=attack_entry["src_ip"],
                dest_ip=attack_entry["dest_ip"],
                protocol=attack_entry["protocol"],
                packet_length=attack_entry["packet_length"],
                confidence=attack_entry["confidence"],
                severity=attack_entry["severity"],
                explanation=json.dumps(explanation_payload) if explanation_payload else None
            )
            db.add(attack_log)
            db.commit()
            db.close()
        except Exception as e:
            print(f"[Warning] Failed to log to database: {e}")

        return attack_entry

    def log_alert(self, alert_data: Dict) -> Dict:
        """Log alert information to both JSON file and database"""
        alert_entry = {
            "timestamp": datetime.now().isoformat(),
            "alert_type": "EMAIL_ALERT",
            "recipients": self.recipient_emails,
            "status": alert_data.get("status", "SENT"),
            **alert_data
        }

        # Log to JSON file (backward compatibility)
        try:
            with open(self.alert_log_path, 'r') as f:
                alerts = json.load(f)
            alerts.append(alert_entry)
            with open(self.alert_log_path, 'w') as f:
                json.dump(alerts, f, indent=2)
        except Exception as e:
            print(f"[Warning] Failed to log alert to JSON: {e}")

        # Log to database
        try:
            db = SessionLocal()
            alert_log = AlertLog(
                timestamp=datetime.now(),
                attack_type=alert_data.get("attack_type", "UNKNOWN"),
                severity=alert_data.get("severity", "UNKNOWN"),
                status=alert_data.get("status", "SENT"),
                method=alert_data.get("method", "UNKNOWN"),
                src_ip=alert_data.get("src_ip", "unknown"),
                dest_ip=alert_data.get("dest_ip", "unknown"),
                recipients=",".join(self.recipient_emails) if self.recipient_emails else "",
                error=alert_data.get("error")
            )
            db.add(alert_log)
            db.commit()
            db.close()
        except Exception as e:
            print(f"[Warning] Failed to log alert to database: {e}")

        return alert_entry

    def send_alert_email(self, packet_data: PacketWithPrediction, provided_severity: Optional[str] = None, use_email: bool = True) -> bool:
        """Send alert email for detected attack, or write to stdout/file if use_email=False (for testing)"""
        # Calculate severity first (for exception handling too)
        severity = self._get_severity_level(
            packet_data.prediction.attack_type,
            packet_data.prediction.confidence,
            provided_severity,
        )
        
        try:
            # Prefer model-generated explanation if available
            if (packet_data.prediction.explanation and isinstance(packet_data.prediction.explanation, dict) and "text" in packet_data.prediction.explanation):
                explanation = packet_data.prediction.explanation["text"]
            else:
                explanation = self._get_attack_explanation(packet_data.prediction.attack_type)

            # Try to format detection time: accept epoch float or ISO string
            try:
                ts = float(packet_data.packet.timestamp)
                detected_time = datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
            except Exception:
                try:
                    detected_time = datetime.fromisoformat(str(packet_data.packet.timestamp))
                    detected_time = detected_time.strftime('%Y-%m-%d %H:%M:%S')
                except Exception:
                    detected_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            body = f"""
SECURITY ALERT - Network Anomaly Detection System

[!] ATTACK DETECTED [!]

Attack Details:
--------------------------------------------------
Attack Type: {packet_data.prediction.attack_type}
Severity: {severity}
Source IP: {getattr(packet_data.packet, 'src_ip', 'unknown')}
Destination IP: {getattr(packet_data.packet, 'dest_ip', 'unknown')}
Protocol: {getattr(packet_data.packet, 'protocol', 'unknown')}
Packet Size: {getattr(packet_data.packet, 'length', 0)} bytes
Detection Time: {detected_time}
Confidence: {packet_data.prediction.confidence:.2%}

Explanation:
--------------------------------------------------
{explanation}

(Generated by Explainable AI module)


Recommended Actions:
--------------------------------------------------
- Review firewall rules
- Monitor affected systems
- Check for additional indicators of compromise
- Consider blocking the source IP if appropriate

This alert has been logged and is available in the attack_log.json file.

Network Security Team
Automated Alert System
"""

            # LOG THE ATTACK FIRST
            attack_info = self.log_attack(packet_data, provided_severity)

            if use_email:
                # Send via email (original behavior)
                msg = MIMEMultipart()
                msg['From'] = self.sender_email
                msg['To'] = ", ".join(self.recipient_emails)
                msg['Subject'] = f"🚨 SECURITY ALERT: {packet_data.prediction.attack_type} Attack Detected"
                msg.attach(MIMEText(body, 'plain'))

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
                    "src_ip": getattr(packet_data.packet, 'src_ip', 'unknown'),
                    "dest_ip": getattr(packet_data.packet, 'dest_ip', 'unknown'),
                    "status": "SENT",
                    "method": "EMAIL"
                })
            else:
                # Write to stdout + file (testing mode)
                print(body)
                
                # Append to alert_log.json with method=STDOUT
                self.log_alert({
                    "attack_type": packet_data.prediction.attack_type,
                    "severity": severity,
                    "src_ip": getattr(packet_data.packet, 'src_ip', 'unknown'),
                    "dest_ip": getattr(packet_data.packet, 'dest_ip', 'unknown'),
                    "status": "LOGGED",
                    "method": "STDOUT"
                })

            return True

        except Exception as e:
            # Log failed alert
            self.log_alert({
                "attack_type": packet_data.prediction.attack_type,
                "severity": severity,
                "src_ip": getattr(packet_data.packet, 'src_ip', 'unknown'),
                "dest_ip": getattr(packet_data.packet, 'dest_ip', 'unknown'),
                "status": "FAILED",
                "method": "EMAIL" if use_email else "STDOUT",
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
            print(f"[Warning] Failed to read attack logs: {e}")
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

def send_attack_alert(packet_data: PacketWithPrediction, provided_severity: Optional[str] = None, use_email: bool = True) -> bool:
    """Convenience function to send attack alert (defaults to stdout for testing)"""
    return alert_system.send_alert_email(packet_data, provided_severity=provided_severity, use_email=use_email)

def get_attack_logs(limit: int = 100) -> List[Dict]:
    """Convenience function to get attack logs"""
    return alert_system.get_attack_logs(limit)

def get_alert_logs(limit: int = 100) -> List[Dict]:
    """Convenience function to get alert logs"""
    return alert_system.get_alert_logs(limit)
