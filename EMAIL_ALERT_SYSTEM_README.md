# Email Alert System Documentation

## Overview
The Email Alert System provides automated security alerts for network attacks detected by the Network Anomaly Detection system. It includes email notifications, comprehensive logging, and API endpoints for monitoring.

## Features

### 📧 Email Alerts
- **Attack Type**: Identifies the type of attack (DDoS, PortScan, Malware, etc.)
- **IP Addresses**: Source and destination IP addresses involved
- **Timestamp**: Exact time when the attack was detected
- **Severity Level**: Critical, High, Medium, or Low based on attack type and confidence
- **Explanation Summary**: Detailed description of the attack and recommended actions

### 📊 Logging System
- **attack_log.json**: Records all detected attacks with full details
- **alert_log.json**: Records all alert attempts (sent emails, failures, etc.)

### 🔗 API Endpoints
- `GET /api/alerts/attack_logs` - Retrieve attack detection logs
- `GET /api/alerts/alert_logs` - Retrieve alert system logs
- `GET /api/alerts/stats` - Get comprehensive statistics

## Setup Instructions

### 1. Environment Variables
Configure the following environment variables for email functionality:

```bash
# Email configuration
ALERT_EMAIL=your-email@gmail.com
ALERT_EMAIL_PASSWORD=your-app-password
ALERT_RECIPIENTS=admin@company.com,security@company.com
```

### 2. Gmail Setup (if using Gmail)
1. Enable 2-factor authentication on your Gmail account
2. Generate an App Password:
   - Go to Google Account settings
   - Security → 2-Step Verification → App passwords
   - Generate password for "Mail"
   - Use this password in ALERT_EMAIL_PASSWORD

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Test the System
```bash
python test_alert_system.py
```

## How It Works

### Decision Engine Integration
The alert system is integrated with the packet prediction engine in `services/traffic.py`. When a packet is classified as an attack:

1. **Detection**: Packet analysis determines attack type and confidence
2. **Alert Trigger**: Email alert is automatically sent
3. **Logging**: Attack details are logged to `attack_log.json`
4. **Alert Logging**: Email sending status is logged to `alert_log.json`

### Severity Classification
- **CRITICAL**: Malware, SQL Injection with high confidence
- **HIGH**: DDoS, Brute Force with high confidence
- **MEDIUM**: Port scans, lower confidence attacks
- **LOW**: Suspicious activity with low confidence

### Email Content
Each alert email contains:
- Attack classification and severity
- Source and destination IP addresses
- Protocol and packet information
- Detection timestamp
- Detailed explanation
- Recommended security actions

## Log File Structure

### attack_log.json
```json
[
  {
    "timestamp": "2024-01-12T14:30:45.123456",
    "attack_type": "DDoS",
    "src_ip": "192.168.1.100",
    "dest_ip": "10.0.0.1",
    "protocol": "TCP",
    "packet_length": 1200,
    "confidence": 0.95,
    "severity": "HIGH"
  }
]
```

### alert_log.json
```json
[
  {
    "timestamp": "2024-01-12T14:30:45.234567",
    "alert_type": "EMAIL_ALERT",
    "recipients": ["admin@company.com"],
    "status": "SENT",
    "attack_type": "DDoS",
    "severity": "HIGH",
    "src_ip": "192.168.1.100",
    "dest_ip": "10.0.0.1",
    "email_subject": "🚨 SECURITY ALERT: DDoS Attack Detected"
  }
]
```

## API Usage Examples

### Get Recent Attack Logs
```bash
curl http://localhost:8000/api/alerts/attack_logs?limit=10
```

### Get Alert Statistics
```bash
curl http://localhost:8000/api/alerts/stats
```

### Get Alert Logs
```bash
curl http://localhost:8000/api/alerts/alert_logs?limit=5
```

## Integration Points

### With Frontend Dashboard
The alert system integrates with the Streamlit dashboard to:
- Display real-time alerts
- Show attack statistics
- Provide log viewing capabilities

### With Packet Processing
Every packet processed through the system is automatically checked for attacks and alerts are triggered when necessary.

## Security Considerations

1. **Email Credentials**: Store email passwords securely, never in code
2. **Rate Limiting**: Consider implementing rate limiting for alerts to prevent email flooding
3. **Encryption**: Use TLS for email transmission (enabled by default)
4. **Monitoring**: Monitor alert system health and email delivery success

## Troubleshooting

### Email Not Sending
1. Check environment variables are set correctly
2. Verify Gmail app password (not regular password)
3. Check network connectivity to SMTP server
4. Review alert_log.json for error messages

### Logs Not Updating
1. Ensure logs directory exists and is writable
2. Check file permissions
3. Verify JSON file structure is valid

### API Endpoints Not Working
1. Ensure FastAPI server is running
2. Check router registration in main.py
3. Verify endpoint URLs

## Future Enhancements

- SMS alerts integration
- Slack/Discord webhook notifications
- Alert escalation based on severity
- Alert suppression for repeated attacks
- Customizable alert templates
- Alert acknowledgment system