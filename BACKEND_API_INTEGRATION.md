# Backend API Integration Guide

## Quick Start - How to Hand Off to Frontend

### Step 1: Start the Backend API Server

```bash
cd backend
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

**Output:**
```
INFO:     Uvicorn running on http://0.0.0.0:8000
INFO:     Application startup complete
```

### Step 2: Access API Documentation

Once running, open: **http://localhost:8000/docs**

You'll see the interactive Swagger UI with all endpoints, request/response schemas, and ability to test endpoints directly.

### Step 3: Frontend Connection

 use this base URL:
```
http://localhost:8000/api
```

Or for production:
```
http://<backend-server-ip>:8000/api
```

---

## API Endpoints

All endpoints return JSON responses and have CORS enabled (`allow_origins=["*"]`).

### 1. **Statistics** - `/api/stats`

#### GET `/api/stats`
Basic dashboard statistics including detection rate and traffic metrics.

**Response:**
```json
{
  "total_packets": 291012,
  "total_bytes": 45000000,
  "total_flows": 5000,
  "detection_rate": 0.0927,
  "alerts_sent": 27,
  "last_updated": "2026-01-20T22:45:51"
}
```

---

### 2. **Alerts & Logs** - `/api/alerts/*`

#### GET `/api/alerts/attack_logs`
Retrieve recent attack detection logs.

**Query Parameters:**
- `limit` (int, default=100): Number of recent logs to retrieve

**Response:**
```json
[
  {
    "timestamp": "2026-01-20T23:39:34.324335",
    "attack_type": "Scan",
    "src_ip": "unknown",
    "dest_ip": "unknown",
    "protocol": "unknown",
    "packet_length": 0,
    "confidence": 0.0023614503153261877,
    "severity": "MEDIUM"
  },
  {
    "timestamp": "2026-01-20T23:39:34.334123",
    "attack_type": "BruteForce",
    "src_ip": "unknown",
    "dest_ip": "unknown",
    "protocol": "unknown",
    "packet_length": 0,
    "confidence": 0.95,
    "severity": "HIGH"
  }
]
```

#### GET `/api/alerts/alert_logs`
Retrieve alert system logs (email delivery status, etc.).

**Query Parameters:**
- `limit` (int, default=100): Number of recent logs to retrieve

**Response:**
```json
[
  {
    "timestamp": "2026-01-20T23:39:34.325335",
    "alert_type": "EMAIL_ALERT",
    "recipients": ["romiyaraju98@gmail.com"],
    "status": "SENT",
    "attack_type": "Scan",
    "severity": "MEDIUM",
    "src_ip": "unknown",
    "dest_ip": "unknown",
    "method": "EMAIL"
  }
]
```

#### GET `/api/alerts/stats`
Comprehensive alert statistics with attack distributions.

**Response:**
```json
{
  "total_attacks_detected": 27,
  "total_alerts_sent": 27,
  "alert_success_rate": 100.0,
  "attacks_by_severity": {
    "HIGH": 1,
    "MEDIUM": 26
  },
  "attacks_by_type": {
    "Scan": 26,
    "BruteForce": 1
  },
  "recent_attacks": [
    {
      "timestamp": "2026-01-20T23:39:34.324335",
      "attack_type": "Scan",
      "severity": "MEDIUM",
      "confidence": 0.0023614503153261877
    }
  ],
  "recent_alerts": [
    {
      "timestamp": "2026-01-20T23:39:34.325335",
      "status": "SENT",
      "attack_type": "Scan",
      "severity": "MEDIUM"
    }
  ]
}
```

---

### 3. **Analytics** - `/api/analytics/*`

#### GET `/api/analytics/attack_distribution`
Distribution of attack types vs normal traffic.

**Response:**
```json
{
  "total_traffic": 291012,
  "benign": 290985,
  "malicious": 27,
  "distribution": {
    "Benign": 99.99,
    "Scan": 0.0089,
    "BruteForce": 0.0003
  }
}
```

#### GET `/api/analytics/time_trends`
Time series trends for detection metrics.

**Response:**
```json
{
  "timestamps": [
    "2026-01-20T22:00:00",
    "2026-01-20T22:15:00",
    "2026-01-20T22:30:00"
  ],
  "packet_rate": [100.5, 95.2, 110.8],
  "flow_rate": [5.1, 4.8, 5.5],
  "bytes_per_second": [15000, 14500, 16200],
  "attacks_detected": [0, 5, 12]
}
```

---

### 4. **Packets** - `/api/packets`

#### GET `/api/packets`
List recent packet data with ML predictions.

**Query Parameters:**
- `count` (int, default=5, range 1-100): Number of packets to retrieve

**Response:**
```json
[
  {
    "packet": {
      "id": 12345,
      "src_ip": "192.168.1.100",
      "dest_ip": "10.0.0.50",
      "length": 1500,
      "protocol": "TCP",
      "timestamp": 1705793394
    },
    "prediction": {
      "label": "attack",
      "confidence": 0.95,
      "attack_type": "BruteForce"
    }
  }
]
```

---

### 5. **Streaming (Server-Sent Events)** - `/stream/*`

#### GET `/stream/alerts`
Real-time alert stream (SSE - Server-Sent Events).

Connect to receive real-time alerts as they're detected.

**JavaScript Example:**
```javascript
const eventSource = new EventSource('http://localhost:8000/stream/alerts');
eventSource.onmessage = (event) => {
  const alert = JSON.parse(event.data);
  console.log('New alert:', alert);
};
eventSource.onerror = () => {
  console.error('Connection error');
  eventSource.close();
};
```

---

## Data Models

### Attack Log Entry
```json
{
  "timestamp": "ISO 8601 string",
  "attack_type": "string (Scan, DoS, BruteForce, Malware, Web, etc.)",
  "src_ip": "string",
  "dest_ip": "string",
  "protocol": "string (TCP, UDP, ICMP, etc.)",
  "packet_length": "integer (bytes)",
  "confidence": "float (0.0 - 1.0)",
  "severity": "string (LOW, MEDIUM, HIGH, CRITICAL)"
}
```

### Alert Log Entry
```json
{
  "timestamp": "ISO 8601 string",
  "alert_type": "string (EMAIL_ALERT)",
  "recipients": "array of email strings",
  "status": "string (SENT, LOGGED, FAILED)",
  "attack_type": "string",
  "severity": "string",
  "src_ip": "string",
  "dest_ip": "string",
  "method": "string (EMAIL, STDOUT, etc.)",
  "error": "string (optional, if status=FAILED)"
}
```

---

## CORS Configuration

The API is configured for frontend development with CORS enabled:

```python
CORSMiddleware(
    allow_origins=["*"],        # Allow all origins (for development)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

### For Production:
Update in [backend/main.py](main.py#L8-L15):
```python
allow_origins=["https://your-frontend-domain.com"],
```

---

## Common Frontend Integration Patterns

### 1. Display Dashboard Stats
```javascript
fetch('http://localhost:8000/api/stats')
  .then(r => r.json())
  .then(data => {
    document.getElementById('detection-rate').textContent = 
      (data.detection_rate * 100).toFixed(2) + '%';
  });
```

### 2. Show Recent Alerts
```javascript
fetch('http://localhost:8000/api/alerts/stats')
  .then(r => r.json())
  .then(data => {
    console.log('Recent attacks:', data.recent_attacks);
    console.log('Total sent:', data.total_alerts_sent);
  });
```

### 3. Real-Time Attack Feed
```javascript
const eventSource = new EventSource('http://localhost:8000/stream/alerts');
eventSource.onmessage = (event) => {
  const alert = JSON.parse(event.data);
  addAlertToTable(alert);
};
```

### 4. Attack Analytics Chart
```javascript
fetch('http://localhost:8000/api/analytics/attack_distribution')
  .then(r => r.json())
  .then(data => {
    // Use Chart.js or similar
    chart.data = data.distribution;
    chart.update();
  });
```

---

## Deployment Checklist

- [ ] Backend API running on accessible IP/port
- [ ] CORS settings configured for frontend domain
- [ ] Environment variables set (ALERT_EMAIL, ALERT_EMAIL_PASSWORD, etc.)
- [ ] Logs directory exists and is writable
- [ ] Fusion pipeline (run_fusion.py) running in background
- [ ] API documented and shared with frontend team
- [ ] Test endpoints with Swagger UI before handoff
- [ ] Verify email alerts working (optional, for production)

---

## API Testing Tools

### Swagger UI (Interactive)
```
http://localhost:8000/docs
```

### ReDoc (Alternative Documentation)
```
http://localhost:8000/redoc
```

### cURL Examples
```bash
# Get stats
curl http://localhost:8000/api/stats

# Get alert stats
curl http://localhost:8000/api/alerts/stats

# Get recent attacks (limit to 5)
curl "http://localhost:8000/api/alerts/attack_logs?limit=5"

# Get attack distribution
curl http://localhost:8000/api/analytics/attack_distribution
```

---

## Frontend Handoff Checklist

**What to provide to frontend team:**

1. ✓ API base URL: `http://localhost:8000/api`
2. ✓ Swagger documentation: `http://localhost:8000/docs`
3. ✓ List of available endpoints (see above)
4. ✓ Example responses for each endpoint
5. ✓ Data model definitions
6. ✓ CORS enabled for frontend development
7. ✓ Real-time SSE endpoint for live alerts
8. ✓ Recommended dashboard components:
   - Attack stats summary (HIGH/MEDIUM/LOW)
   - Recent attacks table
   - Attack type distribution chart
   - Real-time alert notifications
   - Time trends chart (if needed)

---

## Support Information

**Backend API Status:** ✓ Production Ready

**Key Endpoints:**
- Statistics: `/api/stats`
- Alerts: `/api/alerts/stats`, `/api/alerts/attack_logs`
- Analytics: `/api/analytics/attack_distribution`
- Real-time: `/stream/alerts`

**Important Notes for Frontend:**
- All timestamps are ISO 8601 format
- Confidence values are 0.0-1.0 (multiply by 100 for percentage)
- Severity: LOW, MEDIUM, HIGH, CRITICAL
- Attack types: Scan, DoS, BruteForce, Malware, Web, etc.
- Response times should be < 100ms for cached endpoints

---

**Last Updated:** January 20, 2026  
**Status:** Ready for Frontend Integration
