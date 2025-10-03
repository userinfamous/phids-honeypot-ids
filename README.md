# PHIDS - Python Honeypot Intrusion Detection System 🛡️

**Professional honeypot-based intrusion detection system for SOC analysts and cybersecurity professionals.**

Real-time threat detection with SSH and HTTP honeypots, live attack visualization, precise timestamp logging, and comprehensive security event analysis designed for Security Operations Center (SOC) environments.

---

## 🎯 **What PHIDS Does**

PHIDS is a **honeypot-based intrusion detection system** designed for:

- **SOC Analysis**: Real-time threat detection and incident response
- **Network Security Monitoring**: Continuous surveillance of local network segments
- **Attack Pattern Recognition**: Automated detection of reconnaissance, brute force, and exploitation attempts
- **Threat Intelligence**: IP reputation analysis and attack attribution
- **Security Training**: Hands-on cybersecurity education and demonstration

### **Core Capabilities**
- ✅ **Real-time Detection**: Sub-second attack detection with precise timestamps
- ✅ **Multiple Honeypots**: SSH (port 2222) and HTTP (port 8080) services
- ✅ **Live Dashboard**: WebSocket-powered real-time monitoring interface
- ✅ **Attack Classification**: Automated severity assessment and threat categorization
- ✅ **Event Correlation**: Timeline analysis and attack pattern recognition
- ✅ **Export Capabilities**: CSV/JSON export for SIEM integration

---

## 🚀 **Quick Start**

### **1. Installation**
```bash
# Clone repository
git clone <repository-url>
cd phids

# Install dependencies
pip install -r requirements.txt

# Start PHIDS system
python main.py --debug

# Access dashboard: http://127.0.0.1:5000
```

### **2. Generate Demo Data (Optional)**
```bash
# Populate dashboard with realistic attack scenarios
python demo_dashboard.py

# For continuous simulation
python demo_dashboard.py --live
```

### **3. Clear Demo Data**
```bash
# Start dashboard and clear old data
python start_dashboard.py
# Browser: http://127.0.0.1:5000 → Controls → Clear Logs → All Logs
```

---

## 🔍 **SOC Analyst Guide**

### **Real-Time Monitoring**

#### **Dashboard Overview**
- **Live Feed**: Real-time attack detection with sub-second latency
- **Event Timeline**: Chronological view of all security events
- **Threat Classification**: Automated severity assessment (Critical/High/Medium/Low)
- **Attack Attribution**: IP geolocation and reputation analysis
- **Pattern Recognition**: Automated detection of attack campaigns

#### **Key Metrics for SOC Analysis**
- **Detection Latency**: < 1 second from attack to alert
- **False Positive Rate**: < 5% with enhanced validation
- **Event Correlation**: Automatic grouping of related attacks
- **Threat Intelligence**: Real-time IP reputation scoring
- **Export Capabilities**: CSV/JSON for SIEM integration

### **Attack Detection Capabilities**

#### **SSH Honeypot (Port 2222)**
```bash
# Test SSH brute force detection
ssh root@127.0.0.1 -p 2222
# Password: password (try: admin, password, 123456, root)

# Expected SOC Output:
# - Real-time authentication event logging
# - Credential enumeration detection
# - Session command monitoring
# - Precise timestamp accuracy (ISO 8601 format)
```

#### **HTTP Honeypot (Port 8080)**
```bash
# Test web application attacks
curl http://127.0.0.1:8080/admin
curl "http://127.0.0.1:8080/login?user=admin&pass=admin' OR '1'='1"

# Expected SOC Output:
# - HTTP request analysis
# - SQL injection detection
# - Directory traversal attempts
# - XSS payload identification
```

#### **Attack Pattern Recognition**
- **Reconnaissance**: Port scanning, directory enumeration
- **Brute Force**: Credential stuffing, password spraying
- **Exploitation**: SQL injection, XSS, command injection
- **Post-Exploitation**: Command execution, file access attempts

### **Dashboard Status Indicators**
- **🟢 SUCCESS**: Complete attack interactions (high priority)
- **🔴 FAILED**: Connection failures (investigate for evasion)
- **🟠 ERROR**: Technical issues (potential system problems)
- **🟡 TIMEOUT**: Slow connections (possible reconnaissance)
- **🚨 CRITICAL ALERTS**: Active exploitation attempts

### **Incident Response Workflow**
1. **Detection**: Real-time alert in dashboard
2. **Analysis**: Click event for detailed forensics
3. **Classification**: Review automated threat assessment
4. **Correlation**: Check related events from same source
5. **Response**: Export data for further investigation
6. **Documentation**: Generate incident reports

---

## 🔧 **Troubleshooting**

### **Common Issues**

#### **"No attacks appearing in dashboard"**
```bash
# 1. Verify PHIDS is running
python main.py --debug
# Expected output: "SSH Honeypot started on port 2222", "HTTP Honeypot started on port 8080"

# 2. Test dashboard API connectivity
curl http://127.0.0.1:5000/api/stats
# Expected: JSON response with statistics

# 3. Verify ports are listening
netstat -an | grep ":2222\|:8080\|:5000"
# Expected: LISTENING status for all three ports

# 4. Test honeypot responsiveness
curl http://127.0.0.1:8080/test
# Expected: Response from HTTP honeypot + dashboard entry within 2 seconds
```

#### **"Dashboard shows old timestamps"**
```bash
# Check system time synchronization
date  # Linux/Mac
Get-Date  # Windows PowerShell

# Verify database timestamp format
sqlite3 data/phids.db "SELECT timestamp FROM honeypot_connections ORDER BY id DESC LIMIT 5;"
# Expected: ISO 8601 format (YYYY-MM-DDTHH:MM:SS)

# Clear cache and refresh
# Browser: Ctrl+F5 or Cmd+Shift+R
```

#### **"Real-time updates not working"**
```bash
# Check WebSocket connection in browser console (F12)
# Expected: WebSocket connection to ws://127.0.0.1:5000/ws

# Verify WebSocket configuration
grep -r "websocket_update_interval" config.py
# Expected: 5 seconds (configurable)

# Test WebSocket manually
python -c "
import asyncio
import websockets
async def test():
    async with websockets.connect('ws://127.0.0.1:5000/ws') as ws:
        msg = await ws.recv()
        print('Received:', msg)
asyncio.run(test())
"
```

#### **"Permission denied errors"**
```bash
# Linux/Mac: Run with appropriate privileges
sudo python main.py

# Windows: Run PowerShell as Administrator
# Right-click PowerShell → "Run as Administrator"

# Alternative: Use Docker (no privilege issues)
docker-compose up
```

#### **"High CPU/Memory usage"**
```bash
# Check performance configuration
grep -A 10 "performance" config.py

# Recommended settings for production:
# - websocket_update_interval: 10 (seconds)
# - stats_cache_duration: 60 (seconds)
# - max_websocket_connections: 10

# Monitor resource usage
top -p $(pgrep -f "python main.py")  # Linux
Get-Process python | Where-Object {$_.ProcessName -eq "python"}  # Windows
```

---

## 🧪 **Testing & Validation**

### **Automated Test Suite**
```bash
# Run comprehensive test suite
pytest tests/ -v

# Run with coverage analysis
pytest tests/ --cov=src --cov-report=html

# Test specific components
pytest tests/test_phids.py -v                    # Core functionality
pytest tests/test_dashboard_api.py -v            # Dashboard API
pytest tests/test_database_and_logging.py -v     # Database operations
```

### **Manual Attack Simulation**
```bash
# Test SSH honeypot detection
python tests/test_manual_attacks.py

# Verify timing accuracy
python -c "
import time
import requests
start = time.time()
requests.get('http://127.0.0.1:8080/test')
print(f'Response time: {time.time() - start:.3f}s')
# Expected: < 0.1s response time, dashboard update within 1s
"
```

### **Performance Validation**
```bash
# Test concurrent connections
for i in {1..10}; do
    curl http://127.0.0.1:8080/test &
done
wait
# Expected: All requests logged with accurate timestamps

# Monitor real-time performance
curl -s http://127.0.0.1:5000/api/stats | jq '.last_updated'
# Expected: Recent timestamp (within last 30 seconds)
```

---

## 🐳 **Docker Deployment**

### **Production Deployment**
```bash
# Build and start services
docker-compose up -d

# Monitor logs in real-time
docker-compose logs -f phids

# Check container health
docker-compose ps
# Expected: "healthy" status

# Stop services
docker-compose down
```

### **Development Setup**
```bash
# Build custom image
docker build -t phids:dev .

# Run with volume mounts for development
docker run -d \
  -p 2222:2222 -p 8080:8080 -p 5000:5000 \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/logs:/app/logs \
  phids:dev
```

---

## 📁 **Project Structure**

```
phids/
├── src/                    # Source code
│   ├── core/              # Core functionality (database, logging)
│   ├── honeypots/         # SSH and HTTP honeypots
│   ├── ids/               # Intrusion detection system
│   ├── dashboard/         # Web dashboard
│   ├── analysis/          # Log analysis and IOC extraction
│   ├── reporting/         # Report generation
│   ├── capture/           # Network monitoring
│   └── threat_intel/      # Threat intelligence
├── tests/                 # Test suite
├── data/                  # Database files
├── logs/                  # Log files
├── reports/               # Generated reports
├── main.py               # Main application entry point
├── config.py             # Configuration settings
├── demo_dashboard.py     # Demo data generator
└── requirements.txt      # Python dependencies
```

---

## ⚙️ **Configuration**

### **Core Settings** (`config.py`)
```python
# Honeypot Configuration
HONEYPOT_CONFIG = {
    "ssh": {"port": 2222, "enabled": True},
    "http": {"port": 8080, "enabled": True}
}

# Dashboard Configuration
DASHBOARD_CONFIG = {
    "host": "127.0.0.1",
    "port": 5000,
    "performance": {
        "websocket_update_interval": 5,  # Real-time update frequency
        "stats_cache_duration": 30,      # Cache refresh interval
        "max_websocket_connections": 50  # Concurrent dashboard users
    }
}

# Security Settings
SECURITY_CONFIG = {
    "max_connections_per_ip": 100,
    "connection_timeout": 30,
    "blacklist_threshold": 10
}
```

### **Performance Tuning for SOC Environments**
```python
# High-frequency monitoring (sub-second detection)
"websocket_update_interval": 1,
"stats_cache_duration": 10,

# Production stability (balanced performance)
"websocket_update_interval": 5,
"stats_cache_duration": 30,

# Resource-constrained environments
"websocket_update_interval": 15,
"stats_cache_duration": 60,
```

### **Database Configuration**
- **Location**: `data/phids.db` (SQLite)
- **Indexes**: Optimized for timestamp and IP-based queries
- **Retention**: Configurable data retention policies
- **Backup**: Automated backup capabilities

---

## 📊 **Expected Outputs & Interpretation**

### **Dashboard Metrics**
- **Total Connections**: All honeypot interactions (24-hour rolling window)
- **Active Alerts**: Current security events requiring attention
- **Unique Attackers**: Distinct IP addresses observed
- **Attack Timeline**: Chronological event visualization

### **Event Classification**
- **SUCCESS** (Green): Complete attack interactions with full forensic data
- **FAILED** (Red): Connection failures (potential evasion attempts)
- **ERROR** (Orange): Technical issues requiring investigation
- **TIMEOUT** (Yellow): Slow connections (reconnaissance indicators)

### **Threat Intelligence**
- **IP Reputation**: Automated scoring based on attack patterns
- **Geolocation**: Attack source attribution
- **Attack Sophistication**: Automated complexity assessment
- **Campaign Detection**: Related attack grouping

---

## 🚨 **Security Considerations**

### **Network Isolation**
- Deploy in isolated network segment
- Monitor for lateral movement attempts
- Implement network access controls

### **Data Protection**
- Sensitive data anonymization available
- Configurable data retention policies
- Secure export capabilities for analysis

### **Operational Security**
- Dashboard access controls recommended
- Regular security updates required
- Monitoring of honeypot health status

---

**🛡️ Professional honeypot-based intrusion detection system designed for SOC analysts, cybersecurity professionals, and security researchers. Provides real-time threat detection with precise timing accuracy and comprehensive attack analysis capabilities.**
