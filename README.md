# PHIDS - Python Honeypot Intrusion Detection System 🛡️

**Real-time honeypot system with interactive dashboard for cybersecurity demonstration and threat detection.**

SSH and HTTP honeypots with live attack visualization, enhanced logging, and color-coded status classification (SUCCESS/FAILED/ERROR/TIMEOUT).

---

## 🚀 **Quick Start**

### **1. Install and Setup**
```bash
# Install dependencies
pip install -r requirements.txt

# Start PHIDS system
python main.py --debug

# Access dashboard: http://127.0.0.1:5000
```

### **2. Generate Demo Data**
```bash
# Populate dashboard with sample attack data
python demo_dashboard.py

# For continuous live simulation
python demo_dashboard.py --live
```

### **3. Clear Demo Data (Optional)**
```bash
# Start dashboard and clear old data
python start_dashboard.py
# Browser: http://127.0.0.1:5000 → Controls → Clear Logs → All Logs
```

---

## 🧪 **Attack Testing Guide**

### **🔐 SSH Honeypot Testing (Port 2222)**

#### **SUCCESS Scenarios** ✅
```bash
# Complete SSH session with valid credentials
ssh root@127.0.0.1 -p 2222
# Password: password (try: admin, password, 123456, root)
# Execute commands: ls, pwd, whoami
# Type 'exit' to close

# Expected: GREEN entry in dashboard with authentication details
```

#### **FAILED Scenarios** ❌
```bash
# Real SSH client (fails protocol negotiation)
ssh admin@127.0.0.1 -p 2222
# Expected: RED entry with "Protocol negotiation failed"

# Invalid connection
python -c "
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('127.0.0.1', 2222))
sock.send(b'INVALID-BANNER\r\n')
sock.close()
"
# Expected: RED entry with "Invalid SSH banner"
```

#### **ERROR/TIMEOUT Scenarios** ⚠️
```bash
# Immediate disconnect (ERROR)
python -c "
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('127.0.0.1', 2222))
sock.close()
"
# Expected: ORANGE entry with "No meaningful interaction"

# Connection timeout (TIMEOUT)
python -c "
import socket, time
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('127.0.0.1', 2222))
time.sleep(35)  # Wait for timeout
sock.close()
"
# Expected: YELLOW entry with "Connection timeout"
```

### **🌐 HTTP Honeypot Testing (Port 8080)**

#### **SUCCESS Scenarios** ✅
```bash
# Basic requests
curl http://127.0.0.1:8080/
curl http://127.0.0.1:8080/admin
curl http://127.0.0.1:8080/wp-admin

# POST request
curl -X POST http://127.0.0.1:8080/login -d "user=admin&pass=test"

# Expected: GREEN entries with HTTP method and path details
```

#### **Attack Detection** 🚨
```bash
# SQL Injection (triggers IDS alerts)
curl "http://127.0.0.1:8080/login?user=admin&pass=admin' OR '1'='1"
curl "http://127.0.0.1:8080/search?q=' UNION SELECT * FROM users --"

# XSS Attacks
curl "http://127.0.0.1:8080/search?q=<script>alert('XSS')</script>"
curl "http://127.0.0.1:8080/profile?name=<img src=x onerror=alert(1)>"

# Directory Traversal
curl "http://127.0.0.1:8080/file?path=../../../etc/passwd"

# Expected: GREEN entries + RED alert notifications in dashboard
```

#### **FAILED Scenarios** ❌
```bash
# Malformed HTTP request
python -c "
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('127.0.0.1', 8080))
sock.send(b'INVALID HTTP REQUEST\r\n\r\n')
sock.close()
"
# Expected: RED entry with "Invalid HTTP request"
```

### **📊 Dashboard Verification**

#### **Color-Coded Status Classification**
- **🟢 GREEN (SUCCESS)**: Complete interactions with details
- **🔴 RED (FAILED)**: Failed connections with failure reasons
- **🟠 ORANGE (ERROR)**: Technical errors with descriptions
- **🟡 YELLOW (TIMEOUT)**: Timeouts with duration (~30s)
- **🚨 RED ALERTS**: IDS detections for malicious payloads

#### **Real-Time Verification**
1. **Open Dashboard**: http://127.0.0.1:5000
2. **Run Attack**: `curl http://127.0.0.1:8080/admin`
3. **Verify**: Entry appears within 1-2 seconds with correct timestamp
4. **Check Details**: Click entry to see full connection information

### **🪟 Windows PowerShell Alternatives**
```powershell
# Instead of curl
Invoke-WebRequest -Uri "http://127.0.0.1:8080/admin" -Method GET

# Instead of SSH
Test-NetConnection -ComputerName 127.0.0.1 -Port 2222

# TCP connection test
$client = New-Object System.Net.Sockets.TcpClient
$client.Connect("127.0.0.1", 2222)
$client.Close()
```

---

## 🔧 **Troubleshooting**

### **Common Issues**

#### **"Attacks not appearing in dashboard"**
```bash
# Check if PHIDS is running
python main.py --debug  # Should show honeypots started

# Test dashboard API
curl http://127.0.0.1:5000/api/stats  # Should return JSON

# Check ports are listening
netstat -an | grep ":2222\|:8080\|:5000"
```

#### **"SSH/curl commands not found (Windows)"**
```powershell
# Install OpenSSH
Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0

# Use PowerShell alternatives
Invoke-WebRequest -Uri "http://127.0.0.1:8080" -Method GET
Test-NetConnection -ComputerName 127.0.0.1 -Port 2222
```

#### **"Permission denied errors"**
```bash
# Run as administrator (Windows) or with sudo (Linux/Mac)
# Honeypots need elevated privileges to bind to ports
```

---

## 🧪 **Testing**

### **Run Test Suite**
```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=src --cov-report=html

# Run specific test file
pytest tests/test_phids.py -v
```

### **Manual Testing Scripts**
```bash
# Test manual attack scenarios
python tests/test_manual_attacks.py

# Test main application functionality
python tests/test_main.py
```

---

## 🐳 **Docker Deployment**

### **Using Docker Compose**
```bash
# Build and start services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### **Manual Docker Build**
```bash
# Build image
docker build -t phids .

# Run container
docker run -d -p 2222:2222 -p 8080:8080 -p 5000:5000 phids
```

---

## 📁 **Project Structure**

```
python_final_project/
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

Key configuration options in `config.py`:

- **Honeypot Ports**: SSH (2222), HTTP (8080)
- **Dashboard Port**: 5000
- **Database**: SQLite (data/phids.db)
- **Logging**: Configurable levels and formats
- **Network Monitoring**: Optional packet capture

---

**🛡️ Professional honeypot system demonstrating cybersecurity concepts with real-time attack visualization and enhanced logging capabilities.**
