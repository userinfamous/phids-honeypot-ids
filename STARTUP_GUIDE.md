# PHIDS System Startup Guide

## 🚀 **Complete System Startup Instructions**

### **Prerequisites**
- Python 3.8+ installed
- All dependencies installed: `pip install -r requirements.txt`
- Administrative privileges (for packet capture on some systems)
- Ports 2222, 8080, and 5000 available

---

## 📋 **Step-by-Step Startup Process**

### **Step 1: Start PHIDS Main System**
```bash
# Navigate to project directory
cd python_final_project

# Start PHIDS with debug logging
python main.py --debug
```

**Expected Output:**
```
2025-08-27 17:20:32,011 - __main__ - INFO - Starting Python Honeypot IDS (PHIDS)
2025-08-27 17:20:32,021 - database - INFO - Database initialized successfully
2025-08-27 17:20:32,035 - __main__ - INFO - Started SSHHoneypot
2025-08-27 17:20:32,035 - __main__ - INFO - Started HTTPHoneypot
2025-08-27 17:20:32,036 - honeypot.ssh - INFO - Starting SSH honeypot on 0.0.0.0:2222
2025-08-27 17:20:32,036 - honeypot.http - INFO - Starting HTTP honeypot on 0.0.0.0:8080
2025-08-27 17:20:32,043 - src.dashboard.web_server - INFO - Starting dashboard web server on 127.0.0.1:5000
2025-08-27 17:20:32,170 - honeypot.ssh - INFO - SSH honeypot started successfully
2025-08-27 17:20:32,170 - honeypot.http - INFO - HTTP honeypot started successfully
```

### **Step 2: Verify Services Are Running**
```bash
# In a new terminal, run the diagnostic
python diagnose_phids_issues.py
```

**Expected Results:**
```
✅ Port 2222 (SSH Honeypot): Service is listening on port 2222
✅ Port 8080 (HTTP Honeypot): Service is listening on port 8080
✅ Port 5000 (Dashboard): Service is listening on port 5000
✅ SSH Connection: SSH honeypot responding with banner
✅ HTTP Connection: HTTP honeypot responding (status: 200)
✅ Dashboard Access: Dashboard is accessible
```

### **Step 3: Access Dashboard**
1. Open web browser
2. Navigate to: `http://127.0.0.1:5000`
3. Verify dashboard loads with real-time statistics
4. Test Controls button dropdown functionality

---

## 🧪 **Manual Attack Testing**

### **SSH Honeypot Testing (Port 2222)**

#### **Basic Connection Test:**
```bash
# Test SSH banner
telnet 127.0.0.1 2222

# Expected: SSH banner appears
# SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3
```

#### **SSH Attack Simulation:**
```bash
# Brute force simulation
ssh admin@127.0.0.1 -p 2222
# Enter any password when prompted

# Alternative test
nc 127.0.0.1 2222
# Should receive SSH banner
```

### **HTTP Honeypot Testing (Port 8080)**

#### **Basic Web Requests:**
```bash
curl "http://127.0.0.1:8080/"
curl "http://127.0.0.1:8080/admin"
curl "http://127.0.0.1:8080/login"
```

#### **SQL Injection Attacks:**
```bash
curl "http://127.0.0.1:8080/login?user=admin&pass=admin' OR '1'='1"
curl "http://127.0.0.1:8080/search?q=' UNION SELECT * FROM users --"
curl "http://127.0.0.1:8080/product?id=1'; WAITFOR DELAY '00:00:05' --"
```

#### **XSS Attacks:**
```bash
curl "http://127.0.0.1:8080/search?q=<script>alert('XSS')</script>"
curl "http://127.0.0.1:8080/profile?name=<img src=x onerror=alert('XSS')>"
curl "http://127.0.0.1:8080/page?content=<svg onload=alert('DOM XSS')>"
```

#### **Directory Traversal:**
```bash
curl "http://127.0.0.1:8080/file?path=../../../etc/passwd"
curl "http://127.0.0.1:8080/download?file=..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"
curl "http://127.0.0.1:8080/view?doc=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
```

#### **Command Injection:**
```bash
curl "http://127.0.0.1:8080/ping?host=127.0.0.1; cat /etc/passwd"
curl "http://127.0.0.1:8080/lookup?domain=example.com | whoami"
curl "http://127.0.0.1:8080/test?cmd=ls; ps aux"
```

---

## 🎛️ **Dashboard Controls Testing**

### **Controls Button Functionality:**
1. **Open Dashboard:** `http://127.0.0.1:5000`
2. **Click Controls Button:** Should display dropdown menu
3. **Available Options:**
   - Clear Logs (All Logs, Connections Only, Alerts Only)
   - Toggle Live/Historical View
   - Export Connections (CSV)
   - Export Alerts (CSV)

### **Clear Logs Testing:**
1. Click "Controls" → "Clear Logs"
2. Select log type from modal
3. Click "Confirm"
4. Verify operation completes without errors

---

## 🔧 **Troubleshooting**

### **Common Issues and Solutions:**

#### **Issue: "Address already in use" Error**
```bash
# Check what's using the ports
netstat -ano | findstr ":2222\|:8080\|:5000"

# Kill processes using those ports (Windows)
taskkill /PID <PID_NUMBER> /F

# Then restart PHIDS
python main.py --debug
```

#### **Issue: SSH Connection Refused**
```bash
# Verify SSH honeypot is running
python diagnose_phids_issues.py

# Check firewall settings
# Windows: Allow Python through Windows Firewall
# Linux: sudo ufw allow 2222
```

#### **Issue: Controls Button Not Working**
1. Check browser console (F12) for JavaScript errors
2. Verify Bootstrap CSS/JS are loading
3. Test in different browser
4. Clear browser cache

#### **Issue: No Attack Detection**
1. Verify PHIDS is running with `--debug` flag
2. Check logs for error messages
3. Ensure attacks are targeting correct ports (2222, 8080)
4. Wait 2-3 seconds for processing

---

## 📊 **Expected Behavior**

### **When System is Working Correctly:**

1. **SSH Attacks:**
   - Connections accepted on port 2222
   - SSH banner displayed
   - Commands logged with attack analysis
   - Detailed recommendations provided

2. **HTTP Attacks:**
   - Requests accepted on port 8080
   - Attack vectors identified (SQL injection, XSS, etc.)
   - Payloads extracted and analyzed
   - Severity levels assigned

3. **Dashboard:**
   - Real-time updates within 1-2 seconds
   - Accurate timestamps (not page refresh time)
   - Detailed connection and alert information
   - Working Controls dropdown

4. **Logging:**
   - Source IP addresses and connection details
   - Specific attack vectors and payloads
   - Attack classification and severity levels
   - Actionable security recommendations

---

## 🎯 **Success Indicators**

### **System is Ready When:**
- ✅ All three services start without errors
- ✅ SSH banner responds on port 2222
- ✅ HTTP requests succeed on port 8080
- ✅ Dashboard loads at http://127.0.0.1:5000
- ✅ Controls button shows dropdown menu
- ✅ Attack commands generate detailed logs
- ✅ Timestamps reflect actual event times
- ✅ Real-time updates appear in dashboard

### **Professional Demonstration Ready:**
- ✅ All manual attack commands work as documented
- ✅ Dashboard shows comprehensive attack details
- ✅ Controls functionality operates without errors
- ✅ Logs provide actionable security intelligence
- ✅ System handles multiple concurrent attacks
- ✅ Forensic timeline accuracy maintained

---

## 💡 **Quick Start Commands**

```bash
# Complete startup sequence
cd python_final_project
python main.py --debug

# In new terminal - verify system
python diagnose_phids_issues.py

# In new terminal - test attacks
curl "http://127.0.0.1:8080/admin"
ssh admin@127.0.0.1 -p 2222

# Open browser
# http://127.0.0.1:5000
```

**🛡️ Your PHIDS honeypot system is now ready for comprehensive security testing and professional demonstrations!**
