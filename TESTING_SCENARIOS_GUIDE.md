# PHIDS Testing Scenarios Guide 🧪

## Overview

This guide provides comprehensive instructions for testing both **SUCCESS** and **FAILED** scenarios across all PHIDS honeypot services to verify that the enhanced logging system correctly classifies connection outcomes.

## 🎯 **Testing Objectives**

1. **Verify SUCCESS Classification** - Ensure legitimate successful interactions are logged as SUCCESS
2. **Verify FAILED Classification** - Ensure failed attempts are logged as FAILED
3. **Verify ERROR Classification** - Ensure technical errors are logged as ERROR  
4. **Verify TIMEOUT Classification** - Ensure timeouts are logged as TIMEOUT
5. **Validate Enhanced Logging** - Confirm detailed context information is captured

---

## 🚀 **Prerequisites**

### **1. Start PHIDS System**
```bash
# Terminal 1: Start PHIDS with debug logging
python main.py --debug

# Expected output:
# ✅ SSH honeypot started on port 2222
# ✅ HTTP honeypot started on port 8080  
# ✅ Dashboard available at http://127.0.0.1:5000
```

### **2. Clear Previous Logs (Recommended)**
```bash
# Open dashboard: http://127.0.0.1:5000
# Click: Controls → Clear Logs → All Logs
# This ensures clean test results
```

### **3. Open Monitoring Windows**
```bash
# Terminal 2: Monitor logs in real-time
tail -f logs/honeypot.log | grep "SSH:\|HTTP:"

# Browser: Open dashboard at http://127.0.0.1:5000
# Watch for real-time updates with color coding
```

---

## 🔐 **SSH Honeypot Testing (Port 2222)**

### **SUCCESS Scenarios** ✅

#### **Scenario 1: Complete SSH Session with Authentication**
```bash
# This should result in SUCCESS status
python -c "
import socket
import time

# Simulate a complete SSH interaction
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('127.0.0.1', 2222))

# Send SSH banner
sock.send(b'SSH-2.0-TestClient-Success\r\n')
time.sleep(1)

# Receive server banner
banner = sock.recv(1024)
print(f'Server banner: {banner.decode()}')

# Send key exchange
sock.send(b'\x00\x00\x01\x2c\x0a\x14' + b'\x00' * 294)
time.sleep(1)

# Receive key exchange response
kex_response = sock.recv(1024)

# Send authentication data (simulate successful auth)
auth_data = b'admin:admin'  # Valid credentials
sock.send(auth_data)
time.sleep(2)

# Send some shell commands
sock.send(b'ls -la\n')
time.sleep(1)
sock.send(b'whoami\n')
time.sleep(1)

sock.close()
print('✅ Complete SSH session finished')
"

# Expected Result: SUCCESS with authentication details and commands logged
```

#### **Scenario 2: SSH Session with Valid Credentials**
```bash
# Use actual SSH client with valid honeypot credentials
ssh root@127.0.0.1 -p 2222
# Password: password (from fake_users in ssh_honeypot.py)
# Execute some commands: ls, pwd, whoami
# Type 'exit' to close session

# Expected Result: SUCCESS with full session details
```

### **FAILED Scenarios** ❌

#### **Scenario 3: SSH Protocol Negotiation Failure**
```bash
# Real SSH client that fails protocol negotiation
ssh admin@127.0.0.1 -p 2222
# This will fail with protocol errors and should be FAILED

# Expected Result: FAILED - Protocol negotiation failed
```

#### **Scenario 4: Invalid SSH Banner**
```bash
python -c "
import socket
import time

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('127.0.0.1', 2222))

# Send invalid banner
sock.send(b'INVALID-BANNER\r\n')
time.sleep(2)

sock.close()
print('❌ Invalid banner test completed')
"

# Expected Result: FAILED - Invalid SSH banner format
```

#### **Scenario 5: Authentication Failure**
```bash
python -c "
import socket
import time

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('127.0.0.1', 2222))

# Send valid SSH banner
sock.send(b'SSH-2.0-TestClient-AuthFail\r\n')
time.sleep(1)

# Receive server banner
banner = sock.recv(1024)

# Send key exchange
sock.send(b'\x00\x00\x01\x2c\x0a\x14' + b'\x00' * 294)
time.sleep(1)

# Receive key exchange response
kex_response = sock.recv(1024)

# Send invalid authentication data
auth_data = b'invalid:credentials'
sock.send(auth_data)
time.sleep(2)

sock.close()
print('❌ Authentication failure test completed')
"

# Expected Result: FAILED - Authentication failed
```

### **ERROR Scenarios** ⚠️

#### **Scenario 6: Immediate Disconnection**
```bash
python -c "
import socket

# Connect and immediately disconnect
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('127.0.0.1', 2222))
sock.close()
print('⚠️ Immediate disconnection test completed')
"

# Expected Result: ERROR - No meaningful interaction occurred
```

### **TIMEOUT Scenarios** ⏱️

#### **Scenario 7: Connection Timeout**
```bash
python -c "
import socket
import time

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('127.0.0.1', 2222))

# Connect but don't send anything (trigger timeout)
print('⏱️ Waiting for timeout...')
time.sleep(35)  # Wait longer than honeypot timeout

sock.close()
print('⏱️ Timeout test completed')
"

# Expected Result: TIMEOUT - Connection timeout
```

---

## 🌐 **HTTP Honeypot Testing (Port 8080)**

### **SUCCESS Scenarios** ✅

#### **Scenario 8: Complete HTTP Request**
```bash
# Simple GET request that completes successfully
curl -v http://127.0.0.1:8080/

# Expected Result: SUCCESS with HTTP details logged
```

#### **Scenario 9: POST Request with Data**
```bash
# POST request with form data
curl -X POST http://127.0.0.1:8080/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "User-Agent: TestClient/1.0" \
  -d "username=admin&password=test123"

# Expected Result: SUCCESS with POST data and User-Agent logged
```

#### **Scenario 10: Multiple Requests (Keep-Alive)**
```bash
# Multiple requests in sequence
curl http://127.0.0.1:8080/admin
curl http://127.0.0.1:8080/wp-admin  
curl http://127.0.0.1:8080/phpmyadmin

# Expected Result: Multiple SUCCESS entries with different paths
```

### **FAILED Scenarios** ❌

#### **Scenario 11: Malformed HTTP Request**
```bash
python -c "
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('127.0.0.1', 8080))

# Send malformed HTTP request
sock.send(b'INVALID HTTP REQUEST\r\n\r\n')
sock.close()
print('❌ Malformed HTTP request test completed')
"

# Expected Result: FAILED - Invalid HTTP request format
```

### **ERROR Scenarios** ⚠️

#### **Scenario 12: Connection Reset During Request**
```bash
python -c "
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('127.0.0.1', 8080))

# Start sending request but disconnect abruptly
sock.send(b'GET /test HTTP/1.1\r\nHost: ')
sock.close()  # Disconnect before completing request
print('⚠️ Connection reset test completed')
"

# Expected Result: ERROR - Connection reset during request
```

### **TIMEOUT Scenarios** ⏱️

#### **Scenario 13: HTTP Request Timeout**
```bash
python -c "
import socket
import time

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('127.0.0.1', 8080))

# Connect but don't send complete request
sock.send(b'GET /timeout-test HTTP/1.1\r\n')
# Don't send Host header or complete request
time.sleep(35)  # Wait for timeout

sock.close()
print('⏱️ HTTP timeout test completed')
"

# Expected Result: TIMEOUT - Request timeout
```

---

## 🔍 **Verification Checklist**

### **Dashboard Verification**
After each test, verify in the dashboard (http://127.0.0.1:5000):

#### **SUCCESS Tests** ✅
- [ ] Entry shows **green background** or **SUCCESS badge**
- [ ] Duration is **> 0.0s**
- [ ] Service-specific details are shown (auth attempts, HTTP method, etc.)
- [ ] Timestamp matches actual test time

#### **FAILED Tests** ❌  
- [ ] Entry shows **red background** or **FAILED badge**
- [ ] Failure reason is displayed
- [ ] Duration reflects actual connection time
- [ ] Source IP and port are correct

#### **ERROR Tests** ⚠️
- [ ] Entry shows **orange background** or **ERROR badge**  
- [ ] Error description is provided
- [ ] Duration is typically very short
- [ ] Proper error classification

#### **TIMEOUT Tests** ⏱️
- [ ] Entry shows **yellow background** or **TIMEOUT badge**
- [ ] Duration matches timeout period (~30-35s)
- [ ] Timeout reason is specified

### **Log File Verification**
Check `logs/honeypot.log` for enhanced log entries:

```bash
# Look for enhanced log format
grep "SSH: Connection from\|HTTP: Connection from" logs/honeypot.log | tail -10

# Expected format examples:
# SSH: Connection from 127.0.0.1:54321 - SUCCESS - Auth: admin:admin (1 attempts) - Duration: 5.2s
# HTTP: Connection from 127.0.0.1:43210 - SUCCESS - GET /admin - User-Agent: curl/7.68.0 - Duration: 0.8s
# SSH: Connection from 127.0.0.1:12345 - FAILED - Protocol negotiation failed - Duration: 0.2s
```

---

## 🎯 **Quick Test Script**

For automated testing of all scenarios:

```bash
# Create and run comprehensive test
python -c "
import subprocess
import time
import requests
import socket

def test_ssh_success():
    print('🔐 Testing SSH SUCCESS...')
    # Add SSH success test code here
    
def test_ssh_failed():
    print('❌ Testing SSH FAILED...')
    # Add SSH failed test code here
    
def test_http_success():
    print('🌐 Testing HTTP SUCCESS...')
    response = requests.get('http://127.0.0.1:8080/')
    print(f'HTTP Status: {response.status_code}')
    
def test_http_failed():
    print('❌ Testing HTTP FAILED...')
    # Add HTTP failed test code here

# Run all tests
test_ssh_success()
time.sleep(2)
test_ssh_failed()  
time.sleep(2)
test_http_success()
time.sleep(2)
test_http_failed()

print('✅ All tests completed - Check dashboard and logs!')
"
```

---

## 📊 **Expected Results Summary**

| **Test Scenario** | **Expected Status** | **Key Indicators** |
|-------------------|--------------------|--------------------|
| Complete SSH session | SUCCESS | Green, >0s duration, auth details |
| SSH protocol failure | FAILED | Red, protocol error reason |
| Invalid SSH banner | FAILED | Red, invalid banner message |
| SSH auth failure | FAILED | Red, auth failed reason |
| Immediate disconnect | ERROR | Orange, no interaction message |
| Connection timeout | TIMEOUT | Yellow, ~30s duration |
| Complete HTTP request | SUCCESS | Green, HTTP method/path shown |
| Malformed HTTP | FAILED | Red, invalid request reason |
| HTTP connection reset | ERROR | Orange, connection reset message |
| HTTP timeout | TIMEOUT | Yellow, request timeout reason |

This comprehensive testing guide ensures that the enhanced logging system correctly classifies all types of connection outcomes, providing security analysts with accurate and actionable intelligence about attack patterns and success rates.
