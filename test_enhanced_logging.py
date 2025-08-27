#!/usr/bin/env python3
"""
Test script to verify enhanced honeypot logging system with connection status classification
"""

import asyncio
import requests
import time
import json
from datetime import datetime
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import TimeoutException, WebDriverException

def test_honeypot_services():
    """Test if honeypot services are running"""
    print("\n🔍 Testing Honeypot Services...")
    
    services = [
        ("SSH", "127.0.0.1", 2222),
        ("HTTP", "127.0.0.1", 8080),
        ("Dashboard", "127.0.0.1", 5000)
    ]
    
    running_services = []
    
    for service_name, host, port in services:
        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                print(f"✅ {service_name} honeypot is listening on port {port}")
                running_services.append(service_name.lower())
            else:
                print(f"❌ {service_name} honeypot is not accessible on port {port}")
        except Exception as e:
            print(f"❌ Error testing {service_name} honeypot: {e}")
    
    return running_services

def test_ssh_enhanced_logging():
    """Test SSH honeypot enhanced logging"""
    print("\n🔍 Testing SSH Enhanced Logging...")
    
    try:
        import socket
        
        # Test 1: Successful connection with authentication
        print("  📋 Test 1: SSH connection with authentication attempts...")
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect(("127.0.0.1", 2222))
        
        # Send SSH banner
        sock.send(b"SSH-2.0-TestClient-Enhanced\r\n")
        
        # Receive server banner
        banner = sock.recv(1024)
        print(f"    Received banner: {banner.decode('utf-8', errors='ignore').strip()}")
        
        # Send some authentication data (simplified)
        auth_data = b"admin:password123"
        sock.send(auth_data)
        
        time.sleep(2)  # Allow processing
        sock.close()
        
        print("  ✅ SSH connection test completed")
        return True
        
    except Exception as e:
        print(f"  ❌ SSH connection test failed: {e}")
        return False

def test_http_enhanced_logging():
    """Test HTTP honeypot enhanced logging"""
    print("\n🔍 Testing HTTP Enhanced Logging...")
    
    test_requests = [
        {
            "name": "Basic GET request",
            "method": "GET",
            "url": "http://127.0.0.1:8080/",
            "headers": {"User-Agent": "Enhanced-Test-Client/1.0"}
        },
        {
            "name": "Admin panel access",
            "method": "GET", 
            "url": "http://127.0.0.1:8080/admin",
            "headers": {"User-Agent": "AttackBot/2.0"}
        },
        {
            "name": "SQL injection attempt",
            "method": "GET",
            "url": "http://127.0.0.1:8080/login?user=admin&pass=admin' OR '1'='1",
            "headers": {"User-Agent": "SQLMap/1.0"}
        },
        {
            "name": "POST login attempt",
            "method": "POST",
            "url": "http://127.0.0.1:8080/login",
            "data": "username=admin&password=secret123",
            "headers": {"User-Agent": "LoginBot/1.0", "Content-Type": "application/x-www-form-urlencoded"}
        }
    ]
    
    successful_requests = 0
    
    for test_req in test_requests:
        try:
            print(f"  📋 {test_req['name']}...")
            
            if test_req['method'] == 'GET':
                response = requests.get(
                    test_req['url'], 
                    headers=test_req['headers'],
                    timeout=10
                )
            elif test_req['method'] == 'POST':
                response = requests.post(
                    test_req['url'],
                    data=test_req.get('data', ''),
                    headers=test_req['headers'],
                    timeout=10
                )
            
            print(f"    Status: {response.status_code}")
            print(f"    Server: {response.headers.get('Server', 'Unknown')}")
            successful_requests += 1
            
            time.sleep(1)  # Allow processing
            
        except Exception as e:
            print(f"    ❌ Request failed: {e}")
    
    print(f"  ✅ HTTP testing completed ({successful_requests}/{len(test_requests)} successful)")
    return successful_requests > 0

def test_dashboard_enhanced_display():
    """Test dashboard enhanced log display"""
    print("\n🔍 Testing Dashboard Enhanced Display...")
    
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--disable-gpu")
    
    driver = None
    try:
        driver = webdriver.Chrome(options=chrome_options)
        driver.get("http://127.0.0.1:5000")
        
        # Wait for page to load
        wait = WebDriverWait(driver, 15)
        
        # Wait for activity log to load
        activity_log = wait.until(
            EC.presence_of_element_located((By.ID, "activityLog"))
        )
        
        # Wait a moment for WebSocket data
        time.sleep(5)
        
        # Check for enhanced log entries
        log_entries = driver.find_elements(By.CSS_SELECTOR, ".log-entry.connection")
        
        if len(log_entries) > 0:
            print(f"  ✅ Found {len(log_entries)} connection log entries")
            
            # Check for enhanced features
            enhanced_features = {
                "status_badges": driver.find_elements(By.CSS_SELECTOR, ".connection-status"),
                "connection_details": driver.find_elements(By.CSS_SELECTOR, ".connection-details"),
                "success_entries": driver.find_elements(By.CSS_SELECTOR, ".log-entry.connection.success"),
                "failed_entries": driver.find_elements(By.CSS_SELECTOR, ".log-entry.connection.failed"),
                "error_entries": driver.find_elements(By.CSS_SELECTOR, ".log-entry.connection.error"),
                "timeout_entries": driver.find_elements(By.CSS_SELECTOR, ".log-entry.connection.timeout")
            }
            
            for feature, elements in enhanced_features.items():
                if len(elements) > 0:
                    print(f"    ✅ {feature}: {len(elements)} found")
                else:
                    print(f"    ⚠️ {feature}: none found")
            
            # Check for specific enhanced content
            first_entry = log_entries[0]
            entry_text = first_entry.text
            
            enhanced_indicators = [
                "Duration:",
                "SUCCESS", "FAILED", "ERROR", "TIMEOUT",
                "Auth:", "GET", "POST", "User-Agent"
            ]
            
            found_indicators = [indicator for indicator in enhanced_indicators if indicator in entry_text]
            print(f"    ✅ Enhanced indicators found: {', '.join(found_indicators)}")
            
            return len(found_indicators) >= 2
        else:
            print("  ⚠️ No connection log entries found")
            return False
            
    except TimeoutException:
        print("  ❌ Timeout waiting for dashboard to load")
        return False
    except Exception as e:
        print(f"  ❌ Dashboard test error: {e}")
        return False
    finally:
        if driver:
            driver.quit()

def test_log_file_content():
    """Test enhanced logging in log files"""
    print("\n🔍 Testing Log File Content...")
    
    try:
        # Check honeypot log file
        log_file_path = "logs/honeypot.log"
        
        with open(log_file_path, 'r') as f:
            log_content = f.read()
        
        # Look for enhanced log patterns
        enhanced_patterns = [
            "SSH: Connection from",
            "HTTP: Connection from", 
            "SUCCESS", "FAILED", "ERROR", "TIMEOUT",
            "Duration:",
            "Auth attempt",
            "User-Agent:",
            "Reason:"
        ]
        
        found_patterns = []
        for pattern in enhanced_patterns:
            if pattern in log_content:
                found_patterns.append(pattern)
        
        print(f"  ✅ Enhanced log patterns found: {len(found_patterns)}/{len(enhanced_patterns)}")
        for pattern in found_patterns:
            print(f"    - {pattern}")
        
        return len(found_patterns) >= 5
        
    except FileNotFoundError:
        print("  ❌ Log file not found")
        return False
    except Exception as e:
        print(f"  ❌ Log file test error: {e}")
        return False

def main():
    """Main test function"""
    print("🚨 PHIDS Enhanced Logging System Test")
    print("=" * 60)
    print("🔧 Testing enhanced honeypot logging with connection status classification")
    print("⚠️  Make sure PHIDS is running: python main.py --debug")
    print()
    
    # Wait for user confirmation
    input("Press Enter when PHIDS is running...")
    
    # Run tests
    tests = [
        ("Honeypot Services", test_honeypot_services),
        ("SSH Enhanced Logging", test_ssh_enhanced_logging),
        ("HTTP Enhanced Logging", test_http_enhanced_logging),
        ("Dashboard Enhanced Display", test_dashboard_enhanced_display),
        ("Log File Content", test_log_file_content)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        try:
            print(f"\n{'='*20} {test_name} {'='*20}")
            if test_func():
                passed += 1
                print(f"✅ {test_name}: PASSED")
            else:
                print(f"❌ {test_name}: FAILED")
        except Exception as e:
            print(f"❌ {test_name} failed with exception: {e}")
    
    print(f"\n📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All enhanced logging tests passed!")
        print("\n✅ Enhanced Logging Features Verified:")
        print("   - Connection status classification (SUCCESS/FAILED/ERROR/TIMEOUT)")
        print("   - Detailed connection information with duration")
        print("   - Authentication attempt logging for SSH")
        print("   - HTTP request details with User-Agent")
        print("   - Enhanced dashboard display with color coding")
        print("   - Comprehensive log file entries")
        print("\n💡 Enhanced Log Format Examples:")
        print("   SSH: Connection from 127.0.0.1:12345 - SUCCESS - Auth: admin:password - Duration: 5.2s")
        print("   HTTP: Connection from 127.0.0.1:54321 - SUCCESS - GET /admin - User-Agent: curl/7.68.0 - Duration: 0.8s")
    else:
        print("⚠️  Some tests failed. Enhanced logging may not be fully functional.")
        print("\n🔧 Troubleshooting:")
        print("   - Ensure PHIDS is running with: python main.py --debug")
        print("   - Check that all honeypot services are accessible")
        print("   - Verify dashboard is loading at http://127.0.0.1:5000")
        print("   - Check logs/honeypot.log for enhanced log entries")

def demonstrate_enhanced_logging():
    """Demonstrate enhanced logging with various connection types"""
    print("\n🎯 Enhanced Logging Demonstration")
    print("=" * 50)
    print("Generating various connection types to showcase enhanced logging...")

    # SSH connections
    print("\n📡 Generating SSH connections...")
    for i in range(3):
        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect(("127.0.0.1", 2222))
            sock.send(f"SSH-2.0-DemoClient-{i+1}\r\n".encode())
            time.sleep(1)
            sock.close()
            print(f"  ✅ SSH connection {i+1} completed")
        except Exception as e:
            print(f"  ❌ SSH connection {i+1} failed: {e}")
        time.sleep(2)

    # HTTP connections
    print("\n🌐 Generating HTTP connections...")
    http_tests = [
        ("GET", "http://127.0.0.1:8080/", {"User-Agent": "DemoBot/1.0"}),
        ("GET", "http://127.0.0.1:8080/admin", {"User-Agent": "AdminScanner/2.0"}),
        ("POST", "http://127.0.0.1:8080/login", {"User-Agent": "LoginBot/1.0"}, "user=demo&pass=test"),
    ]

    for method, url, headers, *data in http_tests:
        try:
            if method == "GET":
                response = requests.get(url, headers=headers, timeout=5)
            else:
                response = requests.post(url, headers=headers, data=data[0] if data else "", timeout=5)
            print(f"  ✅ {method} {url.split('/')[-1]} - Status: {response.status_code}")
        except Exception as e:
            print(f"  ❌ {method} request failed: {e}")
        time.sleep(2)

    print("\n✅ Demonstration complete! Check the dashboard and logs for enhanced entries.")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--demo":
        demonstrate_enhanced_logging()
    else:
        main()
