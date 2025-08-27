#!/usr/bin/env python3
"""
Comprehensive PHIDS Diagnostic Script
Tests all critical functionality and identifies issues
"""

import asyncio
import socket
import requests
import subprocess
import time
import sys
import os
from datetime import datetime

class PHIDSDiagnostic:
    def __init__(self):
        self.issues_found = []
        self.tests_passed = 0
        self.tests_total = 0
    
    def log_issue(self, test_name, issue_description):
        """Log an issue found during testing"""
        self.issues_found.append(f"❌ {test_name}: {issue_description}")
        print(f"❌ {test_name}: {issue_description}")
    
    def log_success(self, test_name, message="Passed"):
        """Log a successful test"""
        self.tests_passed += 1
        print(f"✅ {test_name}: {message}")
    
    def test_port_availability(self, port, service_name):
        """Test if a port is available for binding"""
        self.tests_total += 1
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(('127.0.0.1', port))
            sock.close()
            
            if result == 0:
                self.log_success(f"Port {port} ({service_name})", f"Service is listening on port {port}")
                return True
            else:
                self.log_issue(f"Port {port} ({service_name})", f"No service listening on port {port}")
                return False
        except Exception as e:
            self.log_issue(f"Port {port} ({service_name})", f"Error testing port: {e}")
            return False
    
    def test_ssh_connection(self):
        """Test SSH honeypot connection"""
        self.tests_total += 1
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect(('127.0.0.1', 2222))
            
            # Try to receive SSH banner
            data = sock.recv(1024)
            sock.close()
            
            if b'SSH' in data:
                self.log_success("SSH Connection", f"SSH honeypot responding with banner: {data[:50]}")
                return True
            else:
                self.log_issue("SSH Connection", f"Connected but no SSH banner received: {data[:50]}")
                return False
                
        except ConnectionRefusedError:
            self.log_issue("SSH Connection", "Connection refused - SSH honeypot not running")
            return False
        except socket.timeout:
            self.log_issue("SSH Connection", "Connection timeout - SSH honeypot not responding")
            return False
        except Exception as e:
            self.log_issue("SSH Connection", f"Connection error: {e}")
            return False
    
    def test_http_connection(self):
        """Test HTTP honeypot connection"""
        self.tests_total += 1
        try:
            response = requests.get("http://127.0.0.1:8080/", timeout=5)
            if response.status_code == 200:
                self.log_success("HTTP Connection", f"HTTP honeypot responding (status: {response.status_code})")
                return True
            else:
                self.log_issue("HTTP Connection", f"HTTP honeypot returned status: {response.status_code}")
                return False
        except requests.exceptions.ConnectionError:
            self.log_issue("HTTP Connection", "Connection refused - HTTP honeypot not running")
            return False
        except requests.exceptions.Timeout:
            self.log_issue("HTTP Connection", "Connection timeout - HTTP honeypot not responding")
            return False
        except Exception as e:
            self.log_issue("HTTP Connection", f"Connection error: {e}")
            return False
    
    def test_dashboard_accessibility(self):
        """Test dashboard accessibility"""
        self.tests_total += 1
        try:
            response = requests.get("http://127.0.0.1:5000", timeout=10)
            if response.status_code == 200:
                self.log_success("Dashboard Access", "Dashboard is accessible")
                return True
            else:
                self.log_issue("Dashboard Access", f"Dashboard returned status: {response.status_code}")
                return False
        except requests.exceptions.ConnectionError:
            self.log_issue("Dashboard Access", "Dashboard not running - start with: python start_dashboard.py")
            return False
        except Exception as e:
            self.log_issue("Dashboard Access", f"Dashboard error: {e}")
            return False
    
    def test_controls_button_html(self):
        """Test Controls button HTML structure"""
        self.tests_total += 1
        try:
            response = requests.get("http://127.0.0.1:5000", timeout=10)
            html_content = response.text
            
            required_elements = [
                'id="controlsDropdown"',
                'data-bs-toggle="dropdown"',
                'bootstrap.Dropdown',
                'showClearLogsModal'
            ]
            
            missing_elements = []
            for element in required_elements:
                if element not in html_content:
                    missing_elements.append(element)
            
            if not missing_elements:
                self.log_success("Controls Button HTML", "All required elements present")
                return True
            else:
                self.log_issue("Controls Button HTML", f"Missing elements: {', '.join(missing_elements)}")
                return False
                
        except Exception as e:
            self.log_issue("Controls Button HTML", f"Error checking HTML: {e}")
            return False
    
    def test_manual_attack_commands(self):
        """Test manual attack commands from README"""
        self.tests_total += 1
        
        # Test HTTP attacks
        http_attacks = [
            "http://127.0.0.1:8080/",
            "http://127.0.0.1:8080/admin",
            "http://127.0.0.1:8080/login?user=admin&pass=admin' OR '1'='1"
        ]
        
        successful_attacks = 0
        for attack_url in http_attacks:
            try:
                response = requests.get(attack_url, timeout=5)
                if response.status_code in [200, 404, 500]:  # Any response is good
                    successful_attacks += 1
            except:
                pass
        
        if successful_attacks == len(http_attacks):
            self.log_success("Manual Attack Commands", f"All {len(http_attacks)} HTTP attacks successful")
            return True
        else:
            self.log_issue("Manual Attack Commands", f"Only {successful_attacks}/{len(http_attacks)} HTTP attacks successful")
            return False
    
    def test_process_running(self):
        """Check if PHIDS main process is running"""
        self.tests_total += 1
        try:
            # Check for Python processes that might be PHIDS
            if os.name == 'nt':  # Windows
                result = subprocess.run(['tasklist', '/FI', 'IMAGENAME eq python.exe'], 
                                      capture_output=True, text=True)
                if 'python.exe' in result.stdout:
                    self.log_success("PHIDS Process", "Python processes found running")
                    return True
            else:  # Unix-like
                result = subprocess.run(['pgrep', '-f', 'main.py'], 
                                      capture_output=True, text=True)
                if result.stdout.strip():
                    self.log_success("PHIDS Process", f"PHIDS process found: PID {result.stdout.strip()}")
                    return True
            
            self.log_issue("PHIDS Process", "No PHIDS process found - start with: python main.py --debug")
            return False
            
        except Exception as e:
            self.log_issue("PHIDS Process", f"Error checking process: {e}")
            return False
    
    def run_comprehensive_diagnosis(self):
        """Run all diagnostic tests"""
        print("🔍 PHIDS Comprehensive Diagnostic")
        print("=" * 60)
        print("Testing all critical functionality...\n")
        
        # Test 1: Check if PHIDS process is running
        print("📋 Test 1: PHIDS Process Status")
        self.test_process_running()
        print()
        
        # Test 2: Port availability
        print("📋 Test 2: Port Availability")
        ssh_port_ok = self.test_port_availability(2222, "SSH Honeypot")
        http_port_ok = self.test_port_availability(8080, "HTTP Honeypot")
        dashboard_port_ok = self.test_port_availability(5000, "Dashboard")
        print()
        
        # Test 3: Service connections
        print("📋 Test 3: Service Connectivity")
        ssh_conn_ok = self.test_ssh_connection()
        http_conn_ok = self.test_http_connection()
        dashboard_ok = self.test_dashboard_accessibility()
        print()
        
        # Test 4: Dashboard functionality
        print("📋 Test 4: Dashboard Functionality")
        controls_ok = self.test_controls_button_html()
        print()
        
        # Test 5: Manual attack commands
        print("📋 Test 5: Manual Attack Commands")
        attacks_ok = self.test_manual_attack_commands()
        print()
        
        # Summary
        print("=" * 60)
        print(f"🎯 DIAGNOSTIC RESULTS: {self.tests_passed}/{self.tests_total} tests passed")
        
        if self.issues_found:
            print("\n🚨 ISSUES FOUND:")
            for issue in self.issues_found:
                print(f"   {issue}")
            
            print("\n🔧 RECOMMENDED ACTIONS:")
            
            if not ssh_port_ok or not ssh_conn_ok:
                print("   1. SSH Honeypot Issue:")
                print("      - Check if PHIDS is running: python main.py --debug")
                print("      - Verify port 2222 is not blocked by firewall")
                print("      - Check logs for SSH honeypot startup errors")
            
            if not http_port_ok or not http_conn_ok:
                print("   2. HTTP Honeypot Issue:")
                print("      - Check if PHIDS is running: python main.py --debug")
                print("      - Verify port 8080 is not blocked by firewall")
                print("      - Check logs for HTTP honeypot startup errors")
            
            if not dashboard_ok:
                print("   3. Dashboard Issue:")
                print("      - Start dashboard: python start_dashboard.py")
                print("      - Check if port 5000 is available")
                print("      - Verify dashboard configuration")
            
            if not controls_ok:
                print("   4. Controls Button Issue:")
                print("      - Check Bootstrap CSS/JS loading")
                print("      - Verify JavaScript console for errors")
                print("      - Test browser compatibility")
        
        else:
            print("\n🎉 ALL TESTS PASSED!")
            print("✅ PHIDS system is functioning correctly")
            print("✅ All honeypots are accessible")
            print("✅ Dashboard is operational")
            print("✅ Manual attack testing should work")
        
        return len(self.issues_found) == 0

def main():
    """Main diagnostic function"""
    diagnostic = PHIDSDiagnostic()
    success = diagnostic.run_comprehensive_diagnosis()
    
    if not success:
        print("\n⚠️  Issues detected. Please address the problems above.")
        print("💡 Start PHIDS with: python main.py --debug")
        print("💡 Start dashboard with: python start_dashboard.py")
        return False
    else:
        print("\n🎉 PHIDS system is ready for testing!")
        return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
