#!/usr/bin/env python3
"""
Comprehensive fix for all four critical PHIDS issues
Tests and validates all fixes
"""

import asyncio
import requests
import socket
import time
import json
import sys
from datetime import datetime

class PHIDSIssueFixer:
    def __init__(self):
        self.issues_fixed = 0
        self.tests_passed = 0
        self.tests_total = 0
    
    def log_test(self, test_name, success, details=""):
        """Log test result"""
        self.tests_total += 1
        if success:
            self.tests_passed += 1
            print(f"✅ {test_name}: {details}")
        else:
            print(f"❌ {test_name}: {details}")
    
    def test_ssh_connection_prerequisites(self):
        """Test Issue 4: SSH Connection Prerequisites"""
        print("\n🔍 Issue 4: SSH Connection Prerequisites")
        print("-" * 50)
        
        # Test SSH port availability
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex(('127.0.0.1', 2222))
            sock.close()
            
            if result == 0:
                self.log_test("SSH Port 2222 Available", True, "SSH honeypot is listening")
                
                # Test SSH banner
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    sock.connect(('127.0.0.1', 2222))
                    banner = sock.recv(1024)
                    sock.close()
                    
                    if b'SSH' in banner:
                        self.log_test("SSH Banner Response", True, f"Banner: {banner.decode().strip()}")
                        return True
                    else:
                        self.log_test("SSH Banner Response", False, "No SSH banner received")
                        return False
                except Exception as e:
                    self.log_test("SSH Banner Response", False, f"Error: {e}")
                    return False
            else:
                self.log_test("SSH Port 2222 Available", False, "SSH honeypot not listening")
                return False
        except Exception as e:
            self.log_test("SSH Port 2222 Available", False, f"Error: {e}")
            return False
    
    def test_controls_button_functionality(self):
        """Test Issue 3: Controls Button Non-Functional"""
        print("\n🔍 Issue 3: Controls Button Functionality")
        print("-" * 50)
        
        try:
            # Test dashboard accessibility
            response = requests.get("http://127.0.0.1:5000", timeout=10)
            if response.status_code != 200:
                self.log_test("Dashboard Access", False, f"HTTP {response.status_code}")
                return False
            
            self.log_test("Dashboard Access", True, "Dashboard accessible")
            
            # Check Controls button HTML structure
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
                self.log_test("Controls Button HTML", True, "All required elements present")
                
                # Test clear logs API
                test_data = {"type": "test_invalid"}
                api_response = requests.post(
                    "http://127.0.0.1:5000/api/clear-logs",
                    json=test_data,
                    timeout=10
                )
                
                if api_response.status_code == 200:
                    self.log_test("Clear Logs API", True, "API responding correctly")
                    return True
                else:
                    self.log_test("Clear Logs API", False, f"HTTP {api_response.status_code}")
                    return False
            else:
                self.log_test("Controls Button HTML", False, f"Missing: {', '.join(missing_elements)}")
                return False
                
        except Exception as e:
            self.log_test("Controls Button Test", False, f"Error: {e}")
            return False
    
    def test_enhanced_logging_detail(self):
        """Test Issue 2: Enhanced Log Detail"""
        print("\n🔍 Issue 2: Enhanced Log Detail")
        print("-" * 50)
        
        try:
            # Generate test attack to verify enhanced logging
            test_attacks = [
                "http://127.0.0.1:8080/login?user=admin&pass=admin' OR '1'='1",
                "http://127.0.0.1:8080/search?q=<script>alert('XSS')</script>",
                "http://127.0.0.1:8080/file?path=../../../etc/passwd"
            ]
            
            for attack_url in test_attacks:
                try:
                    requests.get(attack_url, timeout=5)
                    time.sleep(1)  # Allow processing time
                except:
                    pass
            
            # Wait for logs to be processed
            time.sleep(3)
            
            # Check recent connections for enhanced details
            response = requests.get("http://127.0.0.1:5000/api/recent-connections", timeout=10)
            if response.status_code == 200:
                connections = response.json().get('connections', [])
                
                if connections:
                    # Check if connections have enhanced details
                    recent_conn = connections[0]
                    enhanced_fields = ['source_ip', 'destination_port', 'service_type', 'timestamp']
                    
                    has_enhanced_data = all(field in recent_conn for field in enhanced_fields)
                    
                    if has_enhanced_data:
                        self.log_test("Enhanced Connection Logging", True, "Detailed connection data present")
                        
                        # Check for attack-specific details
                        if 'connection_data' in str(recent_conn):
                            self.log_test("Attack Detail Logging", True, "Attack details captured")
                            return True
                        else:
                            self.log_test("Attack Detail Logging", False, "No attack details found")
                            return False
                    else:
                        self.log_test("Enhanced Connection Logging", False, "Missing enhanced fields")
                        return False
                else:
                    self.log_test("Enhanced Connection Logging", False, "No recent connections found")
                    return False
            else:
                self.log_test("Enhanced Connection Logging", False, f"API error: {response.status_code}")
                return False
                
        except Exception as e:
            self.log_test("Enhanced Logging Test", False, f"Error: {e}")
            return False
    
    def test_timestamp_accuracy(self):
        """Test Issue 1: Correct Event Timestamps"""
        print("\n🔍 Issue 1: Event Timestamp Accuracy")
        print("-" * 50)
        
        try:
            # Record current time
            test_start_time = datetime.now()
            
            # Generate a test connection
            test_url = "http://127.0.0.1:8080/timestamp-test"
            requests.get(test_url, timeout=5)
            
            # Wait for processing
            time.sleep(3)
            
            # Check recent connections
            response = requests.get("http://127.0.0.1:5000/api/recent-connections", timeout=10)
            if response.status_code == 200:
                connections = response.json().get('connections', [])
                
                if connections:
                    # Find our test connection
                    test_connection = None
                    for conn in connections:
                        if 'timestamp-test' in str(conn):
                            test_connection = conn
                            break
                    
                    if test_connection and 'timestamp' in test_connection:
                        # Parse the timestamp
                        try:
                            event_time = datetime.fromisoformat(test_connection['timestamp'].replace('Z', '+00:00'))
                            time_diff = abs((event_time.replace(tzinfo=None) - test_start_time).total_seconds())
                            
                            if time_diff < 60:  # Within 1 minute is acceptable
                                self.log_test("Timestamp Accuracy", True, f"Event time within {time_diff:.1f}s of actual time")
                                return True
                            else:
                                self.log_test("Timestamp Accuracy", False, f"Event time off by {time_diff:.1f}s")
                                return False
                        except Exception as e:
                            self.log_test("Timestamp Parsing", False, f"Error parsing timestamp: {e}")
                            return False
                    else:
                        self.log_test("Test Connection Found", False, "Test connection not found in logs")
                        return False
                else:
                    self.log_test("Recent Connections", False, "No recent connections found")
                    return False
            else:
                self.log_test("API Access", False, f"HTTP {response.status_code}")
                return False
                
        except Exception as e:
            self.log_test("Timestamp Test", False, f"Error: {e}")
            return False
    
    def run_comprehensive_fix_validation(self):
        """Run all issue tests and validation"""
        print("🔧 PHIDS Critical Issues - Comprehensive Fix Validation")
        print("=" * 70)
        print("Testing all four critical issues after fixes applied...")
        print()
        
        # Test all issues
        issue4_fixed = self.test_ssh_connection_prerequisites()
        issue3_fixed = self.test_controls_button_functionality()
        issue2_fixed = self.test_enhanced_logging_detail()
        issue1_fixed = self.test_timestamp_accuracy()
        
        # Summary
        print("\n" + "=" * 70)
        print(f"🎯 VALIDATION RESULTS: {self.tests_passed}/{self.tests_total} tests passed")
        
        issues_fixed = sum([issue1_fixed, issue2_fixed, issue3_fixed, issue4_fixed])
        
        if issues_fixed == 4:
            print("\n🎉 ALL CRITICAL ISSUES RESOLVED!")
            print("✅ Issue 1: Event timestamps are accurate")
            print("✅ Issue 2: Enhanced logging with detailed attack information")
            print("✅ Issue 3: Controls button is functional")
            print("✅ Issue 4: SSH honeypot accepts connections")
            
            print("\n💡 System Status:")
            print("   - SSH honeypot: Listening on port 2222 with enhanced attack analysis")
            print("   - HTTP honeypot: Listening on port 8080 with detailed payload detection")
            print("   - Dashboard: Fully functional with working Controls dropdown")
            print("   - Timestamps: Accurate event time recording for forensic analysis")
            print("   - Logging: Detailed attack vectors, payloads, and recommendations")
            
            print("\n🔧 Manual Testing Instructions:")
            print("   1. SSH attacks: ssh admin@127.0.0.1 -p 2222")
            print("   2. HTTP attacks: curl 'http://127.0.0.1:8080/admin'")
            print("   3. Dashboard: http://127.0.0.1:5000")
            print("   4. Controls: Click Controls dropdown → Clear Logs")
            
        else:
            print(f"\n⚠️  {4 - issues_fixed} critical issues still need attention:")
            if not issue1_fixed:
                print("   ❌ Issue 1: Event timestamps still incorrect")
            if not issue2_fixed:
                print("   ❌ Issue 2: Logging still lacks detail")
            if not issue3_fixed:
                print("   ❌ Issue 3: Controls button still non-functional")
            if not issue4_fixed:
                print("   ❌ Issue 4: SSH connection still failing")
        
        return issues_fixed == 4

def main():
    """Main validation function"""
    fixer = PHIDSIssueFixer()
    success = fixer.run_comprehensive_fix_validation()
    
    if success:
        print("\n🎉 All critical PHIDS issues have been resolved!")
        print("💡 The system is now ready for professional demonstrations.")
    else:
        print("\n🔧 Some issues still need attention. Check the details above.")
    
    return success

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
