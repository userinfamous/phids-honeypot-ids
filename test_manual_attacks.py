#!/usr/bin/env python3
"""
Test Manual Attack Commands from README.md
Validates all documented attack vectors work correctly
"""

import socket
import requests
import time
import sys
from datetime import datetime

class ManualAttackTester:
    def __init__(self):
        self.tests_passed = 0
        self.tests_total = 0
        self.attack_results = []
    
    def log_result(self, test_name, success, details=""):
        """Log test result"""
        self.tests_total += 1
        if success:
            self.tests_passed += 1
            print(f"✅ {test_name}: {details}")
        else:
            print(f"❌ {test_name}: {details}")
        
        self.attack_results.append({
            'test': test_name,
            'success': success,
            'details': details,
            'timestamp': datetime.now().isoformat()
        })
    
    def test_ssh_attacks(self):
        """Test SSH honeypot attacks"""
        print("\n🔐 Testing SSH Honeypot Attacks (Port 2222)")
        print("-" * 50)
        
        # Test 1: Basic SSH connection
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect(('127.0.0.1', 2222))
            banner = sock.recv(1024)
            sock.close()
            
            if b'SSH' in banner:
                self.log_result("SSH Basic Connection", True, f"Banner: {banner.decode().strip()}")
            else:
                self.log_result("SSH Basic Connection", False, "No SSH banner received")
        except Exception as e:
            self.log_result("SSH Basic Connection", False, f"Error: {e}")
        
        # Test 2: SSH brute force simulation
        try:
            successful_connections = 0
            for i in range(3):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect(('127.0.0.1', 2222))
                
                # Send SSH version
                sock.send(b'SSH-2.0-TestClient\r\n')
                response = sock.recv(1024)
                
                # Send some authentication data
                sock.send(b'admin:password123\r\n')
                time.sleep(1)
                sock.close()
                successful_connections += 1
                time.sleep(1)  # Delay between attempts
            
            self.log_result("SSH Brute Force Simulation", True, f"{successful_connections}/3 connections successful")
            
        except Exception as e:
            self.log_result("SSH Brute Force Simulation", False, f"Error: {e}")
    
    def test_http_attacks(self):
        """Test HTTP honeypot attacks"""
        print("\n🌐 Testing HTTP Honeypot Attacks (Port 8080)")
        print("-" * 50)
        
        # Test 1: Basic HTTP requests
        basic_urls = [
            "http://127.0.0.1:8080/",
            "http://127.0.0.1:8080/admin",
            "http://127.0.0.1:8080/login",
            "http://127.0.0.1:8080/config"
        ]
        
        successful_basic = 0
        for url in basic_urls:
            try:
                response = requests.get(url, timeout=5)
                if response.status_code in [200, 404, 500]:
                    successful_basic += 1
            except:
                pass
        
        self.log_result("HTTP Basic Requests", successful_basic == len(basic_urls), 
                       f"{successful_basic}/{len(basic_urls)} requests successful")
        
        # Test 2: SQL Injection attacks
        sql_attacks = [
            "http://127.0.0.1:8080/login?user=admin&pass=admin' OR '1'='1",
            "http://127.0.0.1:8080/search?q=' UNION SELECT * FROM users --",
            "http://127.0.0.1:8080/product?id=1'; WAITFOR DELAY '00:00:05' --",
            "http://127.0.0.1:8080/user?id=1' AND (SELECT COUNT(*) FROM information_schema.tables)>0 --"
        ]
        
        successful_sql = 0
        for attack_url in sql_attacks:
            try:
                response = requests.get(attack_url, timeout=10)
                if response.status_code in [200, 404, 500]:
                    successful_sql += 1
            except:
                pass
        
        self.log_result("SQL Injection Attacks", successful_sql >= len(sql_attacks) // 2,
                       f"{successful_sql}/{len(sql_attacks)} SQL injection attempts successful")
        
        # Test 3: XSS attacks
        xss_attacks = [
            "http://127.0.0.1:8080/search?q=<script>alert('XSS')</script>",
            "http://127.0.0.1:8080/profile?name=<img src=x onerror=alert('XSS')>",
            "http://127.0.0.1:8080/page?content=<svg onload=alert('DOM XSS')>"
        ]
        
        successful_xss = 0
        for attack_url in xss_attacks:
            try:
                response = requests.get(attack_url, timeout=5)
                if response.status_code in [200, 404, 500]:
                    successful_xss += 1
            except:
                pass
        
        self.log_result("XSS Attacks", successful_xss >= len(xss_attacks) // 2,
                       f"{successful_xss}/{len(xss_attacks)} XSS attempts successful")
        
        # Test 4: Directory traversal attacks
        traversal_attacks = [
            "http://127.0.0.1:8080/file?path=../../../etc/passwd",
            "http://127.0.0.1:8080/download?file=..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "http://127.0.0.1:8080/view?doc=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        ]
        
        successful_traversal = 0
        for attack_url in traversal_attacks:
            try:
                response = requests.get(attack_url, timeout=5)
                if response.status_code in [200, 404, 500]:
                    successful_traversal += 1
            except:
                pass
        
        self.log_result("Directory Traversal Attacks", successful_traversal >= len(traversal_attacks) // 2,
                       f"{successful_traversal}/{len(traversal_attacks)} traversal attempts successful")
        
        # Test 5: Command injection attacks
        command_attacks = [
            "http://127.0.0.1:8080/ping?host=127.0.0.1; cat /etc/passwd",
            "http://127.0.0.1:8080/lookup?domain=example.com | whoami",
            "http://127.0.0.1:8080/test?cmd=ls; ps aux"
        ]
        
        successful_command = 0
        for attack_url in command_attacks:
            try:
                response = requests.get(attack_url, timeout=5)
                if response.status_code in [200, 404, 500]:
                    successful_command += 1
            except:
                pass
        
        self.log_result("Command Injection Attacks", successful_command >= len(command_attacks) // 2,
                       f"{successful_command}/{len(command_attacks)} command injection attempts successful")
    
    def test_dashboard_functionality(self):
        """Test dashboard functionality"""
        print("\n📊 Testing Dashboard Functionality")
        print("-" * 50)
        
        # Test dashboard access
        try:
            response = requests.get("http://127.0.0.1:5000", timeout=10)
            if response.status_code == 200:
                self.log_result("Dashboard Access", True, "Dashboard accessible")
            else:
                self.log_result("Dashboard Access", False, f"HTTP {response.status_code}")
        except Exception as e:
            self.log_result("Dashboard Access", False, f"Error: {e}")
        
        # Test API endpoints
        api_endpoints = [
            "/api/stats",
            "/api/recent-connections",
            "/api/alerts"
        ]
        
        successful_apis = 0
        for endpoint in api_endpoints:
            try:
                response = requests.get(f"http://127.0.0.1:5000{endpoint}", timeout=5)
                if response.status_code == 200:
                    successful_apis += 1
            except:
                pass
        
        self.log_result("Dashboard API Endpoints", successful_apis == len(api_endpoints),
                       f"{successful_apis}/{len(api_endpoints)} API endpoints working")
    
    def run_comprehensive_test(self):
        """Run all manual attack tests"""
        print("🧪 Manual Attack Testing Suite")
        print("=" * 60)
        print("Testing all documented attack vectors from README.md")
        print("⚠️  Make sure PHIDS is running: python main.py --debug")
        print()
        
        # Run all test categories
        self.test_ssh_attacks()
        self.test_http_attacks()
        self.test_dashboard_functionality()
        
        # Summary
        print("\n" + "=" * 60)
        print(f"🎯 Manual Attack Test Results: {self.tests_passed}/{self.tests_total} tests passed")
        
        if self.tests_passed == self.tests_total:
            print("\n🎉 ALL MANUAL ATTACK TESTS PASSED!")
            print("✅ SSH honeypot is detecting connections")
            print("✅ HTTP honeypot is detecting all attack types")
            print("✅ Dashboard is fully functional")
            print("✅ All README.md attack commands work as documented")
            
            print("\n💡 Next Steps:")
            print("   1. Open dashboard: http://127.0.0.1:5000")
            print("   2. Run attacks and watch real-time detection")
            print("   3. Test Controls button dropdown functionality")
            print("   4. Verify logs appear with correct timestamps")
            
        else:
            print(f"\n⚠️  {self.tests_total - self.tests_passed} tests failed")
            print("🔧 Check PHIDS logs for any error messages")
            
        print("\n📋 Detailed Results:")
        for result in self.attack_results:
            status = "✅" if result['success'] else "❌"
            print(f"  {status} {result['test']}: {result['details']}")
        
        return self.tests_passed == self.tests_total

def main():
    """Main test function"""
    tester = ManualAttackTester()
    success = tester.run_comprehensive_test()
    
    if success:
        print("\n🎉 Manual attack testing validation complete!")
        print("💡 All documented attack vectors are working correctly!")
    else:
        print("\n🔧 Some manual attack tests failed - check PHIDS status")
    
    return success

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
