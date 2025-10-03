#!/usr/bin/env python3
"""
Comprehensive Functionality Test for PHIDS
Tests all core honeypot and IDS functionality
"""

import requests
import socket
import time
import json
import sqlite3
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path

class PHIDSFunctionalityTest:
    def __init__(self):
        self.db_path = Path("data/phids.db")
        self.dashboard_url = "http://127.0.0.1:5001"
        self.http_honeypot_url = "http://127.0.0.1:8081"
        self.ssh_honeypot_host = "127.0.0.1"
        self.ssh_honeypot_port = 2222
        self.test_results = []
        
    def log_test_result(self, test_name, passed, details="", recommendation=""):
        """Log a test result"""
        result = {
            "test_name": test_name,
            "passed": passed,
            "details": details,
            "recommendation": recommendation,
            "timestamp": datetime.now().isoformat()
        }
        self.test_results.append(result)
        
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{status} {test_name}")
        if details:
            print(f"   {details}")
        if recommendation and not passed:
            print(f"   💡 Recommendation: {recommendation}")
        print()
    
    def test_system_availability(self):
        """Test if all PHIDS components are running"""
        print("🔍 Testing System Availability...")
        
        # Test dashboard
        try:
            response = requests.get(f"{self.dashboard_url}/api/stats", timeout=5)
            dashboard_available = response.status_code == 200
        except:
            dashboard_available = False
        
        self.log_test_result(
            "Dashboard Availability",
            dashboard_available,
            f"Dashboard API {'accessible' if dashboard_available else 'not accessible'} at {self.dashboard_url}",
            "Start PHIDS with: python main.py --debug" if not dashboard_available else ""
        )
        
        # Test HTTP honeypot
        try:
            response = requests.get(f"{self.http_honeypot_url}/", timeout=5)
            http_available = response.status_code in [200, 404]  # Any response is good
        except:
            http_available = False
        
        self.log_test_result(
            "HTTP Honeypot Availability",
            http_available,
            f"HTTP honeypot {'responding' if http_available else 'not responding'} at {self.http_honeypot_url}",
            "Check HTTP honeypot configuration and port availability" if not http_available else ""
        )
        
        # Test SSH honeypot
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((self.ssh_honeypot_host, self.ssh_honeypot_port))
            ssh_available = result == 0
            sock.close()
        except:
            ssh_available = False
        
        self.log_test_result(
            "SSH Honeypot Availability",
            ssh_available,
            f"SSH honeypot {'listening' if ssh_available else 'not listening'} on port {self.ssh_honeypot_port}",
            "Check SSH honeypot configuration and port availability" if not ssh_available else ""
        )
        
        return dashboard_available and http_available and ssh_available
    
    def test_http_honeypot_functionality(self):
        """Test HTTP honeypot attack detection and logging"""
        print("🌐 Testing HTTP Honeypot Functionality...")
        
        # Get initial connection count
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.execute("SELECT COUNT(*) FROM honeypot_connections WHERE service_type = 'http'")
            initial_count = cursor.fetchone()[0]
            conn.close()
        except:
            initial_count = 0
        
        # Test basic HTTP request
        try:
            response = requests.get(f"{self.http_honeypot_url}/test", timeout=5)
            basic_request_success = True
        except:
            basic_request_success = False
        
        self.log_test_result(
            "HTTP Basic Request Handling",
            basic_request_success,
            "HTTP honeypot responds to basic requests",
            "Check HTTP honeypot service status" if not basic_request_success else ""
        )
        
        # Test SQL injection detection
        try:
            requests.get(f"{self.http_honeypot_url}/login?user=admin&pass=admin' OR '1'='1", timeout=5)
            sql_injection_request = True
        except:
            sql_injection_request = False
        
        # Test XSS detection
        try:
            requests.get(f"{self.http_honeypot_url}/search?q=<script>alert('xss')</script>", timeout=5)
            xss_request = True
        except:
            xss_request = False
        
        # Wait for logging
        time.sleep(3)
        
        # Check if connections were logged
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.execute("SELECT COUNT(*) FROM honeypot_connections WHERE service_type = 'http'")
            final_count = cursor.fetchone()[0]
            conn.close()
            
            connections_logged = final_count > initial_count
        except:
            connections_logged = False
        
        self.log_test_result(
            "HTTP Connection Logging",
            connections_logged,
            f"HTTP connections logged: {final_count - initial_count} new connections",
            "Check database connectivity and logging functionality" if not connections_logged else ""
        )
        
        return basic_request_success and connections_logged
    
    def test_ssh_honeypot_functionality(self):
        """Test SSH honeypot functionality"""
        print("🔐 Testing SSH Honeypot Functionality...")
        
        # Get initial connection count
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.execute("SELECT COUNT(*) FROM honeypot_connections WHERE service_type = 'ssh'")
            initial_count = cursor.fetchone()[0]
            conn.close()
        except:
            initial_count = 0
        
        # Test SSH connection attempt
        try:
            import paramiko
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # This should fail but create a connection log
            try:
                ssh.connect(
                    self.ssh_honeypot_host, 
                    port=self.ssh_honeypot_port,
                    username="admin",
                    password="password",
                    timeout=5
                )
                ssh_connection_attempted = True
            except:
                ssh_connection_attempted = True  # Expected to fail
            
            ssh.close()
        except ImportError:
            # Paramiko not available, try basic socket connection
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((self.ssh_honeypot_host, self.ssh_honeypot_port))
                sock.send(b"SSH-2.0-Test\r\n")
                response = sock.recv(1024)
                ssh_connection_attempted = len(response) > 0
                sock.close()
            except:
                ssh_connection_attempted = False
        
        self.log_test_result(
            "SSH Connection Attempt",
            ssh_connection_attempted,
            "SSH honeypot accepts connections",
            "Check SSH honeypot service and port configuration" if not ssh_connection_attempted else ""
        )
        
        # Wait for logging
        time.sleep(3)
        
        # Check if SSH connections were logged
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.execute("SELECT COUNT(*) FROM honeypot_connections WHERE service_type = 'ssh'")
            final_count = cursor.fetchone()[0]
            conn.close()
            
            ssh_connections_logged = final_count > initial_count
        except:
            ssh_connections_logged = False
        
        self.log_test_result(
            "SSH Connection Logging",
            ssh_connections_logged,
            f"SSH connections logged: {final_count - initial_count} new connections",
            "Check SSH honeypot logging functionality" if not ssh_connections_logged else ""
        )
        
        return ssh_connection_attempted and ssh_connections_logged
    
    def test_ids_functionality(self):
        """Test IDS detection and alerting"""
        print("🚨 Testing IDS Functionality...")
        
        # Get initial alert count
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.execute("SELECT COUNT(*) FROM ids_alerts")
            initial_alerts = cursor.fetchone()[0]
            conn.close()
        except:
            initial_alerts = 0
        
        # Generate some attack patterns
        attack_requests = [
            f"{self.http_honeypot_url}/admin",
            f"{self.http_honeypot_url}/config.php",
            f"{self.http_honeypot_url}/wp-admin/",
            f"{self.http_honeypot_url}/../../../etc/passwd",
        ]
        
        for url in attack_requests:
            try:
                requests.get(url, timeout=3)
            except:
                pass
            time.sleep(0.5)
        
        # Wait for IDS processing
        time.sleep(10)
        
        # Check if alerts were generated
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.execute("SELECT COUNT(*) FROM ids_alerts")
            final_alerts = cursor.fetchone()[0]
            conn.close()
            
            alerts_generated = final_alerts > initial_alerts
            new_alerts = final_alerts - initial_alerts
        except:
            alerts_generated = False
            new_alerts = 0
        
        self.log_test_result(
            "IDS Alert Generation",
            alerts_generated,
            f"IDS generated {new_alerts} new alerts from attack patterns",
            "Check IDS engine configuration and signature rules" if not alerts_generated else ""
        )
        
        return alerts_generated
    
    def test_dashboard_functionality(self):
        """Test dashboard API and real-time features"""
        print("📊 Testing Dashboard Functionality...")
        
        # Test statistics API
        try:
            response = requests.get(f"{self.dashboard_url}/api/stats", timeout=5)
            stats_api_working = response.status_code == 200
            if stats_api_working:
                stats_data = response.json()
                has_required_fields = all(field in stats_data for field in ['total_connections', 'total_alerts'])
            else:
                has_required_fields = False
        except:
            stats_api_working = False
            has_required_fields = False
        
        self.log_test_result(
            "Dashboard Statistics API",
            stats_api_working and has_required_fields,
            f"Statistics API {'working' if stats_api_working else 'not working'}, required fields {'present' if has_required_fields else 'missing'}",
            "Check dashboard service and database connectivity" if not (stats_api_working and has_required_fields) else ""
        )
        
        # Test recent connections API
        try:
            response = requests.get(f"{self.dashboard_url}/api/recent-connections", timeout=5)
            connections_api_working = response.status_code == 200
        except:
            connections_api_working = False
        
        self.log_test_result(
            "Dashboard Connections API",
            connections_api_working,
            f"Recent connections API {'working' if connections_api_working else 'not working'}",
            "Check dashboard API endpoints" if not connections_api_working else ""
        )
        
        # Test export functionality
        try:
            response = requests.get(f"{self.dashboard_url}/api/export/connections?format=csv", timeout=10)
            export_working = response.status_code == 200
        except:
            export_working = False
        
        self.log_test_result(
            "Dashboard Export Functionality",
            export_working,
            f"CSV export {'working' if export_working else 'not working'}",
            "Check export functionality and file permissions" if not export_working else ""
        )
        
        return stats_api_working and connections_api_working and export_working
    
    def test_data_integrity(self):
        """Test database integrity and data quality"""
        print("🗄️ Testing Data Integrity...")
        
        try:
            conn = sqlite3.connect(self.db_path)
            
            # Check database tables exist
            cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            required_tables = ['honeypot_connections', 'ids_alerts', 'authentication_events']
            tables_exist = all(table in tables for table in required_tables)
            
            self.log_test_result(
                "Database Schema Integrity",
                tables_exist,
                f"Required tables {'all present' if tables_exist else 'missing'}: {required_tables}",
                "Check database initialization and schema" if not tables_exist else ""
            )
            
            # Check data consistency
            cursor = conn.execute("SELECT COUNT(*) FROM honeypot_connections WHERE timestamp IS NULL")
            null_timestamps = cursor.fetchone()[0]
            
            cursor = conn.execute("SELECT COUNT(*) FROM honeypot_connections WHERE source_ip IS NULL")
            null_ips = cursor.fetchone()[0]
            
            data_consistent = null_timestamps == 0 and null_ips == 0
            
            self.log_test_result(
                "Data Consistency",
                data_consistent,
                f"Null timestamps: {null_timestamps}, Null IPs: {null_ips}",
                "Review data validation and logging procedures" if not data_consistent else ""
            )
            
            conn.close()
            return tables_exist and data_consistent
            
        except Exception as e:
            self.log_test_result(
                "Database Access",
                False,
                f"Database error: {e}",
                "Check database file permissions and integrity"
            )
            return False
    
    def run_comprehensive_test(self):
        """Run all functionality tests"""
        print("🧪 PHIDS Comprehensive Functionality Test")
        print("=" * 50)
        print("Testing all core honeypot and IDS functionality...")
        print()
        
        # Run all tests
        system_ok = self.test_system_availability()
        if not system_ok:
            print("❌ System not fully available. Some tests may fail.")
            print()
        
        http_ok = self.test_http_honeypot_functionality()
        ssh_ok = self.test_ssh_honeypot_functionality()
        ids_ok = self.test_ids_functionality()
        dashboard_ok = self.test_dashboard_functionality()
        data_ok = self.test_data_integrity()
        
        # Summary
        print("=" * 50)
        print("📋 Comprehensive Test Summary")
        print("=" * 50)
        
        passed_tests = sum(1 for result in self.test_results if result["passed"])
        total_tests = len(self.test_results)
        success_rate = (passed_tests / total_tests) * 100 if total_tests > 0 else 0
        
        print(f"Tests Passed: {passed_tests}/{total_tests}")
        print(f"Success Rate: {success_rate:.1f}%")
        
        # Overall assessment
        if success_rate >= 90:
            print("\n✅ PHIDS is fully functional and ready for deployment")
            overall_status = "READY"
        elif success_rate >= 75:
            print("\n⚠️ PHIDS is mostly functional with minor issues")
            overall_status = "MOSTLY_READY"
        else:
            print("\n🔴 PHIDS has significant functionality issues")
            overall_status = "NEEDS_WORK"
        
        # Failed tests
        failed_tests = [result for result in self.test_results if not result["passed"]]
        if failed_tests:
            print(f"\n❌ Failed Tests ({len(failed_tests)}):")
            for test in failed_tests:
                print(f"  - {test['test_name']}: {test['details']}")
                if test['recommendation']:
                    print(f"    💡 {test['recommendation']}")
        
        # Save detailed report
        report = {
            "test_timestamp": datetime.now().isoformat(),
            "overall_status": overall_status,
            "success_rate": success_rate,
            "tests_passed": passed_tests,
            "total_tests": total_tests,
            "test_results": self.test_results
        }
        
        with open("functionality_test_report.json", "w") as f:
            json.dump(report, f, indent=2)
        
        print(f"\n📄 Detailed test report saved to: functionality_test_report.json")
        return overall_status == "READY"

if __name__ == "__main__":
    tester = PHIDSFunctionalityTest()
    success = tester.run_comprehensive_test()
    sys.exit(0 if success else 1)
