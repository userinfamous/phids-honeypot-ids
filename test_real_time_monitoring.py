#!/usr/bin/env python3
"""
Real-time Monitoring Test Suite
Tests immediate logging, single connections, and dashboard functionality
"""

import asyncio
import socket
import time
import threading
import requests
import json
from datetime import datetime

class RealTimeMonitoringTester:
    def __init__(self):
        self.ssh_port = 2222
        self.http_port = 8080
        self.dashboard_url = "http://127.0.0.1:5000"
        self.test_results = []
    
    def log_result(self, test_name, success, message):
        """Log test result"""
        status = "✅" if success else "❌"
        result = f"{status} {test_name}: {message}"
        print(result)
        self.test_results.append({
            'test': test_name,
            'success': success,
            'message': message,
            'timestamp': datetime.now().isoformat()
        })
    
    def test_single_ssh_connection(self):
        """Test single SSH connection logging"""
        print("\n🔍 Testing Single SSH Connection Logging...")
        
        try:
            # Get initial connection count
            response = requests.get(f"{self.dashboard_url}/api/stats")
            initial_count = response.json().get('total_connections', 0)
            
            # Make single SSH connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect(('127.0.0.1', self.ssh_port))
            time.sleep(1)  # Give time for logging
            sock.close()
            
            # Wait for logging to complete
            time.sleep(2)
            
            # Check if connection was logged
            response = requests.get(f"{self.dashboard_url}/api/stats")
            new_count = response.json().get('total_connections', 0)
            
            if new_count > initial_count:
                self.log_result("Single SSH Connection", True, f"Connection logged (count: {initial_count} → {new_count})")
                return True
            else:
                self.log_result("Single SSH Connection", False, f"Connection not logged (count unchanged: {initial_count})")
                return False
                
        except Exception as e:
            self.log_result("Single SSH Connection", False, f"Error: {e}")
            return False
    
    def test_multiple_ssh_connections(self):
        """Test multiple SSH connections for brute force detection"""
        print("\n🔍 Testing Multiple SSH Connections...")
        
        try:
            # Get initial counts
            response = requests.get(f"{self.dashboard_url}/api/stats")
            initial_connections = response.json().get('total_connections', 0)
            initial_alerts = response.json().get('total_alerts', 0)
            
            # Perform multiple connections (simulating brute force)
            for i in range(5):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(3)
                    sock.connect(('127.0.0.1', self.ssh_port))
                    time.sleep(0.5)
                    sock.close()
                    print(f"  Connection {i+1}/5 completed")
                except Exception as e:
                    print(f"  Connection {i+1}/5 failed: {e}")
                
                time.sleep(1)  # Brief pause between connections
            
            # Wait for all logging to complete
            time.sleep(3)
            
            # Check results
            response = requests.get(f"{self.dashboard_url}/api/stats")
            new_connections = response.json().get('total_connections', 0)
            new_alerts = response.json().get('total_alerts', 0)
            
            connections_added = new_connections - initial_connections
            alerts_added = new_alerts - initial_alerts
            
            if connections_added >= 5:
                self.log_result("Multiple SSH Connections", True, f"All connections logged ({connections_added} new connections)")
                if alerts_added > 0:
                    self.log_result("Brute Force Detection", True, f"Brute force detected ({alerts_added} new alerts)")
                return True
            else:
                self.log_result("Multiple SSH Connections", False, f"Only {connections_added}/5 connections logged")
                return False
                
        except Exception as e:
            self.log_result("Multiple SSH Connections", False, f"Error: {e}")
            return False
    
    def test_real_time_updates(self):
        """Test real-time dashboard updates"""
        print("\n🔍 Testing Real-time Dashboard Updates...")
        
        try:
            # Get initial data
            response = requests.get(f"{self.dashboard_url}/api/recent-connections?limit=1")
            initial_data = response.json()
            initial_count = len(initial_data.get('connections', []))
            
            # Make a connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect(('127.0.0.1', self.ssh_port))
            sock.close()
            
            # Check for immediate update (within 2 seconds)
            time.sleep(2)
            response = requests.get(f"{self.dashboard_url}/api/recent-connections?limit=5")
            new_data = response.json()
            new_count = len(new_data.get('connections', []))
            
            if new_count > initial_count:
                # Check timestamp of most recent connection
                recent_connection = new_data['connections'][0]
                connection_time = datetime.fromisoformat(recent_connection['timestamp'].replace('Z', '+00:00'))
                current_time = datetime.now()
                time_diff = (current_time - connection_time.replace(tzinfo=None)).total_seconds()
                
                if time_diff < 10:  # Within 10 seconds
                    self.log_result("Real-time Updates", True, f"Connection appeared within {time_diff:.1f} seconds")
                    return True
                else:
                    self.log_result("Real-time Updates", False, f"Connection delayed by {time_diff:.1f} seconds")
                    return False
            else:
                self.log_result("Real-time Updates", False, "No new connection detected")
                return False
                
        except Exception as e:
            self.log_result("Real-time Updates", False, f"Error: {e}")
            return False
    
    def test_dashboard_controls(self):
        """Test dashboard Controls button functionality"""
        print("\n🔍 Testing Dashboard Controls...")
        
        try:
            # Test if dashboard is accessible
            response = requests.get(self.dashboard_url)
            if response.status_code == 200:
                self.log_result("Dashboard Access", True, "Dashboard is accessible")
                
                # Check if clear logs endpoint exists
                try:
                    response = requests.post(f"{self.dashboard_url}/api/clear-logs", 
                                           json={"type": "test"})
                    if response.status_code in [200, 400]:  # 400 is expected for invalid type
                        self.log_result("Clear Logs API", True, "Clear logs endpoint is functional")
                    else:
                        self.log_result("Clear Logs API", False, f"Unexpected status: {response.status_code}")
                except Exception as e:
                    self.log_result("Clear Logs API", False, f"Endpoint error: {e}")
                
                # Check export endpoints
                try:
                    response = requests.get(f"{self.dashboard_url}/api/export/connections?format=json&limit=1")
                    if response.status_code == 200:
                        self.log_result("Export Functionality", True, "Export endpoints are working")
                    else:
                        self.log_result("Export Functionality", False, f"Export failed: {response.status_code}")
                except Exception as e:
                    self.log_result("Export Functionality", False, f"Export error: {e}")
                
                return True
            else:
                self.log_result("Dashboard Access", False, f"Dashboard not accessible: {response.status_code}")
                return False
                
        except Exception as e:
            self.log_result("Dashboard Controls", False, f"Error: {e}")
            return False
    
    def test_http_honeypot(self):
        """Test HTTP honeypot logging"""
        print("\n🔍 Testing HTTP Honeypot...")
        
        try:
            # Get initial count
            response = requests.get(f"{self.dashboard_url}/api/stats")
            initial_count = response.json().get('total_connections', 0)
            
            # Make HTTP request to honeypot
            try:
                requests.get(f"http://127.0.0.1:{self.http_port}/admin", timeout=5)
            except:
                pass  # Expected to fail/timeout
            
            time.sleep(2)  # Wait for logging
            
            # Check if logged
            response = requests.get(f"{self.dashboard_url}/api/stats")
            new_count = response.json().get('total_connections', 0)
            
            if new_count > initial_count:
                self.log_result("HTTP Honeypot", True, f"HTTP connection logged")
                return True
            else:
                self.log_result("HTTP Honeypot", False, "HTTP connection not logged")
                return False
                
        except Exception as e:
            self.log_result("HTTP Honeypot", False, f"Error: {e}")
            return False
    
    def run_comprehensive_test(self):
        """Run all tests"""
        print("🚀 Real-time Monitoring Test Suite")
        print("=" * 60)
        print("📋 Testing PHIDS real-time capabilities...")
        print("⚠️  Make sure PHIDS is running: python main.py --debug")
        print()
        
        # Wait for user confirmation
        input("Press Enter when PHIDS is running and dashboard is accessible...")
        
        # Run all tests
        tests = [
            self.test_dashboard_controls,
            self.test_single_ssh_connection,
            self.test_real_time_updates,
            self.test_multiple_ssh_connections,
            self.test_http_honeypot
        ]
        
        passed = 0
        total = len(tests)
        
        for test in tests:
            try:
                if test():
                    passed += 1
            except Exception as e:
                print(f"❌ Test {test.__name__} failed with exception: {e}")
        
        # Summary
        print("\n" + "=" * 60)
        print(f"🎯 Test Results: {passed}/{total} tests passed")
        
        if passed == total:
            print("🎉 All tests passed! Real-time monitoring is working correctly.")
        else:
            print("⚠️  Some tests failed. Check the issues above.")
        
        print("\n📊 Detailed Results:")
        for result in self.test_results:
            status = "✅" if result['success'] else "❌"
            print(f"  {status} {result['test']}: {result['message']}")
        
        return passed == total

def main():
    """Main test function"""
    tester = RealTimeMonitoringTester()
    success = tester.run_comprehensive_test()
    
    if success:
        print("\n🎉 All real-time monitoring features are working correctly!")
        print("💡 Tips for optimal performance:")
        print("   - Logs should appear within 1-2 seconds")
        print("   - Controls dropdown should work in dashboard")
        print("   - Both single and multiple connections should be logged")
        print("   - Real-time updates should be immediate")
    else:
        print("\n🔧 Some issues detected. Please check the PHIDS configuration.")

if __name__ == "__main__":
    main()
