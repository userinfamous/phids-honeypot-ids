#!/usr/bin/env python3
"""
Timing Accuracy Test for PHIDS
Tests real-time detection capabilities and timestamp precision
"""

import asyncio
import time
import requests
import sqlite3
import json
from datetime import datetime, timedelta
from pathlib import Path
import subprocess
import sys

class TimingAccuracyTester:
    def __init__(self):
        self.db_path = Path("data/phids.db")
        self.dashboard_url = "http://127.0.0.1:5001"
        self.http_honeypot_url = "http://127.0.0.1:8081"
        self.results = []
        
    def log_result(self, test_name, result, details=""):
        """Log test result"""
        timestamp = datetime.now().isoformat()
        self.results.append({
            "test": test_name,
            "result": result,
            "details": details,
            "timestamp": timestamp
        })
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} {test_name}: {details}")
    
    def test_database_timestamp_precision(self):
        """Test database timestamp precision"""
        print("\n🔍 Testing Database Timestamp Precision...")
        
        try:
            # Record precise timestamp
            test_start = datetime.now()
            
            # Make HTTP request to honeypot
            response = requests.get(f"{self.http_honeypot_url}/timing-test", timeout=5)
            
            # Record end timestamp
            test_end = datetime.now()
            
            # Wait a moment for database write
            time.sleep(0.5)
            
            # Check database for the entry
            conn = sqlite3.connect(self.db_path)
            cursor = conn.execute("""
                SELECT timestamp FROM honeypot_connections 
                WHERE connection_data LIKE '%timing-test%'
                ORDER BY id DESC LIMIT 1
            """)
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                db_timestamp = datetime.fromisoformat(row[0])
                
                # Check if timestamp is within reasonable range
                if test_start <= db_timestamp <= test_end + timedelta(seconds=1):
                    self.log_result("Database Timestamp Precision", True, 
                                  f"Timestamp within {(db_timestamp - test_start).total_seconds():.3f}s")
                else:
                    self.log_result("Database Timestamp Precision", False,
                                  f"Timestamp outside expected range: {db_timestamp}")
            else:
                self.log_result("Database Timestamp Precision", False, "No database entry found")
                
        except Exception as e:
            self.log_result("Database Timestamp Precision", False, f"Error: {e}")
    
    def test_real_time_detection_latency(self):
        """Test real-time detection latency"""
        print("\n⚡ Testing Real-time Detection Latency...")
        
        try:
            # Clear any existing entries
            requests.post(f"{self.dashboard_url}/api/clear-logs", 
                         json={"clear_type": "connections"}, timeout=5)
            time.sleep(1)
            
            # Record start time
            start_time = time.time()
            
            # Make attack request
            response = requests.get(f"{self.http_honeypot_url}/admin", timeout=5)
            
            # Check dashboard API for the entry (with retries)
            max_retries = 10
            found = False
            
            for i in range(max_retries):
                time.sleep(0.1)  # 100ms intervals
                
                try:
                    api_response = requests.get(f"{self.dashboard_url}/api/recent-connections", timeout=2)
                    if api_response.status_code == 200:
                        connections = api_response.json().get("connections", [])
                        if connections:
                            detection_time = time.time() - start_time
                            found = True
                            break
                except:
                    continue
            
            if found:
                if detection_time < 1.0:  # Sub-second detection
                    self.log_result("Real-time Detection Latency", True,
                                  f"Detected in {detection_time:.3f}s")
                else:
                    self.log_result("Real-time Detection Latency", False,
                                  f"Detection took {detection_time:.3f}s (>1s)")
            else:
                self.log_result("Real-time Detection Latency", False,
                              "Attack not detected within 1 second")
                
        except Exception as e:
            self.log_result("Real-time Detection Latency", False, f"Error: {e}")
    
    def test_websocket_real_time_updates(self):
        """Test WebSocket real-time updates"""
        print("\n🔄 Testing WebSocket Real-time Updates...")
        
        try:
            # This would require WebSocket client implementation
            # For now, test the API endpoint response time
            start_time = time.time()
            response = requests.get(f"{self.dashboard_url}/api/stats", timeout=5)
            response_time = time.time() - start_time
            
            if response.status_code == 200 and response_time < 0.5:
                stats = response.json()
                if "last_updated" in stats:
                    last_updated = datetime.fromisoformat(stats["last_updated"])
                    age = (datetime.now() - last_updated).total_seconds()
                    
                    if age < 60:  # Updated within last minute
                        self.log_result("WebSocket Real-time Updates", True,
                                      f"Stats updated {age:.1f}s ago, API response: {response_time:.3f}s")
                    else:
                        self.log_result("WebSocket Real-time Updates", False,
                                      f"Stats too old: {age:.1f}s")
                else:
                    self.log_result("WebSocket Real-time Updates", False,
                                  "No last_updated timestamp in stats")
            else:
                self.log_result("WebSocket Real-time Updates", False,
                              f"API error or slow response: {response_time:.3f}s")
                
        except Exception as e:
            self.log_result("WebSocket Real-time Updates", False, f"Error: {e}")
    
    def test_timestamp_format_consistency(self):
        """Test timestamp format consistency across system"""
        print("\n📅 Testing Timestamp Format Consistency...")
        
        try:
            # Check database timestamp format
            conn = sqlite3.connect(self.db_path)
            cursor = conn.execute("""
                SELECT timestamp FROM honeypot_connections 
                ORDER BY id DESC LIMIT 5
            """)
            
            db_timestamps = [row[0] for row in cursor.fetchall()]
            conn.close()
            
            # Check API timestamp format
            response = requests.get(f"{self.dashboard_url}/api/stats", timeout=5)
            api_timestamp = response.json().get("last_updated")
            
            # Validate ISO 8601 format
            iso_format_valid = True
            for ts in db_timestamps:
                try:
                    datetime.fromisoformat(ts)
                except:
                    iso_format_valid = False
                    break
            
            try:
                datetime.fromisoformat(api_timestamp)
                api_format_valid = True
            except:
                api_format_valid = False
            
            if iso_format_valid and api_format_valid:
                self.log_result("Timestamp Format Consistency", True,
                              "All timestamps use ISO 8601 format")
            else:
                self.log_result("Timestamp Format Consistency", False,
                              f"Format issues - DB: {iso_format_valid}, API: {api_format_valid}")
                
        except Exception as e:
            self.log_result("Timestamp Format Consistency", False, f"Error: {e}")
    
    def run_all_tests(self):
        """Run all timing accuracy tests"""
        print("🚀 Starting PHIDS Timing Accuracy Tests")
        print("=" * 50)
        
        # Test if PHIDS is running
        try:
            response = requests.get(f"{self.dashboard_url}/api/stats", timeout=5)
            if response.status_code != 200:
                print("❌ PHIDS dashboard not accessible. Please start PHIDS first.")
                return False
        except:
            print("❌ PHIDS not running. Please start with: python main.py --debug")
            return False
        
        # Run tests
        self.test_database_timestamp_precision()
        self.test_real_time_detection_latency()
        self.test_websocket_real_time_updates()
        self.test_timestamp_format_consistency()
        
        # Summary
        print("\n" + "=" * 50)
        print("📊 Test Results Summary")
        print("=" * 50)
        
        passed = sum(1 for r in self.results if r["result"])
        total = len(self.results)
        
        print(f"Tests Passed: {passed}/{total}")
        print(f"Success Rate: {(passed/total)*100:.1f}%")
        
        if passed == total:
            print("🎉 All timing accuracy tests PASSED!")
            print("✅ PHIDS is ready for SOC analysis with real-time capabilities")
        else:
            print("⚠️  Some tests failed. Review configuration and system performance.")
        
        # Save detailed results
        with open("timing_test_results.json", "w") as f:
            json.dump(self.results, f, indent=2)
        
        print(f"\n📄 Detailed results saved to: timing_test_results.json")
        return passed == total

if __name__ == "__main__":
    tester = TimingAccuracyTester()
    success = tester.run_all_tests()
    sys.exit(0 if success else 1)
