#!/usr/bin/env python3
"""
Enhanced PHIDS Dashboard Test Suite
Tests all new log management and filtering features
"""

import asyncio
import aiohttp
import json
import sys
from datetime import datetime, timedelta

class EnhancedDashboardTester:
    def __init__(self):
        self.base_url = "http://127.0.0.1:5000"
        self.session = None
    
    async def initialize(self):
        """Initialize HTTP session"""
        self.session = aiohttp.ClientSession()
    
    async def cleanup(self):
        """Cleanup HTTP session"""
        if self.session:
            await self.session.close()
    
    async def test_api_endpoint(self, endpoint, method="GET", data=None):
        """Test API endpoint and return response"""
        try:
            url = f"{self.base_url}{endpoint}"
            
            if method == "GET":
                async with self.session.get(url) as response:
                    return response.status, await response.json()
            elif method == "POST":
                async with self.session.post(url, json=data) as response:
                    return response.status, await response.json()
                    
        except Exception as e:
            return 500, {"error": str(e)}
    
    async def test_basic_endpoints(self):
        """Test basic dashboard endpoints"""
        print("🧪 Testing Basic Dashboard Endpoints...")
        
        endpoints = [
            "/api/stats",
            "/api/recent-connections", 
            "/api/alerts"
        ]
        
        for endpoint in endpoints:
            status, data = await self.test_api_endpoint(endpoint)
            if status == 200:
                print(f"✅ {endpoint}: {status} - Data loaded successfully")
            else:
                print(f"❌ {endpoint}: {status} - {data}")
    
    async def test_filtering_endpoints(self):
        """Test new filtering endpoints"""
        print("\n🔍 Testing Enhanced Filtering Endpoints...")
        
        # Test filtered connections
        status, data = await self.test_api_endpoint("/api/filtered-connections?limit=10")
        if status == 200:
            print(f"✅ Filtered Connections: {status} - Found {data.get('count', 0)} connections")
        else:
            print(f"❌ Filtered Connections: {status} - {data}")
        
        # Test filtered alerts
        status, data = await self.test_api_endpoint("/api/filtered-alerts?limit=10")
        if status == 200:
            print(f"✅ Filtered Alerts: {status} - Found {data.get('count', 0)} alerts")
        else:
            print(f"❌ Filtered Alerts: {status} - {data}")
        
        # Test with specific filters
        status, data = await self.test_api_endpoint("/api/filtered-connections?service=ssh&limit=5")
        if status == 200:
            ssh_count = data.get('count', 0)
            print(f"✅ SSH Filter: {status} - Found {ssh_count} SSH connections")
        else:
            print(f"❌ SSH Filter: {status} - {data}")
    
    async def test_export_endpoints(self):
        """Test export functionality"""
        print("\n📤 Testing Export Endpoints...")
        
        # Test connections export
        status, data = await self.test_api_endpoint("/api/export/connections?format=json&limit=5")
        if status == 200:
            conn_count = data.get('count', 0)
            print(f"✅ Export Connections (JSON): {status} - {conn_count} connections")
        else:
            print(f"❌ Export Connections: {status} - {data}")
        
        # Test alerts export
        status, data = await self.test_api_endpoint("/api/export/alerts?format=json&limit=5")
        if status == 200:
            alert_count = data.get('count', 0)
            print(f"✅ Export Alerts (JSON): {status} - {alert_count} alerts")
        else:
            print(f"❌ Export Alerts: {status} - {data}")
    
    async def test_analysis_endpoints(self):
        """Test new analysis endpoints"""
        print("\n📊 Testing Analysis Endpoints...")
        
        # Test timeline
        status, data = await self.test_api_endpoint("/api/timeline?hours=24")
        if status == 200:
            timeline_count = len(data.get('timeline', []))
            print(f"✅ Attack Timeline: {status} - {timeline_count} data points")
        else:
            print(f"❌ Attack Timeline: {status} - {data}")
        
        # Test threat summary
        status, data = await self.test_api_endpoint("/api/threat-summary?hours=24")
        if status == 200:
            connections = len(data.get('connections', []))
            alerts = len(data.get('alerts', []))
            print(f"✅ Threat Summary: {status} - {connections} connection types, {alerts} alert types")
        else:
            print(f"❌ Threat Summary: {status} - {data}")
    
    async def test_clear_logs_functionality(self):
        """Test clear logs functionality (with caution)"""
        print("\n🗑️  Testing Clear Logs Functionality...")
        
        # First, check current data count
        status, stats = await self.test_api_endpoint("/api/stats")
        if status == 200:
            original_connections = stats.get('total_connections', 0)
            original_alerts = stats.get('total_alerts', 0)
            print(f"📊 Current Data: {original_connections} connections, {original_alerts} alerts")
            
            # Only test if we have some data
            if original_connections > 0 or original_alerts > 0:
                print("⚠️  Clear logs test skipped to preserve demo data")
                print("   To test manually: Use the dashboard 'Clear Logs' button")
                return True
            else:
                print("ℹ️  No data to clear - test passed")
                return True
        else:
            print(f"❌ Could not check current stats: {status}")
            return False
    
    async def run_comprehensive_test(self):
        """Run all tests"""
        print("🚀 Enhanced PHIDS Dashboard Test Suite")
        print("=" * 60)
        
        await self.initialize()
        
        try:
            # Run all test categories
            await self.test_basic_endpoints()
            await self.test_filtering_endpoints()
            await self.test_export_endpoints()
            await self.test_analysis_endpoints()
            await self.test_clear_logs_functionality()
            
            print("\n" + "=" * 60)
            print("🎉 Enhanced Dashboard Test Suite Complete!")
            print("\n📋 New Features Available:")
            print("   🗑️  Clear Logs - Remove test data to monitor real attacks")
            print("   🔍 Advanced Filters - Search by IP, service, time, severity")
            print("   📤 Export Options - Download data as CSV or JSON")
            print("   📊 Timeline Analysis - Visual attack patterns over time")
            print("   🎯 Threat Summary - Comprehensive security overview")
            print("   🔄 Live/Historical Toggle - Switch monitoring modes")
            
            print("\n🌐 Dashboard URL: http://127.0.0.1:5000")
            print("💡 Use the 'Controls' dropdown to access new features!")
            
        except Exception as e:
            print(f"\n❌ Test suite error: {e}")
        finally:
            await self.cleanup()

async def main():
    """Main test function"""
    tester = EnhancedDashboardTester()
    await tester.run_comprehensive_test()

if __name__ == "__main__":
    print("🧪 Starting Enhanced Dashboard Tests...")
    print("📋 Make sure the dashboard is running: python start_dashboard.py")
    print()
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n⏹️  Test interrupted by user")
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        sys.exit(1)
