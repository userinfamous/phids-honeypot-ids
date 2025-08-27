#!/usr/bin/env python3
"""
Test script to verify the broadcast_event() method fix
Tests both calling patterns to ensure compatibility
"""

import asyncio
import sys
import os
from datetime import datetime

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.dashboard.web_server import DashboardWebServer
from src.dashboard.event_broadcaster import EventBroadcaster

class MockWebSocket:
    """Mock WebSocket for testing"""
    def __init__(self, name):
        self.name = name
        self.messages = []
        self.should_fail = False
    
    async def send_json(self, data):
        """Mock send_json method"""
        if self.should_fail:
            raise Exception(f"Mock WebSocket {self.name} connection failed")
        self.messages.append(data)
        print(f"📤 WebSocket {self.name} received: {data}")

async def test_broadcast_event_fix():
    """Test the broadcast_event method with both calling patterns"""
    print("🧪 Testing broadcast_event() Method Fix")
    print("=" * 60)
    
    # Create dashboard server instance
    dashboard = DashboardWebServer()
    
    # Add mock WebSocket connections
    ws1 = MockWebSocket("Client1")
    ws2 = MockWebSocket("Client2")
    dashboard.active_connections = [ws1, ws2]
    
    print("📡 Added 2 mock WebSocket connections")
    
    # Test 1: Clear logs calling pattern (single parameter)
    print("\n🔍 Test 1: Clear Logs Calling Pattern")
    clear_event_data = {
        "type": "logs_cleared",
        "clear_type": "all",
        "timestamp": datetime.now().isoformat()
    }
    
    try:
        await dashboard.broadcast_event(clear_event_data)
        print("✅ Clear logs broadcast successful")
        
        # Verify messages were sent
        assert len(ws1.messages) == 1, "WebSocket 1 should have received 1 message"
        assert len(ws2.messages) == 1, "WebSocket 2 should have received 1 message"
        assert ws1.messages[0]["type"] == "logs_cleared", "Message type should be logs_cleared"
        
    except Exception as e:
        print(f"❌ Clear logs broadcast failed: {e}")
        return False
    
    # Test 2: Event broadcaster calling pattern (two parameters)
    print("\n🔍 Test 2: Event Broadcaster Calling Pattern")
    connection_data = {
        "source_ip": "192.168.1.100",
        "service_type": "ssh",
        "timestamp": datetime.now().isoformat()
    }
    
    try:
        await dashboard.broadcast_event("new_connection", connection_data)
        print("✅ Event broadcaster broadcast successful")
        
        # Verify messages were sent
        assert len(ws1.messages) == 2, "WebSocket 1 should have received 2 messages"
        assert len(ws2.messages) == 2, "WebSocket 2 should have received 2 messages"
        
        # Check the second message structure
        second_message = ws1.messages[1]
        assert second_message["type"] == "new_connection", "Message type should be new_connection"
        assert "data" in second_message, "Message should have data field"
        assert second_message["data"]["source_ip"] == "192.168.1.100", "Data should contain source IP"
        
    except Exception as e:
        print(f"❌ Event broadcaster broadcast failed: {e}")
        return False
    
    # Test 3: Alert broadcasting
    print("\n🔍 Test 3: Alert Broadcasting Pattern")
    alert_data = {
        "alert_type": "sql_injection",
        "severity": "high",
        "source_ip": "10.0.0.1"
    }
    
    try:
        await dashboard.broadcast_event("new_alert", alert_data)
        print("✅ Alert broadcast successful")
        
        # Verify alert message
        alert_message = ws1.messages[2]
        assert alert_message["type"] == "new_alert", "Message type should be new_alert"
        assert alert_message["data"]["alert_type"] == "sql_injection", "Alert type should match"
        
    except Exception as e:
        print(f"❌ Alert broadcast failed: {e}")
        return False
    
    # Test 4: Connection failure handling
    print("\n🔍 Test 4: Connection Failure Handling")
    ws2.should_fail = True  # Make one WebSocket fail
    
    try:
        await dashboard.broadcast_event("test_event", {"test": "data"})
        print("✅ Connection failure handled gracefully")
        
        # Verify failed connection was removed
        assert len(dashboard.active_connections) == 1, "Failed connection should be removed"
        assert dashboard.active_connections[0] == ws1, "Only working connection should remain"
        
    except Exception as e:
        print(f"❌ Connection failure handling failed: {e}")
        return False
    
    # Test 5: Event broadcaster integration
    print("\n🔍 Test 5: Event Broadcaster Integration")
    event_broadcaster = EventBroadcaster()
    event_broadcaster.set_dashboard_server(dashboard)
    
    try:
        # Test connection broadcast
        await event_broadcaster.broadcast_connection({
            "source_ip": "172.16.1.50",
            "service_type": "http"
        })
        print("✅ Event broadcaster integration successful")
        
        # Verify the broadcast worked
        latest_message = ws1.messages[-1]
        assert latest_message["type"] == "new_connection", "Event broadcaster should send new_connection"
        
    except Exception as e:
        print(f"❌ Event broadcaster integration failed: {e}")
        return False
    
    print("\n" + "=" * 60)
    print("🎉 ALL TESTS PASSED!")
    print("✅ broadcast_event() method fix is working correctly")
    print("✅ Both calling patterns are supported:")
    print("   - broadcast_event(event_data) for clear logs")
    print("   - broadcast_event(event_type, data) for event broadcaster")
    print("✅ Connection failure handling works properly")
    print("✅ Event broadcaster integration is functional")
    
    return True

async def test_clear_logs_workflow():
    """Test the complete clear logs workflow"""
    print("\n🧪 Testing Complete Clear Logs Workflow")
    print("=" * 60)
    
    dashboard = DashboardWebServer()
    ws1 = MockWebSocket("TestClient")
    dashboard.active_connections = [ws1]
    
    # Simulate the clear logs call from the API endpoint
    clear_event_data = {
        "type": "logs_cleared",
        "clear_type": "all",
        "timestamp": datetime.now().isoformat()
    }
    
    try:
        # This is the exact call from the clear_logs API endpoint
        await dashboard.broadcast_event(clear_event_data)
        
        print("✅ Clear logs workflow completed successfully")
        print(f"📤 Broadcast message: {ws1.messages[0]}")
        
        # Verify the message structure
        message = ws1.messages[0]
        assert message["type"] == "logs_cleared"
        assert message["clear_type"] == "all"
        assert "timestamp" in message
        
        return True
        
    except Exception as e:
        print(f"❌ Clear logs workflow failed: {e}")
        return False

async def main():
    """Main test function"""
    print("🚨 PHIDS Dashboard broadcast_event() Fix Validation")
    print("🔧 Testing the fix for 'missing 1 required positional argument: data' error")
    print()
    
    # Run all tests
    test1_passed = await test_broadcast_event_fix()
    test2_passed = await test_clear_logs_workflow()
    
    if test1_passed and test2_passed:
        print("\n🎉 ALL TESTS PASSED - broadcast_event() fix is working!")
        print("💡 The clear logs functionality should now work without errors")
        print("🔧 Both calling patterns are properly supported")
    else:
        print("\n❌ Some tests failed - please check the implementation")
        return False
    
    return True

if __name__ == "__main__":
    success = asyncio.run(main())
    if success:
        print("\n✅ broadcast_event() method fix validated successfully!")
    else:
        print("\n❌ broadcast_event() method fix validation failed!")
        sys.exit(1)
