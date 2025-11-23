#!/usr/bin/env python3
"""
Test script to verify authentication event persistence across page refresh
"""
import requests
import time
import sqlite3
import json

def test_persistence():
    """Test that authentication events persist in database and API"""
    print("=" * 70)
    print("Testing Authentication Event Persistence")
    print("=" * 70)
    
    # Wait for services to start
    print("\n[1] Waiting for services to start...")
    time.sleep(3)
    
    # Get initial count
    print("[2] Checking initial authentication events...")
    conn = sqlite3.connect('data/phids.db')
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM authentication_events WHERE service_type = "http"')
    initial_count = cursor.fetchone()[0]
    print(f"    Initial HTTP auth events: {initial_count}")
    conn.close()
    
    # Attempt login
    print("\n[3] Attempting HTTP login with admin:admin...")
    try:
        response = requests.post(
            'http://127.0.0.1:8081/admin',
            data={'username': 'admin', 'password': 'admin'},
            timeout=5,
            allow_redirects=False
        )
        print(f"    ✓ Login response: {response.status_code}")
    except Exception as e:
        print(f"    ✗ Error: {e}")
        return
    
    # Wait for async logging
    print("\n[4] Waiting for async logging...")
    time.sleep(2)
    
    # Check database
    print("[5] Checking database for new event...")
    conn = sqlite3.connect('data/phids.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, username, success FROM authentication_events
        WHERE service_type = "http"
        ORDER BY timestamp DESC
        LIMIT 1
    ''')
    result = cursor.fetchone()
    if result:
        event_id, username, success = result
        print(f"    ✓ Found event: ID={event_id}, User={username}, Success={success}")
        if success == 1:
            print(f"    ✓ Event marked as SUCCESSFUL")
        else:
            print(f"    ✗ Event marked as FAILED (should be successful)")
    else:
        print(f"    ✗ No event found in database")
    conn.close()
    
    # Test API endpoint
    print("\n[6] Testing API endpoint /api/authentication-events...")
    try:
        response = requests.get('http://127.0.0.1:5001/api/authentication-events?hours=24&limit=100')
        if response.status_code == 200:
            data = response.json()
            events = data.get('events', [])
            print(f"    ✓ API returned {len(events)} events")
            
            # Find our login event
            http_events = [e for e in events if e.get('service_type') == 'http' and e.get('username') == 'admin']
            if http_events:
                latest = http_events[0]
                print(f"    ✓ Found HTTP login event in API")
                print(f"      - Username: {latest.get('username')}")
                print(f"      - Success: {latest.get('success')}")
                print(f"      - Timestamp: {latest.get('timestamp')}")
                if latest.get('success'):
                    print(f"    ✓ Event is marked as SUCCESSFUL in API")
                else:
                    print(f"    ✗ Event is marked as FAILED in API")
            else:
                print(f"    ✗ HTTP login event not found in API response")
        else:
            print(f"    ✗ API returned status {response.status_code}")
    except Exception as e:
        print(f"    ✗ API error: {e}")
    
    # Simulate page refresh by querying API again
    print("\n[7] Simulating page refresh (querying API again)...")
    time.sleep(1)
    try:
        response = requests.get('http://127.0.0.1:5001/api/authentication-events?hours=24&limit=100')
        if response.status_code == 200:
            data = response.json()
            events = data.get('events', [])
            http_events = [e for e in events if e.get('service_type') == 'http' and e.get('username') == 'admin']
            if http_events:
                latest = http_events[0]
                if latest.get('success'):
                    print(f"    ✓ Event PERSISTED after refresh and still marked as SUCCESSFUL")
                else:
                    print(f"    ✗ Event PERSISTED but marked as FAILED")
            else:
                print(f"    ✗ Event DISAPPEARED after refresh")
        else:
            print(f"    ✗ API error on refresh")
    except Exception as e:
        print(f"    ✗ Error on refresh: {e}")
    
    print("\n" + "=" * 70)
    print("Test Complete!")
    print("=" * 70)

if __name__ == '__main__':
    test_persistence()

