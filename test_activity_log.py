#!/usr/bin/env python3
"""
Test script to verify activity log shows only authentication events
"""
import requests
import time
import json
from datetime import datetime

def test_activity_log():
    """Test that activity log shows only authentication events"""
    print("=" * 70)
    print("Testing Activity Log - Authentication Events Only")
    print("=" * 70)
    
    # Wait for services to start
    print("\n[1] Waiting for services to start...")
    time.sleep(3)
    
    # Get initial activity log
    print("[2] Getting initial activity log...")
    try:
        response = requests.get('http://127.0.0.1:5001/api/authentication-events?hours=24&limit=100')
        if response.status_code == 200:
            initial_events = response.json().get('events', [])
            print(f"    Initial events: {len(initial_events)}")
        else:
            print(f"    Error: {response.status_code}")
            return
    except Exception as e:
        print(f"    Error: {e}")
        return
    
    # Attempt multiple logins to test activity log
    print("\n[3] Attempting multiple logins...")
    
    # Test 1: Successful login
    print("    [3a] Successful login (admin:admin)...")
    try:
        response = requests.post(
            'http://127.0.0.1:8081/admin',
            data={'username': 'admin', 'password': 'admin'},
            timeout=5,
            allow_redirects=False
        )
        print(f"        Response: {response.status_code}")
    except Exception as e:
        print(f"        Error: {e}")
    
    time.sleep(1)
    
    # Test 2: Failed login
    print("    [3b] Failed login (admin:wrongpass)...")
    try:
        response = requests.post(
            'http://127.0.0.1:8081/admin',
            data={'username': 'admin', 'password': 'wrongpass'},
            timeout=5,
            allow_redirects=False
        )
        print(f"        Response: {response.status_code}")
    except Exception as e:
        print(f"        Error: {e}")
    
    time.sleep(1)
    
    # Test 3: Another successful login
    print("    [3c] Another successful login (admin:password)...")
    try:
        response = requests.post(
            'http://127.0.0.1:8081/admin',
            data={'username': 'admin', 'password': 'password'},
            timeout=5,
            allow_redirects=False
        )
        print(f"        Response: {response.status_code}")
    except Exception as e:
        print(f"        Error: {e}")
    
    # Wait for async logging
    print("\n[4] Waiting for async logging...")
    time.sleep(2)
    
    # Get updated activity log
    print("[5] Getting updated activity log...")
    try:
        response = requests.get('http://127.0.0.1:5001/api/authentication-events?hours=24&limit=100')
        if response.status_code == 200:
            final_events = response.json().get('events', [])
            print(f"    Final events: {len(final_events)}")
            print(f"    New events: {len(final_events) - len(initial_events)}")
        else:
            print(f"    Error: {response.status_code}")
            return
    except Exception as e:
        print(f"    Error: {e}")
        return
    
    # Analyze the events
    print("\n[6] Activity Log Analysis:")
    print("    " + "-" * 60)
    
    new_events = final_events[:len(final_events) - len(initial_events)]
    
    if not new_events:
        print("    ✗ No new events found!")
        return
    
    print(f"    Total new events: {len(new_events)}")
    print()
    
    for i, event in enumerate(reversed(new_events), 1):
        status = "✓ SUCCESS" if event.get('success') else "✗ FAILED"
        username = event.get('username', 'unknown')
        service = event.get('service_type', 'unknown').upper()
        timestamp = event.get('timestamp', 'unknown')
        
        print(f"    [{i}] {service} Authentication {status}")
        print(f"        User: {username}")
        print(f"        Time: {timestamp}")
        print()
    
    # Verify no connection events in activity log
    print("[7] Verification:")
    print("    " + "-" * 60)
    
    # Check that we only have authentication events
    auth_events = [e for e in new_events if e.get('service_type') in ['http', 'ssh']]
    
    if len(auth_events) == len(new_events):
        print("    ✓ Activity log contains ONLY authentication events")
        print(f"    ✓ No connection noise (favicon, CSS, etc.)")
        print(f"    ✓ Clean and focused activity log")
    else:
        print(f"    ✗ Found {len(new_events) - len(auth_events)} non-authentication events")
    
    # Check success/failed counts
    successful = sum(1 for e in new_events if e.get('success'))
    failed = sum(1 for e in new_events if not e.get('success'))
    
    print(f"    ✓ Successful logins: {successful}")
    print(f"    ✓ Failed logins: {failed}")
    
    print("\n" + "=" * 70)
    print("Test Complete!")
    print("=" * 70)

if __name__ == '__main__':
    test_activity_log()

