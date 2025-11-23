#!/usr/bin/env python3
"""
Test script to verify authentication event logging
"""
import requests
import time
import sqlite3
from datetime import datetime

def test_http_login():
    """Test HTTP login and verify it's logged"""
    print("=" * 60)
    print("Testing HTTP Login Event Logging")
    print("=" * 60)
    
    # Wait for honeypot to start
    print("\n[1] Waiting for honeypot to start...")
    time.sleep(3)
    
    # Get initial count
    print("[2] Checking initial authentication events...")
    conn = sqlite3.connect('data/phids.db')
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM authentication_events')
    initial_count = cursor.fetchone()[0]
    print(f"    Initial count: {initial_count}")
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
        print(f"    Response status: {response.status_code}")
        print(f"    Response headers: {dict(response.headers)}")
    except Exception as e:
        print(f"    Error: {e}")
    
    # Wait a moment for async logging
    print("\n[4] Waiting for async logging to complete...")
    time.sleep(2)
    
    # Check new events
    print("[5] Checking authentication events after login...")
    conn = sqlite3.connect('data/phids.db')
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM authentication_events')
    final_count = cursor.fetchone()[0]
    print(f"    Final count: {final_count}")
    print(f"    New events: {final_count - initial_count}")
    
    # Show the latest events
    print("\n[6] Latest authentication events:")
    cursor.execute('''
        SELECT id, timestamp, username, success, failure_reason, service_type
        FROM authentication_events
        ORDER BY timestamp DESC
        LIMIT 5
    ''')
    rows = cursor.fetchall()
    for row in rows:
        print(f"    ID: {row[0]}, Time: {row[1]}, User: {row[2]}, Success: {row[3]}, Reason: {row[4]}, Service: {row[5]}")
    
    conn.close()
    
    # Check if successful login was logged
    print("\n[7] Verification:")
    if final_count > initial_count:
        print("    ✓ New authentication event was logged!")
        # Check if it's marked as successful
        conn = sqlite3.connect('data/phids.db')
        cursor = conn.cursor()
        cursor.execute('''
            SELECT success FROM authentication_events
            WHERE username = 'admin' AND service_type = 'http'
            ORDER BY timestamp DESC
            LIMIT 1
        ''')
        result = cursor.fetchone()
        if result:
            success = result[0]
            if success == 1:
                print("    ✓ Login was marked as SUCCESSFUL!")
            else:
                print("    ✗ Login was marked as FAILED (should be successful)")
        conn.close()
    else:
        print("    ✗ No new authentication event was logged!")

if __name__ == '__main__':
    test_http_login()

