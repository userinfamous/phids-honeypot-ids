#!/usr/bin/env python3
import sqlite3
from datetime import datetime, timedelta

# Connect to database
conn = sqlite3.connect('data/phids.db')
cursor = conn.cursor()

# Check for recent SQL injection alerts
print("Recent SQL injection alerts:")
cursor.execute("""
    SELECT timestamp, severity, description, source_ip 
    FROM ids_alerts 
    WHERE description LIKE '%injection%' 
    ORDER BY timestamp DESC 
    LIMIT 10
""")

alerts = cursor.fetchall()
if alerts:
    for alert in alerts:
        print(f"  {alert[0]} - {alert[1]} - {alert[2]} from {alert[3]}")
else:
    print("  No SQL injection alerts found")

# Check recent connections with payloads
print("\nRecent connections with payloads:")
cursor.execute("""
    SELECT timestamp, source_ip, service_type, payloads, commands
    FROM honeypot_connections
    WHERE payloads IS NOT NULL
    AND (payloads LIKE '%OR%' OR commands LIKE '%OR%')
    ORDER BY timestamp DESC
    LIMIT 5
""")

connections = cursor.fetchall()
if connections:
    for conn_data in connections:
        print(f"  {conn_data[0]} - {conn_data[1]} - {conn_data[2]}")
        if conn_data[3]:  # payloads
            print(f"    Payloads: {conn_data[3][:100]}...")
        if conn_data[4]:  # commands
            print(f"    Commands: {conn_data[4][:100]}...")
else:
    print("  No connections with SQL injection payloads found")

# Check all recent alerts
print("\nAll recent alerts (last 10):")
cursor.execute("""
    SELECT timestamp, severity, signature_id, description, source_ip
    FROM ids_alerts 
    ORDER BY timestamp DESC 
    LIMIT 10
""")

all_alerts = cursor.fetchall()
if all_alerts:
    for alert in all_alerts:
        print(f"  {alert[0]} - {alert[1]} - {alert[2]} - {alert[3][:50]}... from {alert[4]}")
else:
    print("  No recent alerts found")

conn.close()
