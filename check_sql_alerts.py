#!/usr/bin/env python3
import sqlite3

conn = sqlite3.connect('data/phids.db')
cursor = conn.cursor()

# Check for SQL injection alerts
cursor.execute("SELECT COUNT(*) FROM ids_alerts WHERE signature_id = 'sql_injection'")
sql_count = cursor.fetchone()[0]
print(f"SQL injection alerts: {sql_count}")

# Check all recent alerts with signature_id
cursor.execute("""
    SELECT timestamp, signature_id, alert_type, severity, source_ip, description
    FROM ids_alerts
    WHERE signature_id IS NOT NULL
    ORDER BY timestamp DESC
    LIMIT 10
""")

alerts = cursor.fetchall()
print(f"\nRecent alerts with signature_id ({len(alerts)}):")
for alert in alerts:
    print(f"  {alert[0]} - {alert[1]} - {alert[2]} - {alert[3]} from {alert[4]}")
    print(f"    Description: {alert[5][:50]}...")

conn.close()
