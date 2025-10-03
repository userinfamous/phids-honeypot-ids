#!/usr/bin/env python3
import sqlite3
import json

# Connect to database
conn = sqlite3.connect('data/phids.db')
cursor = conn.cursor()

# Get a recent connection with commands
cursor.execute("""
    SELECT commands, payloads 
    FROM honeypot_connections 
    WHERE commands IS NOT NULL 
    AND commands != '[]'
    ORDER BY timestamp DESC 
    LIMIT 1
""")

row = cursor.fetchone()
if row:
    commands_str, payloads_str = row
    
    print("Commands structure:")
    try:
        commands = json.loads(commands_str)
        print(json.dumps(commands, indent=2))
    except:
        print(f"Raw commands: {commands_str}")
    
    print("\nPayloads structure:")
    try:
        payloads = json.loads(payloads_str)
        print(json.dumps(payloads, indent=2))
    except:
        print(f"Raw payloads: {payloads_str}")
else:
    print("No connection data found")

conn.close()
