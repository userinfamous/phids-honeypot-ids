#!/usr/bin/env python3
import sqlite3

conn = sqlite3.connect('data/phids.db')
cursor = conn.cursor()

cursor.execute("""
    SELECT commands 
    FROM honeypot_connections 
    WHERE commands LIKE '%OR%' 
    ORDER BY timestamp DESC 
    LIMIT 1
""")

row = cursor.fetchone()
if row:
    print("Raw commands data:")
    print(repr(row[0]))
    print("\nCommands data:")
    print(row[0])
else:
    print("No data found")

conn.close()
