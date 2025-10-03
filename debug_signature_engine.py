#!/usr/bin/env python3
import sqlite3
import json
from src.ids.signatures import SignatureEngine

# Get a recent SQL injection connection
conn = sqlite3.connect('data/phids.db')
cursor = conn.cursor()

cursor.execute("""
    SELECT source_ip, service_type, commands, payloads, user_agent
    FROM honeypot_connections 
    WHERE commands LIKE '%OR%'
    ORDER BY timestamp DESC 
    LIMIT 1
""")

row = cursor.fetchone()
if row:
    source_ip, service_type, commands_str, payloads_str, user_agent = row
    
    # Parse the data
    try:
        # Try JSON first
        commands = json.loads(commands_str) if commands_str else []
        payloads = json.loads(payloads_str) if payloads_str else []
    except:
        try:
            # If JSON fails, try eval (for Python string representation)
            commands = eval(commands_str) if commands_str else []
            payloads = eval(payloads_str) if payloads_str else []
        except:
            commands = []
            payloads = []
    
    # Create connection data
    connection_data = {
        'source_ip': source_ip,
        'service_type': service_type,
        'commands': commands,
        'payloads': payloads,
        'user_agent': user_agent or ''
    }
    
    print("Connection data:")
    print(f"  Source IP: {source_ip}")
    print(f"  Service: {service_type}")
    print(f"  Commands: {commands}")
    print(f"  Payloads: {payloads}")
    print(f"  User Agent: {user_agent}")
    print()
    
    # Test signature engine
    engine = SignatureEngine()
    alerts = engine.analyze_connection(connection_data)
    
    print(f"Generated {len(alerts)} alerts:")
    for alert in alerts:
        print(f"  - {alert['signature_id']}: {alert['name']}")
        print(f"    Severity: {alert['severity']}")
        print(f"    Matched patterns: {alert.get('matched_patterns', [])}")
    
    # Debug: manually check SQL injection patterns
    print("\nDebug: Manual pattern checking")
    
    # Extract text data like the signature engine does
    text_data = []
    for cmd in commands:
        if isinstance(cmd, dict):
            text_data.extend([
                cmd.get('command', ''),
                cmd.get('method', ''),
                cmd.get('path', ''),
                cmd.get('body', ''),
                str(cmd.get('headers', {}))
            ])
    
    combined_text = ' '.join(text_data).lower()
    print(f"Combined text: {combined_text[:200]}...")
    
    # URL decode
    from urllib.parse import unquote
    try:
        decoded_text = unquote(combined_text)
        print(f"Decoded text: {decoded_text[:200]}...")
    except:
        decoded_text = combined_text
    
    # Check SQL injection patterns
    sql_patterns = [
        r"union\s+select",
        r"or\s+1\s*=\s*1",
        r"drop\s+table",
        r"insert\s+into",
        r"delete\s+from"
    ]
    
    import re
    for pattern in sql_patterns:
        if re.search(pattern, decoded_text, re.IGNORECASE):
            print(f"  ✅ Pattern '{pattern}' MATCHED")
        else:
            print(f"  ❌ Pattern '{pattern}' not matched")

else:
    print("No SQL injection connections found")

conn.close()
