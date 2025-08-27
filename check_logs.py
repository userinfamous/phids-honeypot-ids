#!/usr/bin/env python3
"""
Check honeypot logs to see what's actually being logged
"""

import os
import json
from datetime import datetime, timedelta

def check_honeypot_logs():
    """Check the honeypot log file for recent SSH connections"""
    print("🔍 Checking Honeypot Logs")
    print("=" * 40)
    
    log_file = "logs/honeypot.log"
    
    if not os.path.exists(log_file):
        print(f"❌ Log file not found: {log_file}")
        return
    
    try:
        with open(log_file, 'r') as f:
            lines = f.readlines()
        
        # Look for recent SSH-related log entries
        recent_lines = lines[-100:] if len(lines) > 100 else lines
        
        ssh_entries = []
        enhanced_entries = []
        debug_entries = []
        
        for line in recent_lines:
            if "SSH" in line and "Connection from" in line:
                ssh_entries.append(line.strip())
            elif "SSH session result" in line or "Classified as" in line:
                debug_entries.append(line.strip())
            elif "honeypot.ssh" in line and ("SUCCESS" in line or "FAILED" in line or "ERROR" in line or "TIMEOUT" in line):
                enhanced_entries.append(line.strip())
        
        print(f"📊 Found {len(ssh_entries)} SSH connection entries")
        print(f"📊 Found {len(enhanced_entries)} enhanced log entries")
        print(f"📊 Found {len(debug_entries)} debug entries")
        
        if ssh_entries:
            print("\n📋 Recent SSH Connection Entries:")
            for entry in ssh_entries[-5:]:  # Show last 5
                print(f"  {entry}")
        
        if enhanced_entries:
            print("\n📋 Recent Enhanced Log Entries:")
            for entry in enhanced_entries[-5:]:  # Show last 5
                print(f"  {entry}")
        
        if debug_entries:
            print("\n📋 Recent Debug Entries:")
            for entry in debug_entries[-10:]:  # Show last 10
                print(f"  {entry}")
        
        # Analyze status distribution
        status_counts = {'SUCCESS': 0, 'FAILED': 0, 'ERROR': 0, 'TIMEOUT': 0}
        
        for entry in ssh_entries:
            for status in status_counts.keys():
                if f" - {status} - " in entry:
                    status_counts[status] += 1
                    break
        
        print(f"\n📊 Status Distribution:")
        for status, count in status_counts.items():
            print(f"  {status}: {count}")
        
        # Check for the specific issue
        success_with_zero_duration = 0
        for entry in ssh_entries:
            if " - SUCCESS - " in entry and "Duration: 0.0s" in entry:
                success_with_zero_duration += 1
        
        if success_with_zero_duration > 0:
            print(f"\n⚠️  Found {success_with_zero_duration} SUCCESS entries with 0.0s duration")
            print("   This indicates the issue is still present!")
        else:
            print(f"\n✅ No SUCCESS entries with 0.0s duration found")
        
    except Exception as e:
        print(f"❌ Error reading log file: {e}")

def check_database():
    """Check what's in the database"""
    print("\n🔍 Checking Database")
    print("=" * 30)
    
    try:
        import sqlite3
        
        db_path = "data/phids.db"
        if not os.path.exists(db_path):
            print(f"❌ Database not found: {db_path}")
            return
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Get recent SSH connections
        cursor.execute("""
            SELECT source_ip, source_port, destination_port, service_type, 
                   timestamp, duration, connection_status, failure_reason
            FROM honeypot_connections 
            WHERE service_type = 'ssh' 
            ORDER BY timestamp DESC 
            LIMIT 10
        """)
        
        rows = cursor.fetchall()
        
        if rows:
            print("📋 Recent SSH connections in database:")
            print("   IP:Port -> Service | Status | Duration | Reason")
            for row in rows:
                source_ip, source_port, dest_port, service, timestamp, duration, status, reason = row
                status_str = status or "NULL"
                duration_str = f"{duration:.1f}s" if duration else "NULL"
                reason_str = reason or "None"
                print(f"   {source_ip}:{source_port} -> {service}:{dest_port} | {status_str} | {duration_str} | {reason_str}")
        else:
            print("📋 No SSH connections found in database")
        
        conn.close()
        
    except ImportError:
        print("❌ sqlite3 not available")
    except Exception as e:
        print(f"❌ Error checking database: {e}")

def main():
    """Main function"""
    print("🔍 SSH Status Classification Log Analysis")
    print("=" * 50)
    
    check_honeypot_logs()
    check_database()
    
    print("\n💡 What to look for:")
    print("- Enhanced log entries should show FAILED/ERROR, not SUCCESS")
    print("- Debug entries should show classification logic")
    print("- Database should have connection_status field set correctly")
    print("- No SUCCESS entries with 0.0s duration")

if __name__ == "__main__":
    main()
