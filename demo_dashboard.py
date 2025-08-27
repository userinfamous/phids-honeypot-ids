#!/usr/bin/env python3
"""
Dashboard Demo Script for PHIDS
Generates sample data and shows dashboard functionality
"""
import asyncio
import random
import sys
from datetime import datetime, timedelta
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from src.core.database import DatabaseManager
from src.dashboard.event_broadcaster import event_broadcaster


async def generate_sample_data():
    """Generate sample honeypot data for dashboard demonstration"""
    print("🎯 Generating sample honeypot data...")
    
    db_manager = DatabaseManager()
    await db_manager.initialize()
    
    # Sample IP addresses (attackers)
    sample_ips = [
        "192.168.1.100", "10.0.0.50", "172.16.1.20", "203.0.113.10",
        "198.51.100.25", "192.0.2.15", "203.0.113.100", "198.51.100.50"
    ]
    
    # Generate connections over the last 24 hours
    now = datetime.now()
    connections_generated = 0
    alerts_generated = 0
    
    for i in range(50):  # Generate 50 connections
        # Random time in last 24 hours
        hours_ago = random.randint(0, 24)
        minutes_ago = random.randint(0, 59)
        timestamp = now - timedelta(hours=hours_ago, minutes=minutes_ago)
        
        # Random attacker
        source_ip = random.choice(sample_ips)
        source_port = random.randint(1024, 65535)
        
        # Random service
        service_type = random.choice(["ssh", "http"])
        dest_port = 2222 if service_type == "ssh" else 8080
        
        # Create connection data
        connection_data = {
            'source_ip': source_ip,
            'source_port': source_port,
            'destination_port': dest_port,
            'service_type': service_type,
            'session_id': f'demo-session-{i}',
            'commands': [],
            'payloads': [],
            'user_agent': 'Demo-Agent/1.0',
            'timestamp': timestamp.isoformat()
        }
        
        await db_manager.log_connection(connection_data)
        connections_generated += 1
        
        # Generate some alerts (30% chance)
        if random.random() < 0.3:
            alert_types = [
                "SQL Injection Attempt",
                "Brute Force Attack",
                "Directory Traversal",
                "Command Injection",
                "XSS Attempt"
            ]
            
            alert_data = {
                'alert_type': random.choice(alert_types),
                'severity': random.choice(['high', 'medium', 'low']),
                'source_ip': source_ip,
                'destination_ip': 'honeypot',
                'description': f'Suspicious activity detected from {source_ip}',
                'timestamp': timestamp.isoformat()
            }
            
            await db_manager.log_alert(alert_data)
            alerts_generated += 1
    
    print(f"✅ Generated {connections_generated} connections and {alerts_generated} alerts")
    return connections_generated, alerts_generated


async def simulate_live_activity():
    """Simulate live honeypot activity for real-time dashboard demo"""
    print("🔴 Simulating live activity (press Ctrl+C to stop)...")
    
    sample_ips = ["192.168.1.200", "10.0.0.100", "172.16.1.50"]
    
    try:
        while True:
            # Wait 10-30 seconds between events
            await asyncio.sleep(random.randint(10, 30))
            
            # Generate random connection event
            source_ip = random.choice(sample_ips)
            service_type = random.choice(["ssh", "http"])
            
            connection_data = {
                'source_ip': source_ip,
                'source_port': random.randint(1024, 65535),
                'destination_port': 2222 if service_type == "ssh" else 8080,
                'service_type': service_type,
                'session_id': f'live-{random.randint(1000, 9999)}',
                'timestamp': datetime.now().isoformat()
            }
            
            # Broadcast to dashboard
            await event_broadcaster.broadcast_connection(connection_data)
            print(f"📡 Broadcasted connection from {source_ip} to {service_type}")
            
            # 20% chance of generating an alert
            if random.random() < 0.2:
                alert_data = {
                    'alert_type': 'Live Attack Detected',
                    'severity': random.choice(['high', 'medium']),
                    'source_ip': source_ip,
                    'description': f'Real-time attack from {source_ip}',
                    'timestamp': datetime.now().isoformat()
                }
                
                await event_broadcaster.broadcast_alert(alert_data)
                print(f"🚨 Broadcasted alert for {source_ip}")
                
    except KeyboardInterrupt:
        print("\n⏹️ Stopped live simulation")


async def main():
    """Main demo function"""
    print("🚀 PHIDS Dashboard Demo")
    print("=" * 50)
    
    # Generate sample data
    await generate_sample_data()
    
    print("\n📊 Dashboard Demo Ready!")
    print("=" * 50)
    print("1. Start the dashboard:")
    print("   python start_dashboard.py")
    print()
    print("2. Open your browser to:")
    print("   http://127.0.0.1:5000")
    print()
    print("3. Run this script again with --live to simulate real-time activity:")
    print("   python demo_dashboard.py --live")
    print("=" * 50)
    
    # Check if live simulation requested
    if len(sys.argv) > 1 and sys.argv[1] == "--live":
        print("\n🔴 Starting live simulation...")
        print("Make sure the dashboard is running in another terminal!")
        await asyncio.sleep(3)
        await simulate_live_activity()


if __name__ == "__main__":
    asyncio.run(main())
