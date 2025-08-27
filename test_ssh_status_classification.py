#!/usr/bin/env python3
"""
Test script to verify SSH honeypot connection status classification fixes
"""

import asyncio
import socket
import time
import subprocess
import sys
import os
from datetime import datetime

def test_ssh_protocol_failure():
    """Test SSH protocol-level failures that should be classified as FAILED"""
    print("\n🔍 Testing SSH Protocol Failures...")
    
    test_cases = [
        {
            "name": "Real SSH client connection (should FAIL due to protocol mismatch)",
            "command": ["ssh", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=no", 
                       "admin@127.0.0.1", "-p", "2222"],
            "expected_status": "FAILED",
            "description": "Real SSH client should fail due to protocol negotiation issues"
        },
        {
            "name": "SSH client with verbose output",
            "command": ["ssh", "-v", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=no",
                       "test@127.0.0.1", "-p", "2222"],
            "expected_status": "FAILED", 
            "description": "Verbose SSH client to see detailed failure reasons"
        }
    ]
    
    results = []
    
    for test_case in test_cases:
        print(f"\n  📋 {test_case['name']}")
        print(f"     Expected: {test_case['expected_status']}")
        
        try:
            # Run SSH command and capture output
            start_time = time.time()
            result = subprocess.run(
                test_case['command'],
                capture_output=True,
                text=True,
                timeout=30,
                input="\n"  # Send newline to handle any prompts
            )
            duration = time.time() - start_time
            
            print(f"     Duration: {duration:.1f}s")
            print(f"     Return code: {result.returncode}")
            
            if result.stderr:
                print(f"     SSH Error: {result.stderr.strip()[:200]}...")
            
            # SSH should fail (non-zero return code)
            if result.returncode != 0:
                print(f"     ✅ SSH client failed as expected")
                results.append({
                    'test': test_case['name'],
                    'ssh_failed': True,
                    'expected': test_case['expected_status'],
                    'duration': duration
                })
            else:
                print(f"     ❌ SSH client succeeded unexpectedly")
                results.append({
                    'test': test_case['name'],
                    'ssh_failed': False,
                    'expected': test_case['expected_status'],
                    'duration': duration
                })
                
        except subprocess.TimeoutExpired:
            print(f"     ⚠️ SSH command timed out")
            results.append({
                'test': test_case['name'],
                'ssh_failed': True,
                'expected': test_case['expected_status'],
                'duration': 30.0
            })
        except FileNotFoundError:
            print(f"     ❌ SSH client not found - install openssh-client")
            continue
        except Exception as e:
            print(f"     ❌ Test error: {e}")
            continue
        
        # Wait between tests
        time.sleep(2)
    
    return results

def test_raw_socket_connections():
    """Test raw socket connections with various scenarios"""
    print("\n🔍 Testing Raw Socket Connections...")
    
    test_cases = [
        {
            "name": "Connect and disconnect immediately",
            "action": "connect_disconnect",
            "expected_status": "ERROR",
            "description": "Should be ERROR due to no meaningful interaction"
        },
        {
            "name": "Send invalid banner",
            "action": "invalid_banner", 
            "expected_status": "FAILED",
            "description": "Should be FAILED due to invalid SSH banner"
        },
        {
            "name": "Send valid banner then disconnect",
            "action": "valid_banner_disconnect",
            "expected_status": "FAILED", 
            "description": "Should be FAILED due to protocol negotiation failure"
        },
        {
            "name": "Connection timeout",
            "action": "timeout",
            "expected_status": "TIMEOUT",
            "description": "Should be TIMEOUT due to no response"
        }
    ]
    
    results = []
    
    for test_case in test_cases:
        print(f"\n  📋 {test_case['name']}")
        print(f"     Expected: {test_case['expected_status']}")
        
        try:
            start_time = time.time()
            
            if test_case['action'] == 'connect_disconnect':
                # Connect and immediately disconnect
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect(("127.0.0.1", 2222))
                sock.close()
                
            elif test_case['action'] == 'invalid_banner':
                # Send invalid banner
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect(("127.0.0.1", 2222))
                sock.send(b"INVALID-BANNER\r\n")
                time.sleep(2)
                sock.close()
                
            elif test_case['action'] == 'valid_banner_disconnect':
                # Send valid banner then disconnect
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect(("127.0.0.1", 2222))
                sock.send(b"SSH-2.0-TestClient\r\n")
                # Read server banner
                banner = sock.recv(1024)
                print(f"     Server banner: {banner.decode('utf-8', errors='ignore').strip()}")
                # Disconnect without key exchange
                sock.close()
                
            elif test_case['action'] == 'timeout':
                # Connect but don't send anything
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(15)
                sock.connect(("127.0.0.1", 2222))
                time.sleep(12)  # Wait for honeypot timeout
                sock.close()
            
            duration = time.time() - start_time
            print(f"     Duration: {duration:.1f}s")
            print(f"     ✅ Test completed")
            
            results.append({
                'test': test_case['name'],
                'completed': True,
                'expected': test_case['expected_status'],
                'duration': duration
            })
            
        except Exception as e:
            duration = time.time() - start_time
            print(f"     Duration: {duration:.1f}s")
            print(f"     ⚠️ Test error: {e}")
            results.append({
                'test': test_case['name'],
                'completed': False,
                'expected': test_case['expected_status'],
                'duration': duration,
                'error': str(e)
            })
        
        # Wait between tests
        time.sleep(3)
    
    return results

def check_honeypot_logs():
    """Check honeypot logs for proper status classification"""
    print("\n🔍 Checking Honeypot Logs...")
    
    try:
        log_file = "logs/honeypot.log"
        if not os.path.exists(log_file):
            print("     ❌ Log file not found")
            return False
        
        # Read recent log entries
        with open(log_file, 'r') as f:
            lines = f.readlines()
        
        # Look for recent SSH connection entries (last 50 lines)
        recent_lines = lines[-50:] if len(lines) > 50 else lines
        
        status_counts = {
            'SUCCESS': 0,
            'FAILED': 0,
            'ERROR': 0,
            'TIMEOUT': 0
        }
        
        ssh_connections = []
        
        for line in recent_lines:
            if "SSH: Connection from" in line:
                ssh_connections.append(line.strip())
                for status in status_counts.keys():
                    if f" - {status} - " in line:
                        status_counts[status] += 1
                        break
        
        print(f"     📊 Recent SSH connections found: {len(ssh_connections)}")
        print(f"     📊 Status distribution:")
        for status, count in status_counts.items():
            print(f"        {status}: {count}")
        
        # Show recent SSH connection logs
        if ssh_connections:
            print(f"     📋 Recent SSH connection logs:")
            for conn in ssh_connections[-5:]:  # Show last 5
                print(f"        {conn}")
        
        # Check if we have the expected distribution (more FAILED/ERROR than SUCCESS)
        total_connections = sum(status_counts.values())
        if total_connections > 0:
            failed_ratio = (status_counts['FAILED'] + status_counts['ERROR']) / total_connections
            print(f"     📊 Failed/Error ratio: {failed_ratio:.2f}")
            
            if failed_ratio > 0.5:
                print(f"     ✅ Good - Most connections are properly classified as FAILED/ERROR")
                return True
            else:
                print(f"     ⚠️ Warning - Too many connections classified as SUCCESS")
                return False
        else:
            print(f"     ⚠️ No SSH connections found in recent logs")
            return False
            
    except Exception as e:
        print(f"     ❌ Error checking logs: {e}")
        return False

def main():
    """Main test function"""
    print("🔧 SSH Connection Status Classification Test")
    print("=" * 60)
    print("Testing fixes for SSH honeypot connection status classification")
    print("⚠️  Make sure PHIDS is running: python main.py --debug")
    print()
    
    # Check if SSH honeypot is running
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex(("127.0.0.1", 2222))
        sock.close()
        
        if result != 0:
            print("❌ SSH honeypot is not running on port 2222")
            print("   Start PHIDS with: python main.py --debug")
            return
        else:
            print("✅ SSH honeypot is running on port 2222")
    except Exception as e:
        print(f"❌ Error checking SSH honeypot: {e}")
        return
    
    print("\n" + "="*60)
    
    # Run tests
    ssh_results = test_ssh_protocol_failure()
    socket_results = test_raw_socket_connections()
    
    # Wait for logs to be written
    print("\n⏳ Waiting for logs to be written...")
    time.sleep(5)
    
    log_check = check_honeypot_logs()
    
    # Summary
    print("\n" + "="*60)
    print("📊 Test Summary")
    print("="*60)
    
    print(f"SSH Protocol Tests: {len(ssh_results)} completed")
    for result in ssh_results:
        status = "✅" if result['ssh_failed'] else "❌"
        print(f"  {status} {result['test']} (Expected: {result['expected']})")
    
    print(f"\nSocket Tests: {len(socket_results)} completed")
    for result in socket_results:
        status = "✅" if result['completed'] else "❌"
        print(f"  {status} {result['test']} (Expected: {result['expected']})")
    
    print(f"\nLog Analysis: {'✅ PASSED' if log_check else '❌ FAILED'}")
    
    print("\n💡 Expected Behavior:")
    print("  - Real SSH clients should FAIL due to protocol mismatch")
    print("  - Invalid banners should result in FAILED status")
    print("  - Immediate disconnects should result in ERROR status")
    print("  - Timeouts should result in TIMEOUT status")
    print("  - Only successful auth + shell interaction should be SUCCESS")
    
    print("\n🔍 Check the dashboard at http://127.0.0.1:5000 to see color-coded results!")

def demonstrate_fixed_classification():
    """Demonstrate the fixed SSH connection status classification"""
    print("\n🎯 SSH Status Classification Demonstration")
    print("=" * 50)
    print("Generating various SSH connection types to show proper classification...")

    # Test the specific case mentioned in the issue
    print("\n📡 Testing the reported issue case...")
    print("   Command: ssh admin@127.0.0.1 -p 2222")
    print("   Expected: FAILED (not SUCCESS)")

    try:
        result = subprocess.run(
            ["ssh", "-o", "ConnectTimeout=5", "-o", "StrictHostKeyChecking=no",
             "admin@127.0.0.1", "-p", "2222"],
            capture_output=True,
            text=True,
            timeout=15,
            input="\n"
        )

        print(f"   SSH client return code: {result.returncode}")
        if result.stderr:
            error_lines = result.stderr.strip().split('\n')
            for line in error_lines[:3]:  # Show first 3 error lines
                print(f"   SSH error: {line}")

        if result.returncode != 0:
            print("   ✅ SSH client failed as expected")
        else:
            print("   ❌ SSH client succeeded unexpectedly")

    except subprocess.TimeoutExpired:
        print("   ⚠️ SSH command timed out")
    except FileNotFoundError:
        print("   ❌ SSH client not found")
    except Exception as e:
        print(f"   ❌ Error: {e}")

    print("\n✅ Check the honeypot logs and dashboard to see this is now classified as FAILED!")
    print("   Before fix: This would have been classified as SUCCESS")
    print("   After fix: This should be classified as FAILED")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--demo":
        demonstrate_fixed_classification()
    else:
        main()
