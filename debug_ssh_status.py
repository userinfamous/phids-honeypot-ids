#!/usr/bin/env python3
"""
Debug script to test SSH status classification in real-time
"""

import asyncio
import socket
import time
import subprocess
import sys

def test_ssh_connection():
    """Test a single SSH connection and monitor the result"""
    print("🔍 Testing SSH Connection Status Classification")
    print("=" * 50)
    
    # Test the specific problematic case
    print("Testing: ssh admin@127.0.0.1 -p 2222")
    print("Expected: Should be classified as FAILED, not SUCCESS")
    print()
    
    try:
        start_time = time.time()
        
        # Run the SSH command that was causing issues
        result = subprocess.run(
            ["ssh", "-o", "ConnectTimeout=5", "-o", "StrictHostKeyChecking=no", 
             "admin@127.0.0.1", "-p", "2222"],
            capture_output=True,
            text=True,
            timeout=10,
            input="\n"  # Send newline to handle any prompts
        )
        
        duration = time.time() - start_time
        
        print(f"SSH client result:")
        print(f"  Return code: {result.returncode}")
        print(f"  Duration: {duration:.1f}s")
        
        if result.stderr:
            print(f"  Error output:")
            for line in result.stderr.strip().split('\n')[:5]:
                print(f"    {line}")
        
        if result.returncode != 0:
            print(f"  ✅ SSH client failed as expected")
        else:
            print(f"  ❌ SSH client succeeded unexpectedly")
        
        print()
        print("Now check:")
        print("1. The honeypot logs for the enhanced log message")
        print("2. The dashboard at http://127.0.0.1:5000 for the connection status")
        print("3. Look for FAILED status instead of SUCCESS")
        
        return result.returncode != 0
        
    except subprocess.TimeoutExpired:
        print("  ⚠️ SSH command timed out")
        return True
    except FileNotFoundError:
        print("  ❌ SSH client not found - install openssh-client")
        return False
    except Exception as e:
        print(f"  ❌ Error: {e}")
        return False

def test_raw_socket():
    """Test a raw socket connection"""
    print("\n🔍 Testing Raw Socket Connection")
    print("=" * 30)
    
    try:
        print("Connecting to SSH honeypot and disconnecting immediately...")
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        start_time = time.time()
        
        sock.connect(("127.0.0.1", 2222))
        print("  ✅ Connected")
        
        # Disconnect immediately without sending anything
        sock.close()
        duration = time.time() - start_time
        
        print(f"  Duration: {duration:.1f}s")
        print("  Expected status: ERROR (no meaningful interaction)")
        
        return True
        
    except Exception as e:
        print(f"  ❌ Error: {e}")
        return False

def main():
    """Main test function"""
    print("🚨 SSH Status Classification Debug Test")
    print("⚠️  Make sure PHIDS is running with debug logging: python main.py --debug")
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
    
    print()
    
    # Run tests
    ssh_test = test_ssh_connection()
    socket_test = test_raw_socket()
    
    print("\n" + "=" * 50)
    print("📊 Test Summary")
    print("=" * 50)
    
    if ssh_test:
        print("✅ SSH client test: PASSED (client failed as expected)")
    else:
        print("❌ SSH client test: FAILED")
    
    if socket_test:
        print("✅ Raw socket test: PASSED")
    else:
        print("❌ Raw socket test: FAILED")
    
    print("\n💡 What to check next:")
    print("1. Look at the honeypot logs (logs/honeypot.log)")
    print("2. Check the dashboard at http://127.0.0.1:5000")
    print("3. Look for enhanced log messages with proper status classification")
    print("4. Verify that connections show as FAILED/ERROR, not SUCCESS")
    
    print("\n🔍 If still showing SUCCESS:")
    print("- Check if debug logs show the classification logic")
    print("- Verify the connection_status field is being set correctly")
    print("- Check if the dashboard is reading the right field")

if __name__ == "__main__":
    main()
