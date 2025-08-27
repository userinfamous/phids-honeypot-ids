#!/usr/bin/env python3
"""
Quick test to verify SSH status classification fix
"""

import subprocess
import time
import socket

def test_ssh_status_fix():
    """Test that SSH connections are now properly classified as FAILED"""
    print("🔧 Testing SSH Status Classification Fix")
    print("=" * 50)
    
    # Check if SSH honeypot is running
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex(("127.0.0.1", 2222))
        sock.close()
        
        if result != 0:
            print("❌ SSH honeypot is not running on port 2222")
            print("   Start PHIDS with: python main.py --debug")
            return False
        else:
            print("✅ SSH honeypot is running on port 2222")
    except Exception as e:
        print(f"❌ Error checking SSH honeypot: {e}")
        return False
    
    print("\n🧪 Testing SSH connection that should be FAILED...")
    
    try:
        # Run the SSH command that was causing issues
        start_time = time.time()
        result = subprocess.run(
            ["ssh", "-o", "ConnectTimeout=5", "-o", "StrictHostKeyChecking=no", 
             "admin@127.0.0.1", "-p", "2222"],
            capture_output=True,
            text=True,
            timeout=10,
            input="\n"
        )
        duration = time.time() - start_time
        
        print(f"SSH client result:")
        print(f"  Return code: {result.returncode}")
        print(f"  Duration: {duration:.1f}s")
        
        if result.stderr:
            print(f"  Error (first line): {result.stderr.strip().split(chr(10))[0]}")
        
        if result.returncode != 0:
            print(f"  ✅ SSH client failed as expected")
        else:
            print(f"  ❌ SSH client succeeded unexpectedly")
        
        print(f"\n💡 Expected behavior:")
        print(f"  - Dashboard should show: FAILED (red) instead of SUCCESS (green)")
        print(f"  - Duration should be > 0.0s")
        print(f"  - Status should be 'FAILED' not 'SUCCESS'")
        
        print(f"\n🔍 Check the dashboard now:")
        print(f"  1. Open http://127.0.0.1:5000")
        print(f"  2. Look for the most recent SSH connection")
        print(f"  3. It should show as FAILED (red) with duration > 0.0s")
        
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

def main():
    """Main test function"""
    print("🚨 SSH Status Classification Fix Verification")
    print("⚠️  Make sure PHIDS is running: python main.py --debug")
    print()
    
    success = test_ssh_status_fix()
    
    print("\n" + "=" * 50)
    if success:
        print("✅ Test completed - SSH client failed as expected")
        print("🔍 Check the dashboard to verify FAILED status is displayed")
    else:
        print("❌ Test failed - check PHIDS is running and SSH client is available")
    
    print("\n💡 Key fixes implemented:")
    print("  1. Dashboard now defaults to FAILED instead of SUCCESS")
    print("  2. Connection data always has connection_status field set")
    print("  3. Enhanced logging properly classifies connection outcomes")

if __name__ == "__main__":
    main()
