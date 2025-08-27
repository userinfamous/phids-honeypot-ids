#!/usr/bin/env python3
"""
Test script to verify the Controls button fix and honeypot services.
"""

import requests
import time
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import TimeoutException, WebDriverException

def test_honeypot_services():
    """Test if honeypot services are running"""
    print("\n🔍 Testing Honeypot Services...")
    
    # Test SSH honeypot (port 2222)
    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex(('127.0.0.1', 2222))
        sock.close()
        
        if result == 0:
            print("✅ SSH honeypot is listening on port 2222")
            ssh_working = True
        else:
            print("❌ SSH honeypot is not accessible on port 2222")
            ssh_working = False
    except Exception as e:
        print(f"❌ Error testing SSH honeypot: {e}")
        ssh_working = False
    
    # Test HTTP honeypot (port 8080)
    try:
        response = requests.get("http://127.0.0.1:8080", timeout=5)
        if response.status_code == 200:
            print("✅ HTTP honeypot is responding on port 8080")
            print(f"   Server header: {response.headers.get('Server', 'Not found')}")
            http_working = True
        else:
            print(f"❌ HTTP honeypot returned status code: {response.status_code}")
            http_working = False
    except Exception as e:
        print(f"❌ Error testing HTTP honeypot: {e}")
        http_working = False
    
    return ssh_working and http_working

def test_dashboard_accessibility():
    """Test if dashboard is accessible"""
    print("\n🔍 Testing Dashboard Accessibility...")
    try:
        response = requests.get("http://127.0.0.1:5000", timeout=10)
        if response.status_code == 200:
            print("✅ Dashboard accessible at http://127.0.0.1:5000")
            return True
        else:
            print(f"❌ Dashboard returned status code: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"❌ Dashboard not accessible: {e}")
        return False

def test_controls_button_html():
    """Test if Controls button HTML is properly structured"""
    print("\n🔍 Testing Controls Button HTML Structure...")
    try:
        response = requests.get("http://127.0.0.1:5000", timeout=10)
        html_content = response.text
        
        # Check for the new button structure
        button_indicators = [
            'onclick="showControlsModal()"',
            'id="controlsModal"',
            'function showControlsModal()',
            'Dashboard Controls',
            'btn btn-outline-light btn-sm ms-2'
        ]
        
        # Check that old dropdown elements are removed
        old_dropdown_indicators = [
            'id="controlsDropdown"',
            'data-bs-toggle="dropdown"',
            'dropdown-toggle',
            'dropdown-menu'
        ]
        
        found_button_indicators = []
        for indicator in button_indicators:
            if indicator in html_content:
                found_button_indicators.append(indicator)
        
        found_old_indicators = []
        for indicator in old_dropdown_indicators:
            if indicator in html_content:
                found_old_indicators.append(indicator)
        
        if len(found_button_indicators) >= 4 and len(found_old_indicators) == 0:
            print(f"✅ Controls button properly converted ({len(found_button_indicators)}/5 new indicators found)")
            print("✅ Old dropdown elements removed")
            return True
        else:
            print(f"❌ Controls button conversion incomplete:")
            print(f"   New indicators found: {len(found_button_indicators)}/5")
            print(f"   Old dropdown elements still present: {len(found_old_indicators)}")
            return False
            
    except Exception as e:
        print(f"❌ Error checking Controls button HTML: {e}")
        return False

def test_controls_button_with_selenium():
    """Test Controls button functionality using Selenium"""
    print("\n🔍 Testing Controls Button with Selenium...")
    
    # Setup Chrome options for headless mode
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--disable-gpu")
    
    driver = None
    try:
        driver = webdriver.Chrome(options=chrome_options)
        driver.get("http://127.0.0.1:5000")
        
        # Wait for page to load
        wait = WebDriverWait(driver, 10)
        
        # Find the Controls button (should be a button, not a dropdown)
        controls_button = wait.until(
            EC.element_to_be_clickable((By.XPATH, "//button[contains(text(), 'Controls')]"))
        )
        
        print("✅ Controls button found and clickable")
        
        # Click the Controls button
        controls_button.click()
        
        # Wait for modal to appear
        time.sleep(1)
        
        # Check if modal is visible
        modal = driver.find_element(By.ID, "controlsModal")
        
        if modal.is_displayed() or "show" in modal.get_attribute("class"):
            print("✅ Controls modal opened successfully")
            
            # Try to find modal content
            modal_title = driver.find_element(By.XPATH, "//h5[contains(text(), 'Dashboard Controls')]")
            if modal_title:
                print("✅ Modal contains correct title")
            
            # Check for control buttons in modal
            control_buttons = driver.find_elements(By.CSS_SELECTOR, "#controlsModal .btn")
            if len(control_buttons) >= 4:  # Should have toggle, clear, and export buttons
                print(f"✅ Found {len(control_buttons)} control buttons in modal")
                return True
            else:
                print(f"⚠️ Only found {len(control_buttons)} control buttons (expected 4+)")
                return False
        else:
            print("❌ Controls modal did not open")
            return False
            
    except TimeoutException:
        print("❌ Timeout waiting for Controls button")
        return False
    except WebDriverException as e:
        print(f"❌ WebDriver error: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False
    finally:
        if driver:
            driver.quit()

def main():
    """Main test function"""
    print("🚨 PHIDS Controls Button & Honeypot Services Test")
    print("=" * 60)
    print("🔧 Testing the converted Controls button and honeypot services")
    print("⚠️  Make sure PHIDS is running: python main.py --debug")
    print()
    
    # Wait for user confirmation
    input("Press Enter when PHIDS is running...")
    
    # Run tests
    tests = [
        ("Honeypot Services", test_honeypot_services),
        ("Dashboard Accessibility", test_dashboard_accessibility),
        ("Controls Button HTML", test_controls_button_html),
        ("Controls Button Functionality", test_controls_button_with_selenium)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        try:
            if test_func():
                passed += 1
        except Exception as e:
            print(f"❌ {test_name} failed with exception: {e}")
    
    print(f"\n📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed successfully!")
        print("\n✅ Fixes Validated:")
        print("   - SSH honeypot: Running and accessible on port 2222")
        print("   - HTTP honeypot: Running and accessible on port 8080")
        print("   - Controls button: Converted from dropdown to simple button")
        print("   - Controls modal: Working with all control options")
        print("\n💡 Manual Verification:")
        print("   1. Open http://127.0.0.1:5000 in your browser")
        print("   2. Click the 'Controls' button in the navigation")
        print("   3. Verify the modal opens with all control options")
        print("   4. Test SSH connection: ssh admin@127.0.0.1 -p 2222")
        print("   5. Test HTTP connection: curl http://127.0.0.1:8080")
    else:
        print("⚠️  Some tests failed. Check the issues above.")
        print("\n🔧 Troubleshooting:")
        print("   - Ensure PHIDS is running with: python main.py --debug")
        print("   - Check that ports 2222 and 8080 are not blocked")
        print("   - Verify dashboard is accessible at http://127.0.0.1:5000")

if __name__ == "__main__":
    main()
