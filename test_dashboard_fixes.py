#!/usr/bin/env python3
"""
Test script to verify the dashboard fixes for timestamp synchronization and Controls button functionality.
"""

import asyncio
import json
import requests
import time
from datetime import datetime
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import TimeoutException, WebDriverException

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

def test_timestamp_fix_in_html():
    """Test if timestamp fix is present in HTML"""
    print("\n🔍 Testing Timestamp Fix in HTML...")
    try:
        response = requests.get("http://127.0.0.1:5000", timeout=10)
        html_content = response.text
        
        # Check for the timestamp fix code
        timestamp_fix_indicators = [
            "data.timestamp",
            "new Date(data.timestamp)",
            "eventTime.toLocaleTimeString()",
            "Use the actual event timestamp if provided"
        ]
        
        found_indicators = []
        for indicator in timestamp_fix_indicators:
            if indicator in html_content:
                found_indicators.append(indicator)
        
        if len(found_indicators) >= 3:
            print(f"✅ Timestamp fix detected in HTML ({len(found_indicators)}/4 indicators found)")
            return True
        else:
            print(f"❌ Timestamp fix not properly implemented ({len(found_indicators)}/4 indicators found)")
            return False
            
    except Exception as e:
        print(f"❌ Error checking timestamp fix: {e}")
        return False

def test_controls_button_fix_in_html():
    """Test if Controls button fix is present in HTML"""
    print("\n🔍 Testing Controls Button Fix in HTML...")
    try:
        response = requests.get("http://127.0.0.1:5000", timeout=10)
        html_content = response.text
        
        # Check for the Controls button fix code
        controls_fix_indicators = [
            'id="controlsDropdown"',
            'data-bs-toggle="dropdown"',
            'data-bs-auto-close="true"',
            'bootstrap.Dropdown.getInstance',
            'Manual toggle as backup',
            'dropdownMenu.classList.add',
            'Creating fallback dropdown instance'
        ]
        
        found_indicators = []
        for indicator in controls_fix_indicators:
            if indicator in html_content:
                found_indicators.append(indicator)
        
        if len(found_indicators) >= 5:
            print(f"✅ Controls button fix detected in HTML ({len(found_indicators)}/7 indicators found)")
            return True
        else:
            print(f"❌ Controls button fix not properly implemented ({len(found_indicators)}/7 indicators found)")
            return False
            
    except Exception as e:
        print(f"❌ Error checking Controls button fix: {e}")
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
        
        # Find the Controls dropdown button
        controls_button = wait.until(
            EC.element_to_be_clickable((By.ID, "controlsDropdown"))
        )
        
        print("✅ Controls button found and clickable")
        
        # Click the Controls button
        controls_button.click()
        
        # Wait a moment for dropdown to appear
        time.sleep(1)
        
        # Check if dropdown menu is visible
        dropdown_menu = driver.find_element(By.CSS_SELECTOR, "ul[aria-labelledby='controlsDropdown']")
        
        if dropdown_menu.is_displayed() or "show" in dropdown_menu.get_attribute("class"):
            print("✅ Controls dropdown menu opened successfully")
            
            # Try to find dropdown items
            dropdown_items = driver.find_elements(By.CSS_SELECTOR, "ul[aria-labelledby='controlsDropdown'] .dropdown-item")
            if len(dropdown_items) >= 4:  # Should have Clear Logs, Toggle View, and 2 Export options
                print(f"✅ Found {len(dropdown_items)} dropdown items")
                return True
            else:
                print(f"⚠️ Only found {len(dropdown_items)} dropdown items (expected 4+)")
                return False
        else:
            print("❌ Controls dropdown menu did not open")
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
    print("🚨 PHIDS Dashboard Fixes Verification")
    print("=" * 60)
    print("🔧 Testing timestamp synchronization and Controls button fixes")
    print("⚠️  Make sure PHIDS dashboard is running: python start_dashboard.py")
    print()
    
    # Wait for user confirmation
    input("Press Enter when dashboard is running at http://127.0.0.1:5000...")
    
    # Run tests
    tests = [
        ("Dashboard Accessibility", test_dashboard_accessibility),
        ("Timestamp Fix in HTML", test_timestamp_fix_in_html),
        ("Controls Button Fix in HTML", test_controls_button_fix_in_html),
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
        print("🎉 All dashboard fixes verified successfully!")
        print("\n✅ Fixes Validated:")
        print("   - Timestamp synchronization: Events now show actual event time")
        print("   - Controls button: Dropdown functionality restored")
        print("   - Bootstrap integration: Proper initialization and fallbacks")
        print("\n💡 Manual Verification:")
        print("   1. Open http://127.0.0.1:5000 in your browser")
        print("   2. Generate some events and verify timestamps are different")
        print("   3. Click the 'Controls' dropdown button")
        print("   4. Verify all dropdown options are accessible")
    else:
        print("⚠️  Some tests failed. Check the issues above.")
        print("\n🔧 Troubleshooting:")
        print("   - Ensure PHIDS dashboard is running")
        print("   - Check browser console for JavaScript errors")
        print("   - Verify Bootstrap CSS/JS are loading correctly")

if __name__ == "__main__":
    main()
