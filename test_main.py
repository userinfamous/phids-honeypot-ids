#!/usr/bin/env python3
"""
Test script to verify main application functionality
"""
import sys
import asyncio
from pathlib import Path
import pytest

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from main import PHIDSManager
from src.core.logger import setup_logging

@pytest.mark.asyncio
async def test_main_initialization():
    """Test that the main PHIDS manager can initialize"""
    print("Testing PHIDS Manager initialization...")
    
    # Setup logging
    setup_logging("INFO")
    
    try:
        # Create and initialize PHIDS manager
        phids = PHIDSManager()
        await phids.initialize()
        
        print("✓ PHIDS Manager initialized successfully")
        print("✓ All components loaded without errors")
        
        # Clean shutdown
        await phids.stop()
        print("✓ PHIDS Manager stopped successfully")
        

    except Exception as e:
        print(f"✗ PHIDS Manager initialization failed: {e}")
        pytest.fail(f"PHIDS Manager initialization failed: {e}")

if __name__ == "__main__":
    success = asyncio.run(test_main_initialization())
    if success:
        print("\n🎉 Main application test passed! PHIDS is ready to run.")
        sys.exit(0)
    else:
        print("\n⚠️ Main application test failed.")
        sys.exit(1)
