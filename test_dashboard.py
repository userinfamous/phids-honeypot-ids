#!/usr/bin/env python3
"""
Test script for PHIDS Dashboard
"""
import sys
import asyncio
from pathlib import Path
import pytest

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from src.dashboard.web_server import DashboardWebServer
from src.core.database import DatabaseManager
from config import DASHBOARD_CONFIG


@pytest.mark.asyncio
async def test_dashboard_initialization():
    """Test that the dashboard can initialize properly"""
    print("Testing dashboard initialization...")
    
    try:
        # Initialize database
        db_manager = DatabaseManager()
        await db_manager.initialize()
        
        # Initialize dashboard
        dashboard = DashboardWebServer()
        await dashboard.initialize(db_manager)
        
        print("✓ Dashboard initialized successfully")
        
        # Test API endpoints (without starting server)
        stats = await dashboard._get_cached_stats()
        print(f"✓ Stats API working: {len(stats)} fields")
        
        # Clean shutdown
        await dashboard.stop()
        print("✓ Dashboard stopped successfully")
        
    except Exception as e:
        print(f"✗ Dashboard test failed: {e}")
        pytest.fail(f"Dashboard test failed: {e}")


def test_dashboard_config():
    """Test dashboard configuration"""
    print("Testing dashboard configuration...")
    
    assert "enabled" in DASHBOARD_CONFIG
    assert "host" in DASHBOARD_CONFIG
    assert "port" in DASHBOARD_CONFIG
    assert "debug" in DASHBOARD_CONFIG
    
    print("✓ Dashboard configuration is valid")


if __name__ == "__main__":
    # Run tests directly
    asyncio.run(test_dashboard_initialization())
    test_dashboard_config()
    print("\n🎉 All dashboard tests passed!")
