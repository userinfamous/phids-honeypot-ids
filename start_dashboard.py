#!/usr/bin/env python3
"""
Standalone Dashboard Launcher for PHIDS
This script starts only the web dashboard without the honeypots
"""
import asyncio
import logging
import signal
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from config import DASHBOARD_CONFIG, LOGGING_CONFIG
from src.core.logger import setup_logging
from src.core.database import DatabaseManager
from src.dashboard.web_server import DashboardWebServer


async def main():
    """Main dashboard launcher"""
    # Setup logging
    setup_logging(LOGGING_CONFIG["level"])
    logger = logging.getLogger(__name__)
    
    if not DASHBOARD_CONFIG["enabled"]:
        logger.error("Dashboard is disabled in configuration. Please enable it in config.py")
        return 1
    
    logger.info("Starting PHIDS Dashboard...")
    logger.info(f"Dashboard will be available at: http://{DASHBOARD_CONFIG['host']}:{DASHBOARD_CONFIG['port']}")
    
    # Initialize database
    db_manager = DatabaseManager()
    await db_manager.initialize()
    
    # Initialize dashboard
    dashboard = DashboardWebServer()
    await dashboard.initialize(db_manager)
    
    # Setup signal handlers for graceful shutdown
    def signal_handler(signum, frame):
        logger.info(f"Received signal {signum}, shutting down dashboard...")
        asyncio.create_task(dashboard.stop())
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # Start dashboard
        await dashboard.start()
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt")
    except Exception as e:
        logger.error(f"Dashboard error: {e}", exc_info=True)
        return 1
    finally:
        await dashboard.stop()
    
    return 0


if __name__ == "__main__":
    print("🚀 PHIDS Dashboard Launcher")
    print("=" * 50)
    print(f"Dashboard URL: http://{DASHBOARD_CONFIG['host']}:{DASHBOARD_CONFIG['port']}")
    print("Press Ctrl+C to stop")
    print("=" * 50)
    
    sys.exit(asyncio.run(main()))
