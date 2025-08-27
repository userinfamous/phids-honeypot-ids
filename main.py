#!/usr/bin/env python3
"""
Python Honeypot IDS (PHIDS) - Main Entry Point
"""
import argparse
import asyncio
import logging
import signal
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from config import LOGGING_CONFIG, LOGS_DIR
from src.core.logger import setup_logging
from src.core.database import DatabaseManager
from src.honeypots.ssh_honeypot import SSHHoneypot
from src.honeypots.http_honeypot import HTTPHoneypot
from src.ids.engine import IDSEngine
from src.analysis.log_analyzer import LogAnalyzer
from src.reporting.report_generator import ReportGenerator
from src.dashboard.web_server import DashboardWebServer
from src.dashboard.event_broadcaster import event_broadcaster


class PHIDSManager:
    """Main PHIDS application manager"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.running = False
        self.honeypots = []
        self.ids_engine = None
        self.log_analyzer = None
        self.report_generator = None
        self.dashboard = None
        
    async def initialize(self):
        """Initialize all components"""
        self.logger.info("Initializing PHIDS...")
        
        # Initialize database
        db_manager = DatabaseManager()
        await db_manager.initialize()
        
        # Initialize IDS engine
        self.ids_engine = IDSEngine()
        await self.ids_engine.initialize()
        
        # Initialize log analyzer
        self.log_analyzer = LogAnalyzer()
        
        # Initialize report generator
        self.report_generator = ReportGenerator()

        # Initialize dashboard
        self.dashboard = DashboardWebServer()
        await self.dashboard.initialize(db_manager)

        # Register dashboard with event broadcaster
        event_broadcaster.set_dashboard_server(self.dashboard)

        # Initialize honeypots
        ssh_honeypot = SSHHoneypot()
        http_honeypot = HTTPHoneypot()

        self.honeypots = [ssh_honeypot, http_honeypot]

        self.logger.info("PHIDS initialization complete")
    
    async def start(self):
        """Start all services"""
        self.logger.info("Starting PHIDS services...")
        self.running = True
        
        # Start honeypots
        honeypot_tasks = []
        for honeypot in self.honeypots:
            if honeypot.is_enabled():
                task = asyncio.create_task(honeypot.start())
                honeypot_tasks.append(task)
                self.logger.info(f"Started {honeypot.__class__.__name__}")
        
        # Start IDS engine
        ids_task = asyncio.create_task(self.ids_engine.start())
        
        # Start log analyzer (periodic task)
        analyzer_task = asyncio.create_task(self.log_analyzer.start())
        
        # Start report generator (periodic task)
        reporter_task = asyncio.create_task(self.report_generator.start())

        # Start dashboard (if enabled)
        dashboard_task = None
        if self.dashboard:
            dashboard_task = asyncio.create_task(self.dashboard.start())

        self.logger.info("All PHIDS services started successfully")

        # Wait for all tasks
        all_tasks = honeypot_tasks + [ids_task, analyzer_task, reporter_task]
        if dashboard_task:
            all_tasks.append(dashboard_task)
        try:
            await asyncio.gather(*all_tasks)
        except asyncio.CancelledError:
            self.logger.info("PHIDS services cancelled")
    
    async def stop(self):
        """Stop all services gracefully"""
        self.logger.info("Stopping PHIDS services...")
        self.running = False
        
        # Stop honeypots
        for honeypot in self.honeypots:
            await honeypot.stop()
        
        # Stop other services
        if self.ids_engine:
            await self.ids_engine.stop()
        if self.log_analyzer:
            await self.log_analyzer.stop()
        if self.report_generator:
            await self.report_generator.stop()
        if self.dashboard:
            await self.dashboard.stop()

        self.logger.info("PHIDS stopped successfully")


async def main():
    """Main application entry point"""
    parser = argparse.ArgumentParser(description="Python Honeypot IDS (PHIDS)")
    parser.add_argument("--config", help="Configuration file path")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--daemon", action="store_true", help="Run as daemon")
    
    args = parser.parse_args()
    
    # Setup logging
    log_level = "DEBUG" if args.debug else LOGGING_CONFIG["level"]
    setup_logging(log_level)
    
    logger = logging.getLogger(__name__)
    logger.info("Starting Python Honeypot IDS (PHIDS)")
    
    # Create and initialize PHIDS manager
    phids = PHIDSManager()
    
    # Setup signal handlers for graceful shutdown
    def signal_handler(signum, frame):
        logger.info(f"Received signal {signum}, shutting down...")
        asyncio.create_task(phids.stop())
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        await phids.initialize()
        await phids.start()
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt")
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        return 1
    finally:
        await phids.stop()
    
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
