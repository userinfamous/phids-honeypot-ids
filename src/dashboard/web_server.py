"""
FastAPI Web Dashboard for PHIDS
Real-time honeypot monitoring and analytics
"""
import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
import uvicorn

from config import DASHBOARD_CONFIG, BASE_DIR
from src.core.database import DatabaseManager


class DashboardWebServer:
    """FastAPI-based web dashboard for PHIDS"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.app = FastAPI(title="PHIDS Dashboard", version="1.0.0")
        self.db_manager = None
        self.active_connections: List[WebSocket] = []
        self.stats_cache = {}
        self.cache_timestamp = None
        
        # Setup templates and static files
        self.templates_dir = BASE_DIR / "src" / "dashboard" / "templates"
        self.static_dir = BASE_DIR / "src" / "dashboard" / "static"
        
        # Create directories if they don't exist
        self.templates_dir.mkdir(parents=True, exist_ok=True)
        self.static_dir.mkdir(parents=True, exist_ok=True)
        
        self.templates = Jinja2Templates(directory=str(self.templates_dir))
        
        # Setup routes
        self._setup_routes()
        
    def _setup_routes(self):
        """Setup FastAPI routes"""
        
        @self.app.get("/", response_class=HTMLResponse)
        async def dashboard_home(request: Request):
            """Main dashboard page"""
            return self.templates.TemplateResponse("dashboard.html", {"request": request})
        
        @self.app.get("/api/stats")
        async def get_stats():
            """Get current system statistics"""
            return await self._get_cached_stats()
        
        @self.app.get("/api/recent-connections")
        async def get_recent_connections():
            """Get recent honeypot connections"""
            if not self.db_manager:
                return {"connections": []}
            
            try:
                # Get connections from last 24 hours
                since = datetime.now() - timedelta(hours=24)
                connections = await self.db_manager.get_recent_connections(since, limit=100)
                return {"connections": connections}
            except Exception as e:
                self.logger.error(f"Error fetching recent connections: {e}")
                return {"connections": []}
        
        @self.app.get("/api/alerts")
        async def get_recent_alerts():
            """Get recent IDS alerts"""
            if not self.db_manager:
                return {"alerts": []}
            
            try:
                # Get alerts from last 24 hours
                since = datetime.now() - timedelta(hours=24)
                alerts = await self.db_manager.get_recent_alerts(since, limit=50)
                return {"alerts": alerts}
            except Exception as e:
                self.logger.error(f"Error fetching recent alerts: {e}")
                return {"alerts": []}
        
        @self.app.websocket("/ws")
        async def websocket_endpoint(websocket: WebSocket):
            """WebSocket endpoint for real-time updates"""
            await self._handle_websocket(websocket)
        
        # Mount static files
        self.app.mount("/static", StaticFiles(directory=str(self.static_dir)), name="static")
    
    async def _handle_websocket(self, websocket: WebSocket):
        """Handle WebSocket connections for real-time updates"""
        await websocket.accept()
        self.active_connections.append(websocket)
        self.logger.info(f"WebSocket connected. Active connections: {len(self.active_connections)}")
        
        try:
            while True:
                # Send periodic updates
                await asyncio.sleep(5)  # Update every 5 seconds
                stats = await self._get_cached_stats()
                await websocket.send_json({
                    "type": "stats_update",
                    "data": stats,
                    "timestamp": datetime.now().isoformat()
                })
        except WebSocketDisconnect:
            self.active_connections.remove(websocket)
            self.logger.info(f"WebSocket disconnected. Active connections: {len(self.active_connections)}")
        except Exception as e:
            self.logger.error(f"WebSocket error: {e}")
            if websocket in self.active_connections:
                self.active_connections.remove(websocket)
    
    async def _get_cached_stats(self) -> Dict:
        """Get cached statistics with refresh logic"""
        now = datetime.now()
        
        # Refresh cache every 30 seconds
        if (self.cache_timestamp is None or 
            (now - self.cache_timestamp).total_seconds() > 30):
            
            self.stats_cache = await self._fetch_fresh_stats()
            self.cache_timestamp = now
        
        return self.stats_cache
    
    async def _fetch_fresh_stats(self) -> Dict:
        """Fetch fresh statistics from database"""
        if not self.db_manager:
            return self._get_default_stats()
        
        try:
            # Get statistics for last 24 hours
            since = datetime.now() - timedelta(hours=24)
            
            stats = {
                "total_connections": await self.db_manager.count_connections(since),
                "total_alerts": await self.db_manager.count_alerts(since),
                "unique_ips": await self.db_manager.count_unique_ips(since),
                "top_attackers": await self.db_manager.get_top_attackers(since, limit=5),
                "service_breakdown": await self.db_manager.get_service_breakdown(since),
                "hourly_activity": await self.db_manager.get_hourly_activity(since),
                "alert_severity": await self.db_manager.get_alert_severity_breakdown(since),
                "last_updated": datetime.now().isoformat()
            }
            
            return stats
            
        except Exception as e:
            self.logger.error(f"Error fetching stats: {e}")
            return self._get_default_stats()
    
    def _get_default_stats(self) -> Dict:
        """Return default stats when database is unavailable"""
        return {
            "total_connections": 0,
            "total_alerts": 0,
            "unique_ips": 0,
            "top_attackers": [],
            "service_breakdown": {"ssh": 0, "http": 0},
            "hourly_activity": [],
            "alert_severity": {"high": 0, "medium": 0, "low": 0},
            "last_updated": datetime.now().isoformat()
        }
    
    async def broadcast_event(self, event_type: str, data: Dict):
        """Broadcast real-time events to all connected WebSocket clients"""
        if not self.active_connections:
            return
        
        message = {
            "type": event_type,
            "data": data,
            "timestamp": datetime.now().isoformat()
        }
        
        # Send to all connected clients
        disconnected = []
        for websocket in self.active_connections:
            try:
                await websocket.send_json(message)
            except Exception as e:
                self.logger.warning(f"Failed to send WebSocket message: {e}")
                disconnected.append(websocket)
        
        # Remove disconnected clients
        for ws in disconnected:
            if ws in self.active_connections:
                self.active_connections.remove(ws)
    
    async def initialize(self, db_manager: DatabaseManager):
        """Initialize the web server with database manager"""
        self.db_manager = db_manager
        self.logger.info("Dashboard web server initialized")
    
    async def start(self):
        """Start the web server"""
        if not DASHBOARD_CONFIG["enabled"]:
            self.logger.info("Dashboard is disabled in configuration")
            return
        
        host = DASHBOARD_CONFIG["host"]
        port = DASHBOARD_CONFIG["port"]
        debug = DASHBOARD_CONFIG["debug"]
        
        self.logger.info(f"Starting dashboard web server on {host}:{port}")
        
        # Create server config
        config = uvicorn.Config(
            app=self.app,
            host=host,
            port=port,
            log_level="info" if debug else "warning",
            access_log=debug
        )
        
        # Start server
        server = uvicorn.Server(config)
        await server.serve()
    
    async def stop(self):
        """Stop the web server"""
        self.logger.info("Stopping dashboard web server")
        
        # Close all WebSocket connections
        for websocket in self.active_connections:
            try:
                await websocket.close()
            except Exception:
                pass
        
        self.active_connections.clear()
