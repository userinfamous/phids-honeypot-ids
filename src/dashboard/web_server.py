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

        # Enhanced Log Management Endpoints
        @self.app.post("/api/clear-logs")
        async def clear_logs(request: Request):
            """Clear logs with confirmation"""
            if not self.db_manager:
                return {"success": False, "message": "Database not available"}

            try:
                body = await request.json()
                clear_type = body.get('type', 'all')  # 'all', 'connections', 'alerts'

                if clear_type == 'all':
                    success = await self.db_manager.clear_all_logs()
                elif clear_type == 'connections':
                    success = await self.db_manager.clear_connections_only()
                elif clear_type == 'alerts':
                    success = await self.db_manager.clear_alerts_only()
                else:
                    return {"success": False, "message": "Invalid clear type"}

                if success:
                    # Broadcast clear event to connected clients
                    await self.broadcast_event({
                        "type": "logs_cleared",
                        "clear_type": clear_type,
                        "timestamp": datetime.now().isoformat()
                    })

                return {"success": success, "message": f"Successfully cleared {clear_type}" if success else "Failed to clear logs"}
            except Exception as e:
                self.logger.error(f"Error clearing logs: {e}")
                return {"success": False, "message": str(e)}

        @self.app.get("/api/filtered-connections")
        async def get_filtered_connections(
            ip: str = None,
            service: str = None,
            start_time: str = None,
            end_time: str = None,
            session_id: str = None,
            limit: int = 100
        ):
            """Get filtered connections"""
            if not self.db_manager:
                return {"connections": [], "count": 0}

            try:
                filters = {}
                if ip:
                    filters['ip'] = ip
                if service:
                    filters['service'] = service
                if start_time:
                    filters['start_time'] = start_time
                if end_time:
                    filters['end_time'] = end_time
                if session_id:
                    filters['session_id'] = session_id

                connections = await self.db_manager.get_filtered_connections(filters, limit)
                return {"connections": connections, "count": len(connections)}
            except Exception as e:
                self.logger.error(f"Error fetching filtered connections: {e}")
                return {"connections": [], "count": 0}

        @self.app.get("/api/filtered-alerts")
        async def get_filtered_alerts(
            ip: str = None,
            severity: str = None,
            alert_type: str = None,
            start_time: str = None,
            end_time: str = None,
            limit: int = 100
        ):
            """Get filtered alerts"""
            if not self.db_manager:
                return {"alerts": [], "count": 0}

            try:
                filters = {}
                if ip:
                    filters['ip'] = ip
                if severity:
                    filters['severity'] = severity
                if alert_type:
                    filters['alert_type'] = alert_type
                if start_time:
                    filters['start_time'] = start_time
                if end_time:
                    filters['end_time'] = end_time

                alerts = await self.db_manager.get_filtered_alerts(filters, limit)
                return {"alerts": alerts, "count": len(alerts)}
            except Exception as e:
                self.logger.error(f"Error fetching filtered alerts: {e}")
                return {"alerts": [], "count": 0}

        @self.app.get("/api/export/connections")
        async def export_connections(
            format: str = "csv",
            ip: str = None,
            service: str = None,
            start_time: str = None,
            end_time: str = None
        ):
            """Export connections to CSV or JSON"""
            if not self.db_manager:
                return {"error": "Database not available"}

            try:
                filters = {}
                if ip:
                    filters['ip'] = ip
                if service:
                    filters['service'] = service
                if start_time:
                    filters['start_time'] = start_time
                if end_time:
                    filters['end_time'] = end_time

                if format.lower() == "csv":
                    csv_data = await self.db_manager.export_connections_to_csv(filters)
                    if csv_data:
                        from fastapi.responses import Response
                        return Response(
                            content=csv_data,
                            media_type="text/csv",
                            headers={"Content-Disposition": "attachment; filename=connections.csv"}
                        )
                    else:
                        return {"error": "No data to export"}
                else:
                    connections = await self.db_manager.get_filtered_connections(filters, limit=10000)
                    return {"connections": connections, "count": len(connections)}

            except Exception as e:
                self.logger.error(f"Error exporting connections: {e}")
                return {"error": str(e)}

        @self.app.get("/api/export/alerts")
        async def export_alerts(
            format: str = "csv",
            ip: str = None,
            severity: str = None,
            alert_type: str = None,
            start_time: str = None,
            end_time: str = None
        ):
            """Export alerts to CSV or JSON"""
            if not self.db_manager:
                return {"error": "Database not available"}

            try:
                filters = {}
                if ip:
                    filters['ip'] = ip
                if severity:
                    filters['severity'] = severity
                if alert_type:
                    filters['alert_type'] = alert_type
                if start_time:
                    filters['start_time'] = start_time
                if end_time:
                    filters['end_time'] = end_time

                if format.lower() == "csv":
                    csv_data = await self.db_manager.export_alerts_to_csv(filters)
                    if csv_data:
                        from fastapi.responses import Response
                        return Response(
                            content=csv_data,
                            media_type="text/csv",
                            headers={"Content-Disposition": "attachment; filename=alerts.csv"}
                        )
                    else:
                        return {"error": "No data to export"}
                else:
                    alerts = await self.db_manager.get_filtered_alerts(filters, limit=10000)
                    return {"alerts": alerts, "count": len(alerts)}

            except Exception as e:
                self.logger.error(f"Error exporting alerts: {e}")
                return {"error": str(e)}

        @self.app.get("/api/timeline")
        async def get_attack_timeline(hours: int = 24):
            """Get attack timeline data"""
            if not self.db_manager:
                return {"timeline": []}

            try:
                timeline = await self.db_manager.get_attack_timeline(hours)
                return {"timeline": timeline, "period_hours": hours}
            except Exception as e:
                self.logger.error(f"Error fetching timeline: {e}")
                return {"timeline": []}

        @self.app.get("/api/threat-summary")
        async def get_threat_summary(hours: int = 24):
            """Get comprehensive threat summary"""
            if not self.db_manager:
                return {"connections": [], "alerts": [], "period_hours": hours}

            try:
                summary = await self.db_manager.get_threat_summary(hours)
                return summary
            except Exception as e:
                self.logger.error(f"Error fetching threat summary: {e}")
                return {"connections": [], "alerts": [], "period_hours": hours}

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
            # Get configurable update interval (default 5 seconds for better performance)
            update_interval = DASHBOARD_CONFIG.get("performance", {}).get("websocket_update_interval", 5)

            while True:
                # Send periodic updates with configurable interval
                await asyncio.sleep(update_interval)
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

    async def broadcast_event(self, event_type_or_data, data=None):
        """Broadcast event to all connected WebSocket clients

        Args:
            event_type_or_data: Either event type string (when data is provided) or complete event data dict
            data: Event data (when first parameter is event type)
        """
        if not self.active_connections:
            return

        # Handle both calling patterns:
        # 1. broadcast_event(event_type, data) - from event_broadcaster
        # 2. broadcast_event(event_data) - from clear_logs
        if data is not None:
            # Called with event_type and data separately
            event_message = {
                "type": event_type_or_data,
                "data": data,
                "timestamp": datetime.now().isoformat()
            }
        else:
            # Called with complete event data
            event_message = event_type_or_data

        disconnected = []
        for websocket in self.active_connections:
            try:
                await websocket.send_json(event_message)
            except Exception as e:
                self.logger.error(f"Error broadcasting to WebSocket: {e}")
                disconnected.append(websocket)

        # Remove disconnected clients
        for websocket in disconnected:
            if websocket in self.active_connections:
                self.active_connections.remove(websocket)
    
    async def _get_cached_stats(self) -> Dict:
        """Get cached statistics with refresh logic"""
        now = datetime.now()

        # Get configurable cache duration (default 30 seconds)
        cache_duration = DASHBOARD_CONFIG.get("performance", {}).get("stats_cache_duration", 30)

        # Refresh cache based on configured duration
        if (self.cache_timestamp is None or
            (now - self.cache_timestamp).total_seconds() > cache_duration):

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
