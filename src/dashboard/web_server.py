"""
FastAPI Web Dashboard for PHIDS
Real-time honeypot monitoring and analytics
"""
import asyncio
import json
import logging
import subprocess
import random
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, JSONResponse
import uvicorn

from config import DASHBOARD_CONFIG, BASE_DIR
from src.core.database import DatabaseManager


class DashboardWebServer:
    """FastAPI-based web dashboard for PHIDS honeypot monitoring.

    Provides real-time monitoring, analytics, and attack simulation capabilities
    through a modern web interface with WebSocket support for live updates.

    Attributes:
        logger: Logger instance for dashboard operations
        app: FastAPI application instance
        db_manager: Database manager for data persistence
        active_connections: List of active WebSocket connections
        stats_cache: Cached statistics for performance optimization
        cache_timestamp: Timestamp of last cache update
        templates: Jinja2 template engine
        templates_dir: Path to templates directory
        static_dir: Path to static files directory
    """

    def __init__(self) -> None:
        """Initialize the dashboard web server with FastAPI and templates."""
        self.logger: logging.Logger = logging.getLogger(__name__)
        self.app: FastAPI = FastAPI(title="PHIDS Dashboard", version="1.0.0")
        self.db_manager: Optional[DatabaseManager] = None
        self.active_connections: List[WebSocket] = []
        self.stats_cache: Dict[str, Any] = {}
        self.cache_timestamp: Optional[datetime] = None
        
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
        async def dashboard_home(request: Request) -> HTMLResponse:
            """Main dashboard page with real-time monitoring interface."""
            return self.templates.TemplateResponse("dashboard.html", {"request": request})

        @self.app.get("/info", response_class=HTMLResponse)
        async def info_page(request: Request) -> HTMLResponse:
            """Information and documentation page about PHIDS."""
            return self.templates.TemplateResponse("info.html", {"request": request})

        @self.app.get("/attacks", response_class=HTMLResponse)
        async def attacks_page(request: Request) -> HTMLResponse:
            """Attack scenarios and automation page for testing honeypots."""
            return self.templates.TemplateResponse("attacks.html", {"request": request})

        @self.app.get("/how-it-works", response_class=HTMLResponse)
        async def how_it_works_page(request: Request) -> HTMLResponse:
            """Educational page explaining how PHIDS works and attack simulation."""
            return self.templates.TemplateResponse("how-it-works.html", {"request": request})



        @self.app.get("/ip-tracking", response_class=HTMLResponse)
        async def ip_tracking_page(request: Request) -> HTMLResponse:
            """IP tracking page showing unique attacking IPs and their event timelines."""
            return self.templates.TemplateResponse("ip-tracking.html", {"request": request})

        @self.app.get("/success", response_class=HTMLResponse)
        async def success_page(request: Request) -> HTMLResponse:
            """Success page displayed after successful authentication."""
            return self.templates.TemplateResponse("success.html", {"request": request})

        @self.app.get("/error", response_class=HTMLResponse)
        async def error_page(request: Request) -> HTMLResponse:
            """Generic error page for displaying error information."""
            return self.templates.TemplateResponse("error.html", {"request": request})

        @self.app.get("/api/stats")
        async def get_stats() -> Dict[str, Any]:
            """Get current system statistics including connections and alerts."""
            return await self._get_cached_stats()

        @self.app.get("/api/recent-connections")
        async def get_recent_connections() -> Dict[str, List[Any]]:
            """Get recent honeypot connections from the last 24 hours."""
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
        async def get_recent_alerts() -> Dict[str, List[Any]]:
            """Get recent IDS alerts from the last 24 hours (high/medium severity only)."""
            if not self.db_manager:
                return {"alerts": []}

            try:
                # Get alerts from last 24 hours
                since = datetime.now() - timedelta(hours=24)
                alerts = await self.db_manager.get_recent_alerts(since, limit=50)

                # Filter to show only high and medium severity alerts (exclude low severity)
                # This focuses the dashboard on noteworthy events
                important_alerts = [
                    alert for alert in alerts
                    if alert.get('severity', '').lower() in ['high', 'medium', 'critical']
                ]

                return {"alerts": important_alerts}
            except Exception as e:
                self.logger.error(f"Error fetching recent alerts: {e}")
                return {"alerts": []}

        @self.app.get("/api/alerts/{alert_id}")
        async def get_alert_details(alert_id: int):
            """Get detailed information for a specific alert"""
            if not self.db_manager:
                return {"error": "Database not available"}

            try:
                alert_details = await self.get_alert_details(alert_id)
                if alert_details:
                    return {"alert": alert_details}
                else:
                    return {"error": "Alert not found"}
            except Exception as e:
                self.logger.error(f"Error fetching alert details: {e}")
                return {"error": "Failed to fetch alert details"}

        @self.app.get("/api/authentication-events")
        async def get_authentication_events(hours: int = 24, limit: int = 100):
            """Get recent authentication events"""
            if not self.db_manager:
                return {"events": []}

            try:
                since = datetime.now() - timedelta(hours=hours)
                events = await self.db_manager.get_recent_authentication_events(since, limit)
                return {"events": events, "period_hours": hours}
            except Exception as e:
                self.logger.error(f"Error fetching authentication events: {e}")
                return {"events": []}

        @self.app.get("/api/authentication-stats")
        async def get_authentication_stats(hours: int = 24):
            """Get authentication success/failed statistics"""
            if not self.db_manager:
                return {"successful": 0, "failed": 0}

            try:
                since = datetime.now() - timedelta(hours=hours)
                stats = await self.db_manager.get_authentication_stats(since)
                return stats
            except Exception as e:
                self.logger.error(f"Error fetching authentication stats: {e}")
                return {"successful": 0, "failed": 0}

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

        @self.app.post("/api/execute-attack/{attack_type}")
        async def execute_attack(attack_type: str):
            """Execute a specific attack scenario"""
            try:
                result = await self._execute_attack_scenario(attack_type)
                return result
            except Exception as e:
                self.logger.error(f"Error executing attack {attack_type}: {e}")
                return {"success": False, "error": str(e)}

        @self.app.get("/api/attack-status")
        async def get_attack_status():
            """Get current attack execution status"""
            return {"status": "ready", "active_attacks": []}



        @self.app.post("/api/block-ip")
        async def block_ip(request: Request):
            """Block an IP address by adding it to the blocklist"""
            try:
                data = await request.json()
                ip_address = data.get('ip_address')
                reason = data.get('reason', 'Blocked from dashboard')

                if not ip_address:
                    return JSONResponse(
                        status_code=400,
                        content={"error": "IP address is required"}
                    )

                # Add IP to blocklist in database
                if self.db_manager:
                    await self.db_manager.add_blocked_ip(ip_address, reason)
                    self.logger.info(f"IP {ip_address} blocked: {reason}")

                    return {
                        "success": True,
                        "message": f"IP {ip_address} has been blocked",
                        "ip": ip_address
                    }
                else:
                    return JSONResponse(
                        status_code=500,
                        content={"error": "Database not available"}
                    )

            except Exception as e:
                self.logger.error(f"Error blocking IP: {e}")
                return JSONResponse(
                    status_code=500,
                    content={"error": f"Failed to block IP: {str(e)}"}
                )

        @self.app.get("/api/unique-ips")
        async def get_unique_ips():
            """Get list of unique attacking IPs with event counts"""
            if not self.db_manager:
                return {"ips": []}

            try:
                ips = await self.db_manager.get_unique_attacking_ips()
                return {"ips": ips}
            except Exception as e:
                self.logger.error(f"Error fetching unique IPs: {e}")
                return {"ips": []}

        @self.app.get("/api/ip-timeline/{ip_address}")
        async def get_ip_timeline(ip_address: str):
            """Get chronological timeline of events for a specific IP"""
            if not self.db_manager:
                return {"events": []}

            try:
                events = await self.db_manager.get_ip_event_timeline(ip_address)
                return {"ip": ip_address, "events": events}
            except Exception as e:
                self.logger.error(f"Error fetching IP timeline: {e}")
                return {"ip": ip_address, "events": []}

        @self.app.websocket("/ws")
        async def websocket_endpoint(websocket: WebSocket):
            """WebSocket endpoint for real-time updates"""
            await self._handle_websocket(websocket)
        
        # Mount static files
        self.app.mount("/static", StaticFiles(directory=str(self.static_dir)), name="static")

        # Exception handlers
        @self.app.exception_handler(404)
        async def not_found_handler(request: Request, exc):
            """Handle 404 Not Found errors"""
            self.logger.warning(f"404 Not Found: {request.url.path}")
            return self.templates.TemplateResponse(
                "error.html",
                {
                    "request": request,
                    "code": 404,
                    "title": "Page Not Found",
                    "message": f"The page '{request.url.path}' could not be found."
                },
                status_code=404
            )

        @self.app.exception_handler(500)
        async def internal_error_handler(request: Request, exc):
            """Handle 500 Internal Server errors"""
            self.logger.error(f"500 Internal Server Error: {exc}")
            return self.templates.TemplateResponse(
                "error.html",
                {
                    "request": request,
                    "code": 500,
                    "title": "Internal Server Error",
                    "message": "An unexpected error occurred. Please try again later."
                },
                status_code=500
            )

        @self.app.exception_handler(Exception)
        async def general_exception_handler(request: Request, exc: Exception):
            """Handle general exceptions"""
            self.logger.error(f"Unhandled exception: {exc}", exc_info=True)
            return JSONResponse(
                status_code=500,
                content={
                    "error": "Internal Server Error",
                    "message": "An unexpected error occurred. Please try again later."
                }
            )

    async def _handle_websocket(self, websocket: WebSocket) -> None:
        """Handle WebSocket connections for real-time updates.

        Maintains persistent connection and sends periodic statistics updates
        to connected clients with configurable intervals.

        Args:
            websocket: WebSocket connection instance
        """
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

    async def broadcast_event(self, event_type_or_data: Any, data: Optional[Any] = None) -> None:
        """Broadcast event to all connected WebSocket clients.

        Supports two calling patterns:
        1. broadcast_event(event_type, data) - separate type and data
        2. broadcast_event(event_data) - complete event data dict

        Args:
            event_type_or_data: Either event type string or complete event data dict
            data: Optional event data (when first parameter is event type)
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
    
    async def _get_cached_stats(self) -> Dict[str, Any]:
        """Get cached statistics with automatic refresh logic.

        Returns cached statistics if cache is still valid, otherwise fetches
        fresh statistics from the database. Cache duration is configurable.

        Returns:
            Dictionary containing system statistics including connections, alerts, and status
        """
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
            
            # Use optimized statistics summary for better performance
            basic_stats = await self.db_manager.get_statistics_summary(since)

            # Get additional stats in parallel
            additional_stats = await asyncio.gather(
                self.db_manager.get_top_attackers(since, limit=5),
                self.db_manager.get_service_breakdown(since),
                self.db_manager.get_hourly_activity(since),
                self.db_manager.get_alert_severity_breakdown(since),
                self.db_manager.get_authentication_stats(since),
                self.db_manager.get_geo_distribution(since),
                return_exceptions=True
            )

            stats = {
                **basic_stats,
                "top_attackers": additional_stats[0] if not isinstance(additional_stats[0], Exception) else [],
                "service_breakdown": additional_stats[1] if not isinstance(additional_stats[1], Exception) else {},
                "hourly_activity": additional_stats[2] if not isinstance(additional_stats[2], Exception) else [],
                "alert_severity": additional_stats[3] if not isinstance(additional_stats[3], Exception) else {},
                "auth_stats": additional_stats[4] if not isinstance(additional_stats[4], Exception) else {"successful": 0, "failed": 0},
                "geo_distribution": additional_stats[5] if not isinstance(additional_stats[5], Exception) else {},
                "last_updated": datetime.now().isoformat()
            }
            
            return stats
            
        except Exception as e:
            self.logger.error(f"Error fetching stats: {e}")
            return self._get_default_stats()

    def _get_default_stats(self) -> Dict:
        """Return default empty statistics"""
        return {
            "total_connections": 0,
            "total_alerts": 0,
            "unique_ips": 0,
            "top_attackers": [],
            "service_breakdown": {},
            "hourly_activity": [],
            "alert_severity": {},
            "last_updated": datetime.now().isoformat()
        }
    
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
            "auth_stats": {"successful": 0, "failed": 0},
            "geo_distribution": {},
            "last_updated": datetime.now().isoformat()
        }
    

    
    async def initialize(self, db_manager: DatabaseManager) -> None:
        """Initialize the web server with database manager.

        Args:
            db_manager: Database manager instance for data access
        """
        self.db_manager = db_manager
        self.logger.info("Dashboard web server initialized")

    async def start(self) -> None:
        """Start the web server with configured host and port.

        Starts the FastAPI application using Uvicorn with configuration
        from DASHBOARD_CONFIG. Respects the enabled flag in configuration.

        Raises:
            Exception: If server fails to start or bind to port
        """
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

    async def stop(self) -> None:
        """Stop the web server and close all connections.

        Gracefully closes all active WebSocket connections and cleans up resources.
        """
        self.logger.info("Stopping dashboard web server")

        # Close all WebSocket connections
        for websocket in self.active_connections:
            try:
                await websocket.close()
            except Exception:
                pass

        self.active_connections.clear()

    async def get_alert_details(self, alert_id: int):
        """Get comprehensive details for a specific alert"""
        try:
            import aiosqlite
            from src.threat_intel.threat_intelligence import ThreatIntelligenceManager

            async with aiosqlite.connect(self.db_manager.db_path) as db:
                db.row_factory = aiosqlite.Row

                # Get the main alert data
                cursor = await db.execute("""
                    SELECT * FROM ids_alerts WHERE id = ?
                """, (alert_id,))
                alert_row = await cursor.fetchone()

                if not alert_row:
                    return None

                alert = dict(alert_row)

                # Get related connections from the same source IP around the same time
                alert_time = datetime.fromisoformat(alert['timestamp'])
                time_window_start = alert_time - timedelta(minutes=30)
                time_window_end = alert_time + timedelta(minutes=30)

                cursor = await db.execute("""
                    SELECT * FROM honeypot_connections
                    WHERE source_ip = ?
                    AND timestamp BETWEEN ? AND ?
                    ORDER BY timestamp DESC
                    LIMIT 10
                """, (alert['source_ip'], time_window_start.isoformat(), time_window_end.isoformat()))

                related_connections = [dict(row) for row in await cursor.fetchall()]

                # Get related alerts from the same source IP
                cursor = await db.execute("""
                    SELECT * FROM ids_alerts
                    WHERE source_ip = ?
                    AND id != ?
                    AND timestamp BETWEEN ? AND ?
                    ORDER BY timestamp DESC
                    LIMIT 5
                """, (alert['source_ip'], alert_id, time_window_start.isoformat(), time_window_end.isoformat()))

                related_alerts = [dict(row) for row in await cursor.fetchall()]

                # Get threat intelligence for the source IP
                threat_intel = None
                try:
                    threat_manager = ThreatIntelligenceManager()
                    threat_intel = await threat_manager.get_ip_reputation(alert['source_ip'])
                except Exception as e:
                    self.logger.debug(f"Could not get threat intelligence: {e}")

                # Analyze attack patterns and severity
                attack_analysis = self._analyze_attack_patterns(alert, related_connections, related_alerts)

                # Validate attack legitimacy
                validation_result = self._validate_attack_legitimacy(alert, related_connections)

                # Generate recommendations
                recommendations = self._generate_recommendations(alert, attack_analysis)

                # Compile comprehensive alert details
                detailed_alert = {
                    **alert,
                    'related_connections': related_connections,
                    'related_alerts': related_alerts,
                    'threat_intelligence': threat_intel,
                    'attack_analysis': attack_analysis,
                    'validation': validation_result,
                    'recommendations': recommendations,
                    'geolocation': self._get_geolocation_info(alert['source_ip']),
                    'severity_details': self._get_severity_details(alert['severity']),
                    'timeline': self._create_attack_timeline(alert, related_connections, related_alerts)
                }

                return detailed_alert

        except Exception as e:
            self.logger.error(f"Error getting alert details: {e}")
            return None

    def _analyze_attack_patterns(self, alert, related_connections, related_alerts):
        """Analyze attack patterns from alert and related data"""
        analysis = {
            'attack_type': alert.get('alert_type', 'Unknown'),
            'attack_frequency': len(related_alerts) + 1,
            'target_services': set(),
            'attack_duration': 0,
            'techniques_used': [],
            'risk_level': 'medium'
        }

        # Analyze target services
        for conn in related_connections:
            if conn.get('service_type'):
                analysis['target_services'].add(conn['service_type'])

        # Calculate attack duration
        if related_connections:
            timestamps = [datetime.fromisoformat(conn['timestamp']) for conn in related_connections]
            timestamps.append(datetime.fromisoformat(alert['timestamp']))
            analysis['attack_duration'] = (max(timestamps) - min(timestamps)).total_seconds()

        # Identify techniques used
        techniques = set()
        for conn in related_connections:
            commands = conn.get('commands', '')
            if isinstance(commands, str) and commands:
                if 'cat /etc/passwd' in commands:
                    techniques.add('System Reconnaissance')
                if 'wget' in commands or 'curl' in commands:
                    techniques.add('File Download')
                if 'nc ' in commands or 'netcat' in commands:
                    techniques.add('Reverse Shell')
                if any(sql in commands.lower() for sql in ['union select', 'or 1=1', 'drop table']):
                    techniques.add('SQL Injection')

        analysis['techniques_used'] = list(techniques)

        # Determine risk level
        if analysis['attack_frequency'] > 5 or len(analysis['target_services']) > 2:
            analysis['risk_level'] = 'high'
        elif analysis['attack_frequency'] > 2 or analysis['attack_duration'] > 300:
            analysis['risk_level'] = 'medium'
        else:
            analysis['risk_level'] = 'low'

        return analysis

    def _generate_recommendations(self, alert, attack_analysis):
        """Generate security recommendations based on alert analysis"""
        recommendations = []

        # Base recommendations by alert type
        alert_type = alert.get('alert_type', '').lower()

        if 'sql' in alert_type or 'injection' in alert_type:
            recommendations.extend([
                "Implement input validation and parameterized queries",
                "Deploy Web Application Firewall (WAF)",
                "Regular security code reviews"
            ])

        if 'brute' in alert_type or 'force' in alert_type:
            recommendations.extend([
                "Implement account lockout policies",
                "Deploy multi-factor authentication",
                "Monitor for credential stuffing attacks"
            ])

        if 'scan' in alert_type:
            recommendations.extend([
                "Implement rate limiting",
                "Deploy intrusion prevention system",
                "Monitor for reconnaissance activities"
            ])

        # Risk-based recommendations
        if attack_analysis['risk_level'] == 'high':
            recommendations.extend([
                "Consider blocking source IP immediately",
                "Escalate to security team",
                "Review all systems for compromise"
            ])

        # Service-specific recommendations
        if 'ssh' in attack_analysis['target_services']:
            recommendations.append("Consider changing SSH port and implementing key-based authentication")

        if 'http' in attack_analysis['target_services']:
            recommendations.append("Review web application security and update to latest versions")

        return list(set(recommendations))  # Remove duplicates

    def _get_geolocation_info(self, ip_address):
        """Get geolocation information for IP address with improved accuracy

        IMPORTANT: This system uses SIMULATED geolocation data for educational purposes.
        This is NOT real attack data. The geolocation is generated based on IP ranges
        for demonstration and testing purposes only.

        For production use with real geolocation data, integrate with:
        - MaxMind GeoIP2 (requires license)
        - IPinfo.io API (requires API key)
        - IP2Location database (requires license)
        """
        try:
            import ipaddress
            ip = ipaddress.ip_address(ip_address)

            # Handle private/local networks accurately
            if ip.is_private:
                return {
                    'country': 'Private Network',
                    'city': 'Local Network',
                    'latitude': None,
                    'longitude': None,
                    'isp': 'Private Network',
                    'is_private': True,
                    'accuracy': 'high',
                    'data_type': 'deterministic'  # Not simulated, actual private network
                }

            # Handle localhost/loopback
            if ip.is_loopback:
                return {
                    'country': 'Localhost',
                    'city': 'Local Machine',
                    'latitude': None,
                    'longitude': None,
                    'isp': 'Loopback',
                    'is_private': True,
                    'accuracy': 'high',
                    'data_type': 'deterministic'  # Not simulated, actual loopback
                }

            # Handle reserved/special addresses
            if ip.is_reserved or ip.is_multicast:
                return {
                    'country': 'Reserved/Special',
                    'city': 'Reserved Address Space',
                    'latitude': None,
                    'longitude': None,
                    'isp': 'Reserved',
                    'is_private': True,
                    'accuracy': 'high',
                    'data_type': 'deterministic'  # Not simulated, actual reserved address
                }

            # For public IPs, use a basic geolocation approach
            # In a real implementation, you would use services like MaxMind GeoIP2, IPinfo, etc.
            return self._get_public_ip_geolocation(str(ip))

        except Exception as e:
            self.logger.warning(f"Error getting geolocation for {ip_address}: {e}")
            return {
                'country': 'Unknown',
                'city': 'Unknown',
                'latitude': None,
                'longitude': None,
                'isp': 'Unknown',
                'is_private': False,
                'accuracy': 'low',
                'error': str(e)
            }

    def _get_public_ip_geolocation(self, ip_address):
        """Get geolocation for public IP addresses - SIMULATED FOR EDUCATIONAL PURPOSES

        IMPORTANT: This method returns SIMULATED geolocation data based on IP ranges.
        This is NOT real attack data and should NOT be used for production threat intelligence.

        The simulation is based on first octet ranges:
        - 1-50: United States
        - 51-100: Europe
        - 101-150: Asia
        - 151-200: Various
        - 201-255: Global

        For production systems, integrate with real GeoIP services:
        - MaxMind GeoIP2 (most accurate, requires license)
        - IPinfo.io (API-based, requires API key)
        - IP2Location (database-based, requires license)
        """
        # This is a simplified implementation for educational purposes
        # In production, integrate with services like MaxMind, IPinfo, or similar

        # For educational/testing purposes, provide realistic but clearly simulated data
        # This explains why localhost might show as different countries

        # Basic country mapping based on IP ranges (very simplified)
        ip_parts = ip_address.split('.')
        first_octet = int(ip_parts[0])

        # Simplified mapping - in reality, use proper GeoIP databases
        # Note: This is intentionally simplified and may show unexpected results for testing
        country_mapping = {
            (1, 50): 'United States',
            (51, 100): 'Europe',
            (101, 150): 'Asia',
            (151, 200): 'Various',
            (201, 255): 'Global'
        }

        country = 'Unknown'
        for (start, end), mapped_country in country_mapping.items():
            if start <= first_octet <= end:
                country = mapped_country
                break

        return {
            'country': country,
            'city': 'Simulated Location',
            'latitude': None,
            'longitude': None,
            'isp': 'Educational ISP Simulation',
            'is_private': False,
            'accuracy': 'low',
            'data_type': 'simulated',  # Clearly marked as simulated
            'note': 'EDUCATIONAL GEOLOCATION - Simulated data for testing purposes. Real production systems would use actual GeoIP databases (MaxMind, IPinfo, IP2Location).'
        }

    def _validate_attack_legitimacy(self, alert, connection_data=None):
        """Validate if an attack is legitimate vs false positive"""
        validation_result = {
            'is_legitimate': True,
            'confidence': 'medium',
            'flags': [],
            'classification': 'malicious',
            'reasons': []
        }

        source_ip = alert.get('source_ip', '')

        # Check for local/testing traffic
        if self._is_local_testing_traffic(source_ip):
            validation_result['is_legitimate'] = False
            validation_result['classification'] = 'testing'
            validation_result['flags'].append('local_testing')
            validation_result['reasons'].append('Traffic originates from local/testing environment')

        # Check for penetration testing patterns
        pentest_indicators = self._detect_penetration_testing(alert, connection_data)
        if pentest_indicators['is_pentest']:
            validation_result['classification'] = 'penetration_testing'
            validation_result['flags'].extend(pentest_indicators['indicators'])
            validation_result['reasons'].extend(pentest_indicators['reasons'])

        # Check for automated scanner patterns
        scanner_indicators = self._detect_automated_scanners(alert, connection_data)
        if scanner_indicators['is_scanner']:
            validation_result['classification'] = 'automated_scanner'
            validation_result['flags'].extend(scanner_indicators['indicators'])
            validation_result['reasons'].extend(scanner_indicators['reasons'])

        # Validate attack complexity and sophistication
        sophistication = self._assess_attack_sophistication(alert, connection_data)
        validation_result['sophistication'] = sophistication

        if sophistication['level'] == 'low' and sophistication['automated']:
            validation_result['confidence'] = 'low'
            validation_result['flags'].append('low_sophistication')

        return validation_result

    def _is_local_testing_traffic(self, ip_address):
        """Check if traffic is from local testing environment"""
        try:
            import ipaddress
            ip = ipaddress.ip_address(ip_address)

            # Local networks and testing ranges
            local_ranges = [
                ipaddress.ip_network('127.0.0.0/8'),    # Loopback
                ipaddress.ip_network('10.0.0.0/8'),     # Private Class A
                ipaddress.ip_network('172.16.0.0/12'),  # Private Class B
                ipaddress.ip_network('192.168.0.0/16'), # Private Class C
                ipaddress.ip_network('169.254.0.0/16'), # Link-local
            ]

            return any(ip in network for network in local_ranges)
        except:
            return False

    def _detect_penetration_testing(self, alert, connection_data):
        """Detect patterns indicating legitimate penetration testing"""
        indicators = {
            'is_pentest': False,
            'indicators': [],
            'reasons': []
        }

        # Check for common penetration testing tools
        pentest_tools = [
            'nmap', 'metasploit', 'burp', 'sqlmap', 'nikto',
            'dirb', 'gobuster', 'hydra', 'john', 'hashcat'
        ]

        alert_text = str(alert).lower()
        if connection_data:
            alert_text += str(connection_data).lower()

        detected_tools = [tool for tool in pentest_tools if tool in alert_text]
        if detected_tools:
            indicators['is_pentest'] = True
            indicators['indicators'].append('pentest_tools')
            indicators['reasons'].append(f'Detected penetration testing tools: {", ".join(detected_tools)}')

        # Check for systematic/methodical approach
        if self._is_systematic_testing(alert, connection_data):
            indicators['is_pentest'] = True
            indicators['indicators'].append('systematic_approach')
            indicators['reasons'].append('Systematic testing pattern detected')

        return indicators

    def _detect_automated_scanners(self, alert, connection_data):
        """Detect automated scanner patterns"""
        indicators = {
            'is_scanner': False,
            'indicators': [],
            'reasons': []
        }

        # Check for scanner user agents
        scanner_agents = [
            'masscan', 'zmap', 'shodan', 'censys', 'binaryedge',
            'scanner', 'bot', 'crawler', 'spider'
        ]

        user_agent = alert.get('user_agent', '').lower()
        if any(agent in user_agent for agent in scanner_agents):
            indicators['is_scanner'] = True
            indicators['indicators'].append('scanner_user_agent')
            indicators['reasons'].append(f'Scanner user agent detected: {user_agent}')

        # Check for rapid sequential requests
        if self._has_rapid_sequential_pattern(alert):
            indicators['is_scanner'] = True
            indicators['indicators'].append('rapid_sequential')
            indicators['reasons'].append('Rapid sequential request pattern detected')

        return indicators

    def _assess_attack_sophistication(self, alert, connection_data):
        """Assess the sophistication level of an attack"""
        sophistication = {
            'level': 'medium',
            'automated': False,
            'factors': []
        }

        # Check for automation indicators
        if self._has_automation_indicators(alert, connection_data):
            sophistication['automated'] = True
            sophistication['factors'].append('automated_behavior')

        # Assess complexity
        complexity_score = 0

        # Simple patterns indicate low sophistication
        simple_patterns = ['admin:admin', 'root:password', 'test:test']
        if any(pattern in str(alert).lower() for pattern in simple_patterns):
            complexity_score -= 2
            sophistication['factors'].append('simple_credentials')

        # Advanced techniques indicate higher sophistication
        advanced_patterns = ['sql injection', 'xss', 'buffer overflow', 'privilege escalation']
        if any(pattern in str(alert).lower() for pattern in advanced_patterns):
            complexity_score += 2
            sophistication['factors'].append('advanced_techniques')

        # Determine final level
        if complexity_score <= -2:
            sophistication['level'] = 'low'
        elif complexity_score >= 2:
            sophistication['level'] = 'high'

        return sophistication

    def _is_systematic_testing(self, alert, connection_data):
        """Check for systematic testing patterns"""
        # This would analyze timing, sequence, and methodology
        # Simplified implementation for educational purposes
        return False

    def _has_rapid_sequential_pattern(self, alert):
        """Check for rapid sequential request patterns"""
        # This would analyze request timing and patterns
        # Simplified implementation for educational purposes
        return False

    def _has_automation_indicators(self, alert, connection_data):
        """Check for automation indicators"""
        # Look for perfect timing, identical requests, etc.
        # Simplified implementation for educational purposes
        return False

    def _get_severity_details(self, severity):
        """Get detailed severity information"""
        severity_map = {
            'low': {
                'level': 1,
                'description': 'Low risk activity that requires monitoring',
                'color': 'success',
                'action': 'Monitor and log'
            },
            'medium': {
                'level': 2,
                'description': 'Moderate risk activity that may indicate malicious intent',
                'color': 'warning',
                'action': 'Investigate and monitor closely'
            },
            'high': {
                'level': 3,
                'description': 'High risk activity indicating likely attack',
                'color': 'danger',
                'action': 'Immediate investigation and response required'
            },
            'critical': {
                'level': 4,
                'description': 'Critical security incident requiring immediate action',
                'color': 'danger',
                'action': 'Emergency response protocol'
            }
        }

        return severity_map.get(severity.lower(), severity_map['medium'])

    def _create_attack_timeline(self, alert, related_connections, related_alerts):
        """Create a timeline of attack events"""
        timeline = []

        # Add alert to timeline
        timeline.append({
            'timestamp': alert['timestamp'],
            'type': 'alert',
            'description': f"Security Alert: {alert['alert_type']}",
            'details': alert['description'],
            'severity': alert['severity']
        })

        # Add related connections
        for conn in related_connections:
            timeline.append({
                'timestamp': conn['timestamp'],
                'type': 'connection',
                'description': f"Connection to {conn.get('service_type', 'unknown')} service",
                'details': f"Port {conn.get('destination_port', 'unknown')}",
                'severity': 'info'
            })

        # Add related alerts
        for related_alert in related_alerts:
            timeline.append({
                'timestamp': related_alert['timestamp'],
                'type': 'alert',
                'description': f"Related Alert: {related_alert['alert_type']}",
                'details': related_alert['description'],
                'severity': related_alert['severity']
            })

        # Sort by timestamp
        timeline.sort(key=lambda x: x['timestamp'])

        return timeline



    async def _execute_attack_scenario(self, attack_type: str):
        """Execute a specific attack scenario and return realistic results"""
        # Simulate realistic attacker information
        # For local testing, use honest local information
        source_ip = "127.0.0.1"
        location_info = {"country": "Local", "city": "Local Network", "isp": "Local System"}

        attack_scenarios = {
            "ssh_brute_force": {
                "target": "127.0.0.1:2222",
                "payloads": ["root:password", "admin:admin", "user:123456", "root:toor"],
                "method": "SSH Password Authentication",
                "success_rate": 0.8
            },
            "sql_injection": {
                "target": "127.0.0.1:8080",
                "payloads": ["' OR '1'='1", "'; DROP TABLE users; --", "' UNION SELECT * FROM users --"],
                "method": "HTTP POST/GET Parameters",
                "success_rate": 0.9
            },
            "xss_attack": {
                "target": "127.0.0.1:8080",
                "payloads": ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"],
                "method": "HTTP Form Injection",
                "success_rate": 0.7
            },
            "directory_traversal": {
                "target": "127.0.0.1:8080",
                "payloads": ["../../../etc/passwd", "..\\..\\..\\windows\\system32\\config\\sam"],
                "method": "HTTP Path Manipulation",
                "success_rate": 0.6
            },
            "port_scan": {
                "target": "127.0.0.1",
                "payloads": ["TCP SYN scan ports 1-1000", "Service version detection"],
                "method": "Network Reconnaissance",
                "success_rate": 1.0
            },
            "multi_vector": {
                "target": "127.0.0.1",
                "payloads": ["Port scan + SSH brute force + Web attacks"],
                "method": "Combined Attack Chain",
                "success_rate": 0.85
            }
        }

        if attack_type not in attack_scenarios:
            return {"success": False, "error": "Unknown attack type"}

        scenario = attack_scenarios[attack_type]

        # Execute the actual attack based on type
        successful_credentials = []
        try:
            if attack_type == "ssh_brute_force":
                successful_credentials = await self._execute_ssh_attack(source_ip)
            elif attack_type == "sql_injection":
                await self._execute_sql_attack(source_ip)
            elif attack_type == "xss_attack":
                await self._execute_xss_attack(source_ip)
            elif attack_type == "directory_traversal":
                await self._execute_traversal_attack(source_ip)
            elif attack_type == "port_scan":
                await self._execute_port_scan(source_ip)
            elif attack_type == "multi_vector":
                await self._execute_multi_attack(source_ip)

            # Local attacks are always detected by the honeypot
            detected = True

            result = {
                "success": True,
                "attack_type": attack_type,
                "source_ip": source_ip,
                "target": scenario["target"],
                "location": location_info['city'],
                "isp": location_info["isp"],
                "method": scenario["method"],
                "payloads_sent": len(scenario["payloads"]),
                "detected": detected,
                "timestamp": datetime.now().isoformat()
            }

            # Add successful credentials for SSH attacks
            if attack_type == "ssh_brute_force" and successful_credentials:
                result["successful_credentials"] = successful_credentials
                result["compromised"] = True
            else:
                result["compromised"] = False

            return result

        except Exception as e:
            self.logger.error(f"Attack execution failed: {e}")
            return {"success": False, "error": str(e)}
    async def _execute_ssh_attack(self, source_ip: str):
        """Execute SSH brute force attack"""
        self.logger.info(f"*** AUTOMATED SSH BRUTE FORCE ATTACK INITIATED ***")
        self.logger.info(f"Attack source: {source_ip}")
        self.logger.info(f"Target: SSH Honeypot on port 2222")

        # Use credentials that will actually work with the honeypot
        credentials = [
            ("root", "password"),    # This will succeed
            ("admin", "admin"),      # This will succeed
            ("user", "123456"),      # This will fail
            ("test", "wrongpass"),   # This will fail
            ("root", "toor"),        # This will fail
            ("admin", "password123") # This will fail
        ]

        successful_logins = []
        failed_attempts = []

        for i, (username, password) in enumerate(credentials, 1):
            try:
                self.logger.info(f"SSH Brute Force {i}/{len(credentials)}: Attempting {username}:{password}")

                # Simulate SSH connection attempt
                process = await asyncio.create_subprocess_exec(
                    "ssh", "-o", "ConnectTimeout=5", "-o", "StrictHostKeyChecking=no",
                    "-o", "PreferredAuthentications=password",
                    f"{username}@127.0.0.1", "-p", "2222",
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )

                # Send password and exit
                stdout, stderr = await process.communicate(input=f"{password}\nexit\n".encode())

                # Check if authentication was successful based on return code
                success = process.returncode == 0

                # Log authentication event to database
                auth_event = {
                    'source_ip': source_ip,
                    'source_port': 12345 + i,  # Simulate different source ports
                    'destination_port': 2222,
                    'service_type': 'ssh',
                    'session_id': f"ssh_attack_{source_ip}_{i}",
                    'username': username,
                    'password': password,
                    'auth_method': 'password',
                    'success': success,
                    'failure_reason': None if success else 'Invalid credentials'
                }
                await self.db_manager.log_authentication_event(auth_event)

                # Log alert for failed attempts
                if not success:
                    alert_data = {
                        'alert_type': 'ssh_brute_force',
                        'severity': 'high',
                        'source_ip': source_ip,
                        'destination_ip': '127.0.0.1',
                        'description': f'SSH brute force attempt: {username}:{password}',
                        'details': {'username': username, 'attempt': i}
                    }
                    await self.db_manager.log_alert(alert_data)

                if success:
                    successful_logins.append(f"{username}:{password}")
                    self.logger.warning(f"*** SSH LOGIN SUCCESS: {username}:{password} ***")
                else:
                    failed_attempts.append(f"{username}:{password}")
                    self.logger.info(f"SSH authentication failed: {username}:{password}")

                await asyncio.sleep(1)  # Brief delay between attempts

            except Exception as e:
                failed_attempts.append(f"{username}:{password}")
                self.logger.error(f"SSH connection error for {username}:{password} - {e}")

        # Summary
        self.logger.info(f"*** SSH BRUTE FORCE ATTACK COMPLETED ***")
        self.logger.info(f"Total attempts: {len(credentials)}")
        self.logger.info(f"Successful logins: {len(successful_logins)}")
        self.logger.info(f"Failed attempts: {len(failed_attempts)}")

        if successful_logins:
            self.logger.warning(f"COMPROMISED CREDENTIALS: {', '.join(successful_logins)}")
        else:
            self.logger.info("No successful logins - honeypot security held")

        return successful_logins

    async def _execute_sql_attack(self, source_ip: str):
        """Execute SQL injection attack"""
        import aiohttp

        self.logger.info(f"Starting SQL injection attack from {source_ip}")

        payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT * FROM users --",
            "admin'--",
            "' OR 1=1#",
            "1' AND (SELECT COUNT(*) FROM users) > 0 --",
            "' UNION SELECT username, password FROM users --"
        ]

        successful_injections = 0

        async with aiohttp.ClientSession() as session:
            for i, payload in enumerate(payloads, 1):
                try:
                    self.logger.info(f"SQL Injection {i}/{len(payloads)}: {payload}")

                    # Attack search endpoint
                    response1 = await session.get(f"http://127.0.0.1:8080/search?q={payload}")
                    self.logger.info(f"   -> GET /search?q={payload} -> Status: {response1.status}")

                    # Log alert for SQL injection attempt
                    alert_data = {
                        'alert_type': 'sql_injection',
                        'severity': 'high',
                        'source_ip': source_ip,
                        'destination_ip': '127.0.0.1',
                        'description': f'SQL injection attempt: {payload}',
                        'details': {'payload': payload, 'endpoint': '/search'}
                    }
                    await self.db_manager.log_alert(alert_data)

                    await asyncio.sleep(0.5)

                    # Attack login endpoint
                    response2 = await session.post("http://127.0.0.1:8080/login",
                                                 data={"username": payload, "password": "test"})
                    self.logger.info(f"   -> POST /login (username={payload}) -> Status: {response2.status}")

                    # Log alert for login endpoint attack
                    alert_data = {
                        'alert_type': 'sql_injection',
                        'severity': 'high',
                        'source_ip': source_ip,
                        'destination_ip': '127.0.0.1',
                        'description': f'SQL injection attempt: {payload}',
                        'details': {'payload': payload, 'endpoint': '/login'}
                    }
                    await self.db_manager.log_alert(alert_data)

                    if response1.status == 200 or response2.status == 200:
                        successful_injections += 1

                    await asyncio.sleep(0.5)

                except Exception as e:
                    self.logger.error(f"SQL attack attempt failed: {e}")

        self.logger.info(f"SQL Attack completed: {successful_injections}/{len(payloads)} successful injections")

    async def _execute_xss_attack(self, source_ip: str):
        """Execute XSS attack"""
        import aiohttp

        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')></iframe>"
        ]

        async with aiohttp.ClientSession() as session:
            for i, payload in enumerate(payloads, 1):
                try:
                    # Attack various endpoints
                    await session.get(f"http://127.0.0.1:8080/search?q={payload}")

                    # Log alert for XSS attempt
                    alert_data = {
                        'alert_type': 'xss_attack',
                        'severity': 'high',
                        'source_ip': source_ip,
                        'destination_ip': '127.0.0.1',
                        'description': f'XSS attack attempt: {payload}',
                        'details': {'payload': payload, 'endpoint': '/search'}
                    }
                    await self.db_manager.log_alert(alert_data)

                    await session.post("http://127.0.0.1:8080/comment",
                                     data={"comment": payload})

                    # Log alert for comment endpoint attack
                    alert_data = {
                        'alert_type': 'xss_attack',
                        'severity': 'high',
                        'source_ip': source_ip,
                        'destination_ip': '127.0.0.1',
                        'description': f'XSS attack attempt: {payload}',
                        'details': {'payload': payload, 'endpoint': '/comment'}
                    }
                    await self.db_manager.log_alert(alert_data)

                    await asyncio.sleep(0.5)

                except Exception as e:
                    self.logger.debug(f"XSS attack attempt failed: {e}")

    async def _execute_traversal_attack(self, source_ip: str):
        """Execute directory traversal attack"""
        import aiohttp

        payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd"
        ]

        async with aiohttp.ClientSession() as session:
            for i, payload in enumerate(payloads, 1):
                try:
                    await session.get(f"http://127.0.0.1:8080/file?path={payload}")

                    # Log alert for directory traversal attempt
                    alert_data = {
                        'alert_type': 'directory_traversal',
                        'severity': 'high',
                        'source_ip': source_ip,
                        'destination_ip': '127.0.0.1',
                        'description': f'Directory traversal attempt: {payload}',
                        'details': {'payload': payload, 'endpoint': '/file'}
                    }
                    await self.db_manager.log_alert(alert_data)

                    await session.get(f"http://127.0.0.1:8080/download/{payload}")

                    # Log alert for download endpoint attack
                    alert_data = {
                        'alert_type': 'directory_traversal',
                        'severity': 'high',
                        'source_ip': source_ip,
                        'destination_ip': '127.0.0.1',
                        'description': f'Directory traversal attempt: {payload}',
                        'details': {'payload': payload, 'endpoint': '/download'}
                    }
                    await self.db_manager.log_alert(alert_data)

                    await asyncio.sleep(0.5)

                except Exception as e:
                    self.logger.debug(f"Traversal attack attempt failed: {e}")

    async def _execute_port_scan(self, source_ip: str):
        """Execute port scan"""
        # Simulate port scanning by connecting to various ports
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 2222, 8080]

        for port in ports:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection('127.0.0.1', port),
                    timeout=1.0
                )
                writer.close()
                await writer.wait_closed()

                # Log alert for port scan attempt
                alert_data = {
                    'alert_type': 'port_scan',
                    'severity': 'medium',
                    'source_ip': source_ip,
                    'destination_ip': '127.0.0.1',
                    'description': f'Port scan detected: connection to port {port}',
                    'details': {'port': port, 'protocol': 'TCP'}
                }
                await self.db_manager.log_alert(alert_data)

                await asyncio.sleep(0.1)

            except Exception:
                # Port closed or filtered
                pass

    async def _execute_multi_attack(self, source_ip: str):
        """Execute multi-vector attack"""
        # Combine multiple attack types
        await self._execute_port_scan(source_ip)
        await asyncio.sleep(1)
        await self._execute_ssh_attack(source_ip)
        await asyncio.sleep(1)
        await self._execute_sql_attack(source_ip)
        await asyncio.sleep(1)
        await self._execute_xss_attack(source_ip)
