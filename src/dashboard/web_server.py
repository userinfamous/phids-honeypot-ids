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

                # Generate recommendations
                recommendations = self._generate_recommendations(alert, attack_analysis)

                # Compile comprehensive alert details
                detailed_alert = {
                    **alert,
                    'related_connections': related_connections,
                    'related_alerts': related_alerts,
                    'threat_intelligence': threat_intel,
                    'attack_analysis': attack_analysis,
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
        """Get geolocation information for IP address"""
        # This is a simplified implementation
        # In production, you'd use a real geolocation service
        try:
            import ipaddress
            ip = ipaddress.ip_address(ip_address)

            if ip.is_private:
                return {
                    'country': 'Private Network',
                    'city': 'Local',
                    'latitude': None,
                    'longitude': None,
                    'isp': 'Private'
                }
            else:
                # Placeholder for external geolocation service
                return {
                    'country': 'Unknown',
                    'city': 'Unknown',
                    'latitude': None,
                    'longitude': None,
                    'isp': 'Unknown'
                }
        except Exception:
            return {
                'country': 'Unknown',
                'city': 'Unknown',
                'latitude': None,
                'longitude': None,
                'isp': 'Unknown'
            }

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
