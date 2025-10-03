"""
Event Broadcasting System for Real-time Dashboard Updates
"""
import asyncio
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime


def serialize_for_json(obj: Any) -> Any:
    """Convert datetime objects to ISO format strings for JSON serialization"""
    if isinstance(obj, datetime):
        return obj.isoformat()
    elif isinstance(obj, dict):
        return {key: serialize_for_json(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [serialize_for_json(item) for item in obj]
    else:
        return obj


class EventBroadcaster:
    """Singleton event broadcaster for real-time dashboard updates"""

    _instance = None
    _initialized = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if not self._initialized:
            self.logger = logging.getLogger(__name__)
            self.dashboard_server = None
            self._initialized = True
    
    def set_dashboard_server(self, dashboard_server):
        """Set the dashboard server for broadcasting events"""
        self.dashboard_server = dashboard_server
        self.logger.info("Dashboard server registered for event broadcasting")
    
    async def broadcast_connection(self, connection_data: Dict):
        """Broadcast new connection event"""
        if self.dashboard_server:
            try:
                # Serialize datetime objects for JSON compatibility
                serialized_data = serialize_for_json(connection_data)
                await self.dashboard_server.broadcast_event("new_connection", serialized_data)
            except Exception as e:
                self.logger.error(f"Error broadcasting connection event: {e}")

    async def broadcast_alert(self, alert_data: Dict):
        """Broadcast new alert event"""
        if self.dashboard_server:
            try:
                # Serialize datetime objects for JSON compatibility
                serialized_data = serialize_for_json(alert_data)
                await self.dashboard_server.broadcast_event("new_alert", serialized_data)
            except Exception as e:
                self.logger.error(f"Error broadcasting alert event: {e}")

    async def broadcast_stats_update(self, stats_data: Dict):
        """Broadcast statistics update"""
        if self.dashboard_server:
            try:
                # Serialize datetime objects for JSON compatibility
                serialized_data = serialize_for_json(stats_data)
                await self.dashboard_server.broadcast_event("stats_update", serialized_data)
            except Exception as e:
                self.logger.error(f"Error broadcasting stats update: {e}")


# Global instance
event_broadcaster = EventBroadcaster()
