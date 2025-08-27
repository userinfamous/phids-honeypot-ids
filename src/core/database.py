"""
Database management for PHIDS
"""
import sqlite3
import asyncio
import aiosqlite
import logging
from datetime import datetime
from pathlib import Path
from config import DATABASE_PATH


class DatabaseManager:
    """Manages SQLite database operations for PHIDS"""
    
    def __init__(self):
        self.db_path = DATABASE_PATH
        self.logger = logging.getLogger("database")
        
    async def initialize(self):
        """Initialize database and create tables"""
        self.logger.info(f"Initializing database at {self.db_path}")
        
        # Ensure data directory exists
        self.db_path.parent.mkdir(exist_ok=True)
        
        async with aiosqlite.connect(self.db_path) as db:
            await self._create_tables(db)
            await db.commit()
        
        self.logger.info("Database initialized successfully")
    
    async def _create_tables(self, db):
        """Create all necessary tables"""
        
        # Honeypot connections table
        await db.execute("""
            CREATE TABLE IF NOT EXISTS honeypot_connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                source_ip TEXT NOT NULL,
                source_port INTEGER,
                destination_port INTEGER,
                service_type TEXT NOT NULL,
                connection_data TEXT,
                session_id TEXT,
                duration INTEGER,
                bytes_sent INTEGER DEFAULT 0,
                bytes_received INTEGER DEFAULT 0,
                commands TEXT,
                payloads TEXT,
                user_agent TEXT,
                status TEXT DEFAULT 'active'
            )
        """)
        
        # IDS alerts table
        await db.execute("""
            CREATE TABLE IF NOT EXISTS ids_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                source_ip TEXT,
                destination_ip TEXT,
                source_port INTEGER,
                destination_port INTEGER,
                protocol TEXT,
                signature_id TEXT,
                description TEXT,
                raw_data TEXT,
                false_positive BOOLEAN DEFAULT FALSE,
                acknowledged BOOLEAN DEFAULT FALSE
            )
        """)
        
        # Threat intelligence table
        await db.execute("""
            CREATE TABLE IF NOT EXISTS threat_intelligence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
                reputation_score INTEGER,
                country TEXT,
                asn TEXT,
                is_malicious BOOLEAN DEFAULT FALSE,
                threat_types TEXT,
                first_seen DATETIME,
                last_seen DATETIME,
                virustotal_data TEXT,
                abuseipdb_data TEXT,
                whois_data TEXT
            )
        """)
        
        # Attack patterns table
        await db.execute("""
            CREATE TABLE IF NOT EXISTS attack_patterns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                source_ip TEXT NOT NULL,
                attack_type TEXT NOT NULL,
                target_service TEXT,
                pattern_data TEXT,
                frequency INTEGER DEFAULT 1,
                first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # System events table
        await db.execute("""
            CREATE TABLE IF NOT EXISTS system_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                event_type TEXT NOT NULL,
                component TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT,
                details TEXT
            )
        """)
        
        # Create indexes for better performance
        await db.execute("CREATE INDEX IF NOT EXISTS idx_connections_timestamp ON honeypot_connections(timestamp)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_connections_source_ip ON honeypot_connections(source_ip)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON ids_alerts(timestamp)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON ids_alerts(source_ip)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_threat_intel_ip ON threat_intelligence(ip_address)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_patterns_source_ip ON attack_patterns(source_ip)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_patterns_timestamp ON attack_patterns(timestamp)")
    
    async def log_connection(self, connection_data):
        """Log a honeypot connection with accurate timestamp"""
        async with aiosqlite.connect(self.db_path) as db:
            # Use the actual event timestamp if provided, otherwise current time
            timestamp = connection_data.get('timestamp')
            if timestamp:
                # If timestamp is a datetime object, convert to ISO format
                if isinstance(timestamp, datetime):
                    timestamp = timestamp.isoformat()
            else:
                # Use start_time if available, otherwise current time
                start_time = connection_data.get('start_time')
                if start_time:
                    timestamp = start_time.isoformat() if isinstance(start_time, datetime) else start_time
                else:
                    timestamp = datetime.now().isoformat()

            await db.execute("""
                INSERT INTO honeypot_connections
                (timestamp, source_ip, source_port, destination_port, service_type,
                 connection_data, session_id, commands, payloads, user_agent)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                timestamp,
                connection_data.get('source_ip'),
                connection_data.get('source_port'),
                connection_data.get('destination_port'),
                connection_data.get('service_type'),
                str(connection_data.get('connection_data', '')),
                connection_data.get('session_id'),
                str(connection_data.get('commands', [])),
                str(connection_data.get('payloads', [])),
                connection_data.get('user_agent')
            ))
            await db.commit()
    
    async def log_alert(self, alert_data):
        """Log an IDS alert with accurate timestamp"""
        async with aiosqlite.connect(self.db_path) as db:
            # Use the actual event timestamp if provided, otherwise current time
            timestamp = alert_data.get('timestamp')
            if timestamp:
                # If timestamp is a datetime object, convert to ISO format
                if isinstance(timestamp, datetime):
                    timestamp = timestamp.isoformat()
            else:
                timestamp = datetime.now().isoformat()

            await db.execute("""
                INSERT INTO ids_alerts
                (timestamp, alert_type, severity, source_ip, destination_ip,
                 source_port, destination_port, protocol, signature_id,
                 description, raw_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                timestamp,
                alert_data.get('alert_type'),
                alert_data.get('severity'),
                alert_data.get('source_ip'),
                alert_data.get('destination_ip'),
                alert_data.get('source_port'),
                alert_data.get('destination_port'),
                alert_data.get('protocol'),
                alert_data.get('signature_id'),
                alert_data.get('description'),
                str(alert_data.get('raw_data', ''))
            ))
            await db.commit()
    
    async def update_threat_intelligence(self, ip_data):
        """Update threat intelligence for an IP address"""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT OR REPLACE INTO threat_intelligence 
                (ip_address, reputation_score, country, asn, is_malicious, 
                 threat_types, virustotal_data, abuseipdb_data, whois_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                ip_data.get('ip_address'),
                ip_data.get('reputation_score'),
                ip_data.get('country'),
                ip_data.get('asn'),
                ip_data.get('is_malicious', False),
                str(ip_data.get('threat_types', [])),
                str(ip_data.get('virustotal_data', {})),
                str(ip_data.get('abuseipdb_data', {})),
                str(ip_data.get('whois_data', {}))
            ))
            await db.commit()
    
    async def get_recent_connections(self, hours=24, limit=100):
        """Get recent honeypot connections"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("""
                SELECT * FROM honeypot_connections 
                WHERE timestamp > datetime('now', '-{} hours')
                ORDER BY timestamp DESC 
                LIMIT ?
            """.format(hours), (limit,))
            return await cursor.fetchall()
    
    async def get_recent_alerts(self, hours=24, limit=100):
        """Get recent IDS alerts"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("""
                SELECT * FROM ids_alerts 
                WHERE timestamp > datetime('now', '-{} hours')
                ORDER BY timestamp DESC 
                LIMIT ?
            """.format(hours), (limit,))
            return await cursor.fetchall()
    
    async def get_top_attackers(self, hours=24, limit=10):
        """Get top attacking IP addresses"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("""
                SELECT source_ip, COUNT(*) as connection_count
                FROM honeypot_connections 
                WHERE timestamp > datetime('now', '-{} hours')
                GROUP BY source_ip
                ORDER BY connection_count DESC 
                LIMIT ?
            """.format(hours), (limit,))
            return await cursor.fetchall()
    
    async def close(self):
        """Close database connections"""
        # No persistent connections to close in this implementation
        pass

    # Dashboard-specific query methods
    async def count_connections(self, since: datetime) -> int:
        """Count connections since given datetime"""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                cursor = await db.execute(
                    "SELECT COUNT(*) FROM honeypot_connections WHERE timestamp >= ?",
                    (since.isoformat(),)
                )
                result = await cursor.fetchone()
                return result[0] if result else 0
        except Exception as e:
            self.logger.error(f"Error counting connections: {e}")
            return 0

    async def count_alerts(self, since: datetime) -> int:
        """Count alerts since given datetime"""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                cursor = await db.execute(
                    "SELECT COUNT(*) FROM ids_alerts WHERE timestamp >= ?",
                    (since.isoformat(),)
                )
                result = await cursor.fetchone()
                return result[0] if result else 0
        except Exception as e:
            self.logger.error(f"Error counting alerts: {e}")
            return 0

    async def count_unique_ips(self, since: datetime) -> int:
        """Count unique IP addresses since given datetime"""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                cursor = await db.execute(
                    "SELECT COUNT(DISTINCT source_ip) FROM honeypot_connections WHERE timestamp >= ?",
                    (since.isoformat(),)
                )
                result = await cursor.fetchone()
                return result[0] if result else 0
        except Exception as e:
            self.logger.error(f"Error counting unique IPs: {e}")
            return 0

    async def get_recent_connections(self, since: datetime, limit: int = 100) -> list:
        """Get recent connections"""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                db.row_factory = aiosqlite.Row
                cursor = await db.execute(
                    """SELECT source_ip, source_port, destination_port, service_type,
                              session_id, timestamp
                       FROM honeypot_connections
                       WHERE timestamp >= ?
                       ORDER BY timestamp DESC
                       LIMIT ?""",
                    (since.isoformat(), limit)
                )
                rows = await cursor.fetchall()
                return [dict(row) for row in rows]
        except Exception as e:
            self.logger.error(f"Error fetching recent connections: {e}")
            return []

    async def get_recent_alerts(self, since: datetime, limit: int = 50) -> list:
        """Get recent alerts"""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                db.row_factory = aiosqlite.Row
                cursor = await db.execute(
                    """SELECT alert_type, severity, source_ip, destination_ip,
                              description, timestamp
                       FROM ids_alerts
                       WHERE timestamp >= ?
                       ORDER BY timestamp DESC
                       LIMIT ?""",
                    (since.isoformat(), limit)
                )
                rows = await cursor.fetchall()
                return [dict(row) for row in rows]
        except Exception as e:
            self.logger.error(f"Error fetching recent alerts: {e}")
            return []

    async def get_top_attackers(self, since: datetime, limit: int = 10) -> list:
        """Get top attacking IP addresses"""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                cursor = await db.execute(
                    """SELECT source_ip, COUNT(*) as count
                       FROM honeypot_connections
                       WHERE timestamp >= ?
                       GROUP BY source_ip
                       ORDER BY count DESC
                       LIMIT ?""",
                    (since.isoformat(), limit)
                )
                rows = await cursor.fetchall()
                return [{"ip": row[0], "count": row[1]} for row in rows]
        except Exception as e:
            self.logger.error(f"Error fetching top attackers: {e}")
            return []

    async def get_service_breakdown(self, since: datetime) -> dict:
        """Get breakdown of connections by service type"""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                cursor = await db.execute(
                    """SELECT service_type, COUNT(*) as count
                       FROM honeypot_connections
                       WHERE timestamp >= ?
                       GROUP BY service_type""",
                    (since.isoformat(),)
                )
                rows = await cursor.fetchall()
                return {row[0]: row[1] for row in rows}
        except Exception as e:
            self.logger.error(f"Error fetching service breakdown: {e}")
            return {}

    async def get_hourly_activity(self, since: datetime) -> list:
        """Get hourly activity breakdown"""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                cursor = await db.execute(
                    """SELECT strftime('%H', timestamp) as hour, COUNT(*) as count
                       FROM honeypot_connections
                       WHERE timestamp >= ?
                       GROUP BY hour
                       ORDER BY hour""",
                    (since.isoformat(),)
                )
                rows = await cursor.fetchall()
                return [{"hour": int(row[0]), "count": row[1]} for row in rows]
        except Exception as e:
            self.logger.error(f"Error fetching hourly activity: {e}")
            return []

    async def get_alert_severity_breakdown(self, since: datetime) -> dict:
        """Get breakdown of alerts by severity"""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                cursor = await db.execute(
                    """SELECT severity, COUNT(*) as count
                       FROM ids_alerts
                       WHERE timestamp >= ?
                       GROUP BY severity""",
                    (since.isoformat(),)
                )
                rows = await cursor.fetchall()
                return {row[0]: row[1] for row in rows}
        except Exception as e:
            self.logger.error(f"Error fetching alert severity breakdown: {e}")
            return {}

    # Enhanced Log Management Methods
    async def clear_all_logs(self):
        """Clear all honeypot connections and IDS alerts"""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("DELETE FROM honeypot_connections")
                await db.execute("DELETE FROM ids_alerts")
                await db.commit()
                self.logger.info("All logs cleared successfully")
                return True
        except Exception as e:
            self.logger.error(f"Error clearing logs: {e}")
            return False

    async def clear_connections_only(self):
        """Clear only honeypot connections"""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("DELETE FROM honeypot_connections")
                await db.commit()
                self.logger.info("Honeypot connections cleared successfully")
                return True
        except Exception as e:
            self.logger.error(f"Error clearing connections: {e}")
            return False

    async def clear_alerts_only(self):
        """Clear only IDS alerts"""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("DELETE FROM ids_alerts")
                await db.commit()
                self.logger.info("IDS alerts cleared successfully")
                return True
        except Exception as e:
            self.logger.error(f"Error clearing alerts: {e}")
            return False

    async def get_filtered_connections(self, filters=None, limit=100):
        """Get connections with advanced filtering"""
        try:
            query = """
                SELECT source_ip, source_port, destination_port, service_type,
                       session_id, timestamp, connection_data, commands, payloads
                FROM honeypot_connections
            """
            params = []
            conditions = []

            if filters:
                if filters.get('ip'):
                    conditions.append("source_ip LIKE ?")
                    params.append(f"%{filters['ip']}%")
                if filters.get('service'):
                    conditions.append("service_type = ?")
                    params.append(filters['service'])
                if filters.get('start_time'):
                    conditions.append("timestamp >= ?")
                    params.append(filters['start_time'])
                if filters.get('end_time'):
                    conditions.append("timestamp <= ?")
                    params.append(filters['end_time'])
                if filters.get('session_id'):
                    conditions.append("session_id LIKE ?")
                    params.append(f"%{filters['session_id']}%")

            if conditions:
                query += " WHERE " + " AND ".join(conditions)

            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)

            async with aiosqlite.connect(self.db_path) as db:
                db.row_factory = aiosqlite.Row
                cursor = await db.execute(query, params)
                rows = await cursor.fetchall()
                return [dict(row) for row in rows]

        except Exception as e:
            self.logger.error(f"Error getting filtered connections: {e}")
            return []

    async def get_filtered_alerts(self, filters=None, limit=100):
        """Get alerts with advanced filtering"""
        try:
            query = """
                SELECT alert_type, severity, source_ip, destination_ip,
                       source_port, destination_port, protocol, signature_id,
                       description, timestamp, raw_data
                FROM ids_alerts
            """
            params = []
            conditions = []

            if filters:
                if filters.get('ip'):
                    conditions.append("(source_ip LIKE ? OR destination_ip LIKE ?)")
                    params.extend([f"%{filters['ip']}%", f"%{filters['ip']}%"])
                if filters.get('severity'):
                    conditions.append("severity = ?")
                    params.append(filters['severity'])
                if filters.get('alert_type'):
                    conditions.append("alert_type LIKE ?")
                    params.append(f"%{filters['alert_type']}%")
                if filters.get('start_time'):
                    conditions.append("timestamp >= ?")
                    params.append(filters['start_time'])
                if filters.get('end_time'):
                    conditions.append("timestamp <= ?")
                    params.append(filters['end_time'])

            if conditions:
                query += " WHERE " + " AND ".join(conditions)

            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)

            async with aiosqlite.connect(self.db_path) as db:
                db.row_factory = aiosqlite.Row
                cursor = await db.execute(query, params)
                rows = await cursor.fetchall()
                return [dict(row) for row in rows]

        except Exception as e:
            self.logger.error(f"Error getting filtered alerts: {e}")
            return []

    async def export_connections_to_csv(self, filters=None):
        """Export connections to CSV format"""
        try:
            connections = await self.get_filtered_connections(filters, limit=10000)

            if not connections:
                return None

            import csv
            import io

            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=connections[0].keys())
            writer.writeheader()
            writer.writerows(connections)

            return output.getvalue()

        except Exception as e:
            self.logger.error(f"Error exporting connections to CSV: {e}")
            return None

    async def export_alerts_to_csv(self, filters=None):
        """Export alerts to CSV format"""
        try:
            alerts = await self.get_filtered_alerts(filters, limit=10000)

            if not alerts:
                return None

            import csv
            import io

            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=alerts[0].keys())
            writer.writeheader()
            writer.writerows(alerts)

            return output.getvalue()

        except Exception as e:
            self.logger.error(f"Error exporting alerts to CSV: {e}")
            return None

    async def get_attack_timeline(self, hours=24):
        """Get attack timeline data for visualization"""
        try:
            since = datetime.now() - timedelta(hours=hours)

            async with aiosqlite.connect(self.db_path) as db:
                cursor = await db.execute("""
                    SELECT
                        strftime('%Y-%m-%d %H:00:00', timestamp) as hour,
                        COUNT(*) as connection_count,
                        COUNT(DISTINCT source_ip) as unique_ips,
                        service_type
                    FROM honeypot_connections
                    WHERE timestamp >= ?
                    GROUP BY hour, service_type
                    ORDER BY hour
                """, (since.isoformat(),))

                rows = await cursor.fetchall()
                timeline_data = []
                for row in rows:
                    timeline_data.append({
                        'hour': row[0],
                        'connection_count': row[1],
                        'unique_ips': row[2],
                        'service_type': row[3]
                    })

                return timeline_data

        except Exception as e:
            self.logger.error(f"Error getting attack timeline: {e}")
            return []

    async def get_threat_summary(self, hours=24):
        """Get comprehensive threat summary"""
        try:
            since = datetime.now() - timedelta(hours=hours)

            async with aiosqlite.connect(self.db_path) as db:
                # Get connection summary
                cursor = await db.execute("""
                    SELECT
                        COUNT(*) as total_connections,
                        COUNT(DISTINCT source_ip) as unique_attackers,
                        service_type
                    FROM honeypot_connections
                    WHERE timestamp >= ?
                    GROUP BY service_type
                """, (since.isoformat(),))

                connection_summary = await cursor.fetchall()

                # Get alert summary
                cursor = await db.execute("""
                    SELECT
                        COUNT(*) as total_alerts,
                        severity,
                        alert_type
                    FROM ids_alerts
                    WHERE timestamp >= ?
                    GROUP BY severity, alert_type
                """, (since.isoformat(),))

                alert_summary = await cursor.fetchall()

                return {
                    'connections': [dict(zip(['total_connections', 'unique_attackers', 'service_type'], row))
                                  for row in connection_summary],
                    'alerts': [dict(zip(['total_alerts', 'severity', 'alert_type'], row))
                             for row in alert_summary],
                    'period_hours': hours,
                    'generated_at': datetime.now().isoformat()
                }

        except Exception as e:
            self.logger.error(f"Error getting threat summary: {e}")
            return {'connections': [], 'alerts': [], 'period_hours': hours}
