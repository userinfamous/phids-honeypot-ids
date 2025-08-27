"""
Main IDS Engine for PHIDS
"""
import asyncio
import logging
from datetime import datetime, timedelta
from config import IDS_CONFIG
from src.core.database import DatabaseManager
from src.capture.packet_capture import PacketCapture
from .signatures import SignatureEngine
from .anomaly_detection import AnomalyDetector


class IDSEngine:
    """Main Intrusion Detection System Engine"""
    
    def __init__(self):
        self.logger = logging.getLogger("ids")
        self.db_manager = DatabaseManager()
        self.signature_engine = SignatureEngine()
        self.anomaly_detector = AnomalyDetector()
        self.packet_capture = PacketCapture()
        self.running = False
        
        # Configuration
        self.config = IDS_CONFIG
        
        # Statistics
        self.stats = {
            'alerts_generated': 0,
            'connections_analyzed': 0,
            'packets_processed': 0,
            'start_time': None
        }
    
    async def initialize(self):
        """Initialize IDS engine"""
        self.logger.info("Initializing IDS engine")
        
        # Initialize components
        if self.config['signature_detection']['enabled']:
            self.logger.info("Signature detection enabled")
        
        if self.config['anomaly_detection']['enabled']:
            self.logger.info("Anomaly detection enabled")
            await self.anomaly_detector.initialize()
        
        self.logger.info("IDS engine initialized successfully")
    
    async def start(self):
        """Start IDS engine"""
        if self.running:
            self.logger.warning("IDS engine already running")
            return
        
        self.logger.info("Starting IDS engine")
        self.running = True
        self.stats['start_time'] = datetime.now()
        
        # Start packet capture
        await self.packet_capture.start()
        
        # Start monitoring tasks
        tasks = []
        
        if self.config['signature_detection']['enabled']:
            tasks.append(asyncio.create_task(self._monitor_connections()))
        
        if self.config['anomaly_detection']['enabled']:
            tasks.append(asyncio.create_task(self._monitor_anomalies()))
        
        # Start statistics reporting
        tasks.append(asyncio.create_task(self._report_statistics()))
        
        self.logger.info("IDS engine started successfully")
        
        # Wait for all monitoring tasks
        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            self.logger.info("IDS engine monitoring cancelled")
    
    async def stop(self):
        """Stop IDS engine"""
        self.logger.info("Stopping IDS engine")
        self.running = False
        
        # Stop packet capture
        await self.packet_capture.stop()
        
        self.logger.info("IDS engine stopped")
    
    async def analyze_connection(self, connection_data):
        """Analyze a connection for threats"""
        try:
            self.stats['connections_analyzed'] += 1
            alerts = []
            
            # Signature-based detection
            if self.config['signature_detection']['enabled']:
                sig_alerts = self.signature_engine.analyze_connection(connection_data)
                for alert in sig_alerts:
                    await self._process_alert(alert, connection_data)
                    alerts.extend(sig_alerts)
            
            # Anomaly-based detection
            if self.config['anomaly_detection']['enabled']:
                anomaly_alerts = await self.anomaly_detector.analyze_connection(connection_data)
                for alert in anomaly_alerts:
                    await self._process_alert(alert, connection_data)
                    alerts.extend(anomaly_alerts)
            
            return alerts
            
        except Exception as e:
            self.logger.error(f"Error analyzing connection: {e}")
            return []
    
    async def _process_alert(self, alert, connection_data):
        """Process and store an alert"""
        try:
            # Enhance alert with connection data
            alert_data = {
                'alert_type': alert.get('name', 'Unknown'),
                'severity': alert.get('severity', 'medium'),
                'source_ip': connection_data.get('source_ip'),
                'destination_ip': connection_data.get('destination_ip', 'honeypot'),
                'source_port': connection_data.get('source_port'),
                'destination_port': connection_data.get('destination_port'),
                'protocol': connection_data.get('service_type', 'unknown'),
                'signature_id': alert.get('signature_id', ''),
                'description': alert.get('description', ''),
                'raw_data': str(connection_data)
            }
            
            # Store alert in database
            await self.db_manager.log_alert(alert_data)
            
            # Add to signature engine history
            self.signature_engine.add_alert_to_history(alert)
            
            # Update statistics
            self.stats['alerts_generated'] += 1
            
            # Log alert
            self.logger.warning(
                f"ALERT: {alert_data['alert_type']} from {alert_data['source_ip']} "
                f"(Severity: {alert_data['severity']})"
            )
            
        except Exception as e:
            self.logger.error(f"Error processing alert: {e}")
    
    async def _monitor_connections(self):
        """Monitor honeypot connections for threats"""
        self.logger.info("Starting connection monitoring")
        
        while self.running:
            try:
                # Get recent connections from database
                since = datetime.now() - timedelta(hours=1)
                recent_connections = await self.db_manager.get_recent_connections(since, limit=50)
                
                for connection in recent_connections:
                    # Convert database row to dict
                    connection_data = dict(connection)
                    
                    # Analyze connection
                    await self.analyze_connection(connection_data)
                
                # Wait before next check
                await asyncio.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                self.logger.error(f"Error in connection monitoring: {e}")
                await asyncio.sleep(60)  # Wait longer on error
    
    async def _monitor_anomalies(self):
        """Monitor for anomalous behavior"""
        self.logger.info("Starting anomaly monitoring")
        
        while self.running:
            try:
                # Get packet capture statistics
                packet_stats = self.packet_capture.get_statistics()
                self.stats['packets_processed'] = packet_stats.get('total_packets', 0)
                
                # Analyze for anomalies
                anomalies = await self.anomaly_detector.analyze_statistics(packet_stats)
                
                for anomaly in anomalies:
                    # Create alert for anomaly
                    alert_data = {
                        'alert_type': 'anomaly_detection',
                        'severity': anomaly.get('severity', 'medium'),
                        'source_ip': anomaly.get('source_ip', 'multiple'),
                        'destination_ip': 'honeypot',
                        'protocol': 'network',
                        'signature_id': 'PHIDS_ANOMALY',
                        'description': anomaly.get('description', 'Anomalous behavior detected'),
                        'raw_data': str(anomaly)
                    }
                    
                    await self.db_manager.log_alert(alert_data)
                    self.stats['alerts_generated'] += 1
                    
                    self.logger.warning(f"ANOMALY: {alert_data['description']}")
                
                # Wait before next check
                await asyncio.sleep(60)  # Check every minute
                
            except Exception as e:
                self.logger.error(f"Error in anomaly monitoring: {e}")
                await asyncio.sleep(120)  # Wait longer on error
    
    async def _report_statistics(self):
        """Periodically report IDS statistics"""
        while self.running:
            try:
                # Log statistics every 5 minutes
                await asyncio.sleep(300)
                
                if self.stats['start_time']:
                    uptime = datetime.now() - self.stats['start_time']
                    self.logger.info(
                        f"IDS Stats - Uptime: {uptime}, "
                        f"Connections: {self.stats['connections_analyzed']}, "
                        f"Packets: {self.stats['packets_processed']}, "
                        f"Alerts: {self.stats['alerts_generated']}"
                    )
                
            except Exception as e:
                self.logger.error(f"Error reporting statistics: {e}")
    
    def get_statistics(self):
        """Get current IDS statistics"""
        stats = self.stats.copy()
        
        # Add signature statistics
        stats['signature_stats'] = self.signature_engine.get_signature_stats()
        
        # Add packet capture statistics
        stats['packet_stats'] = self.packet_capture.get_statistics()
        
        # Add anomaly detector statistics
        if hasattr(self.anomaly_detector, 'get_statistics'):
            stats['anomaly_stats'] = self.anomaly_detector.get_statistics()
        
        return stats
    
    async def get_recent_alerts(self, hours=24, limit=100):
        """Get recent alerts"""
        return await self.db_manager.get_recent_alerts(hours, limit)
    
    async def get_top_attackers(self, hours=24, limit=10):
        """Get top attacking IP addresses"""
        return await self.db_manager.get_top_attackers(hours, limit)
