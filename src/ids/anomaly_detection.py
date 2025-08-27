"""
Anomaly detection module for PHIDS
"""
import asyncio
import logging
import statistics
from datetime import datetime, timedelta
from collections import defaultdict, deque
from config import IDS_CONFIG


class AnomalyDetector:
    """Anomaly-based intrusion detection"""
    
    def __init__(self):
        self.logger = logging.getLogger("anomaly_detector")
        self.config = IDS_CONFIG['anomaly_detection']
        
        # Baseline tracking
        self.baselines = {
            'packet_rate': deque(maxlen=100),
            'connection_rate': deque(maxlen=100),
            'port_distribution': defaultdict(int),
            'ip_frequency': defaultdict(int),
            'payload_sizes': deque(maxlen=1000)
        }
        
        # Anomaly thresholds
        self.thresholds = {
            'packet_rate': self.config.get('packet_rate_threshold', 100),
            'connection_rate': self.config.get('connection_rate_threshold', 50),
            'unusual_port': self.config.get('unusual_port_threshold', 10)
        }
        
        # Statistics
        self.stats = {
            'anomalies_detected': 0,
            'baseline_samples': 0,
            'last_analysis': None
        }
        
        # Time windows for analysis
        self.time_windows = {
            'short': 60,    # 1 minute
            'medium': 300,  # 5 minutes
            'long': 3600    # 1 hour
        }
        
        # Recent activity tracking
        self.recent_activity = {
            'connections': deque(maxlen=1000),
            'packets': deque(maxlen=5000),
            'alerts': deque(maxlen=500)
        }
    
    async def initialize(self):
        """Initialize anomaly detector"""
        self.logger.info("Initializing anomaly detector")
        
        # Start baseline learning
        asyncio.create_task(self._learn_baseline())
        
        self.logger.info("Anomaly detector initialized")
    
    async def analyze_connection(self, connection_data):
        """Analyze connection for anomalies"""
        anomalies = []
        current_time = datetime.now()
        
        try:
            # Record connection
            self.recent_activity['connections'].append({
                'timestamp': current_time,
                'source_ip': connection_data.get('source_ip'),
                'destination_port': connection_data.get('destination_port'),
                'service_type': connection_data.get('service_type'),
                'duration': connection_data.get('duration', 0),
                'bytes_sent': connection_data.get('bytes_sent', 0),
                'bytes_received': connection_data.get('bytes_received', 0)
            })
            
            # Check for various anomalies
            anomalies.extend(await self._detect_connection_rate_anomaly(connection_data))
            anomalies.extend(await self._detect_unusual_port_activity(connection_data))
            anomalies.extend(await self._detect_payload_size_anomaly(connection_data))
            anomalies.extend(await self._detect_behavioral_anomaly(connection_data))
            
            # Update statistics
            if anomalies:
                self.stats['anomalies_detected'] += len(anomalies)
            
            self.stats['last_analysis'] = current_time
            
        except Exception as e:
            self.logger.error(f"Error in anomaly analysis: {e}")
        
        return anomalies
    
    async def analyze_statistics(self, packet_stats):
        """Analyze packet statistics for anomalies"""
        anomalies = []
        current_time = datetime.now()
        
        try:
            # Analyze packet rate
            total_packets = packet_stats.get('total_packets', 0)
            if self.baselines['packet_rate']:
                avg_rate = statistics.mean(self.baselines['packet_rate'])
                if total_packets > avg_rate * 3:  # 3x normal rate
                    anomalies.append({
                        'type': 'high_packet_rate',
                        'severity': 'medium',
                        'description': f'Unusually high packet rate: {total_packets} (normal: {avg_rate:.1f})',
                        'timestamp': current_time,
                        'value': total_packets,
                        'baseline': avg_rate
                    })
            
            # Analyze port distribution
            port_anomalies = await self._analyze_port_distribution(packet_stats)
            anomalies.extend(port_anomalies)
            
            # Analyze IP frequency
            ip_anomalies = await self._analyze_ip_frequency(packet_stats)
            anomalies.extend(ip_anomalies)
            
            # Update baselines
            self.baselines['packet_rate'].append(total_packets)
            
        except Exception as e:
            self.logger.error(f"Error analyzing statistics: {e}")
        
        return anomalies
    
    async def _detect_connection_rate_anomaly(self, connection_data):
        """Detect anomalous connection rates"""
        anomalies = []
        source_ip = connection_data.get('source_ip')
        current_time = datetime.now()
        
        # Count recent connections from this IP
        recent_connections = [
            conn for conn in self.recent_activity['connections']
            if conn['source_ip'] == source_ip and
               (current_time - conn['timestamp']).total_seconds() <= self.time_windows['short']
        ]
        
        connection_rate = len(recent_connections)
        
        if connection_rate > self.thresholds['connection_rate']:
            anomalies.append({
                'type': 'high_connection_rate',
                'severity': 'high',
                'description': f'High connection rate from {source_ip}: {connection_rate} connections/minute',
                'source_ip': source_ip,
                'timestamp': current_time,
                'value': connection_rate,
                'threshold': self.thresholds['connection_rate']
            })
        
        return anomalies
    
    async def _detect_unusual_port_activity(self, connection_data):
        """Detect unusual port access patterns"""
        anomalies = []
        source_ip = connection_data.get('source_ip')
        destination_port = connection_data.get('destination_port')
        current_time = datetime.now()
        
        # Track unique ports accessed by this IP
        recent_connections = [
            conn for conn in self.recent_activity['connections']
            if conn['source_ip'] == source_ip and
               (current_time - conn['timestamp']).total_seconds() <= self.time_windows['medium']
        ]
        
        unique_ports = set(conn['destination_port'] for conn in recent_connections if conn['destination_port'])
        
        if len(unique_ports) > self.thresholds['unusual_port']:
            anomalies.append({
                'type': 'port_scanning',
                'severity': 'medium',
                'description': f'Potential port scan from {source_ip}: {len(unique_ports)} unique ports accessed',
                'source_ip': source_ip,
                'timestamp': current_time,
                'value': len(unique_ports),
                'threshold': self.thresholds['unusual_port'],
                'ports': list(unique_ports)
            })
        
        # Check for access to unusual ports
        unusual_ports = [21, 23, 135, 139, 445, 1433, 3389, 5432, 5900]
        if destination_port in unusual_ports:
            anomalies.append({
                'type': 'unusual_port_access',
                'severity': 'medium',
                'description': f'Access to unusual port {destination_port} from {source_ip}',
                'source_ip': source_ip,
                'timestamp': current_time,
                'port': destination_port
            })
        
        return anomalies
    
    async def _detect_payload_size_anomaly(self, connection_data):
        """Detect unusual payload sizes"""
        anomalies = []
        
        bytes_sent = connection_data.get('bytes_sent', 0)
        bytes_received = connection_data.get('bytes_received', 0)
        total_bytes = bytes_sent + bytes_received
        
        if total_bytes > 0:
            self.baselines['payload_sizes'].append(total_bytes)
            
            # Check if we have enough baseline data
            if len(self.baselines['payload_sizes']) > 50:
                avg_size = statistics.mean(self.baselines['payload_sizes'])
                std_dev = statistics.stdev(self.baselines['payload_sizes'])
                
                # Detect unusually large payloads (3 standard deviations)
                if total_bytes > avg_size + (3 * std_dev):
                    anomalies.append({
                        'type': 'large_payload',
                        'severity': 'low',
                        'description': f'Unusually large payload: {total_bytes} bytes (normal: {avg_size:.1f}±{std_dev:.1f})',
                        'source_ip': connection_data.get('source_ip'),
                        'timestamp': datetime.now(),
                        'value': total_bytes,
                        'baseline': avg_size
                    })
        
        return anomalies
    
    async def _detect_behavioral_anomaly(self, connection_data):
        """Detect behavioral anomalies"""
        anomalies = []
        source_ip = connection_data.get('source_ip')
        service_type = connection_data.get('service_type')
        current_time = datetime.now()
        
        # Analyze connection duration patterns
        duration = connection_data.get('duration', 0)
        
        # Very short connections might indicate scanning
        if duration < 1 and service_type in ['ssh', 'http']:
            anomalies.append({
                'type': 'short_connection',
                'severity': 'low',
                'description': f'Very short {service_type} connection from {source_ip}: {duration}s',
                'source_ip': source_ip,
                'timestamp': current_time,
                'duration': duration,
                'service_type': service_type
            })
        
        # Analyze command patterns for SSH
        if service_type == 'ssh':
            commands = connection_data.get('commands', [])
            if isinstance(commands, list) and len(commands) > 20:
                anomalies.append({
                    'type': 'excessive_commands',
                    'severity': 'medium',
                    'description': f'Excessive SSH commands from {source_ip}: {len(commands)} commands',
                    'source_ip': source_ip,
                    'timestamp': current_time,
                    'command_count': len(commands)
                })
        
        return anomalies
    
    async def _analyze_port_distribution(self, packet_stats):
        """Analyze port access distribution"""
        anomalies = []
        
        # Extract port statistics
        port_stats = {
            key.replace('dst_port_', ''): value
            for key, value in packet_stats.items()
            if key.startswith('dst_port_')
        }
        
        # Update port distribution baseline
        for port, count in port_stats.items():
            self.baselines['port_distribution'][port] += count
        
        # Detect unusual port activity
        total_connections = sum(port_stats.values())
        if total_connections > 0:
            for port, count in port_stats.items():
                percentage = (count / total_connections) * 100
                
                # Alert if single port receives >80% of traffic
                if percentage > 80:
                    anomalies.append({
                        'type': 'port_concentration',
                        'severity': 'medium',
                        'description': f'High concentration of traffic on port {port}: {percentage:.1f}%',
                        'timestamp': datetime.now(),
                        'port': port,
                        'percentage': percentage
                    })
        
        return anomalies
    
    async def _analyze_ip_frequency(self, packet_stats):
        """Analyze IP address frequency patterns"""
        anomalies = []
        
        # Extract IP statistics
        ip_stats = {
            key.replace('src_ip_', ''): value
            for key, value in packet_stats.items()
            if key.startswith('src_ip_')
        }
        
        # Update IP frequency baseline
        for ip, count in ip_stats.items():
            self.baselines['ip_frequency'][ip] += count
        
        # Detect IPs with unusually high activity
        total_packets = sum(ip_stats.values())
        if total_packets > 0:
            for ip, count in ip_stats.items():
                percentage = (count / total_packets) * 100
                
                # Alert if single IP generates >50% of traffic
                if percentage > 50:
                    anomalies.append({
                        'type': 'ip_concentration',
                        'severity': 'high',
                        'description': f'High traffic concentration from {ip}: {percentage:.1f}%',
                        'source_ip': ip,
                        'timestamp': datetime.now(),
                        'percentage': percentage,
                        'packet_count': count
                    })
        
        return anomalies
    
    async def _learn_baseline(self):
        """Continuously learn baseline behavior"""
        while True:
            try:
                await asyncio.sleep(300)  # Update baseline every 5 minutes
                
                # Clean old data
                current_time = datetime.now()
                cutoff_time = current_time - timedelta(hours=24)
                
                # Clean recent activity
                self.recent_activity['connections'] = deque(
                    [conn for conn in self.recent_activity['connections']
                     if conn['timestamp'] > cutoff_time],
                    maxlen=1000
                )
                
                # Update baseline samples count
                self.stats['baseline_samples'] += 1
                
                self.logger.debug(f"Updated baseline (sample #{self.stats['baseline_samples']})")
                
            except Exception as e:
                self.logger.error(f"Error updating baseline: {e}")
                await asyncio.sleep(600)  # Wait longer on error
    
    def get_statistics(self):
        """Get anomaly detector statistics"""
        return {
            'anomalies_detected': self.stats['anomalies_detected'],
            'baseline_samples': self.stats['baseline_samples'],
            'last_analysis': self.stats['last_analysis'],
            'baseline_sizes': {
                'packet_rate': len(self.baselines['packet_rate']),
                'connection_rate': len(self.baselines['connection_rate']),
                'payload_sizes': len(self.baselines['payload_sizes'])
            },
            'thresholds': self.thresholds,
            'recent_activity_counts': {
                'connections': len(self.recent_activity['connections']),
                'packets': len(self.recent_activity['packets']),
                'alerts': len(self.recent_activity['alerts'])
            }
        }
    
    def clear_baselines(self):
        """Clear all baseline data"""
        for baseline in self.baselines.values():
            if hasattr(baseline, 'clear'):
                baseline.clear()
        
        for activity in self.recent_activity.values():
            activity.clear()
        
        self.stats['baseline_samples'] = 0
        self.logger.info("Cleared all baseline data")
