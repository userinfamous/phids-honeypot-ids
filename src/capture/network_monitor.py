#!/usr/bin/env python3
"""
Real Network Traffic Monitoring Module
Captures and analyzes live network traffic for genuine threat detection
"""

import asyncio
import logging
import socket
import struct
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional, Callable
import json

try:
    from scapy.all import sniff, IP, TCP, UDP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("⚠️ Scapy not available. Install with: pip install scapy")

from ..core.database import DatabaseManager
from ..ids.engine import IDSEngine


class NetworkMonitor:
    """Real-time network traffic monitor for live threat detection"""
    
    def __init__(self, db_manager: DatabaseManager, ids_engine: IDSEngine):
        self.db_manager = db_manager
        self.ids_engine = ids_engine
        self.logger = logging.getLogger(__name__)
        
        # Monitoring configuration
        self.is_monitoring = False
        self.monitor_thread = None
        self.packet_count = 0
        self.threat_count = 0
        
        # Network interfaces and filters
        self.interface = None
        # Only monitor traffic to/from honeypot ports to avoid background noise
        self.packet_filter = "tcp port 2222 or tcp port 8080"
        
        # Callbacks for real-time updates
        self.threat_callbacks: List[Callable] = []
        
        # Statistics
        self.stats = {
            'packets_captured': 0,
            'threats_detected': 0,
            'connections_monitored': 0,
            'start_time': None
        }
    
    def add_threat_callback(self, callback: Callable):
        """Add callback function for real-time threat notifications"""
        self.threat_callbacks.append(callback)
    
    async def start_monitoring(self, interface: str = None, packet_filter: str = None):
        """Start real-time network monitoring"""
        if not SCAPY_AVAILABLE:
            self.logger.error("Scapy not available. Cannot start network monitoring.")
            return False
        
        if self.is_monitoring:
            self.logger.warning("Network monitoring already active")
            return True
        
        self.interface = interface
        if packet_filter:
            self.packet_filter = packet_filter
        
        self.is_monitoring = True
        self.stats['start_time'] = datetime.now()
        
        # Start monitoring in separate thread
        self.monitor_thread = threading.Thread(
            target=self._monitor_network_traffic,
            daemon=True
        )
        self.monitor_thread.start()
        
        self.logger.info(f"Started network monitoring on interface: {interface or 'default'}")
        return True
    
    def stop_monitoring(self):
        """Stop network monitoring"""
        self.is_monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        
        self.logger.info("Stopped network monitoring")
    
    def _monitor_network_traffic(self):
        """Monitor network traffic using Scapy"""
        try:
            self.logger.info(f"Starting packet capture with filter: {self.packet_filter}")
            
            sniff(
                iface=self.interface,
                filter=self.packet_filter,
                prn=self._process_packet,
                stop_filter=lambda x: not self.is_monitoring,
                store=False
            )
            
        except Exception as e:
            self.logger.error(f"Network monitoring error: {e}")
            self.is_monitoring = False
    
    def _process_packet(self, packet):
        """Process captured network packet"""
        try:
            self.packet_count += 1
            self.stats['packets_captured'] += 1
            
            # Extract packet information
            packet_info = self._extract_packet_info(packet)
            if not packet_info:
                return
            
            # Check if this is targeting our honeypots
            if self._is_honeypot_traffic(packet_info):
                self._schedule_async_task(self._handle_honeypot_traffic(packet_info))

            # Analyze for threats
            threats = self._analyze_packet_for_threats(packet_info)
            if threats:
                self.threat_count += len(threats)
                self.stats['threats_detected'] += len(threats)

                for threat in threats:
                    self._schedule_async_task(self._handle_threat_detection(threat))
        
        except Exception as e:
            self.logger.error(f"Error processing packet: {e}")

    def _schedule_async_task(self, coro):
        """Schedule async task from thread context"""
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(coro)
        except RuntimeError:
            # No event loop running, run in new thread
            def run_async():
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(coro)
                loop.close()
            threading.Thread(target=run_async, daemon=True).start()

    def _extract_packet_info(self, packet) -> Optional[Dict]:
        """Extract relevant information from network packet"""
        try:
            if not packet.haslayer(IP):
                return None
            
            ip_layer = packet[IP]
            packet_info = {
                'timestamp': datetime.now().isoformat(),
                'src_ip': ip_layer.src,
                'dst_ip': ip_layer.dst,
                'protocol': ip_layer.proto,
                'packet_size': len(packet),
                'is_live_traffic': True  # Mark as real network traffic
            }
            
            # Add transport layer information
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                packet_info.update({
                    'src_port': tcp_layer.sport,
                    'dst_port': tcp_layer.dport,
                    'transport': 'tcp',
                    'flags': tcp_layer.flags
                })
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                packet_info.update({
                    'src_port': udp_layer.sport,
                    'dst_port': udp_layer.dport,
                    'transport': 'udp'
                })
            
            # Extract payload if available
            if packet.haslayer(Raw):
                payload = packet[Raw].load
                try:
                    packet_info['payload'] = payload.decode('utf-8', errors='ignore')[:1000]
                except:
                    packet_info['payload'] = str(payload)[:1000]
            
            return packet_info
            
        except Exception as e:
            self.logger.error(f"Error extracting packet info: {e}")
            return None
    
    def _is_honeypot_traffic(self, packet_info: Dict) -> bool:
        """Check if packet is targeting our honeypots"""
        honeypot_ports = [2222, 8080]  # SSH and HTTP honeypot ports
        
        return (
            packet_info.get('dst_port') in honeypot_ports or
            packet_info.get('src_port') in honeypot_ports
        )
    
    async def _handle_honeypot_traffic(self, packet_info: Dict):
        """Handle traffic targeting honeypots"""
        try:
            # Log as honeypot connection
            connection_data = {
                'source_ip': packet_info['src_ip'],
                'source_port': packet_info.get('src_port', 0),
                'destination_port': packet_info.get('dst_port', 0),
                'service_type': 'ssh' if packet_info.get('dst_port') == 2222 else 'http',
                'session_id': f"live-{packet_info['src_ip']}-{int(time.time())}",
                'timestamp': packet_info['timestamp'],
                'connection_data': json.dumps(packet_info),
                'commands': packet_info.get('payload', ''),
                'payloads': packet_info.get('payload', ''),
                'is_live_traffic': True
            }
            
            await self.db_manager.log_connection(connection_data)
            self.stats['connections_monitored'] += 1
            
            self.logger.info(f"Live honeypot traffic: {packet_info['src_ip']} -> {packet_info['dst_ip']}:{packet_info.get('dst_port')}")
            
        except Exception as e:
            self.logger.error(f"Error handling honeypot traffic: {e}")
    
    def _analyze_packet_for_threats(self, packet_info: Dict) -> List[Dict]:
        """Analyze packet for potential threats"""
        threats = []
        
        try:
            payload = packet_info.get('payload', '')
            if not payload:
                return threats
            
            # Use IDS engine for threat detection
            if self.ids_engine:
                alerts = asyncio.run(self.ids_engine.analyze_payload(payload))
                for alert in alerts:
                    threat = {
                        'alert_type': alert.get('signature_name', 'Unknown'),
                        'severity': alert.get('severity', 'medium'),
                        'source_ip': packet_info['src_ip'],
                        'destination_ip': packet_info['dst_ip'],
                        'source_port': packet_info.get('src_port', 0),
                        'destination_port': packet_info.get('dst_port', 0),
                        'protocol': packet_info.get('transport', 'unknown'),
                        'signature_id': alert.get('signature_id', 0),
                        'description': alert.get('description', 'Live network threat detected'),
                        'timestamp': packet_info['timestamp'],
                        'raw_data': payload[:500],
                        'is_live_traffic': True
                    }
                    threats.append(threat)
            
            # Additional live traffic analysis
            if self._is_suspicious_traffic(packet_info):
                threat = {
                    'alert_type': 'Suspicious Network Activity',
                    'severity': 'medium',
                    'source_ip': packet_info['src_ip'],
                    'destination_ip': packet_info['dst_ip'],
                    'source_port': packet_info.get('src_port', 0),
                    'destination_port': packet_info.get('dst_port', 0),
                    'protocol': packet_info.get('transport', 'unknown'),
                    'signature_id': 9999,
                    'description': 'Suspicious network traffic pattern detected',
                    'timestamp': packet_info['timestamp'],
                    'raw_data': payload[:500],
                    'is_live_traffic': True
                }
                threats.append(threat)
            
        except Exception as e:
            self.logger.error(f"Error analyzing packet for threats: {e}")
        
        return threats
    
    def _is_suspicious_traffic(self, packet_info: Dict) -> bool:
        """Detect suspicious traffic patterns"""
        payload = packet_info.get('payload', '').lower()
        
        # Simple heuristics for suspicious activity
        suspicious_patterns = [
            'select * from',
            '<script>',
            'union select',
            '../../../',
            'cmd.exe',
            '/bin/bash',
            'wget http',
            'curl http'
        ]
        
        return any(pattern in payload for pattern in suspicious_patterns)
    
    async def _handle_threat_detection(self, threat: Dict):
        """Handle detected threat"""
        try:
            # Log threat to database
            await self.db_manager.log_alert(threat)
            
            # Notify callbacks
            for callback in self.threat_callbacks:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        await callback(threat)
                    else:
                        callback(threat)
                except Exception as e:
                    self.logger.error(f"Error in threat callback: {e}")
            
            self.logger.warning(f"Live threat detected: {threat['alert_type']} from {threat['source_ip']}")
            
        except Exception as e:
            self.logger.error(f"Error handling threat detection: {e}")
    
    def get_monitoring_stats(self) -> Dict:
        """Get current monitoring statistics"""
        if self.stats['start_time']:
            runtime = datetime.now() - self.stats['start_time']
            self.stats['runtime_seconds'] = runtime.total_seconds()
        
        return self.stats.copy()
    
    def is_live_traffic_enabled(self) -> bool:
        """Check if live traffic monitoring is active"""
        return self.is_monitoring and SCAPY_AVAILABLE


# Utility functions for network monitoring setup
def get_network_interfaces():
    """Get available network interfaces"""
    try:
        if SCAPY_AVAILABLE:
            from scapy.all import get_if_list
            return get_if_list()
        else:
            return ["eth0", "wlan0", "lo"]  # Common interface names
    except Exception as e:
        logging.error(f"Error getting network interfaces: {e}")
        return []


def check_network_monitoring_requirements():
    """Check if network monitoring requirements are met"""
    requirements = {
        'scapy_available': SCAPY_AVAILABLE,
        'admin_privileges': False,
        'interfaces_available': len(get_network_interfaces()) > 0
    }
    
    # Check for admin privileges (simplified)
    try:
        import os
        if os.name == 'nt':  # Windows
            import ctypes
            requirements['admin_privileges'] = ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:  # Unix-like
            requirements['admin_privileges'] = os.geteuid() == 0
    except Exception:
        requirements['admin_privileges'] = False
    
    return requirements
