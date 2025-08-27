"""
Packet capture functionality for PHIDS using Scapy
"""
import asyncio
import logging
import threading
import time
from datetime import datetime
from collections import defaultdict, deque
from scapy.all import sniff, IP, TCP, UDP, ICMP
from src.core.database import DatabaseManager


class PacketCapture:
    """Packet capture and analysis using Scapy"""
    
    def __init__(self, interface=None, filter_str=None):
        self.interface = interface
        self.filter_str = filter_str or "tcp or udp or icmp"
        self.logger = logging.getLogger("packet_capture")
        self.db_manager = DatabaseManager()
        self.running = False
        self.capture_thread = None
        
        # Statistics tracking
        self.packet_stats = defaultdict(int)
        self.connection_tracker = defaultdict(dict)
        self.recent_packets = deque(maxlen=1000)
        
        # Rate limiting for alerts
        self.alert_cooldown = defaultdict(float)
        self.cooldown_period = 60  # seconds
        
    async def start(self):
        """Start packet capture"""
        if self.running:
            self.logger.warning("Packet capture already running")
            return
        
        self.logger.info(f"Starting packet capture on interface: {self.interface}")
        self.logger.info(f"Using filter: {self.filter_str}")
        
        self.running = True
        
        # Start capture in separate thread to avoid blocking
        self.capture_thread = threading.Thread(
            target=self._capture_packets,
            daemon=True
        )
        self.capture_thread.start()
        
        self.logger.info("Packet capture started successfully")
    
    async def stop(self):
        """Stop packet capture"""
        self.logger.info("Stopping packet capture")
        self.running = False
        
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=5)
        
        self.logger.info("Packet capture stopped")
    
    def _capture_packets(self):
        """Capture packets using Scapy (runs in separate thread)"""
        try:
            sniff(
                iface=self.interface,
                filter=self.filter_str,
                prn=self._process_packet,
                stop_filter=lambda x: not self.running,
                store=False
            )
        except Exception as e:
            self.logger.error(f"Packet capture error: {e}")
    
    def _process_packet(self, packet):
        """Process captured packet"""
        try:
            if not self.running:
                return
            
            # Extract packet information
            packet_info = self._extract_packet_info(packet)
            if not packet_info:
                return
            
            # Update statistics
            self._update_statistics(packet_info)
            
            # Store recent packet
            self.recent_packets.append(packet_info)
            
            # Detect suspicious patterns
            self._detect_suspicious_activity(packet_info)
            
        except Exception as e:
            self.logger.error(f"Error processing packet: {e}")
    
    def _extract_packet_info(self, packet):
        """Extract relevant information from packet"""
        try:
            if not packet.haslayer(IP):
                return None
            
            ip_layer = packet[IP]
            
            packet_info = {
                'timestamp': datetime.now(),
                'src_ip': ip_layer.src,
                'dst_ip': ip_layer.dst,
                'protocol': ip_layer.proto,
                'length': len(packet),
                'ttl': ip_layer.ttl,
                'flags': getattr(ip_layer, 'flags', 0)
            }
            
            # Extract transport layer information
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                packet_info.update({
                    'src_port': tcp_layer.sport,
                    'dst_port': tcp_layer.dport,
                    'tcp_flags': tcp_layer.flags,
                    'seq': tcp_layer.seq,
                    'ack': tcp_layer.ack,
                    'window': tcp_layer.window
                })
                packet_info['transport'] = 'TCP'
                
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                packet_info.update({
                    'src_port': udp_layer.sport,
                    'dst_port': udp_layer.dport
                })
                packet_info['transport'] = 'UDP'
                
            elif packet.haslayer(ICMP):
                icmp_layer = packet[ICMP]
                packet_info.update({
                    'icmp_type': icmp_layer.type,
                    'icmp_code': icmp_layer.code
                })
                packet_info['transport'] = 'ICMP'
            
            return packet_info
            
        except Exception as e:
            self.logger.error(f"Error extracting packet info: {e}")
            return None
    
    def _update_statistics(self, packet_info):
        """Update packet statistics"""
        # Basic counters
        self.packet_stats['total_packets'] += 1
        self.packet_stats[f"protocol_{packet_info['protocol']}"] += 1
        self.packet_stats[f"transport_{packet_info.get('transport', 'unknown')}"] += 1
        
        # Source IP tracking
        src_ip = packet_info['src_ip']
        self.packet_stats[f"src_ip_{src_ip}"] += 1
        
        # Port tracking
        if 'dst_port' in packet_info:
            dst_port = packet_info['dst_port']
            self.packet_stats[f"dst_port_{dst_port}"] += 1
    
    def _detect_suspicious_activity(self, packet_info):
        """Detect suspicious network activity"""
        src_ip = packet_info['src_ip']
        current_time = time.time()
        
        # Skip if in cooldown period
        if current_time - self.alert_cooldown[src_ip] < self.cooldown_period:
            return
        
        # Port scan detection
        if self._detect_port_scan(packet_info):
            self._generate_alert("port_scan", packet_info, "Potential port scan detected")
            self.alert_cooldown[src_ip] = current_time
        
        # SYN flood detection
        if self._detect_syn_flood(packet_info):
            self._generate_alert("syn_flood", packet_info, "Potential SYN flood detected")
            self.alert_cooldown[src_ip] = current_time
        
        # Unusual traffic patterns
        if self._detect_unusual_traffic(packet_info):
            self._generate_alert("unusual_traffic", packet_info, "Unusual traffic pattern detected")
            self.alert_cooldown[src_ip] = current_time
    
    def _detect_port_scan(self, packet_info):
        """Detect potential port scanning"""
        if packet_info.get('transport') != 'TCP':
            return False
        
        src_ip = packet_info['src_ip']
        
        # Track unique destination ports per source IP
        if src_ip not in self.connection_tracker:
            self.connection_tracker[src_ip] = {
                'ports': set(),
                'first_seen': time.time(),
                'last_seen': time.time()
            }
        
        tracker = self.connection_tracker[src_ip]
        tracker['ports'].add(packet_info['dst_port'])
        tracker['last_seen'] = time.time()
        
        # Clean old entries
        if tracker['last_seen'] - tracker['first_seen'] > 300:  # 5 minutes
            tracker['ports'].clear()
            tracker['first_seen'] = time.time()
        
        # Alert if too many ports accessed
        return len(tracker['ports']) > 10
    
    def _detect_syn_flood(self, packet_info):
        """Detect potential SYN flood attacks"""
        if packet_info.get('transport') != 'TCP':
            return False
        
        tcp_flags = packet_info.get('tcp_flags', 0)
        
        # Check for SYN flag (0x02)
        if tcp_flags & 0x02:
            src_ip = packet_info['src_ip']
            
            # Count SYN packets from this IP in recent packets
            syn_count = sum(1 for p in self.recent_packets 
                          if p.get('src_ip') == src_ip and 
                             p.get('tcp_flags', 0) & 0x02 and
                             (packet_info['timestamp'] - p['timestamp']).total_seconds() < 60)
            
            return syn_count > 50  # More than 50 SYN packets per minute
        
        return False
    
    def _detect_unusual_traffic(self, packet_info):
        """Detect unusual traffic patterns"""
        # Check for unusual destination ports
        dst_port = packet_info.get('dst_port')
        if dst_port:
            # Common ports that shouldn't receive much traffic
            unusual_ports = [23, 135, 139, 445, 1433, 3389, 5432, 5900]
            if dst_port in unusual_ports:
                return True
        
        # Check for unusual packet sizes
        if packet_info['length'] > 1500 or packet_info['length'] < 20:
            return True
        
        # Check for unusual TTL values
        ttl = packet_info.get('ttl', 64)
        if ttl < 10 or ttl > 255:
            return True
        
        return False
    
    def _generate_alert(self, alert_type, packet_info, description):
        """Generate security alert"""
        alert_data = {
            'alert_type': alert_type,
            'severity': 'medium',
            'source_ip': packet_info['src_ip'],
            'destination_ip': packet_info['dst_ip'],
            'source_port': packet_info.get('src_port'),
            'destination_port': packet_info.get('dst_port'),
            'protocol': packet_info.get('transport', 'unknown'),
            'signature_id': f"PHIDS_{alert_type.upper()}",
            'description': description,
            'raw_data': str(packet_info)
        }
        
        # Log alert
        self.logger.warning(f"ALERT: {description} from {packet_info['src_ip']}")
        
        # Store in database (async operation)
        asyncio.create_task(self._store_alert(alert_data))
    
    async def _store_alert(self, alert_data):
        """Store alert in database"""
        try:
            await self.db_manager.log_alert(alert_data)
        except Exception as e:
            self.logger.error(f"Failed to store alert: {e}")
    
    def get_statistics(self):
        """Get current packet capture statistics"""
        return dict(self.packet_stats)
    
    def get_recent_packets(self, count=10):
        """Get recent packets"""
        return list(self.recent_packets)[-count:]
    
    def clear_statistics(self):
        """Clear packet statistics"""
        self.packet_stats.clear()
        self.connection_tracker.clear()
        self.recent_packets.clear()
        self.logger.info("Packet capture statistics cleared")
