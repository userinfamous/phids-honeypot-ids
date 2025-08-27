"""
Log analysis module for PHIDS
"""
import asyncio
import logging
import json
import re
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict, Counter
from config import LOGS_DIR
from src.core.database import DatabaseManager
from .ioc_extractor import IOCExtractor


class LogAnalyzer:
    """Analyze logs and extract insights"""
    
    def __init__(self):
        self.logger = logging.getLogger("log_analyzer")
        self.db_manager = DatabaseManager()
        self.ioc_extractor = IOCExtractor()
        self.running = False
        
        # Analysis results storage
        self.analysis_results = {
            'attack_patterns': defaultdict(int),
            'top_attackers': Counter(),
            'service_activity': defaultdict(int),
            'geographic_distribution': defaultdict(int),
            'time_patterns': defaultdict(int),
            'ioc_summary': defaultdict(int)
        }
        
        # Analysis intervals
        self.analysis_intervals = {
            'quick': 300,    # 5 minutes
            'detailed': 1800,  # 30 minutes
            'comprehensive': 3600  # 1 hour
        }
    
    async def start(self):
        """Start log analysis tasks"""
        if self.running:
            self.logger.warning("Log analyzer already running")
            return
        
        self.logger.info("Starting log analyzer")
        self.running = True
        
        # Start analysis tasks
        tasks = [
            asyncio.create_task(self._quick_analysis_loop()),
            asyncio.create_task(self._detailed_analysis_loop()),
            asyncio.create_task(self._comprehensive_analysis_loop())
        ]
        
        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            self.logger.info("Log analysis tasks cancelled")
    
    async def stop(self):
        """Stop log analysis"""
        self.logger.info("Stopping log analyzer")
        self.running = False
    
    async def _quick_analysis_loop(self):
        """Quick analysis every 5 minutes"""
        while self.running:
            try:
                await self._analyze_recent_activity()
                await asyncio.sleep(self.analysis_intervals['quick'])
            except Exception as e:
                self.logger.error(f"Error in quick analysis: {e}")
                await asyncio.sleep(60)
    
    async def _detailed_analysis_loop(self):
        """Detailed analysis every 30 minutes"""
        while self.running:
            try:
                await self._analyze_attack_patterns()
                await self._analyze_geographic_patterns()
                await asyncio.sleep(self.analysis_intervals['detailed'])
            except Exception as e:
                self.logger.error(f"Error in detailed analysis: {e}")
                await asyncio.sleep(300)
    
    async def _comprehensive_analysis_loop(self):
        """Comprehensive analysis every hour"""
        while self.running:
            try:
                await self._analyze_time_patterns()
                await self._analyze_ioc_trends()
                await self._generate_analysis_report()
                await asyncio.sleep(self.analysis_intervals['comprehensive'])
            except Exception as e:
                self.logger.error(f"Error in comprehensive analysis: {e}")
                await asyncio.sleep(600)
    
    async def _analyze_recent_activity(self):
        """Analyze recent activity for immediate threats"""
        self.logger.debug("Analyzing recent activity")
        
        # Get recent connections (last hour)
        since = datetime.now() - timedelta(hours=1)
        recent_connections = await self.db_manager.get_recent_connections(since, limit=200)
        
        # Analyze each connection
        for connection in recent_connections:
            connection_data = dict(connection)
            
            # Extract IOCs
            iocs = self.ioc_extractor.analyze_connection_iocs(connection_data)
            
            # Update analysis results
            self._update_analysis_results(connection_data, iocs)
        
        # Get recent alerts
        alert_since = datetime.now() - timedelta(hours=1)
        recent_alerts = await self.db_manager.get_recent_alerts(alert_since, limit=100)
        
        # Analyze alert patterns
        for alert in recent_alerts:
            alert_data = dict(alert)
            self.analysis_results['attack_patterns'][alert_data.get('alert_type', 'unknown')] += 1
    
    async def _analyze_attack_patterns(self):
        """Analyze attack patterns and trends"""
        self.logger.debug("Analyzing attack patterns")
        
        # Get connections from last 24 hours
        since = datetime.now() - timedelta(hours=24)
        connections = await self.db_manager.get_recent_connections(since, limit=1000)
        
        attack_sequences = defaultdict(list)
        
        for connection in connections:
            connection_data = dict(connection)
            source_ip = connection_data.get('source_ip')
            
            if source_ip:
                attack_sequences[source_ip].append({
                    'timestamp': connection_data.get('timestamp'),
                    'service': connection_data.get('service_type'),
                    'commands': connection_data.get('commands', []),
                    'duration': connection_data.get('duration', 0)
                })
        
        # Analyze sequences for each IP
        for ip, sequence in attack_sequences.items():
            if len(sequence) > 1:
                # Sort by timestamp
                sequence.sort(key=lambda x: x['timestamp'])
                
                # Detect multi-stage attacks
                services_used = set(item['service'] for item in sequence)
                if len(services_used) > 1:
                    self.analysis_results['attack_patterns']['multi_service_attack'] += 1
                
                # Detect rapid-fire attacks
                if len(sequence) > 10:
                    self.analysis_results['attack_patterns']['rapid_fire_attack'] += 1
    
    async def _analyze_geographic_patterns(self):
        """Analyze geographic distribution of attacks"""
        self.logger.debug("Analyzing geographic patterns")
        
        # Get top attackers
        top_attackers = await self.db_manager.get_top_attackers(hours=24, limit=50)
        
        for attacker in top_attackers:
            ip = attacker['source_ip']
            count = attacker['connection_count']
            
            # Update top attackers
            self.analysis_results['top_attackers'][ip] = count
            
            # Note: In a real implementation, you would use a GeoIP database
            # to determine the geographic location of IP addresses
            # For now, we'll use a placeholder
            self.analysis_results['geographic_distribution']['unknown'] += count
    
    async def _analyze_time_patterns(self):
        """Analyze temporal patterns in attacks"""
        self.logger.debug("Analyzing time patterns")
        
        # Get connections from last week
        since = datetime.now() - timedelta(hours=168)
        connections = await self.db_manager.get_recent_connections(since, limit=5000)
        
        hourly_activity = defaultdict(int)
        daily_activity = defaultdict(int)
        
        for connection in connections:
            connection_data = dict(connection)
            timestamp_str = connection_data.get('timestamp')
            
            if timestamp_str:
                try:
                    # Parse timestamp
                    timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                    
                    # Extract hour and day
                    hour = timestamp.hour
                    day = timestamp.strftime('%A')
                    
                    hourly_activity[hour] += 1
                    daily_activity[day] += 1
                    
                except Exception as e:
                    self.logger.debug(f"Error parsing timestamp {timestamp_str}: {e}")
        
        # Store patterns
        self.analysis_results['time_patterns']['hourly'] = dict(hourly_activity)
        self.analysis_results['time_patterns']['daily'] = dict(daily_activity)
    
    async def _analyze_ioc_trends(self):
        """Analyze IOC trends and patterns"""
        self.logger.debug("Analyzing IOC trends")
        
        # Get recent connections
        connections = await self.db_manager.get_recent_connections(hours=24, limit=1000)
        
        all_iocs = {
            'ip_addresses': set(),
            'domains': set(),
            'attack_patterns': set(),
            'user_agents': set()
        }
        
        for connection in connections:
            connection_data = dict(connection)
            iocs = self.ioc_extractor.analyze_connection_iocs(connection_data)
            
            # Aggregate IOCs
            all_iocs['ip_addresses'].update(iocs['ip_addresses'])
            all_iocs['domains'].update(iocs['domains'])
            all_iocs['attack_patterns'].update(iocs['attack_patterns'])
            all_iocs['user_agents'].update(iocs['user_agents'])
        
        # Update IOC summary
        self.analysis_results['ioc_summary'] = {
            'unique_ips': len(all_iocs['ip_addresses']),
            'unique_domains': len(all_iocs['domains']),
            'attack_patterns': len(all_iocs['attack_patterns']),
            'user_agents': len(all_iocs['user_agents'])
        }
    
    def _update_analysis_results(self, connection_data, iocs):
        """Update analysis results with new data"""
        # Update service activity
        service_type = connection_data.get('service_type', 'unknown')
        self.analysis_results['service_activity'][service_type] += 1
        
        # Update attack patterns based on IOCs
        risk_score = iocs['metadata'].get('risk_score', 0)
        if risk_score > 50:
            self.analysis_results['attack_patterns']['high_risk_connection'] += 1
        
        # Update top attackers
        source_ip = connection_data.get('source_ip')
        if source_ip:
            self.analysis_results['top_attackers'][source_ip] += 1
    
    async def _generate_analysis_report(self):
        """Generate comprehensive analysis report"""
        self.logger.info("Generating analysis report")
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_attack_patterns': sum(self.analysis_results['attack_patterns'].values()),
                'unique_attackers': len(self.analysis_results['top_attackers']),
                'most_targeted_service': max(self.analysis_results['service_activity'].items(), 
                                           key=lambda x: x[1], default=('none', 0))[0],
                'total_connections_analyzed': sum(self.analysis_results['service_activity'].values())
            },
            'top_attackers': dict(self.analysis_results['top_attackers'].most_common(10)),
            'attack_patterns': dict(self.analysis_results['attack_patterns']),
            'service_activity': dict(self.analysis_results['service_activity']),
            'time_patterns': dict(self.analysis_results['time_patterns']),
            'ioc_summary': dict(self.analysis_results['ioc_summary'])
        }
        
        # Save report to file
        report_file = LOGS_DIR / f"analysis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            with open(report_file, 'w') as f:
                json.dump(report, f, indent=2)
            
            self.logger.info(f"Analysis report saved to {report_file}")
        except Exception as e:
            self.logger.error(f"Error saving analysis report: {e}")
        
        return report
    
    async def analyze_log_file(self, log_file_path: Path):
        """Analyze a specific log file"""
        self.logger.info(f"Analyzing log file: {log_file_path}")
        
        try:
            with open(log_file_path, 'r') as f:
                content = f.read()
            
            # Extract IOCs from log content
            iocs = self.ioc_extractor.extract_iocs(content, "log_file")
            
            # Analyze patterns
            patterns = self._analyze_log_patterns(content)
            
            return {
                'file_path': str(log_file_path),
                'iocs': iocs,
                'patterns': patterns,
                'analysis_time': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Error analyzing log file {log_file_path}: {e}")
            return None
    
    def _analyze_log_patterns(self, content: str):
        """Analyze patterns in log content"""
        patterns = {
            'failed_logins': len(re.findall(r'failed.*login', content, re.IGNORECASE)),
            'error_messages': len(re.findall(r'error|exception|fail', content, re.IGNORECASE)),
            'suspicious_requests': len(re.findall(r'(\.\.\/|union\s+select|<script)', content, re.IGNORECASE)),
            'admin_access': len(re.findall(r'\/admin|\/administrator|\/wp-admin', content, re.IGNORECASE)),
            'scan_attempts': len(re.findall(r'(nmap|nikto|dirb|gobuster)', content, re.IGNORECASE))
        }
        
        return patterns
    
    def get_analysis_summary(self):
        """Get current analysis summary"""
        return {
            'last_update': datetime.now().isoformat(),
            'attack_patterns': dict(self.analysis_results['attack_patterns']),
            'top_attackers': dict(self.analysis_results['top_attackers'].most_common(10)),
            'service_activity': dict(self.analysis_results['service_activity']),
            'ioc_summary': dict(self.analysis_results['ioc_summary']),
            'total_connections': sum(self.analysis_results['service_activity'].values())
        }
    
    def clear_analysis_results(self):
        """Clear analysis results"""
        for result_dict in self.analysis_results.values():
            result_dict.clear()
        
        self.logger.info("Analysis results cleared")
