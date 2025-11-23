"""
Simple attack classification module for PHIDS
Classifies common, easy-to-identify attacks without complex ML
"""
import logging
from collections import defaultdict
from datetime import datetime, timedelta


class AttackClassifier:
    """Classify attacks into common categories"""
    
    def __init__(self):
        self.logger = logging.getLogger("attack_classifier")
        # Track failed auth attempts per IP
        self.failed_attempts = defaultdict(list)
        # Track port access patterns per IP
        self.port_access = defaultdict(list)
    
    def classify_alert(self, alert):
        """Classify an alert into attack categories"""
        classifications = []
        
        # Check for brute force patterns
        if self._is_brute_force(alert):
            classifications.append({
                'type': 'brute_force',
                'name': 'Brute Force Attack',
                'description': 'Multiple failed authentication attempts detected',
                'severity': 'high'
            })
        
        # Check for port scanning
        if self._is_port_scan(alert):
            classifications.append({
                'type': 'port_scan',
                'name': 'Port Scanning',
                'description': 'Connections to multiple ports in short time window',
                'severity': 'medium'
            })
        
        # Check for SQL injection attempts
        if self._is_sql_injection(alert):
            classifications.append({
                'type': 'sql_injection',
                'name': 'SQL Injection Attempt',
                'description': 'Suspicious SQL patterns detected in payload',
                'severity': 'high'
            })
        
        # Check for directory traversal
        if self._is_directory_traversal(alert):
            classifications.append({
                'type': 'directory_traversal',
                'name': 'Directory Traversal',
                'description': 'Path traversal patterns detected',
                'severity': 'medium'
            })
        
        return classifications
    
    def _is_brute_force(self, alert):
        """Detect brute force login attempts"""
        # Check if this is an authentication failure
        if 'authentication' not in alert.get('alert_type', '').lower():
            return False
        
        if 'failed' not in alert.get('description', '').lower():
            return False
        
        source_ip = alert.get('source_ip')
        current_time = datetime.now()
        
        # Record this failed attempt
        self.failed_attempts[source_ip].append(current_time)
        
        # Clean old attempts (older than 5 minutes)
        self.failed_attempts[source_ip] = [
            t for t in self.failed_attempts[source_ip]
            if (current_time - t).total_seconds() < 300
        ]
        
        # Brute force if 3+ failed attempts in 5 minutes
        return len(self.failed_attempts[source_ip]) >= 3
    
    def _is_port_scan(self, alert):
        """Detect port scanning activity"""
        # Check if alert mentions multiple ports or port scanning
        description = alert.get('description', '').lower()
        
        if 'port' not in description:
            return False
        
        if any(keyword in description for keyword in ['scan', 'multiple ports', 'unique ports']):
            return True
        
        # Check if alert type indicates port scanning
        alert_type = alert.get('alert_type', '').lower()
        return 'port' in alert_type and 'scan' in alert_type
    
    def _is_sql_injection(self, alert):
        """Detect SQL injection attempts"""
        description = alert.get('description', '').lower()
        
        # Common SQL injection patterns
        sql_patterns = [
            'union select',
            'or 1=1',
            'or 1=1--',
            'drop table',
            'insert into',
            'delete from',
            'exec(',
            'execute(',
            'sql injection',
            'sqlmap'
        ]
        
        return any(pattern in description for pattern in sql_patterns)
    
    def _is_directory_traversal(self, alert):
        """Detect directory traversal attempts"""
        description = alert.get('description', '').lower()
        
        # Common directory traversal patterns
        traversal_patterns = [
            '../',
            '..\\',
            'directory traversal',
            'path traversal',
            '/etc/passwd',
            '/etc/shadow',
            'c:\\windows',
            'c:\\winnt'
        ]
        
        return any(pattern in description for pattern in traversal_patterns)
    
    def clear_history(self):
        """Clear tracking history"""
        self.failed_attempts.clear()
        self.port_access.clear()
        self.logger.info("Cleared attack classification history")

