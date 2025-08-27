"""
Signature-based detection rules for PHIDS
"""
import re
import time
from datetime import datetime, timedelta
from collections import defaultdict


class SignatureEngine:
    """Signature-based intrusion detection engine"""
    
    def __init__(self):
        self.signatures = self._load_signatures()
        self.detection_cache = defaultdict(list)
        self.alert_history = defaultdict(list)
        
    def _load_signatures(self):
        """Load detection signatures"""
        return {
            # Network-based signatures
            "nmap_scan": {
                "name": "Nmap Port Scan",
                "description": "Detects Nmap port scanning activity",
                "severity": "medium",
                "patterns": [
                    r"nmap",
                    r"User-Agent.*Nmap",
                    r"X-Nmap-.*"
                ],
                "conditions": {
                    "multiple_ports": True,
                    "syn_scan": True,
                    "rapid_connections": True
                }
            },
            
            "ssh_bruteforce": {
                "name": "SSH Brute Force Attack",
                "description": "CRITICAL: Automated SSH brute force attack detected. Attacker is systematically attempting to guess SSH credentials. This indicates a targeted attack against SSH services. Immediate action required: block source IP, review SSH configuration, enable fail2ban.",
                "severity": "high",
                "patterns": [
                    r"Failed password for .* from",
                    r"Invalid user .* from",
                    r"authentication failure.*ssh"
                ],
                "conditions": {
                    "failed_attempts_threshold": 5,
                    "time_window": 300  # 5 minutes
                },
                "recommendations": [
                    "Block source IP immediately",
                    "Enable SSH key-based authentication",
                    "Implement fail2ban or similar protection",
                    "Change default SSH port",
                    "Review SSH logs for successful logins"
                ]
            },
            
            "http_bruteforce": {
                "name": "HTTP Brute Force Attack",
                "description": "Detects HTTP brute force login attempts",
                "severity": "high",
                "patterns": [
                    r"POST.*login",
                    r"POST.*admin",
                    r"POST.*wp-login"
                ],
                "conditions": {
                    "failed_attempts_threshold": 10,
                    "time_window": 300
                }
            },
            
            "sql_injection": {
                "name": "SQL Injection Attempt",
                "description": "HIGH RISK: SQL injection attack detected. Attacker is attempting to manipulate database queries to extract sensitive data, bypass authentication, or execute unauthorized commands. This could lead to data breach, data corruption, or complete system compromise.",
                "severity": "high",
                "patterns": [
                    r"union\s+select",
                    r"or\s+1\s*=\s*1",
                    r"drop\s+table",
                    r"insert\s+into",
                    r"delete\s+from",
                    r"exec\s*\(",
                    r"sp_executesql",
                    r"xp_cmdshell"
                ],
                "recommendations": [
                    "Implement parameterized queries/prepared statements",
                    "Enable SQL injection protection (WAF)",
                    "Validate and sanitize all user inputs",
                    "Apply principle of least privilege to database accounts",
                    "Monitor database logs for suspicious activity"
                ]
            },
            
            "xss_attempt": {
                "name": "Cross-Site Scripting (XSS)",
                "description": "SECURITY ALERT: Cross-Site Scripting (XSS) attack detected. Attacker is attempting to inject malicious scripts into web pages to steal user credentials, session tokens, or perform unauthorized actions on behalf of users. This could lead to account takeover or data theft.",
                "severity": "medium",
                "patterns": [
                    r"<script[^>]*>",
                    r"javascript:",
                    r"onerror\s*=",
                    r"onload\s*=",
                    r"onclick\s*=",
                    r"alert\s*\(",
                    r"document\.cookie"
                ],
                "recommendations": [
                    "Implement Content Security Policy (CSP)",
                    "Encode/escape all user inputs before output",
                    "Use XSS protection headers (X-XSS-Protection)",
                    "Validate and sanitize user inputs",
                    "Consider using a Web Application Firewall (WAF)"
                ]
            },
            
            "directory_traversal": {
                "name": "Directory Traversal",
                "description": "Detects directory traversal attempts",
                "severity": "medium",
                "patterns": [
                    r"\.\./",
                    r"\.\.\\",
                    r"/etc/passwd",
                    r"/windows/system32",
                    r"boot\.ini",
                    r"web\.config"
                ]
            },
            
            "command_injection": {
                "name": "Command Injection",
                "description": "Detects command injection attempts",
                "severity": "high",
                "patterns": [
                    r";\s*cat\s+",
                    r";\s*ls\s+",
                    r";\s*id\s*;",
                    r";\s*whoami",
                    r"\|\s*cat\s+",
                    r"`cat\s+",
                    r"\$\(cat\s+",
                    r"nc\s+-l",
                    r"/bin/sh",
                    r"/bin/bash"
                ]
            },
            
            "web_shell": {
                "name": "Web Shell Access",
                "description": "CRITICAL THREAT: Web shell access attempt detected. Attacker is trying to access or upload malicious scripts that provide remote command execution capabilities. This indicates a potential system compromise or advanced persistent threat (APT). IMMEDIATE RESPONSE REQUIRED.",
                "severity": "critical",
                "patterns": [
                    r"shell\.php",
                    r"cmd\.php",
                    r"backdoor\.php",
                    r"c99\.php",
                    r"r57\.php",
                    r"webshell",
                    r"eval\s*\(",
                    r"system\s*\(",
                    r"exec\s*\(",
                    r"passthru\s*\("
                ],
                "recommendations": [
                    "IMMEDIATE: Isolate affected system from network",
                    "Scan for web shells and malicious files",
                    "Review web server logs for compromise indicators",
                    "Check file integrity and recent modifications",
                    "Implement file upload restrictions and validation",
                    "Consider incident response and forensic analysis"
                ]
            },
            
            "vulnerability_scan": {
                "name": "Vulnerability Scanner",
                "description": "Detects vulnerability scanning tools",
                "severity": "medium",
                "patterns": [
                    r"User-Agent.*Nikto",
                    r"User-Agent.*sqlmap",
                    r"User-Agent.*Burp",
                    r"User-Agent.*OWASP",
                    r"User-Agent.*dirb",
                    r"User-Agent.*gobuster",
                    r"User-Agent.*wfuzz"
                ]
            },
            
            "suspicious_user_agent": {
                "name": "Suspicious User Agent",
                "description": "Detects suspicious or malicious user agents",
                "severity": "low",
                "patterns": [
                    r"User-Agent.*python",
                    r"User-Agent.*curl",
                    r"User-Agent.*wget",
                    r"User-Agent.*libwww",
                    r"User-Agent.*bot",
                    r"User-Agent.*crawler",
                    r"User-Agent.*scanner"
                ]
            }
        }
    
    def analyze_connection(self, connection_data):
        """Analyze connection data for signature matches"""
        alerts = []
        
        # Extract relevant data for analysis
        source_ip = connection_data.get('source_ip', '')
        service_type = connection_data.get('service_type', '')
        commands = connection_data.get('commands', [])
        payloads = connection_data.get('payloads', [])
        user_agent = connection_data.get('user_agent', '')
        
        # Combine all text data for pattern matching
        text_data = []
        
        # Add commands
        if isinstance(commands, list):
            for cmd in commands:
                if isinstance(cmd, dict):
                    text_data.extend([
                        cmd.get('command', ''),
                        cmd.get('path', ''),
                        cmd.get('body', ''),
                        str(cmd.get('headers', {}))
                    ])
                else:
                    text_data.append(str(cmd))
        
        # Add payloads
        if isinstance(payloads, list):
            for payload in payloads:
                if isinstance(payload, dict):
                    text_data.append(payload.get('data', ''))
                else:
                    text_data.append(str(payload))
        
        # Add user agent
        text_data.append(user_agent)
        
        # Combine all text
        combined_text = ' '.join(text_data).lower()
        
        # Check each signature
        for sig_id, signature in self.signatures.items():
            if self._check_signature(sig_id, signature, combined_text, connection_data):
                alert = {
                    'signature_id': sig_id,
                    'name': signature['name'],
                    'description': signature['description'],
                    'severity': signature['severity'],
                    'source_ip': source_ip,
                    'service_type': service_type,
                    'timestamp': datetime.now(),
                    'matched_patterns': self._get_matched_patterns(signature, combined_text),
                    'recommendations': signature.get('recommendations', []),
                    'attack_details': self._get_attack_details(sig_id, connection_data, combined_text)
                }
                alerts.append(alert)
        
        return alerts
    
    def _check_signature(self, sig_id, signature, text_data, connection_data):
        """Check if signature matches the data"""
        patterns = signature.get('patterns', [])
        conditions = signature.get('conditions', {})
        
        # Check pattern matches
        pattern_matches = 0
        for pattern in patterns:
            if re.search(pattern, text_data, re.IGNORECASE):
                pattern_matches += 1
        
        if pattern_matches == 0:
            return False
        
        # Check additional conditions
        if conditions:
            return self._check_conditions(sig_id, conditions, connection_data)
        
        return True
    
    def _check_conditions(self, sig_id, conditions, connection_data):
        """Check additional signature conditions"""
        source_ip = connection_data.get('source_ip', '')
        current_time = datetime.now()
        
        # Check failed attempts threshold
        if 'failed_attempts_threshold' in conditions:
            threshold = conditions['failed_attempts_threshold']
            time_window = conditions.get('time_window', 300)
            
            # Count recent attempts from this IP
            recent_attempts = [
                alert for alert in self.alert_history[source_ip]
                if (current_time - alert['timestamp']).total_seconds() <= time_window
                and alert['signature_id'] == sig_id
            ]
            
            if len(recent_attempts) >= threshold:
                return True
        
        # Check for multiple ports (port scan detection)
        if conditions.get('multiple_ports'):
            commands = connection_data.get('commands', [])
            ports = set()
            for cmd in commands:
                if isinstance(cmd, dict) and 'destination_port' in cmd:
                    ports.add(cmd['destination_port'])
            
            if len(ports) > 5:  # More than 5 different ports
                return True
        
        # Check for rapid connections
        if conditions.get('rapid_connections'):
            recent_connections = [
                alert for alert in self.alert_history[source_ip]
                if (current_time - alert['timestamp']).total_seconds() <= 60
            ]
            
            if len(recent_connections) > 10:  # More than 10 connections per minute
                return True
        
        return False
    
    def _get_matched_patterns(self, signature, text_data):
        """Get list of patterns that matched"""
        matched = []
        for pattern in signature.get('patterns', []):
            if re.search(pattern, text_data, re.IGNORECASE):
                matched.append(pattern)
        return matched

    def _get_attack_details(self, sig_id, connection_data, text_data):
        """Get detailed attack information for better analysis"""
        details = {
            'attack_type': sig_id,
            'source_port': connection_data.get('source_port'),
            'destination_port': connection_data.get('destination_port'),
            'service': connection_data.get('service_type'),
            'session_id': connection_data.get('session_id'),
            'user_agent': connection_data.get('user_agent', 'Unknown'),
            'payload_size': len(str(connection_data.get('payloads', []))),
            'command_count': len(connection_data.get('commands', [])),
            'connection_duration': connection_data.get('duration', 0)
        }

        # Add attack-specific details
        if sig_id == 'sql_injection':
            details['injection_type'] = self._identify_sql_injection_type(text_data)
        elif sig_id == 'xss_attempt':
            details['xss_type'] = self._identify_xss_type(text_data)
        elif sig_id == 'ssh_bruteforce':
            details['attempted_usernames'] = self._extract_usernames(connection_data)

        return details

    def _identify_sql_injection_type(self, text_data):
        """Identify the type of SQL injection"""
        if re.search(r'union\s+select', text_data, re.IGNORECASE):
            return 'Union-based injection'
        elif re.search(r'or\s+1\s*=\s*1', text_data, re.IGNORECASE):
            return 'Boolean-based blind injection'
        elif re.search(r'waitfor\s+delay', text_data, re.IGNORECASE):
            return 'Time-based blind injection'
        elif re.search(r'drop\s+table', text_data, re.IGNORECASE):
            return 'Destructive injection (DROP)'
        else:
            return 'Generic SQL injection'

    def _identify_xss_type(self, text_data):
        """Identify the type of XSS attack"""
        if re.search(r'<script[^>]*>', text_data, re.IGNORECASE):
            return 'Script-based XSS'
        elif re.search(r'javascript:', text_data, re.IGNORECASE):
            return 'JavaScript protocol XSS'
        elif re.search(r'on\w+\s*=', text_data, re.IGNORECASE):
            return 'Event handler XSS'
        else:
            return 'Generic XSS attempt'

    def _extract_usernames(self, connection_data):
        """Extract attempted usernames from SSH brute force"""
        usernames = []
        commands = connection_data.get('commands', [])
        for cmd in commands:
            if isinstance(cmd, dict) and 'username' in cmd:
                username = cmd['username']
                if username and username not in usernames:
                    usernames.append(username)
        return usernames[:10]  # Limit to first 10 usernames
    
    def add_alert_to_history(self, alert):
        """Add alert to history for condition checking"""
        source_ip = alert.get('source_ip', '')
        self.alert_history[source_ip].append(alert)
        
        # Clean old alerts (keep only last 24 hours)
        cutoff_time = datetime.now() - timedelta(hours=24)
        self.alert_history[source_ip] = [
            a for a in self.alert_history[source_ip]
            if a['timestamp'] > cutoff_time
        ]
    
    def get_signature_stats(self):
        """Get signature detection statistics"""
        stats = {}
        for source_ip, alerts in self.alert_history.items():
            for alert in alerts:
                sig_id = alert['signature_id']
                if sig_id not in stats:
                    stats[sig_id] = {
                        'name': alert['name'],
                        'count': 0,
                        'severity': alert['severity']
                    }
                stats[sig_id]['count'] += 1
        
        return stats
    
    def clear_history(self):
        """Clear alert history"""
        self.alert_history.clear()
        self.detection_cache.clear()
