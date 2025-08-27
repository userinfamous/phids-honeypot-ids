"""
Indicators of Compromise (IOC) extraction for PHIDS
"""
import re
import hashlib
import ipaddress
import logging
from datetime import datetime
from typing import List, Dict, Set
from urllib.parse import urlparse


class IOCExtractor:
    """Extract Indicators of Compromise from logs and data"""
    
    def __init__(self):
        self.logger = logging.getLogger("ioc_extractor")
        
        # Compiled regex patterns for performance
        self.patterns = {
            'ip_address': re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
            'domain': re.compile(r'\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\b'),
            'url': re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+'),
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
            'sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
            'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
            'file_path': re.compile(r'(?:[a-zA-Z]:\\|/)[^\s<>"{}|\\^`\[\]]*'),
            'registry_key': re.compile(r'HKEY_[A-Z_]+\\[^\s<>"{}|\\^`\[\]]*'),
            'user_agent': re.compile(r'User-Agent:\s*([^\r\n]+)', re.IGNORECASE),
            'sql_injection': re.compile(r'(union\s+select|or\s+1\s*=\s*1|drop\s+table|insert\s+into)', re.IGNORECASE),
            'xss_payload': re.compile(r'(<script[^>]*>|javascript:|onerror\s*=|onload\s*=)', re.IGNORECASE),
            'command_injection': re.compile(r'(;\s*cat\s+|;\s*ls\s+|;\s*id\s*;|\|\s*cat\s+|`cat\s+)', re.IGNORECASE)
        }
        
        # Known malicious indicators
        self.known_malicious = {
            'user_agents': {
                'sqlmap', 'nikto', 'burp', 'owasp', 'dirb', 'gobuster', 'wfuzz',
                'nmap', 'masscan', 'zmap', 'shodan', 'censys'
            },
            'file_extensions': {
                '.php', '.asp', '.aspx', '.jsp', '.cgi', '.pl', '.py', '.sh', '.bat', '.cmd'
            },
            'suspicious_paths': {
                '/admin', '/phpmyadmin', '/wp-admin', '/administrator', '/manager',
                '/shell.php', '/cmd.php', '/backdoor.php', '/c99.php', '/r57.php'
            }
        }
    
    def extract_iocs(self, data: str, source_type: str = "unknown") -> Dict:
        """Extract all IOCs from given data"""
        iocs = {
            'ip_addresses': set(),
            'domains': set(),
            'urls': set(),
            'emails': set(),
            'file_hashes': {'md5': set(), 'sha1': set(), 'sha256': set()},
            'file_paths': set(),
            'registry_keys': set(),
            'user_agents': set(),
            'attack_patterns': set(),
            'suspicious_commands': set(),
            'metadata': {
                'source_type': source_type,
                'extraction_time': datetime.now().isoformat(),
                'data_length': len(data)
            }
        }
        
        try:
            # Extract basic IOCs
            iocs['ip_addresses'] = self._extract_ip_addresses(data)
            iocs['domains'] = self._extract_domains(data)
            iocs['urls'] = self._extract_urls(data)
            iocs['emails'] = self._extract_emails(data)
            iocs['file_hashes'] = self._extract_file_hashes(data)
            iocs['file_paths'] = self._extract_file_paths(data)
            iocs['registry_keys'] = self._extract_registry_keys(data)
            iocs['user_agents'] = self._extract_user_agents(data)
            
            # Extract attack patterns
            iocs['attack_patterns'] = self._extract_attack_patterns(data)
            iocs['suspicious_commands'] = self._extract_suspicious_commands(data)
            
            # Calculate risk score
            iocs['metadata']['risk_score'] = self._calculate_risk_score(iocs)
            
        except Exception as e:
            self.logger.error(f"Error extracting IOCs: {e}")
        
        return iocs
    
    def _extract_ip_addresses(self, data: str) -> Set[str]:
        """Extract IP addresses"""
        ips = set()
        matches = self.patterns['ip_address'].findall(data)
        
        for ip in matches:
            try:
                # Validate IP address
                ipaddress.ip_address(ip)
                # Filter out private/local IPs for external threat analysis
                ip_obj = ipaddress.ip_address(ip)
                if not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast):
                    ips.add(ip)
            except ValueError:
                continue
        
        return ips
    
    def _extract_domains(self, data: str) -> Set[str]:
        """Extract domain names"""
        domains = set()
        matches = self.patterns['domain'].findall(data)
        
        for match in matches:
            if isinstance(match, tuple):
                domain = ''.join(match)
            else:
                domain = match
            
            # Basic validation
            if '.' in domain and len(domain) > 3 and not domain.replace('.', '').isdigit():
                domains.add(domain.lower())
        
        return domains
    
    def _extract_urls(self, data: str) -> Set[str]:
        """Extract URLs"""
        urls = set()
        matches = self.patterns['url'].findall(data)
        
        for url in matches:
            try:
                parsed = urlparse(url)
                if parsed.netloc:
                    urls.add(url)
            except Exception:
                continue
        
        return urls
    
    def _extract_emails(self, data: str) -> Set[str]:
        """Extract email addresses"""
        emails = set()
        matches = self.patterns['email'].findall(data)
        
        for email in matches:
            emails.add(email.lower())
        
        return emails
    
    def _extract_file_hashes(self, data: str) -> Dict[str, Set[str]]:
        """Extract file hashes"""
        hashes = {'md5': set(), 'sha1': set(), 'sha256': set()}
        
        # MD5 hashes
        hashes['md5'] = set(self.patterns['md5'].findall(data))
        
        # SHA1 hashes
        hashes['sha1'] = set(self.patterns['sha1'].findall(data))
        
        # SHA256 hashes
        hashes['sha256'] = set(self.patterns['sha256'].findall(data))
        
        return hashes
    
    def _extract_file_paths(self, data: str) -> Set[str]:
        """Extract file paths"""
        paths = set()
        matches = self.patterns['file_path'].findall(data)
        
        for path in matches:
            # Filter out very short or common paths
            if len(path) > 3 and not path.endswith(('.', '..')):
                paths.add(path)
        
        return paths
    
    def _extract_registry_keys(self, data: str) -> Set[str]:
        """Extract Windows registry keys"""
        keys = set()
        matches = self.patterns['registry_key'].findall(data)
        
        for key in matches:
            keys.add(key)
        
        return keys
    
    def _extract_user_agents(self, data: str) -> Set[str]:
        """Extract User-Agent strings"""
        user_agents = set()
        matches = self.patterns['user_agent'].findall(data)
        
        for ua in matches:
            user_agents.add(ua.strip())
        
        return user_agents
    
    def _extract_attack_patterns(self, data: str) -> Set[str]:
        """Extract attack patterns"""
        patterns = set()
        
        # SQL injection patterns
        sql_matches = self.patterns['sql_injection'].findall(data)
        for match in sql_matches:
            patterns.add(f"sql_injection: {match}")
        
        # XSS patterns
        xss_matches = self.patterns['xss_payload'].findall(data)
        for match in xss_matches:
            patterns.add(f"xss: {match}")
        
        # Command injection patterns
        cmd_matches = self.patterns['command_injection'].findall(data)
        for match in cmd_matches:
            patterns.add(f"command_injection: {match}")
        
        # Directory traversal
        if '../' in data or '..\\' in data:
            patterns.add("directory_traversal")
        
        # Web shell indicators
        web_shell_patterns = ['eval(', 'system(', 'exec(', 'shell_exec(', 'passthru(']
        for pattern in web_shell_patterns:
            if pattern in data.lower():
                patterns.add(f"web_shell: {pattern}")
        
        return patterns
    
    def _extract_suspicious_commands(self, data: str) -> Set[str]:
        """Extract suspicious commands"""
        commands = set()
        
        # Common reconnaissance commands
        recon_commands = [
            'whoami', 'id', 'uname', 'cat /etc/passwd', 'cat /etc/shadow',
            'netstat', 'ps aux', 'ls -la', 'pwd', 'ifconfig', 'ip addr'
        ]
        
        for cmd in recon_commands:
            if cmd in data.lower():
                commands.add(cmd)
        
        # Privilege escalation attempts
        privesc_patterns = ['sudo', 'su -', 'chmod +s', 'setuid']
        for pattern in privesc_patterns:
            if pattern in data.lower():
                commands.add(f"privesc: {pattern}")
        
        # Network tools
        network_tools = ['nmap', 'nc ', 'netcat', 'wget', 'curl', 'ping']
        for tool in network_tools:
            if tool in data.lower():
                commands.add(f"network_tool: {tool}")
        
        return commands
    
    def _calculate_risk_score(self, iocs: Dict) -> int:
        """Calculate risk score based on extracted IOCs"""
        score = 0
        
        # IP addresses (external)
        score += len(iocs['ip_addresses']) * 2
        
        # Attack patterns
        score += len(iocs['attack_patterns']) * 10
        
        # Suspicious commands
        score += len(iocs['suspicious_commands']) * 5
        
        # File hashes
        total_hashes = sum(len(hashes) for hashes in iocs['file_hashes'].values())
        score += total_hashes * 3
        
        # Malicious user agents
        for ua in iocs['user_agents']:
            if any(malicious in ua.lower() for malicious in self.known_malicious['user_agents']):
                score += 15
        
        # URLs with suspicious paths
        for url in iocs['urls']:
            if any(path in url.lower() for path in self.known_malicious['suspicious_paths']):
                score += 8
        
        return min(score, 100)  # Cap at 100
    
    def analyze_connection_iocs(self, connection_data: Dict) -> Dict:
        """Analyze IOCs from connection data"""
        all_text = []
        
        # Extract text from various fields
        if 'commands' in connection_data:
            commands = connection_data['commands']
            if isinstance(commands, list):
                for cmd in commands:
                    if isinstance(cmd, dict):
                        all_text.extend([
                            str(cmd.get('command', '')),
                            str(cmd.get('path', '')),
                            str(cmd.get('body', '')),
                            str(cmd.get('headers', {}))
                        ])
                    else:
                        all_text.append(str(cmd))
        
        if 'payloads' in connection_data:
            payloads = connection_data['payloads']
            if isinstance(payloads, list):
                for payload in payloads:
                    if isinstance(payload, dict):
                        all_text.append(str(payload.get('data', '')))
                    else:
                        all_text.append(str(payload))
        
        if 'user_agent' in connection_data:
            all_text.append(str(connection_data['user_agent']))
        
        # Combine all text
        combined_text = ' '.join(all_text)
        
        # Extract IOCs
        iocs = self.extract_iocs(combined_text, "connection")
        
        # Add connection-specific metadata
        iocs['metadata'].update({
            'source_ip': connection_data.get('source_ip'),
            'destination_port': connection_data.get('destination_port'),
            'service_type': connection_data.get('service_type'),
            'session_id': connection_data.get('session_id')
        })
        
        return iocs
    
    def get_ioc_summary(self, iocs: Dict) -> Dict:
        """Get summary of extracted IOCs"""
        return {
            'total_indicators': sum([
                len(iocs['ip_addresses']),
                len(iocs['domains']),
                len(iocs['urls']),
                len(iocs['emails']),
                sum(len(hashes) for hashes in iocs['file_hashes'].values()),
                len(iocs['file_paths']),
                len(iocs['registry_keys']),
                len(iocs['user_agents']),
                len(iocs['attack_patterns']),
                len(iocs['suspicious_commands'])
            ]),
            'risk_score': iocs['metadata'].get('risk_score', 0),
            'categories': {
                'network': len(iocs['ip_addresses']) + len(iocs['domains']) + len(iocs['urls']),
                'files': sum(len(hashes) for hashes in iocs['file_hashes'].values()) + len(iocs['file_paths']),
                'attacks': len(iocs['attack_patterns']) + len(iocs['suspicious_commands']),
                'other': len(iocs['emails']) + len(iocs['registry_keys']) + len(iocs['user_agents'])
            }
        }
