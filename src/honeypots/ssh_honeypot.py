"""
SSH Honeypot implementation for PHIDS
"""
import asyncio
import logging
import base64
import hashlib
from datetime import datetime
from config import HONEYPOT_CONFIG
from .base_honeypot import BaseHoneypot


class SSHHoneypot(BaseHoneypot):
    """SSH Honeypot that simulates an SSH server"""
    
    def __init__(self):
        config = HONEYPOT_CONFIG["ssh"]
        super().__init__("ssh", config)
        self.fake_users = {
            "root": "password",
            "admin": "admin",
            "user": "user",
            "test": "test",
            "ubuntu": "ubuntu"
        }
        
    async def start(self):
        """Start the SSH honeypot server"""
        if not self.is_enabled():
            self.logger.info("SSH honeypot is disabled")
            return
        
        self.logger.info(f"Starting SSH honeypot on {self.config['bind_address']}:{self.config['port']}")
        
        try:
            self.server = await asyncio.start_server(
                self.handle_connection,
                self.config["bind_address"],
                self.config["port"]
            )
            self.running = True
            self.logger.info(f"SSH honeypot started successfully")
            
            async with self.server:
                await self.server.serve_forever()
                
        except Exception as e:
            self.logger.error(f"Failed to start SSH honeypot: {e}")
            self.running = False
    
    async def stop(self):
        """Stop the SSH honeypot server"""
        self.logger.info("Stopping SSH honeypot")
        self.running = False
        
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        
        # Close all active connections
        for session_id in list(self.active_connections.keys()):
            connection = self.active_connections[session_id]
            await self.close_connection(connection.get('writer'), session_id)
        
        self.logger.info("SSH honeypot stopped")
    
    async def handle_connection(self, reader, writer):
        """Handle incoming SSH connections"""
        session_id = self.generate_session_id()
        client_info = self.get_client_info(writer)
        
        self.logger.info(f"New SSH connection from {client_info['source_ip']}:{client_info['source_port']} (session: {session_id})")
        
        # Store connection info with proper timestamp and enhanced metadata
        start_time = datetime.now()
        connection_data = {
            'session_id': session_id,
            'source_ip': client_info['source_ip'],
            'source_port': client_info['source_port'],
            'destination_port': self.config['port'],
            'service_type': 'ssh',
            'start_time': start_time,
            'timestamp': start_time,  # Explicit timestamp for database logging
            'commands': [],
            'payloads': [],
            'connection_data': {
                'connection_type': 'ssh_attempt',
                'client_version': 'unknown',
                'authentication_attempts': 0,
                'successful_commands': 0,
                'failed_commands': 0,
                'attack_indicators': [],
                'session_duration': 0,
                'bytes_transferred': 0,
                'suspicious_activity': False,
                'attack_classification': 'reconnaissance',
                'severity': 'low',
                'recommendations': []
            },
            'user_agent': f"SSH-Client-{client_info['source_ip']}"
        }
        
        self.active_connections[session_id] = {
            'reader': reader,
            'writer': writer,
            'data': connection_data
        }

        # Log connection attempt immediately (before session simulation)
        initial_log_data = connection_data.copy()
        initial_log_data['connection_type'] = 'attempt'
        initial_log_data['end_time'] = datetime.now()
        initial_log_data['duration'] = 0
        await self.log_connection(initial_log_data)

        try:
            await self.simulate_ssh_session(reader, writer, connection_data)
        except Exception as e:
            self.logger.error(f"Error handling SSH connection {session_id}: {e}")
        finally:
            # Log the complete session
            connection_data['end_time'] = datetime.now()
            connection_data['duration'] = (connection_data['end_time'] - connection_data['start_time']).total_seconds()
            await self.log_connection(connection_data)
            await self.close_connection(writer, session_id)
    
    async def simulate_ssh_session(self, reader, writer, connection_data):
        """Simulate an SSH session"""
        
        # Send SSH banner
        await self.send_banner(writer, self.config["banner"])
        
        # SSH protocol negotiation
        await self.ssh_protocol_negotiation(reader, writer, connection_data)
        
        # Authentication phase
        authenticated = await self.ssh_authentication(reader, writer, connection_data)
        
        if authenticated:
            # Interactive shell simulation
            await self.ssh_shell_simulation(reader, writer, connection_data)
    
    async def ssh_protocol_negotiation(self, reader, writer, connection_data):
        """Handle SSH protocol negotiation"""
        try:
            # Read client banner
            client_banner = await self.read_data(reader, 255)
            if client_banner:
                banner_str = client_banner.decode('utf-8', errors='ignore').strip()
                connection_data['connection_data']['client_banner'] = banner_str
                self.logger.info(f"Client banner: {banner_str}")
            
            # Send server banner
            server_banner = f"SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3"
            writer.write(server_banner.encode() + b'\r\n')
            await writer.drain()
            
            # Simulate key exchange (simplified)
            kex_data = await self.read_data(reader, 1024)
            if kex_data:
                connection_data['payloads'].append({
                    'type': 'kex_init',
                    'data': base64.b64encode(kex_data).decode(),
                    'timestamp': datetime.now().isoformat()
                })
            
            # Send fake key exchange response
            fake_kex = b'\x00\x00\x01\x2c\x0a\x14' + b'\x00' * 294  # Simplified KEX
            writer.write(fake_kex)
            await writer.drain()
            
        except Exception as e:
            self.logger.error(f"SSH protocol negotiation error: {e}")
    
    async def ssh_authentication(self, reader, writer, connection_data):
        """Handle SSH authentication attempts"""
        max_attempts = 3
        attempts = 0
        
        while attempts < max_attempts:
            try:
                # Read authentication request
                auth_data = await self.read_data(reader, 1024)
                if not auth_data:
                    break
                
                attempts += 1
                
                # Parse authentication attempt (simplified)
                auth_str = auth_data.decode('utf-8', errors='ignore')
                
                # Look for username/password patterns
                username = self.extract_username(auth_str)
                password = self.extract_password(auth_str)
                
                if username or password:
                    auth_attempt = {
                        'attempt': attempts,
                        'username': username,
                        'password': password,
                        'timestamp': datetime.now().isoformat(),
                        'success': False
                    }
                    
                    connection_data['commands'].append(auth_attempt)
                    
                    self.logger.info(f"SSH auth attempt {attempts}: {username}:{password}")
                    
                    # Check if credentials match our fake users
                    if username in self.fake_users and self.fake_users[username] == password:
                        auth_attempt['success'] = True
                        # Send success response
                        writer.write(b'\x00\x00\x00\x0c\x0a\x34\x00\x00\x00\x00\x00\x00\x00\x00')
                        await writer.drain()
                        return True
                
                # Send failure response
                writer.write(b'\x00\x00\x00\x0c\x0a\x33\x00\x00\x00\x00\x00\x00\x00\x00')
                await writer.drain()
                
            except Exception as e:
                self.logger.error(f"SSH authentication error: {e}")
                break
        
        return False
    
    async def ssh_shell_simulation(self, reader, writer, connection_data):
        """Simulate an interactive SSH shell"""
        self.logger.info("Starting SSH shell simulation")
        
        # Send shell prompt
        prompt = b"root@honeypot:~# "
        writer.write(prompt)
        await writer.drain()
        
        while True:
            try:
                # Read command
                command_data = await self.read_data(reader, 1024)
                if not command_data:
                    break
                
                command = self.parse_command(command_data)
                if command:
                    connection_data['commands'].append({
                        'command': command,
                        'timestamp': datetime.now().isoformat()
                    })
                    
                    self.logger.info(f"SSH command: {command}")
                    
                    # Simulate command responses
                    response = self.simulate_command_response(command)
                    if response:
                        writer.write(response.encode() + b'\r\n')
                        await writer.drain()
                    
                    # Send new prompt
                    writer.write(prompt)
                    await writer.drain()
                
            except Exception as e:
                self.logger.error(f"SSH shell simulation error: {e}")
                break
    
    def extract_username(self, auth_str):
        """Extract username from authentication string"""
        # Simple pattern matching for username
        patterns = [r'user[:\s]+(\w+)', r'login[:\s]+(\w+)', r'username[:\s]+(\w+)']
        import re
        
        for pattern in patterns:
            match = re.search(pattern, auth_str, re.IGNORECASE)
            if match:
                return match.group(1)
        
        # Fallback: look for common usernames
        common_users = ['root', 'admin', 'user', 'test', 'ubuntu']
        for user in common_users:
            if user in auth_str.lower():
                return user
        
        return "unknown"
    
    def extract_password(self, auth_str):
        """Extract password from authentication string"""
        # Simple pattern matching for password
        patterns = [r'pass[:\s]+(\w+)', r'password[:\s]+(\w+)', r'pwd[:\s]+(\w+)']
        import re
        
        for pattern in patterns:
            match = re.search(pattern, auth_str, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return "unknown"
    
    def simulate_command_response(self, command):
        """Simulate responses to common commands"""
        command = command.lower().strip()
        
        responses = {
            'ls': 'bin  boot  dev  etc  home  lib  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var',
            'pwd': '/root',
            'whoami': 'root',
            'id': 'uid=0(root) gid=0(root) groups=0(root)',
            'uname -a': 'Linux honeypot 4.15.0-96-generic #97-Ubuntu SMP Wed Apr 1 03:25:46 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux',
            'cat /etc/passwd': 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin',
            'ps aux': 'USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\nroot         1  0.0  0.1  77616  8784 ?        Ss   10:00   0:01 /sbin/init',
            'netstat -an': 'Active Internet connections (servers and established)\nProto Recv-Q Send-Q Local Address           Foreign Address         State',
            'exit': None,  # Will close connection
            'logout': None,  # Will close connection
        }
        
        if command in ['exit', 'logout']:
            return None
        
        return responses.get(command, f"bash: {command}: command not found")

    def analyze_ssh_command(self, command, connection_data):
        """Analyze SSH command for attack patterns and suspicious activity"""
        command_lower = command.lower().strip()

        attack_indicators = []
        severity = 'low'
        attack_type = 'reconnaissance'
        recommendations = []

        # Reconnaissance commands
        recon_commands = {
            'whoami': {'severity': 'low', 'type': 'reconnaissance', 'desc': 'User enumeration'},
            'id': {'severity': 'low', 'type': 'reconnaissance', 'desc': 'User ID enumeration'},
            'uname -a': {'severity': 'medium', 'type': 'reconnaissance', 'desc': 'System information gathering'},
            'cat /etc/passwd': {'severity': 'high', 'type': 'reconnaissance', 'desc': 'Password file access attempt'},
            'ps aux': {'severity': 'medium', 'type': 'reconnaissance', 'desc': 'Process enumeration'},
            'netstat -an': {'severity': 'medium', 'type': 'reconnaissance', 'desc': 'Network service enumeration'},
            'ls -la': {'severity': 'low', 'type': 'reconnaissance', 'desc': 'Directory listing'},
            'pwd': {'severity': 'low', 'type': 'reconnaissance', 'desc': 'Current directory check'}
        }

        # Malicious command patterns
        malicious_patterns = {
            'rm -rf': {'severity': 'critical', 'type': 'destruction', 'desc': 'File deletion attempt'},
            'wget': {'severity': 'high', 'type': 'download', 'desc': 'File download attempt'},
            'curl': {'severity': 'high', 'type': 'download', 'desc': 'File download attempt'},
            'chmod +x': {'severity': 'high', 'type': 'execution', 'desc': 'File permission modification'},
            'crontab': {'severity': 'high', 'type': 'persistence', 'desc': 'Scheduled task creation'},
            'nohup': {'severity': 'high', 'type': 'persistence', 'desc': 'Background process execution'},
            'nc -l': {'severity': 'critical', 'type': 'backdoor', 'desc': 'Netcat listener setup'},
            'python -c': {'severity': 'high', 'type': 'execution', 'desc': 'Python code execution'},
            'bash -i': {'severity': 'high', 'type': 'shell', 'desc': 'Interactive shell spawn'},
            '/bin/sh': {'severity': 'high', 'type': 'shell', 'desc': 'Shell execution'},
            'sudo': {'severity': 'high', 'type': 'privilege_escalation', 'desc': 'Privilege escalation attempt'}
        }

        # Check for exact command matches
        if command_lower in recon_commands:
            info = recon_commands[command_lower]
            attack_indicators.append(f"Reconnaissance: {info['desc']}")
            severity = info['severity']
            attack_type = info['type']

        # Check for malicious patterns
        for pattern, info in malicious_patterns.items():
            if pattern in command_lower:
                attack_indicators.append(f"Malicious Activity: {info['desc']}")
                severity = self._max_severity_ssh(severity, info['severity'])
                attack_type = info['type']

        # Additional suspicious patterns
        if any(char in command for char in ['|', ';', '&&', '||']):
            attack_indicators.append("Command chaining detected")
            severity = self._max_severity_ssh(severity, 'medium')

        if any(pattern in command_lower for pattern in ['base64', 'echo', 'printf']):
            attack_indicators.append("Potential obfuscation detected")
            severity = self._max_severity_ssh(severity, 'medium')

        # Generate recommendations
        if attack_type == 'reconnaissance':
            recommendations = [
                "Monitor for follow-up attacks from this IP",
                "Implement rate limiting for SSH connections",
                "Consider blocking reconnaissance attempts"
            ]
        elif attack_type in ['destruction', 'backdoor']:
            recommendations = [
                f"IMMEDIATE: Block IP {connection_data['source_ip']}",
                "Conduct security audit of SSH access",
                "Review and strengthen SSH security policies",
                "Monitor for lateral movement attempts"
            ]
        elif attack_type in ['download', 'execution']:
            recommendations = [
                "Monitor network traffic for malware downloads",
                "Scan systems for unauthorized files",
                "Review file integrity monitoring alerts",
                "Consider implementing application whitelisting"
            ]

        return {
            'attack_indicators': attack_indicators,
            'severity': severity,
            'attack_type': attack_type,
            'recommendations': recommendations,
            'suspicious': len(attack_indicators) > 0
        }

    def _max_severity_ssh(self, current, new):
        """Compare severity levels and return the higher one"""
        severity_order = ['low', 'medium', 'high', 'critical']
        current_idx = severity_order.index(current) if current in severity_order else 0
        new_idx = severity_order.index(new) if new in severity_order else 0
        return severity_order[max(current_idx, new_idx)]
