"""
HTTP Honeypot implementation for PHIDS
"""
import asyncio
import logging
import json
import urllib.parse
import time
from datetime import datetime
from config import HONEYPOT_CONFIG
from .base_honeypot import BaseHoneypot
from ..core.enhanced_logger import EnhancedHoneypotLogger, ConnectionStatus, ServiceType
from ..dashboard.event_broadcaster import event_broadcaster


class HTTPHoneypot(BaseHoneypot):
    """HTTP Honeypot that simulates a web server"""
    
    def __init__(self):
        config = HONEYPOT_CONFIG["http"]
        super().__init__("http", config)
        self.fake_pages = {
            "/": self.generate_index_page(),
            "/admin": self.generate_admin_page(),
            "/login": self.generate_login_page(),
            "/phpmyadmin": self.generate_phpmyadmin_page(),
            "/wp-admin": self.generate_wordpress_page(),
            "/robots.txt": "User-agent: *\nDisallow: /admin\nDisallow: /backup\nDisallow: /config"
        }
        # Initialize enhanced logger
        self.enhanced_logger = EnhancedHoneypotLogger("HTTP", self.logger)
        # Store reference to main event loop for async operations
        self.main_loop = None
        
    async def start(self):
        """Start the HTTP honeypot server"""
        if not self.is_enabled():
            self.logger.info("HTTP honeypot is disabled")
            return

        # Store reference to main event loop for async operations
        self.main_loop = asyncio.get_event_loop()

        self.logger.info(f"Starting HTTP honeypot on {self.config['bind_address']}:{self.config['port']}")

        try:
            self.server = await asyncio.start_server(
                self.handle_connection,
                self.config["bind_address"],
                self.config["port"]
            )
            self.running = True
            self.logger.info(f"HTTP honeypot started successfully")

            async with self.server:
                await self.server.serve_forever()

        except Exception as e:
            self.logger.error(f"Failed to start HTTP honeypot: {e}")
            self.running = False
    
    async def stop(self):
        """Stop the HTTP honeypot server"""
        self.logger.info("Stopping HTTP honeypot")
        self.running = False
        
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        
        # Close all active connections
        for session_id in list(self.active_connections.keys()):
            connection = self.active_connections[session_id]
            await self.close_connection(connection.get('writer'), session_id)
        
        self.logger.info("HTTP honeypot stopped")
    
    async def handle_connection(self, reader, writer):
        """Handle incoming HTTP connections"""
        session_id = self.generate_session_id()
        client_info = self.get_client_info(writer)

        # Start enhanced connection logging
        connection_log = self.enhanced_logger.start_connection_log(
            session_id=session_id,
            source_ip=client_info['source_ip'],
            source_port=client_info['source_port'],
            destination_port=self.config['port'],
            service_type=ServiceType.HTTP
        )
        
        # Store connection info with proper timestamp
        start_time = datetime.now()
        connection_data = {
            'session_id': session_id,
            'source_ip': client_info['source_ip'],
            'source_port': client_info['source_port'],
            'destination_port': self.config['port'],
            'service_type': 'http',
            'start_time': start_time,
            'timestamp': start_time,  # Explicit timestamp for database logging
            'commands': [],
            'payloads': [],
            'connection_data': {},
            'connection_status': 'FAILED',  # Default to FAILED, will be updated if successful
            'failure_reason': 'Connection in progress'
        }
        
        self.active_connections[session_id] = {
            'reader': reader,
            'writer': writer,
            'data': connection_data
        }
        
        connection_status = ConnectionStatus.FAILED
        failure_reason = None

        try:
            # Attempt HTTP request handling
            request_result = await self.handle_http_request(reader, writer, connection_data)

            if request_result.get('success', False):
                connection_status = ConnectionStatus.SUCCESS
            elif request_result.get('timeout', False):
                connection_status = ConnectionStatus.TIMEOUT
                failure_reason = "Request timeout"
            else:
                connection_status = ConnectionStatus.FAILED
                failure_reason = request_result.get('reason', "Request processing failed")

        except asyncio.TimeoutError:
            connection_status = ConnectionStatus.TIMEOUT
            failure_reason = "Connection timeout"
            self.logger.warning(f"HTTP connection {session_id} timed out")
        except ConnectionResetError:
            connection_status = ConnectionStatus.FAILED
            failure_reason = "Connection reset by client"
            self.logger.info(f"HTTP connection {session_id} reset by client")
        except Exception as e:
            connection_status = ConnectionStatus.ERROR
            failure_reason = f"Protocol error: {str(e)}"
            self.logger.error(f"Error handling HTTP connection {session_id}: {e}")
        finally:
            # End enhanced logging with outcome
            enhanced_log = self.enhanced_logger.end_connection_log(
                session_id=session_id,
                status=connection_status,
                reason=failure_reason
            )

            # Log the complete session (existing system)
            connection_data['end_time'] = datetime.now()
            connection_data['duration'] = (connection_data['end_time'] - connection_data['start_time']).total_seconds()

            # Add enhanced logging data to connection_data for database
            if enhanced_log:
                connection_data['connection_status'] = connection_status.value
                connection_data['failure_reason'] = failure_reason
                connection_data['enhanced_log'] = enhanced_log.to_dict()

            # Analyze attack success and add to connection data
            attack_analysis = self._analyze_attack_success(connection_data)
            connection_data.update(attack_analysis)

            await self.log_connection(connection_data)
            await self.close_connection(writer, session_id)
    
    async def handle_http_request(self, reader, writer, connection_data):
        """Handle HTTP request"""
        request_result = {'success': False, 'timeout': False, 'reason': None}

        try:
            # Read HTTP request with timeout
            request_data = await asyncio.wait_for(
                self.read_data(reader, 8192),
                timeout=30.0
            )

            if not request_data:
                request_result['reason'] = "No request data received"
                return request_result

            request_str = request_data.decode('utf-8', errors='ignore')

            # Parse HTTP request
            request_info = self.parse_http_request(request_str)
            request_info['source_ip'] = connection_data['source_ip']  # Add source IP for attack analysis

            # Enhanced attack detection
            attack_details = self.detect_attack_patterns_enhanced(request_info)

            # Log HTTP request with enhanced logger
            user_agent = request_info['headers'].get('User-Agent', 'Unknown')
            query_params = {}
            if '?' in request_info['path']:
                path_parts = request_info['path'].split('?', 1)
                if len(path_parts) > 1:
                    query_params = dict(urllib.parse.parse_qsl(path_parts[1]))

            self.enhanced_logger.log_http_request(
                session_id=connection_data['session_id'],
                method=request_info['method'],
                path=request_info['path'],
                user_agent=user_agent,
                headers=request_info['headers'],
                query_params=query_params,
                body_size=len(request_info.get('body', '')),
                attack_vectors=attack_details['attack_vectors']
            )

            # Log request details with attack information
            request_log = {
                'method': request_info['method'],
                'path': request_info['path'],
                'headers': request_info['headers'],
                'body': request_info['body'],
                'timestamp': datetime.now().isoformat(),
                'attack_vectors': attack_details['attack_vectors'],
                'payloads': attack_details['payloads'],
                'severity': attack_details['severity'],
                'attack_type': attack_details['primary_attack_type']
            }

            connection_data['commands'].append(request_log)
            connection_data['payloads'].extend(attack_details['payloads'])
            connection_data['user_agent'] = request_info['headers'].get('User-Agent', 'Unknown')

            # Enhanced logging with attack details
            if attack_details['attack_vectors']:
                self.logger.warning(f"ATTACK DETECTED: {attack_details['primary_attack_type']} from {connection_data['source_ip']} - {attack_details['description']}")
                self.logger.info(f"Attack vectors: {', '.join(attack_details['attack_vectors'])}")
                self.logger.info(f"Payloads: {', '.join(attack_details['payloads'])}")
                self.logger.info(f"Severity: {attack_details['severity']}")
                self.logger.info(f"Recommendations: {'; '.join(attack_details['recommendations'])}")
            else:
                self.logger.info(f"HTTP {request_info['method']} {request_info['path']} from {connection_data['source_ip']}")

            # Store enhanced connection data
            connection_data['connection_data'] = {
                'method': request_info['method'],
                'path': request_info['path'],
                'user_agent': connection_data['user_agent'],
                'attack_summary': {
                    'attack_type': attack_details['primary_attack_type'],
                    'severity': attack_details['severity'],
                    'vectors_count': len(attack_details['attack_vectors']),
                    'payloads_count': len(attack_details['payloads']),
                    'description': attack_details['description'],
                    'recommendations': attack_details['recommendations']
                }
            }

            # Generate response
            response = self.generate_http_response(request_info)

            # Send response
            writer.write(response.encode())
            await writer.drain()

            # Mark request as successful
            request_result['success'] = True

            # Check for additional requests (keep-alive)
            if request_info['headers'].get('Connection', '').lower() == 'keep-alive':
                # Handle additional requests
                while True:
                    additional_data = await asyncio.wait_for(
                        self.read_data(reader, 8192), 
                        timeout=5.0
                    )
                    if not additional_data:
                        break
                    
                    additional_request = self.parse_http_request(
                        additional_data.decode('utf-8', errors='ignore')
                    )
                    
                    connection_data['commands'].append({
                        'method': additional_request['method'],
                        'path': additional_request['path'],
                        'headers': additional_request['headers'],
                        'body': additional_request['body'],
                        'timestamp': datetime.now().isoformat()
                    })
                    
                    additional_response = self.generate_http_response(additional_request)
                    writer.write(additional_response.encode())
                    await writer.drain()
            
            return request_result

        except asyncio.TimeoutError:
            request_result['timeout'] = True
            request_result['reason'] = "Request timeout"
            return request_result
        except Exception as e:
            request_result['reason'] = f"Request processing error: {str(e)}"
            self.logger.error(f"HTTP request handling error: {e}")
            return request_result
    
    def parse_http_request(self, request_str):
        """Parse HTTP request string"""
        lines = request_str.split('\r\n')
        if not lines:
            return self.empty_request()
        
        # Parse request line
        request_line = lines[0].split(' ')
        if len(request_line) < 3:
            return self.empty_request()
        
        method = request_line[0]
        path = request_line[1]
        version = request_line[2]
        
        # Parse headers
        headers = {}
        body_start = 1
        for i, line in enumerate(lines[1:], 1):
            if line == '':
                body_start = i + 1
                break
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        
        # Parse body
        body = '\r\n'.join(lines[body_start:]) if body_start < len(lines) else ''
        
        return {
            'method': method,
            'path': path,
            'version': version,
            'headers': headers,
            'body': body,
            'query_params': self.parse_query_params(path)
        }
    
    def empty_request(self):
        """Return empty request structure"""
        return {
            'method': 'UNKNOWN',
            'path': '/',
            'version': 'HTTP/1.1',
            'headers': {},
            'body': '',
            'query_params': {}
        }
    
    def parse_query_params(self, path):
        """Parse query parameters from path"""
        if '?' not in path:
            return {}
        
        try:
            query_string = path.split('?', 1)[1]
            return dict(urllib.parse.parse_qsl(query_string))
        except Exception:
            return {}
    
    def generate_http_response(self, request_info):
        """Generate HTTP response based on request"""
        path = request_info['path'].split('?')[0]  # Remove query params
        method = request_info['method']

        # Check for common attack patterns
        if self.is_attack_pattern(request_info):
            return self.generate_error_response(403, "Forbidden")

        # Handle login attempts (check POST before serving GET pages)
        if path == "/login" and method == "POST":
            return self.handle_login_attempt(request_info)

        # Handle admin login attempts (check POST before serving GET pages)
        if path == "/admin" and method == "POST":
            return self.handle_admin_login_attempt(request_info)

        # Handle other admin-related POST requests
        if path in ["/wp-admin", "/phpmyadmin"] and method == "POST":
            return self.handle_admin_login_attempt(request_info)

        # Handle different paths (GET requests for pages)
        if path in self.fake_pages:
            content = self.fake_pages[path]
            return self.generate_success_response(content)
        
        # Handle common vulnerable paths
        vulnerable_paths = [
            "/wp-login.php", "/administrator", "/admin.php",
            "/phpmyadmin/index.php", "/mysql/admin", "/dbadmin",
            "/shell.php", "/cmd.php", "/backdoor.php"
        ]
        
        if any(vuln_path in path for vuln_path in vulnerable_paths):
            return self.generate_vulnerable_response(path)
        
        # Default 404 response
        return self.generate_error_response(404, "Not Found")
    
    def is_attack_pattern(self, request_info):
        """Detect common attack patterns - simplified version for basic detection"""
        # Use the enhanced detection method and return boolean
        attack_details = self.detect_attack_patterns_enhanced(request_info)
        return len(attack_details['attack_vectors']) > 0

    def detect_attack_patterns_enhanced(self, request_info):
        """Enhanced attack pattern detection with detailed analysis"""
        path = request_info['path'].lower()
        body = request_info['body'].lower()
        headers = {k.lower(): v.lower() for k, v in request_info.get('headers', {}).items()}
        user_agent = headers.get('user-agent', '')

        attack_details = {
            'attack_vectors': [],
            'payloads': [],
            'severity': 'low',
            'primary_attack_type': 'reconnaissance',
            'description': 'Basic web request',
            'recommendations': [],
            'source_ip': request_info.get('source_ip', 'unknown')
        }

        # SQL injection patterns with severity
        sql_patterns = {
            'union select': {'severity': 'high', 'description': 'SQL Union injection attempt'},
            'or 1=1': {'severity': 'high', 'description': 'SQL boolean injection'},
            'drop table': {'severity': 'critical', 'description': 'SQL table deletion attempt'},
            'insert into': {'severity': 'high', 'description': 'SQL data insertion attempt'},
            'delete from': {'severity': 'high', 'description': 'SQL data deletion attempt'},
            "' or '": {'severity': 'medium', 'description': 'SQL quote injection'},
            'waitfor delay': {'severity': 'high', 'description': 'SQL time-based injection'},
            'information_schema': {'severity': 'high', 'description': 'SQL schema enumeration'}
        }

        # XSS patterns with severity
        xss_patterns = {
            '<script': {'severity': 'high', 'description': 'JavaScript injection attempt'},
            'javascript:': {'severity': 'medium', 'description': 'JavaScript protocol injection'},
            'onerror=': {'severity': 'high', 'description': 'Event handler XSS'},
            'onload=': {'severity': 'high', 'description': 'Onload event XSS'},
            'alert(': {'severity': 'medium', 'description': 'Alert-based XSS test'},
            '<img src=x': {'severity': 'high', 'description': 'Image-based XSS'},
            '<svg onload': {'severity': 'high', 'description': 'SVG-based XSS'}
        }

        # Directory traversal patterns
        traversal_patterns = {
            '../': {'severity': 'high', 'description': 'Directory traversal attempt'},
            '..\\': {'severity': 'high', 'description': 'Windows directory traversal'},
            '%2e%2e%2f': {'severity': 'high', 'description': 'URL-encoded traversal'},
            '%2e%2e%5c': {'severity': 'high', 'description': 'URL-encoded Windows traversal'},
            '/etc/passwd': {'severity': 'critical', 'description': 'Linux password file access'},
            '/windows/system32': {'severity': 'critical', 'description': 'Windows system access'}
        }

        # Command injection patterns
        command_patterns = {
            ';cat ': {'severity': 'critical', 'description': 'Command injection - file reading'},
            '|whoami': {'severity': 'high', 'description': 'Command injection - user enumeration'},
            '&dir': {'severity': 'high', 'description': 'Command injection - directory listing'},
            '`ls': {'severity': 'high', 'description': 'Command injection - backtick execution'},
            '$(': {'severity': 'high', 'description': 'Command injection - subshell execution'},
            '; ps aux': {'severity': 'high', 'description': 'Command injection - process enumeration'}
        }

        # Check SQL injection
        for pattern, info in sql_patterns.items():
            if pattern in path or pattern in body:
                attack_details['attack_vectors'].append(f"SQL Injection: {info['description']}")
                attack_details['payloads'].append(pattern)
                attack_details['primary_attack_type'] = 'sql_injection'
                attack_details['severity'] = self._max_severity(attack_details['severity'], info['severity'])
                attack_details['description'] = info['description']

        # Check XSS
        for pattern, info in xss_patterns.items():
            if pattern in path or pattern in body:
                attack_details['attack_vectors'].append(f"XSS: {info['description']}")
                attack_details['payloads'].append(pattern)
                if attack_details['primary_attack_type'] == 'reconnaissance':
                    attack_details['primary_attack_type'] = 'xss'
                attack_details['severity'] = self._max_severity(attack_details['severity'], info['severity'])
                if 'XSS' not in attack_details['description']:
                    attack_details['description'] = info['description']

        # Check directory traversal
        for pattern, info in traversal_patterns.items():
            if pattern in path or pattern in body:
                attack_details['attack_vectors'].append(f"Directory Traversal: {info['description']}")
                attack_details['payloads'].append(pattern)
                if attack_details['primary_attack_type'] == 'reconnaissance':
                    attack_details['primary_attack_type'] = 'directory_traversal'
                attack_details['severity'] = self._max_severity(attack_details['severity'], info['severity'])
                if 'traversal' not in attack_details['description'].lower():
                    attack_details['description'] = info['description']

        # Check command injection
        for pattern, info in command_patterns.items():
            if pattern in path or pattern in body:
                attack_details['attack_vectors'].append(f"Command Injection: {info['description']}")
                attack_details['payloads'].append(pattern)
                if attack_details['primary_attack_type'] in ['reconnaissance', 'xss']:
                    attack_details['primary_attack_type'] = 'command_injection'
                attack_details['severity'] = self._max_severity(attack_details['severity'], info['severity'])
                if 'command' not in attack_details['description'].lower():
                    attack_details['description'] = info['description']

        # Generate recommendations based on detected attacks
        if attack_details['attack_vectors']:
            attack_details['recommendations'] = self.generate_security_recommendations(attack_details)

        return attack_details

    def _max_severity(self, current, new):
        """Compare severity levels and return the higher one"""
        severity_order = ['low', 'medium', 'high', 'critical']
        current_idx = severity_order.index(current) if current in severity_order else 0
        new_idx = severity_order.index(new) if new in severity_order else 0
        return severity_order[max(current_idx, new_idx)]

    def generate_security_recommendations(self, attack_details):
        """Generate actionable security recommendations"""
        recommendations = []

        if attack_details['primary_attack_type'] == 'sql_injection':
            recommendations.extend([
                "Implement parameterized queries/prepared statements",
                "Enable SQL injection detection in WAF",
                "Validate and sanitize all user inputs",
                "Use least privilege database accounts",
                "Monitor database access logs"
            ])

        if attack_details['primary_attack_type'] == 'xss':
            recommendations.extend([
                "Implement Content Security Policy (CSP)",
                "Encode output data before rendering",
                "Validate and sanitize user inputs",
                "Use XSS protection headers",
                "Implement input validation on client and server"
            ])

        if attack_details['primary_attack_type'] == 'directory_traversal':
            recommendations.extend([
                "Implement proper file path validation",
                "Use chroot jails or sandboxing",
                "Restrict file system access permissions",
                "Validate file names and paths",
                "Monitor file access attempts"
            ])

        if attack_details['primary_attack_type'] == 'command_injection':
            recommendations.extend([
                "Avoid system command execution with user input",
                "Use parameterized APIs instead of shell commands",
                "Implement strict input validation",
                "Use application sandboxing",
                "Monitor system command execution"
            ])

        # General recommendations for high/critical severity
        if attack_details['severity'] in ['high', 'critical']:
            recommendations.extend([
                f"IMMEDIATE ACTION: Block source IP {attack_details.get('source_ip', 'unknown')}",
                "Review and update security policies",
                "Conduct security audit of affected systems",
                "Implement rate limiting and DDoS protection"
            ])

        return recommendations[:5]  # Limit to top 5 recommendations

    def generate_success_response(self, content, content_type="text/html"):
        """Generate successful HTTP response"""
        response = f"""HTTP/1.1 200 OK\r
Server: {self.config['banner']}\r
Content-Type: {content_type}\r
Content-Length: {len(content)}\r
Connection: close\r
\r
{content}"""
        return response
    
    def generate_error_response(self, status_code, status_text):
        """Generate HTTP error response"""
        content = f"<html><body><h1>{status_code} {status_text}</h1></body></html>"
        response = f"""HTTP/1.1 {status_code} {status_text}\r
Server: {self.config['banner']}\r
Content-Type: text/html\r
Content-Length: {len(content)}\r
Connection: close\r
\r
{content}"""
        return response
    
    def generate_vulnerable_response(self, path):
        """Generate response for vulnerable paths"""
        content = f"""<html>
<head><title>Login Required</title></head>
<body>
<h2>Authentication Required</h2>
<form method="post" action="{path}">
Username: <input type="text" name="username"><br>
Password: <input type="password" name="password"><br>
<input type="submit" value="Login">
</form>
</body>
</html>"""
        return self.generate_success_response(content)
    
    def handle_login_attempt(self, request_info):
        """Handle login form submission"""
        # Parse form data
        form_data = {}
        if request_info['body']:
            try:
                form_data = dict(urllib.parse.parse_qsl(request_info['body']))
            except Exception:
                pass
        
        username = form_data.get('username', '')
        password = form_data.get('password', '')
        
        self.logger.info(f"Login attempt: {username}:{password}")
        
        # Always return login failed
        content = """<html>
<head><title>Login Failed</title></head>
<body>
<h2>Login Failed</h2>
<p>Invalid username or password.</p>
<a href="/login">Try again</a>
</body>
</html>"""
        return self.generate_success_response(content)

    def handle_admin_login_attempt(self, request_info):
        """Handle admin login form submission with honeypot authentication"""
        # Parse form data
        form_data = {}
        if request_info['body']:
            try:
                form_data = dict(urllib.parse.parse_qsl(request_info['body']))
            except Exception:
                pass

        # Extract credentials from different form field names
        username = (form_data.get('username', '') or
                   form_data.get('log', '') or
                   form_data.get('pma_username', ''))
        password = (form_data.get('password', '') or
                   form_data.get('pwd', '') or
                   form_data.get('pma_password', ''))

        self.logger.info(f"Admin login attempt: {username}:{password} on {request_info['path']}")

        # Honeypot behavior: Accept specific "weak" credentials to simulate vulnerability
        # This allows attackers to think they've gained access while we monitor them
        weak_credentials = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', '123456'),
            ('root', 'root'),
            ('administrator', 'admin'),
            ('test', 'test'),
            ('guest', 'guest'),
            ('demo', 'demo')
        ]

        if (username.lower(), password.lower()) in weak_credentials:
            # Redirect to success page on the dashboard
            session_id = self.generate_session_id()
            redirect_url = f"http://127.0.0.1:5001/success?username={urllib.parse.quote(username)}&session_id={session_id}"

            # Log successful authentication event to database
            auth_event_data = {
                'timestamp': datetime.now(),
                'source_ip': request_info.get('source_ip', 'unknown'),
                'source_port': request_info.get('source_port', 0),
                'destination_port': self.config['port'],
                'service_type': 'http',
                'session_id': session_id,
                'username': username,
                'password': password,
                'auth_method': 'form',
                'success': True,
                'failure_reason': None,
                'user_agent': request_info.get('user_agent', 'unknown'),
                'connection_data': {
                    'path': request_info.get('path', '/admin'),
                    'method': 'POST',
                    'auth_type': 'form'
                }
            }

            # Schedule database logging and broadcasting (async operation)
            import asyncio
            if hasattr(self, 'main_loop') and self.main_loop:
                try:
                    # Log to database
                    asyncio.run_coroutine_threadsafe(
                        self.db_manager.log_authentication_event(auth_event_data),
                        self.main_loop
                    )
                    # Broadcast to dashboard for real-time display
                    asyncio.run_coroutine_threadsafe(
                        event_broadcaster.broadcast_authentication(auth_event_data),
                        self.main_loop
                    )
                except Exception as e:
                    self.logger.error(f"Failed to log/broadcast authentication event: {e}")

            response = f"""HTTP/1.1 302 Found\r
Server: {self.config['banner']}\r
Location: {redirect_url}\r
Content-Length: 0\r
Connection: close\r
\r
"""
            return response
        else:
            # Log failed authentication event to database
            session_id = self.generate_session_id()
            auth_event_data = {
                'timestamp': datetime.now(),
                'source_ip': request_info.get('source_ip', 'unknown'),
                'source_port': request_info.get('source_port', 0),
                'destination_port': self.config['port'],
                'service_type': 'http',
                'session_id': session_id,
                'username': username,
                'password': password,
                'auth_method': 'form',
                'success': False,
                'failure_reason': 'Invalid credentials',
                'user_agent': request_info.get('user_agent', 'unknown'),
                'connection_data': {
                    'path': request_info.get('path', '/admin'),
                    'method': 'POST',
                    'auth_type': 'form'
                }
            }

            # Schedule database logging and broadcasting (async operation)
            import asyncio
            if hasattr(self, 'main_loop') and self.main_loop:
                try:
                    # Log to database
                    asyncio.run_coroutine_threadsafe(
                        self.db_manager.log_authentication_event(auth_event_data),
                        self.main_loop
                    )
                    # Broadcast to dashboard for real-time display
                    asyncio.run_coroutine_threadsafe(
                        event_broadcaster.broadcast_authentication(auth_event_data),
                        self.main_loop
                    )
                except Exception as e:
                    self.logger.error(f"Failed to log/broadcast authentication event: {e}")

            # Return login failed for other credentials
            content = f"""<html>
<head><title>Login Failed</title></head>
<body>
<h2>Authentication Failed</h2>
<p>Invalid username or password for admin panel.</p>
<p>Attempted credentials: {username} / {'*' * len(password)}</p>
<a href="{request_info['path']}">Try again</a>
</body>
</html>"""
            return self.generate_success_response(content)

    def generate_index_page(self):
        """Generate fake index page"""
        return """<!DOCTYPE html>
<html>
<head>
    <title>Welcome to Ubuntu Server</title>
</head>
<body>
    <h1>It works!</h1>
    <p>This is the default web page for this server.</p>
    <p>The web server software is running but no content has been added, yet.</p>
    <hr>
    <p><em>Apache/2.4.41 (Ubuntu) Server</em></p>
</body>
</html>"""
    
    def generate_admin_page(self):
        """Generate fake admin page"""
        return """<!DOCTYPE html>
<html>
<head>
    <title>Admin Panel</title>
</head>
<body>
    <h1>Administration Panel</h1>
    <form method="post" action="/admin">
        <p>Username: <input type="text" name="username"></p>
        <p>Password: <input type="password" name="password"></p>
        <p><input type="submit" value="Login"></p>
    </form>
</body>
</html>"""
    
    def generate_login_page(self):
        """Generate fake login page"""
        return """<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
</head>
<body>
    <h2>Please Login</h2>
    <form method="post" action="/login">
        <p>Username: <input type="text" name="username"></p>
        <p>Password: <input type="password" name="password"></p>
        <p><input type="submit" value="Login"></p>
    </form>
</body>
</html>"""
    
    def generate_phpmyadmin_page(self):
        """Generate fake phpMyAdmin page"""
        return """<!DOCTYPE html>
<html>
<head>
    <title>phpMyAdmin</title>
</head>
<body>
    <h1>Welcome to phpMyAdmin</h1>
    <form method="post" action="/phpmyadmin">
        <p>Username: <input type="text" name="pma_username"></p>
        <p>Password: <input type="password" name="pma_password"></p>
        <p><input type="submit" value="Go"></p>
    </form>
</body>
</html>"""
    
    def generate_wordpress_page(self):
        """Generate fake WordPress admin page"""
        return """<!DOCTYPE html>
<html>
<head>
    <title>WordPress Admin</title>
</head>
<body>
    <h1>WordPress</h1>
    <form method="post" action="/wp-admin">
        <p>Username: <input type="text" name="log"></p>
        <p>Password: <input type="password" name="pwd"></p>
        <p><input type="submit" value="Log In"></p>
    </form>
</body>
</html>"""

    def _analyze_attack_success(self, connection_data):
        """Analyze whether attacks were successful and what level of access was gained"""
        analysis = {
            'attack_success_status': 'unknown',
            'access_level_gained': 'none',
            'attack_indicators': [],
            'honeypot_response': 'standard',
            'success_reason': None
        }

        try:
            # Get request and response data
            commands = connection_data.get('commands', [])
            payloads = connection_data.get('payloads', [])
            user_agent = connection_data.get('user_agent', '')

            # Analyze for attack patterns
            attack_patterns_found = []

            for command in commands:
                if isinstance(command, dict):
                    path = command.get('path', '').lower()
                    method = command.get('method', '').upper()
                    body = command.get('body', '').lower()

                    # Check for common attack patterns
                    if any(pattern in path for pattern in ['admin', 'login', 'config', 'backup']):
                        attack_patterns_found.append('admin_access_attempt')

                    if any(pattern in path + body for pattern in ["'", 'union', 'select', 'drop', 'insert']):
                        attack_patterns_found.append('sql_injection')

                    if any(pattern in path + body for pattern in ['<script', 'javascript:', 'onerror']):
                        attack_patterns_found.append('xss_attempt')

                    if any(pattern in path for pattern in ['../', '..\\']):
                        attack_patterns_found.append('directory_traversal')

                    if method in ['PUT', 'DELETE', 'PATCH'] or 'upload' in path:
                        attack_patterns_found.append('file_manipulation')

            # Check user agent for attack tools
            if any(tool in user_agent.lower() for tool in ['sqlmap', 'nikto', 'burp', 'nmap', 'attackbot']):
                attack_patterns_found.append('automated_tool')

            analysis['attack_indicators'] = attack_patterns_found

            # Determine attack success status
            if not attack_patterns_found:
                analysis['attack_success_status'] = 'no_attack_detected'
                analysis['honeypot_response'] = 'normal_response'
            else:
                # For honeypot purposes, we intentionally allow some "successful" responses
                # to make attackers think they're making progress
                if 'admin_access_attempt' in attack_patterns_found:
                    analysis['attack_success_status'] = 'simulated_success'
                    analysis['access_level_gained'] = 'admin_panel_access'
                    analysis['honeypot_response'] = 'fake_admin_panel'
                    analysis['success_reason'] = 'Honeypot provided fake admin interface'
                elif 'sql_injection' in attack_patterns_found:
                    analysis['attack_success_status'] = 'simulated_success'
                    analysis['access_level_gained'] = 'database_simulation'
                    analysis['honeypot_response'] = 'fake_sql_response'
                    analysis['success_reason'] = 'Honeypot simulated vulnerable database'
                elif 'automated_tool' in attack_patterns_found:
                    analysis['attack_success_status'] = 'detected_and_logged'
                    analysis['access_level_gained'] = 'none'
                    analysis['honeypot_response'] = 'standard_response'
                    analysis['success_reason'] = 'Attack tool detected and monitored'
                else:
                    analysis['attack_success_status'] = 'attempted_but_failed'
                    analysis['access_level_gained'] = 'none'
                    analysis['honeypot_response'] = 'error_response'
                    analysis['success_reason'] = 'Attack attempt blocked by honeypot'

        except Exception as e:
            self.logger.warning(f"Error analyzing attack success: {e}")
            analysis['attack_success_status'] = 'analysis_error'
            analysis['success_reason'] = f'Analysis failed: {str(e)}'

        return analysis
