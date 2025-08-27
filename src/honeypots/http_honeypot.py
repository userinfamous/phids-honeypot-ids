"""
HTTP Honeypot implementation for PHIDS
"""
import asyncio
import logging
import json
import urllib.parse
from datetime import datetime
from config import HONEYPOT_CONFIG
from .base_honeypot import BaseHoneypot


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
        
    async def start(self):
        """Start the HTTP honeypot server"""
        if not self.is_enabled():
            self.logger.info("HTTP honeypot is disabled")
            return
        
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
        
        self.logger.info(f"New HTTP connection from {client_info['source_ip']}:{client_info['source_port']} (session: {session_id})")
        
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
            'connection_data': {}
        }
        
        self.active_connections[session_id] = {
            'reader': reader,
            'writer': writer,
            'data': connection_data
        }
        
        try:
            await self.handle_http_request(reader, writer, connection_data)
        except Exception as e:
            self.logger.error(f"Error handling HTTP connection {session_id}: {e}")
        finally:
            # Log the complete session
            connection_data['end_time'] = datetime.now()
            connection_data['duration'] = (connection_data['end_time'] - connection_data['start_time']).total_seconds()
            await self.log_connection(connection_data)
            await self.close_connection(writer, session_id)
    
    async def handle_http_request(self, reader, writer, connection_data):
        """Handle HTTP request"""
        try:
            # Read HTTP request
            request_data = await self.read_data(reader, 8192)
            if not request_data:
                return
            
            request_str = request_data.decode('utf-8', errors='ignore')
            
            # Parse HTTP request
            request_info = self.parse_http_request(request_str)
            
            # Log request details
            connection_data['commands'].append({
                'method': request_info['method'],
                'path': request_info['path'],
                'headers': request_info['headers'],
                'body': request_info['body'],
                'timestamp': datetime.now().isoformat()
            })
            
            connection_data['user_agent'] = request_info['headers'].get('User-Agent', 'Unknown')
            
            self.logger.info(f"HTTP {request_info['method']} {request_info['path']} from {connection_data['source_ip']}")
            
            # Generate response
            response = self.generate_http_response(request_info)
            
            # Send response
            writer.write(response.encode())
            await writer.drain()
            
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
            
        except asyncio.TimeoutError:
            # Normal timeout for keep-alive connections
            pass
        except Exception as e:
            self.logger.error(f"HTTP request handling error: {e}")
    
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
        
        # Handle different paths
        if path in self.fake_pages:
            content = self.fake_pages[path]
            return self.generate_success_response(content)
        
        # Handle login attempts
        if path == "/login" and method == "POST":
            return self.handle_login_attempt(request_info)
        
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
        """Detect common attack patterns"""
        path = request_info['path'].lower()
        body = request_info['body'].lower()
        
        # SQL injection patterns
        sql_patterns = ['union select', 'or 1=1', 'drop table', 'insert into', 'delete from']
        
        # XSS patterns
        xss_patterns = ['<script>', 'javascript:', 'onerror=', 'onload=']
        
        # Directory traversal
        traversal_patterns = ['../', '..\\', '/etc/passwd', '/windows/system32']
        
        # Command injection
        command_patterns = [';cat ', '|cat ', '`cat ', '$(cat']
        
        all_patterns = sql_patterns + xss_patterns + traversal_patterns + command_patterns
        
        for pattern in all_patterns:
            if pattern in path or pattern in body:
                return True
        
        return False
    
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
