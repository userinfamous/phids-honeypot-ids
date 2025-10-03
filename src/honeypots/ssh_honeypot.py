"""
SSH Honeypot implementation for PHIDS using Paramiko
"""
import asyncio
import logging
import base64
import hashlib
import time
import threading
import socket
from datetime import datetime
from config import HONEYPOT_CONFIG
from .base_honeypot import BaseHoneypot
from ..core.enhanced_logger import EnhancedHoneypotLogger, ConnectionStatus, ServiceType

try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False
    logging.warning("Paramiko not available - SSH honeypot will use fallback implementation")


class SSHServerInterface(paramiko.ServerInterface):
    """Paramiko SSH server interface for the honeypot"""

    def __init__(self, honeypot, session_id, client_info):
        self.honeypot = honeypot
        self.session_id = session_id
        self.client_info = client_info
        self.authenticated = False
        self.username = None
        self.password = None

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        """Check password authentication"""
        self.username = username
        self.password = password

        # Check against fake users
        auth_success = username in self.honeypot.fake_users and self.honeypot.fake_users[username] == password

        # Log authentication attempt with correct success status
        self.honeypot.enhanced_logger.log_authentication_attempt(
            session_id=self.session_id,
            username=username,
            password=password,
            method="password",
            success=auth_success
        )

        # Log authentication event to database
        auth_event_data = {
            'timestamp': datetime.now(),
            'source_ip': self.client_info['source_ip'],
            'source_port': self.client_info['source_port'],
            'destination_port': self.honeypot.config['port'],
            'service_type': 'ssh',
            'session_id': self.session_id,
            'username': username,
            'password': password,
            'auth_method': 'password',
            'success': auth_success,
            'failure_reason': None if auth_success else 'Invalid credentials',
            'connection_data': {
                'client_version': getattr(self, 'client_version', 'unknown'),
                'auth_type': 'password'
            }
        }

        # Schedule database logging (async operation)
        import asyncio
        if hasattr(self.honeypot, 'main_loop') and self.honeypot.main_loop:
            asyncio.run_coroutine_threadsafe(
                self.honeypot.db_manager.log_authentication_event(auth_event_data),
                self.honeypot.main_loop
            )

        if auth_success:
            self.authenticated = True
            self.honeypot.logger.info(f"SSH authentication SUCCESS: {username}:{password}")
            return paramiko.AUTH_SUCCESSFUL
        else:
            self.honeypot.logger.info(f"SSH authentication FAILED: {username}:{password}")
            return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return 'password'

    def check_channel_shell_request(self, channel):
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True


class SSHHoneypot(BaseHoneypot):
    """SSH Honeypot that simulates an SSH server using Paramiko"""

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
        # Initialize enhanced logger
        self.enhanced_logger = EnhancedHoneypotLogger("SSH", self.logger)

        # Generate or load SSH host key
        self.host_key = None
        self.main_loop = None  # Store reference to main event loop
        if PARAMIKO_AVAILABLE:
            self._setup_host_key()

    def _setup_host_key(self):
        """Setup SSH host key for the server"""
        try:
            # Generate a temporary RSA key for the honeypot
            self.host_key = paramiko.RSAKey.generate(2048)
            self.logger.info("Generated temporary SSH host key")
        except Exception as e:
            self.logger.error(f"Failed to generate SSH host key: {e}")
            self.host_key = None
        
    async def start(self):
        """Start the SSH honeypot server"""
        if not self.is_enabled():
            self.logger.info("SSH honeypot is disabled")
            return

        if not PARAMIKO_AVAILABLE:
            self.logger.error("Paramiko not available - cannot start SSH honeypot")
            return

        if not self.host_key:
            self.logger.error("No SSH host key available - cannot start SSH honeypot")
            return

        self.logger.info(f"Starting SSH honeypot on {self.config['bind_address']}:{self.config['port']}")

        try:
            # Store reference to main event loop
            self.main_loop = asyncio.get_event_loop()

            # Start the server in a separate thread since paramiko is synchronous
            self.running = True
            self.server_thread = threading.Thread(target=self._run_server, daemon=True)
            self.server_thread.start()
            self.logger.info(f"SSH honeypot started successfully")

            # Keep the async method running
            while self.running:
                await asyncio.sleep(1)

        except Exception as e:
            self.logger.error(f"Failed to start SSH honeypot: {e}")
            self.running = False

    def _run_server(self):
        """Run the SSH server in a separate thread"""
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.config["bind_address"], self.config["port"]))
            sock.listen(100)

            self.logger.info(f"SSH honeypot listening on {self.config['bind_address']}:{self.config['port']}")

            while self.running:
                try:
                    client_sock, addr = sock.accept()
                    self.logger.info(f"SSH connection from {addr[0]}:{addr[1]}")

                    # Handle connection in a separate thread
                    client_thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_sock, addr),
                        daemon=True
                    )
                    client_thread.start()

                except Exception as e:
                    if self.running:
                        self.logger.error(f"Error accepting SSH connection: {e}")

        except Exception as e:
            self.logger.error(f"SSH server error: {e}")
        finally:
            try:
                sock.close()
            except:
                pass
    
    def _handle_client(self, client_sock, addr):
        """Handle individual SSH client connections"""
        session_id = self.generate_session_id()
        client_info = {
            'source_ip': addr[0],
            'source_port': addr[1]
        }

        # Start enhanced connection logging
        connection_log = self.enhanced_logger.start_connection_log(
            session_id=session_id,
            source_ip=client_info['source_ip'],
            source_port=client_info['source_port'],
            destination_port=self.config['port'],
            service_type=ServiceType.SSH
        )

        start_time = datetime.now()
        connection_data = {
            'session_id': session_id,
            'source_ip': client_info['source_ip'],
            'source_port': client_info['source_port'],
            'destination_port': self.config['port'],
            'service_type': 'ssh',
            'start_time': start_time,
            'timestamp': start_time,
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
            'user_agent': f"SSH-Client-{client_info['source_ip']}",
            'connection_status': 'FAILED',
            'failure_reason': 'Connection in progress'
        }

        connection_status = ConnectionStatus.FAILED
        failure_reason = None

        try:
            # Create SSH transport
            transport = paramiko.Transport(client_sock)
            transport.add_server_key(self.host_key)

            # Create server interface
            server_interface = SSHServerInterface(self, session_id, client_info)

            # Start SSH server
            transport.start_server(server=server_interface)

            # Wait for authentication
            channel = transport.accept(timeout=30)
            if channel is None:
                failure_reason = "No channel established"
                connection_status = ConnectionStatus.FAILED
            else:
                if server_interface.authenticated:
                    connection_status = ConnectionStatus.SUCCESS
                    failure_reason = None

                    # Handle shell session
                    self._handle_shell_session(channel, connection_data, server_interface)
                else:
                    connection_status = ConnectionStatus.FAILED
                    failure_reason = "Authentication failed"

        except paramiko.SSHException as e:
            connection_status = ConnectionStatus.ERROR
            failure_reason = f"SSH protocol error: {str(e)}"
            self.logger.warning(f"SSH protocol error for {session_id}: {e}")
        except socket.timeout:
            connection_status = ConnectionStatus.TIMEOUT
            failure_reason = "Connection timeout"
            self.logger.warning(f"SSH connection {session_id} timed out")
        except Exception as e:
            connection_status = ConnectionStatus.ERROR
            failure_reason = f"Unexpected error: {str(e)}"
            self.logger.error(f"Error handling SSH connection {session_id}: {e}")
        finally:
            try:
                client_sock.close()
            except:
                pass

            # End enhanced logging
            enhanced_log = self.enhanced_logger.end_connection_log(
                session_id=session_id,
                status=connection_status,
                reason=failure_reason
            )

            # Complete connection data
            connection_data['end_time'] = datetime.now()
            connection_data['duration'] = (connection_data['end_time'] - connection_data['start_time']).total_seconds()
            connection_data['connection_status'] = connection_status.value
            connection_data['failure_reason'] = failure_reason
            if enhanced_log:
                connection_data['enhanced_log'] = enhanced_log.to_dict()

            # Log final connection status
            status_msg = f"SSH Connection {connection_status.value.upper()}"
            if connection_status == ConnectionStatus.SUCCESS:
                self.logger.info(f"{status_msg}: {client_info['source_ip']} -> Full session with authentication and shell access")
            elif connection_status == ConnectionStatus.FAILED:
                self.logger.warning(f"{status_msg}: {client_info['source_ip']} -> {failure_reason}")
            elif connection_status == ConnectionStatus.ERROR:
                self.logger.error(f"{status_msg}: {client_info['source_ip']} -> {failure_reason}")
            elif connection_status == ConnectionStatus.TIMEOUT:
                self.logger.warning(f"{status_msg}: {client_info['source_ip']} -> {failure_reason}")

            # Log connection asynchronously using main event loop
            if self.main_loop and not self.main_loop.is_closed():
                try:
                    asyncio.run_coroutine_threadsafe(
                        self.log_connection(connection_data),
                        self.main_loop
                    )
                except Exception as e:
                    self.logger.error(f"Failed to log connection asynchronously: {e}")
            else:
                # Fallback: log synchronously
                self.logger.warning("Main event loop not available, skipping async connection logging")

    async def handle_connection(self, reader, writer):
        """Handle incoming connections - required by base class but not used in paramiko implementation"""
        # This method is required by the abstract base class but not used
        # since we're using paramiko's synchronous interface
        pass

    async def stop(self):
        """Stop the SSH honeypot server"""
        self.logger.info("Stopping SSH honeypot")
        self.running = False

        # Wait for server thread to finish
        if hasattr(self, 'server_thread') and self.server_thread.is_alive():
            self.server_thread.join(timeout=5)

        # Close all active connections
        for session_id in list(self.active_connections.keys()):
            connection = self.active_connections[session_id]
            if 'writer' in connection:
                await self.close_connection(connection.get('writer'), session_id)

        self.logger.info("SSH honeypot stopped")
    
    def _handle_shell_session(self, channel, connection_data, server_interface):
        """Handle interactive shell session"""
        try:
            # Send welcome message
            channel.send("Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-96-generic x86_64)\r\n\r\n")
            channel.send("root@honeypot:~# ")

            # Set timeout for shell interaction
            channel.settimeout(300)  # 5 minutes

            command_buffer = ""

            while True:
                try:
                    # Read data from channel
                    data = channel.recv(1024)
                    if not data:
                        break

                    # Decode and process input
                    try:
                        text = data.decode('utf-8')
                    except UnicodeDecodeError:
                        text = data.decode('utf-8', errors='ignore')

                    # Handle special characters
                    for char in text:
                        if char == '\r' or char == '\n':
                            # Send newline echo
                            channel.send("\r\n")

                            # Command completed
                            if command_buffer.strip():
                                command = command_buffer.strip()

                                # Log command execution
                                self.enhanced_logger.log_command_execution(
                                    session_id=connection_data['session_id'],
                                    command=command,
                                    success=True
                                )

                                connection_data['commands'].append({
                                    'command': command,
                                    'timestamp': datetime.now().isoformat()
                                })

                                # Analyze command for attack patterns
                                analysis = self.analyze_ssh_command(command, connection_data)
                                if analysis['suspicious']:
                                    connection_data['connection_data']['attack_indicators'].extend(analysis['attack_indicators'])
                                    connection_data['connection_data']['severity'] = analysis['severity']
                                    connection_data['connection_data']['attack_classification'] = analysis['attack_type']
                                    connection_data['connection_data']['recommendations'] = analysis['recommendations']
                                    connection_data['connection_data']['suspicious_activity'] = True

                                # Send command response
                                response = self.simulate_command_response(command)
                                if response is not None:
                                    channel.send(response + "\r\n")
                                    channel.send("root@honeypot:~# ")
                                else:
                                    # Exit command
                                    break

                                command_buffer = ""
                            else:
                                channel.send("root@honeypot:~# ")
                        elif char == '\x7f' or char == '\x08':  # Backspace
                            if command_buffer:
                                command_buffer = command_buffer[:-1]
                                # Echo backspace (move cursor back, space, move back again)
                                channel.send("\x08 \x08")
                        elif char == '\x03':  # Ctrl+C
                            command_buffer = ""
                            channel.send("^C\r\nroot@honeypot:~# ")
                        elif char == '\x04':  # Ctrl+D (EOF)
                            # Exit on Ctrl+D
                            break
                        elif ord(char) >= 32:  # Printable characters
                            command_buffer += char
                            # Echo the character back to the client
                            channel.send(char)

                except socket.timeout:
                    self.logger.info(f"SSH shell session timeout for {connection_data['session_id']}")
                    break
                except Exception as e:
                    self.logger.error(f"Error in SSH shell session: {e}")
                    break

        except Exception as e:
            self.logger.error(f"SSH shell session error: {e}")
        finally:
            try:
                channel.close()
            except:
                pass
    




    
    def simulate_command_response(self, command):
        """Simulate responses to common commands"""
        command = command.lower().strip()
        command_parts = command.split()
        base_command = command_parts[0] if command_parts else ""

        # Handle exit commands first
        if base_command in ['exit', 'logout']:
            return None

        # Define base command responses
        base_responses = {
            'ls': 'bin  boot  dev  etc  home  lib  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var',
            'pwd': '/root',
            'whoami': 'root',
            'id': 'uid=0(root) gid=0(root) groups=0(root)',
            'uname': 'Linux honeypot 4.15.0-96-generic #97-Ubuntu SMP Wed Apr 1 03:25:46 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux',
            'ps': 'USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\nroot         1  0.0  0.1  77616  8784 ?        Ss   10:00   0:01 /sbin/init\nroot       123  0.0  0.0  12345  1234 pts/0    S    10:30   0:00 bash',
            'netstat': 'Active Internet connections (servers and established)\nProto Recv-Q Send-Q Local Address           Foreign Address         State\ntcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\ntcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN',
            'cat': self._handle_cat_command(command_parts),
            'wget': 'bash: wget: command not found',
            'curl': 'bash: curl: command not found',
            'nc': 'bash: nc: command not found',
            'nmap': 'bash: nmap: command not found',
            'python': 'Python 2.7.17 (default, Apr 10 2020, 13:48:39)\n[GCC 7.5.0] on linux2\nType "help", "copyright", "credits" or "license" for more information.\n>>> ',
            'python3': 'Python 3.6.9 (default, Apr 18 2020, 01:56:04)\n[GCC 8.4.0] on linux\nType "help", "copyright", "credits" or "license" for more information.\n>>> ',
            'chmod': '',  # Silent success for chmod commands
            'mkdir': '',  # Silent success for mkdir commands
            'touch': '',  # Silent success for touch commands
            'echo': self._handle_echo_command(command_parts),
            'history': '    1  whoami\n    2  ls -la\n    3  cat /etc/passwd\n    4  history',
            'w': ' 10:30:15 up  1:30,  1 user,  load average: 0.00, 0.01, 0.05\nUSER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\nroot     pts/0    192.168.1.100    10:00    0.00s  0.04s  0.00s w',
            'who': 'root     pts/0        2020-04-01 10:00 (192.168.1.100)',
            'uptime': ' 10:30:15 up  1:30,  1 user,  load average: 0.00, 0.01, 0.05',
            'df': 'Filesystem     1K-blocks    Used Available Use% Mounted on\n/dev/sda1       20971520 5242880  15728640  26% /\ntmpfs            1048576       0   1048576   0% /tmp',
            'free': '              total        used        free      shared  buff/cache   available\nMem:        2097152      524288     1048576        8192      524288     1572864\nSwap:       1048576           0     1048576',
            'ifconfig': 'eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 192.168.1.100  netmask 255.255.255.0  broadcast 192.168.1.255\n        ether 00:0c:29:12:34:56  txqueuelen 1000  (Ethernet)',
            'ip': 'bash: ip: command not found'
        }

        # Handle specific command patterns
        if base_command == 'cat':
            return self._handle_cat_command(command_parts)
        elif base_command == 'echo':
            return self._handle_echo_command(command_parts)
        elif base_command in base_responses:
            response = base_responses[base_command]
            return response if isinstance(response, str) else response
        else:
            return f"bash: {base_command}: command not found"

    def _handle_cat_command(self, command_parts):
        """Handle cat command with different file arguments"""
        if len(command_parts) < 2:
            return "cat: missing file operand"

        file_path = command_parts[1]

        file_responses = {
            '/etc/passwd': 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nsync:x:4:65534:sync:/bin:/bin/sync\ngames:x:5:60:games:/usr/games:/usr/sbin/nologin\nman:x:6:12:man:/var/cache/man:/usr/sbin/nologin\nlp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\nmail:x:8:8:mail:/var/mail:/usr/sbin/nologin\nnews:x:9:9:news:/var/spool/news:/usr/sbin/nologin\nuucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\nproxy:x:13:13:proxy:/bin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nbackup:x:34:34:backup:/var/backups:/usr/sbin/nologin\nlist:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin\nirc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin\ngnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\nsystemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin\nsystemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin\nsyslog:x:102:106::/home/syslog:/usr/sbin/nologin\nmessagebus:x:103:107::/nonexistent:/usr/sbin/nologin\n_apt:x:104:65534::/nonexistent:/usr/sbin/nologin\nlxd:x:105:65534::/var/lib/lxd/:/bin/false\nuuidd:x:106:110::/run/uuidd:/usr/sbin/nologin\ndnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin\nlandscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin\npollinate:x:109:1::/var/cache/pollinate:/bin/false\nsshd:x:110:65534::/run/sshd:/usr/sbin/nologin\nubuntu:x:1000:1000:Ubuntu,,,:/home/ubuntu:/bin/bash',
            '/etc/shadow': 'cat: /etc/shadow: Permission denied',
            '/etc/hosts': '127.0.0.1\tlocalhost\n127.0.1.1\thoneypot\n\n# The following lines are desirable for IPv6 capable hosts\n::1     ip6-localhost ip6-loopback\nfe00::0 ip6-localnet\nff00::0 ip6-mcastprefix\nff02::1 ip6-allnodes\nff02::2 ip6-allrouters',
            '/proc/version': 'Linux version 4.15.0-96-generic (buildd@lgw01-amd64-038) (gcc version 7.5.0 (Ubuntu 7.5.0-3ubuntu1~18.04)) #97-Ubuntu SMP Wed Apr 1 03:25:46 UTC 2020',
            '/proc/cpuinfo': 'processor\t: 0\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t\t: 142\nmodel name\t: Intel(R) Core(TM) i7-8550U CPU @ 1.80GHz\nstepping\t: 10\nmicrocode\t: 0xca\ncpu MHz\t\t: 1992.000\ncache size\t: 8192 KB',
            '/etc/issue': 'Ubuntu 18.04.3 LTS \\n \\l',
            '/etc/os-release': 'NAME="Ubuntu"\nVERSION="18.04.3 LTS (Bionic Beaver)"\nID=ubuntu\nID_LIKE=debian\nPRETTY_NAME="Ubuntu 18.04.3 LTS"\nVERSION_ID="18.04"\nHOME_URL="https://www.ubuntu.com/"\nSUPPORT_URL="https://help.ubuntu.com/"\nBUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"\nPRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"\nVERSION_CODENAME=bionic\nUBUNTU_CODENAME=bionic'
        }

        return file_responses.get(file_path, f"cat: {file_path}: No such file or directory")

    def _handle_echo_command(self, command_parts):
        """Handle echo command"""
        if len(command_parts) < 2:
            return ""

        # Join all arguments after 'echo'
        return " ".join(command_parts[1:])

    def analyze_ssh_command(self, command, connection_data):
        """Analyze SSH command for attack patterns and suspicious activity"""
        command_lower = command.lower().strip()
        command_parts = command_lower.split()
        base_command = command_parts[0] if command_parts else ""

        attack_indicators = []
        severity = 'low'
        attack_type = 'reconnaissance'
        recommendations = []

        # Reconnaissance commands (base commands and specific patterns)
        recon_base_commands = {
            'whoami': {'severity': 'low', 'type': 'reconnaissance', 'desc': 'User enumeration'},
            'id': {'severity': 'low', 'type': 'reconnaissance', 'desc': 'User ID enumeration'},
            'uname': {'severity': 'medium', 'type': 'reconnaissance', 'desc': 'System information gathering'},
            'ps': {'severity': 'medium', 'type': 'reconnaissance', 'desc': 'Process enumeration'},
            'netstat': {'severity': 'medium', 'type': 'reconnaissance', 'desc': 'Network service enumeration'},
            'ls': {'severity': 'low', 'type': 'reconnaissance', 'desc': 'Directory listing'},
            'cat': {'severity': 'medium', 'type': 'reconnaissance', 'desc': 'File content access'},
            'w': {'severity': 'low', 'type': 'reconnaissance', 'desc': 'User activity enumeration'},
            'who': {'severity': 'low', 'type': 'reconnaissance', 'desc': 'Logged in users enumeration'},
            'uptime': {'severity': 'low', 'type': 'reconnaissance', 'desc': 'System uptime check'},
            'df': {'severity': 'low', 'type': 'reconnaissance', 'desc': 'Disk usage enumeration'},
            'free': {'severity': 'low', 'type': 'reconnaissance', 'desc': 'Memory usage enumeration'},
            'ifconfig': {'severity': 'medium', 'type': 'reconnaissance', 'desc': 'Network interface enumeration'},
            'history': {'severity': 'medium', 'type': 'reconnaissance', 'desc': 'Command history access'},
        }

        # Specific high-risk file access patterns
        high_risk_patterns = {
            'cat /etc/passwd': {'severity': 'high', 'type': 'reconnaissance', 'desc': 'Password file access attempt'},
            'cat /etc/shadow': {'severity': 'critical', 'type': 'reconnaissance', 'desc': 'Shadow file access attempt'},
            'cat /proc/version': {'severity': 'medium', 'type': 'reconnaissance', 'desc': 'Kernel version enumeration'},
            'cat /etc/issue': {'severity': 'medium', 'type': 'reconnaissance', 'desc': 'OS version enumeration'},
            'pwd': {'severity': 'low', 'type': 'reconnaissance', 'desc': 'Current directory check'}
        }

        # Malicious base commands and patterns
        malicious_base_commands = {
            'wget': {'severity': 'high', 'type': 'download', 'desc': 'File download attempt'},
            'curl': {'severity': 'high', 'type': 'download', 'desc': 'File download attempt'},
            'crontab': {'severity': 'high', 'type': 'persistence', 'desc': 'Scheduled task creation'},
            'nohup': {'severity': 'high', 'type': 'persistence', 'desc': 'Background process execution'},
            'nc': {'severity': 'critical', 'type': 'backdoor', 'desc': 'Netcat usage detected'},
            'nmap': {'severity': 'high', 'type': 'scanning', 'desc': 'Network scanning attempt'},
            'sudo': {'severity': 'high', 'type': 'privilege_escalation', 'desc': 'Privilege escalation attempt'},
            'su': {'severity': 'high', 'type': 'privilege_escalation', 'desc': 'User switching attempt'},
            'python': {'severity': 'medium', 'type': 'execution', 'desc': 'Python interpreter usage'},
            'python3': {'severity': 'medium', 'type': 'execution', 'desc': 'Python3 interpreter usage'},
            'perl': {'severity': 'medium', 'type': 'execution', 'desc': 'Perl interpreter usage'},
            'ruby': {'severity': 'medium', 'type': 'execution', 'desc': 'Ruby interpreter usage'},
            'bash': {'severity': 'medium', 'type': 'shell', 'desc': 'Bash shell execution'},
            'sh': {'severity': 'medium', 'type': 'shell', 'desc': 'Shell execution'},
            'rm': {'severity': 'high', 'type': 'destruction', 'desc': 'File deletion attempt'},
            'chmod': {'severity': 'medium', 'type': 'modification', 'desc': 'File permission modification'},
            'chown': {'severity': 'medium', 'type': 'modification', 'desc': 'File ownership modification'},
        }

        # Malicious command patterns (for more complex detection)
        malicious_patterns = {
            'rm -rf': {'severity': 'critical', 'type': 'destruction', 'desc': 'Recursive file deletion attempt'},
            'chmod +x': {'severity': 'high', 'type': 'execution', 'desc': 'Making file executable'},
            'nc -l': {'severity': 'critical', 'type': 'backdoor', 'desc': 'Netcat listener setup'},
            'python -c': {'severity': 'high', 'type': 'execution', 'desc': 'Python code execution'},
            'bash -i': {'severity': 'high', 'type': 'shell', 'desc': 'Interactive shell spawn'},
            '/bin/sh': {'severity': 'high', 'type': 'shell', 'desc': 'Direct shell execution'},
            'base64': {'severity': 'medium', 'type': 'obfuscation', 'desc': 'Base64 encoding/decoding'},
        }

        # Check for specific high-risk patterns first
        for pattern, info in high_risk_patterns.items():
            if command_lower == pattern:
                attack_indicators.append(f"High-Risk Access: {info['desc']}")
                severity = info['severity']
                attack_type = info['type']
                break

        # Check base command for reconnaissance
        if base_command in recon_base_commands and not attack_indicators:
            info = recon_base_commands[base_command]
            attack_indicators.append(f"Reconnaissance: {info['desc']}")
            severity = info['severity']
            attack_type = info['type']

        # Check base command for malicious activity
        if base_command in malicious_base_commands:
            info = malicious_base_commands[base_command]
            attack_indicators.append(f"Malicious Activity: {info['desc']}")
            severity = self._max_severity_ssh(severity, info['severity'])
            attack_type = info['type']

        # Check for malicious patterns in full command
        for pattern, info in malicious_patterns.items():
            if pattern in command_lower:
                attack_indicators.append(f"Malicious Pattern: {info['desc']}")
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
