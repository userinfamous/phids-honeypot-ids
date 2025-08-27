"""
Enhanced logging system for PHIDS honeypots with connection status classification
"""

import logging
import time
from datetime import datetime
from enum import Enum
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict


class ConnectionStatus(Enum):
    """Connection status classification"""
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    ERROR = "ERROR"
    TIMEOUT = "TIMEOUT"


class ServiceType(Enum):
    """Supported service types"""
    SSH = "SSH"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    TELNET = "TELNET"
    FTP = "FTP"


@dataclass
class ConnectionOutcome:
    """Detailed connection outcome information"""
    status: ConnectionStatus
    reason: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


@dataclass
class AuthenticationAttempt:
    """Authentication attempt details"""
    username: str
    password: str
    method: str
    success: bool
    timestamp: str


@dataclass
class HTTPRequestDetails:
    """HTTP request specific details"""
    method: str
    path: str
    user_agent: str
    headers: Dict[str, str]
    query_params: Dict[str, str]
    body_size: int
    attack_vectors: list = None


@dataclass
class EnhancedConnectionLog:
    """Enhanced connection log entry with comprehensive details"""
    # Basic connection info
    session_id: str
    source_ip: str
    source_port: int
    destination_port: int
    service_type: ServiceType
    
    # Timing information
    start_time: datetime
    end_time: Optional[datetime] = None
    duration: Optional[float] = None
    
    # Connection outcome
    outcome: ConnectionOutcome = None
    
    # Service-specific details
    authentication_attempts: list = None
    http_details: HTTPRequestDetails = None
    commands_executed: list = None
    
    # Security analysis
    attack_indicators: list = None
    severity_level: str = "low"
    threat_classification: str = "reconnaissance"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for database storage"""
        data = asdict(self)
        
        # Convert datetime objects to ISO strings
        if self.start_time:
            data['start_time'] = self.start_time.isoformat()
        if self.end_time:
            data['end_time'] = self.end_time.isoformat()
            
        # Convert enums to strings
        if self.service_type:
            data['service_type'] = self.service_type.value
        if self.outcome and self.outcome.status:
            data['outcome']['status'] = self.outcome.status.value
            
        return data
    
    def format_log_message(self) -> str:
        """Format enhanced log message according to requirements"""
        # Calculate duration if not set
        if self.duration is None and self.end_time and self.start_time:
            self.duration = (self.end_time - self.start_time).total_seconds()
        
        duration_str = f"{self.duration:.1f}s" if self.duration else "0.0s"
        status_str = self.outcome.status.value if self.outcome else "UNKNOWN"
        
        # Base message format
        base_msg = (
            f"{self.service_type.value}: Connection from {self.source_ip}:{self.source_port} - "
            f"{status_str} - Duration: {duration_str}"
        )
        
        # Add service-specific details
        details = []
        
        if self.service_type == ServiceType.SSH and self.authentication_attempts:
            auth_details = []
            for auth in self.authentication_attempts:
                auth_details.append(f"user={auth.username}, pass={auth.password}")
            if auth_details:
                details.append(f"Auth attempts: {'; '.join(auth_details)}")
        
        elif self.service_type in [ServiceType.HTTP, ServiceType.HTTPS] and self.http_details:
            http_info = f"{self.http_details.method} {self.http_details.path}"
            if self.http_details.user_agent:
                http_info += f" - User-Agent: {self.http_details.user_agent}"
            details.append(http_info)
        
        elif self.service_type == ServiceType.TELNET and self.commands_executed:
            details.append(f"Commands: {len(self.commands_executed)}")
        
        # Add failure reason if applicable
        if self.outcome and self.outcome.reason:
            details.append(f"Reason: {self.outcome.reason}")
        
        # Combine all details
        if details:
            return f"{base_msg} - {' - '.join(details)}"
        else:
            return base_msg


class EnhancedHoneypotLogger:
    """Enhanced logger for honeypot services with connection status tracking"""
    
    def __init__(self, service_name: str, logger: logging.Logger):
        self.service_name = service_name
        self.logger = logger
        self.active_sessions: Dict[str, EnhancedConnectionLog] = {}
    
    def start_connection_log(self, session_id: str, source_ip: str, source_port: int, 
                           destination_port: int, service_type: ServiceType) -> EnhancedConnectionLog:
        """Start tracking a new connection"""
        connection_log = EnhancedConnectionLog(
            session_id=session_id,
            source_ip=source_ip,
            source_port=source_port,
            destination_port=destination_port,
            service_type=service_type,
            start_time=datetime.now(),
            authentication_attempts=[],
            commands_executed=[],
            attack_indicators=[]
        )
        
        self.active_sessions[session_id] = connection_log
        
        # Log connection start
        self.logger.info(f"Connection started: {source_ip}:{source_port} -> {service_type.value}:{destination_port} (session: {session_id})")
        
        return connection_log
    
    def log_authentication_attempt(self, session_id: str, username: str, password: str, 
                                 method: str = "password", success: bool = False):
        """Log authentication attempt"""
        if session_id in self.active_sessions:
            auth_attempt = AuthenticationAttempt(
                username=username,
                password=password,
                method=method,
                success=success,
                timestamp=datetime.now().isoformat()
            )
            
            self.active_sessions[session_id].authentication_attempts.append(auth_attempt)
            
            # Log immediately
            status = "SUCCESS" if success else "FAILED"
            self.logger.info(f"Auth attempt ({status}): {username}:{password} (session: {session_id})")
    
    def log_http_request(self, session_id: str, method: str, path: str, user_agent: str = "",
                        headers: Dict[str, str] = None, query_params: Dict[str, str] = None,
                        body_size: int = 0, attack_vectors: list = None):
        """Log HTTP request details"""
        if session_id in self.active_sessions:
            http_details = HTTPRequestDetails(
                method=method,
                path=path,
                user_agent=user_agent,
                headers=headers or {},
                query_params=query_params or {},
                body_size=body_size,
                attack_vectors=attack_vectors or []
            )
            
            self.active_sessions[session_id].http_details = http_details
            
            # Log immediately
            self.logger.info(f"HTTP request: {method} {path} - User-Agent: {user_agent} (session: {session_id})")
    
    def log_command_execution(self, session_id: str, command: str, success: bool = True):
        """Log command execution"""
        if session_id in self.active_sessions:
            cmd_log = {
                'command': command,
                'success': success,
                'timestamp': datetime.now().isoformat()
            }
            
            self.active_sessions[session_id].commands_executed.append(cmd_log)
            
            # Log immediately
            status = "SUCCESS" if success else "FAILED"
            self.logger.info(f"Command ({status}): {command} (session: {session_id})")
    
    def end_connection_log(self, session_id: str, status: ConnectionStatus, 
                          reason: str = None, details: Dict[str, Any] = None) -> Optional[EnhancedConnectionLog]:
        """End connection tracking and generate final log"""
        if session_id not in self.active_sessions:
            return None
        
        connection_log = self.active_sessions[session_id]
        connection_log.end_time = datetime.now()
        connection_log.duration = (connection_log.end_time - connection_log.start_time).total_seconds()
        connection_log.outcome = ConnectionOutcome(
            status=status,
            reason=reason,
            details=details
        )
        
        # Generate and log the enhanced message
        enhanced_message = connection_log.format_log_message()
        
        # Log with appropriate level based on status
        if status == ConnectionStatus.SUCCESS:
            self.logger.info(enhanced_message)
        elif status == ConnectionStatus.FAILED:
            self.logger.warning(enhanced_message)
        elif status in [ConnectionStatus.ERROR, ConnectionStatus.TIMEOUT]:
            self.logger.error(enhanced_message)
        
        # Remove from active sessions
        del self.active_sessions[session_id]
        
        return connection_log
    
    def get_active_session(self, session_id: str) -> Optional[EnhancedConnectionLog]:
        """Get active session log"""
        return self.active_sessions.get(session_id)
