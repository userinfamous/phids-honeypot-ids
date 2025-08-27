"""
Base honeypot class for PHIDS
"""
import asyncio
import logging
import uuid
from abc import ABC, abstractmethod
from datetime import datetime
from src.core.database import DatabaseManager


class BaseHoneypot(ABC):
    """Base class for all honeypots"""
    
    def __init__(self, service_name, config):
        self.service_name = service_name
        self.config = config
        self.logger = logging.getLogger(f"honeypot.{service_name}")
        self.db_manager = DatabaseManager()
        self.running = False
        self.server = None
        self.active_connections = {}
        
    def is_enabled(self):
        """Check if this honeypot is enabled"""
        return self.config.get("enabled", False)
    
    @abstractmethod
    async def start(self):
        """Start the honeypot service"""
        pass
    
    @abstractmethod
    async def stop(self):
        """Stop the honeypot service"""
        pass
    
    @abstractmethod
    async def handle_connection(self, reader, writer):
        """Handle incoming connections"""
        pass
    
    async def log_connection(self, connection_data):
        """Log connection data to database"""
        try:
            await self.db_manager.log_connection(connection_data)
            self.logger.info(f"Logged connection from {connection_data.get('source_ip')}")
        except Exception as e:
            self.logger.error(f"Failed to log connection: {e}")
    
    def generate_session_id(self):
        """Generate a unique session ID"""
        return str(uuid.uuid4())
    
    def get_client_info(self, writer):
        """Extract client information from connection"""
        try:
            peername = writer.get_extra_info('peername')
            if peername:
                return {
                    'source_ip': peername[0],
                    'source_port': peername[1]
                }
        except Exception as e:
            self.logger.error(f"Failed to get client info: {e}")
        
        return {'source_ip': 'unknown', 'source_port': 0}
    
    async def send_banner(self, writer, banner):
        """Send service banner to client"""
        try:
            writer.write(banner.encode() + b'\r\n')
            await writer.drain()
        except Exception as e:
            self.logger.error(f"Failed to send banner: {e}")
    
    async def read_data(self, reader, max_size=4096):
        """Read data from client with timeout"""
        try:
            data = await asyncio.wait_for(reader.read(max_size), timeout=30.0)
            return data
        except asyncio.TimeoutError:
            self.logger.debug("Read timeout")
            return b''
        except Exception as e:
            self.logger.error(f"Failed to read data: {e}")
            return b''
    
    def parse_command(self, data):
        """Parse command from raw data"""
        try:
            return data.decode('utf-8', errors='ignore').strip()
        except Exception:
            return str(data)
    
    async def close_connection(self, writer, session_id=None):
        """Close connection gracefully"""
        try:
            if session_id and session_id in self.active_connections:
                del self.active_connections[session_id]
            
            writer.close()
            await writer.wait_closed()
        except Exception as e:
            self.logger.error(f"Error closing connection: {e}")
    
    def get_stats(self):
        """Get honeypot statistics"""
        return {
            'service_name': self.service_name,
            'running': self.running,
            'active_connections': len(self.active_connections),
            'config': self.config
        }
