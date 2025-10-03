"""
Configuration settings for Python Honeypot IDS (PHIDS)
"""
import os
from pathlib import Path

# Base directories
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
LOGS_DIR = BASE_DIR / "logs"
REPORTS_DIR = BASE_DIR / "reports"

# Create directories if they don't exist
for directory in [DATA_DIR, LOGS_DIR, REPORTS_DIR]:
    directory.mkdir(exist_ok=True)

# Database configuration
DATABASE_PATH = DATA_DIR / "phids.db"

# Honeypot configuration
HONEYPOT_CONFIG = {
    "ssh": {
        "enabled": True,
        "port": 2222,
        "banner": "SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3",
        "bind_address": "0.0.0.0"
    },
    "http": {
        "enabled": True,
        "port": 8081,  # Changed from 8080 to avoid conflicts
        "banner": "Apache/2.4.41 (Ubuntu)",
        "bind_address": "0.0.0.0"
    },
    "ftp": {
        "enabled": False,
        "port": 2121,
        "banner": "220 ProFTPD 1.3.5 Server ready",
        "bind_address": "0.0.0.0"
    }
}

# IDS configuration
IDS_CONFIG = {
    "signature_detection": {
        "enabled": True,
        "rules_file": BASE_DIR / "rules" / "signatures.yaml"
    },
    "anomaly_detection": {
        "enabled": True,
        "packet_rate_threshold": 500,  # packets per second (increased to reduce false positives)
        "connection_rate_threshold": 100,  # connections per minute (increased to reduce false positives)
        "unusual_port_threshold": 20  # connections to unusual ports (increased to reduce false positives)
    }
}

# Threat intelligence configuration
THREAT_INTEL_CONFIG = {
    "virustotal": {
        "enabled": False,
        "api_key": os.getenv("VIRUSTOTAL_API_KEY", ""),
        "rate_limit": 4  # requests per minute for free tier
    },
    "abuseipdb": {
        "enabled": False,
        "api_key": os.getenv("ABUSEIPDB_API_KEY", ""),
        "rate_limit": 1000  # requests per day for free tier
    }
}

# Logging configuration
LOGGING_CONFIG = {
    "level": "INFO",
    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    "file_rotation": {
        "max_bytes": 10 * 1024 * 1024,  # 10MB
        "backup_count": 5
    }
}

# Reporting configuration
REPORTING_CONFIG = {
    "daily_reports": True,
    "weekly_reports": True,
    "report_formats": ["html", "json"],  # Available: html, json, pdf
    "email_notifications": {
        "enabled": False,
        "smtp_server": "",
        "smtp_port": 587,
        "username": "",
        "password": "",
        "recipients": []
    }
}

# Dashboard configuration (optional)
DASHBOARD_CONFIG = {
    "enabled": True,
    "host": "127.0.0.1",
    "port": 5001,  # Changed from 5000 to avoid conflicts
    "debug": False,
    "performance": {
        "websocket_update_interval": 1,  # seconds (optimized for real-time SOC analysis)
        "stats_cache_duration": 10,     # seconds (faster refresh for real-time monitoring)
        "max_websocket_connections": 50,
        "connection_timeout": 60,       # seconds
        "enable_real_time_mode": True,
        "enable_debug_logging": False
    }
}

# Security settings
SECURITY_CONFIG = {
    "max_connections_per_ip": 100,
    "connection_timeout": 30,  # seconds
    "blacklist_threshold": 10,  # failed attempts before blacklisting
    "blacklist_duration": 3600  # seconds (1 hour)
}
