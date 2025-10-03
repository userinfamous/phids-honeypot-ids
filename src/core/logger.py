"""
Logging configuration and utilities for PHIDS
"""
import logging
import logging.handlers
from pathlib import Path
from config import LOGS_DIR, LOGGING_CONFIG


def setup_logging(level="INFO"):
    """Setup logging configuration for PHIDS"""
    
    # Create logs directory if it doesn't exist
    LOGS_DIR.mkdir(exist_ok=True)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper()))
    
    # Clear any existing handlers
    root_logger.handlers.clear()
    
    # Create formatter
    formatter = logging.Formatter(LOGGING_CONFIG["format"])
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(getattr(logging, level.upper()))
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)
    
    # File handler with rotation
    file_handler = logging.handlers.RotatingFileHandler(
        LOGS_DIR / "phids.log",
        maxBytes=LOGGING_CONFIG["file_rotation"]["max_bytes"],
        backupCount=LOGGING_CONFIG["file_rotation"]["backup_count"]
    )
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(formatter)
    root_logger.addHandler(file_handler)
    
    # Separate handlers for different components
    setup_component_loggers()


def setup_component_loggers():
    """Setup specialized loggers for different components - optimized version"""

    formatter = logging.Formatter(LOGGING_CONFIG["format"])

    # Define component loggers with their respective log files
    components = [
        ("honeypot", "honeypot.log"),
        ("ids", "ids.log"),
        ("analysis", "analysis.log")
    ]

    # Create loggers efficiently
    for component_name, log_file in components:
        handler = logging.handlers.RotatingFileHandler(
            LOGS_DIR / log_file,
            maxBytes=LOGGING_CONFIG["file_rotation"]["max_bytes"],
            backupCount=LOGGING_CONFIG["file_rotation"]["backup_count"]
        )
        handler.setFormatter(formatter)

        logger = logging.getLogger(component_name)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)


def get_logger(name):
    """Get a logger instance for a specific component"""
    return logging.getLogger(name)
