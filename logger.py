#!/usr/bin/env python3
"""
Logging configuration for Secure File Manager
"""

import os
import logging
import logging.handlers
from pathlib import Path
from typing import Optional

def setup_logging(log_dir: Optional[Path] = None, 
                 verbose: bool = False,
                 log_to_file: bool = True) -> logging.Logger:
    """
    Setup application logging with proper formatting and handling.
    
    Args:
        log_dir: Directory for log files. If None, uses system temp directory
        verbose: Enable debug level logging
        log_to_file: Whether to save logs to file
        
    Returns:
        Configured logger instance
    """
    if log_dir is None:
        import tempfile
        log_dir = Path(tempfile.gettempdir()) / "secure_file_manager"
    
    log_dir.mkdir(parents=True, exist_ok=True)
    
    # Create logger
    logger = logging.getLogger('SecureFileManager')
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    
    # Clear any existing handlers
    logger.handlers = []
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    console_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    if log_to_file:
        # File handler for all logs
        log_file = log_dir / "secure_file_manager.log"
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5,
            encoding='utf-8'
        )
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
        
        # Separate error log file
        error_log = log_dir / "error.log"
        error_handler = logging.handlers.RotatingFileHandler(
            error_log,
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5,
            encoding='utf-8'
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(file_formatter)
        logger.addHandler(error_handler)
    
    # Log startup message
    logger.info("Logging initialized")
    if verbose:
        logger.debug("Debug logging enabled")
    
    return logger
