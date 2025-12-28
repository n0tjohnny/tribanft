"""
TribanFT Logging Configuration

Centralized logging setup for the application.

Configures:
- File logging with automatic rotation and compression (v2.9.0+)
- Console output to stdout
- Log level management (INFO/DEBUG)
- Module-specific filtering to reduce noise

Simplifies logging setup across all modules with consistent formatting
and appropriate verbosity levels.

Author: TribanFT Project
License: GNU GPL v3
"""

import logging
import logging.handlers
import sys
import os
import gzip
import shutil
from pathlib import Path


def _gzip_rotator(source, dest):
    """
    Custom rotator to compress rotated log files with gzip.

    Compresses the rotated log file and removes the uncompressed version,
    saving approximately 90% disk space for text log files.

    Args:
        source: Source log file path
        dest: Destination path for rotated log
    """
    with open(source, 'rb') as f_in:
        with gzip.open(f'{dest}.gz', 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)
    os.remove(source)


def setup_logging(level=logging.INFO):
    """
    Configure application-wide logging with file rotation and console handlers.

    Sets up dual logging (v2.9.0+):
    - Rotating file handler: Automatic rotation with gzip compression
      - Max size: 10MB per file (configurable via config.conf)
      - Rotation: Keeps 5 backup files (configurable)
      - Compression: Old logs auto-compressed with gzip (90% space savings)
    - Console handler: stdout

    In non-DEBUG mode, reduces verbosity for parsers and detectors
    to minimize log noise during normal operation.

    Args:
        level: Logging level (logging.INFO, logging.DEBUG, etc.)

    Example:
        >>> setup_logging(level=logging.DEBUG)  # Verbose mode
        >>> setup_logging()  # Normal mode (INFO)
    """
    # Determine log file location and rotation settings
    log_file = None
    max_bytes = 10485760  # 10MB default
    backup_count = 5      # 5 rotated files default

    # Try config-based path first
    try:
        from ..config import get_config
        config = get_config()
        log_file = config.get_logs_dir() / 'tribanft.log'
        log_file.parent.mkdir(parents=True, exist_ok=True)
        max_bytes = config.log_max_bytes
        backup_count = config.log_backup_count
    except (ImportError, AttributeError, PermissionError) as e:
        # Config not available or permission denied
        pass
    
    # Fallback: try /var/log
    if log_file is None:
        try:
            log_file = Path('/var/log/tribanft.log')
            # Test if we can write
            log_file.touch(exist_ok=True)
        except (PermissionError, OSError):
            # Final fallback: use /tmp
            log_file = Path('/tmp/tribanft.log')
    
    # Clean formatter for readable logs
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    
    # Dual output: file + console
    handlers = [
        logging.StreamHandler(sys.stdout)
    ]
    
    # Add rotating file handler with gzip compression
    try:
        file_handler = logging.handlers.RotatingFileHandler(
            str(log_file),
            maxBytes=max_bytes,
            backupCount=backup_count
        )
        # Set custom rotator for gzip compression
        file_handler.rotator = _gzip_rotator
        handlers.append(file_handler)
    except (PermissionError, OSError) as e:
        # If file logging fails, just log to console
        print(f"Warning: Could not create log file {log_file}: {e}", file=sys.stderr)
        print("Logging to console only", file=sys.stderr)
    
    # Configure root logger
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=handlers
    )
    
    # Reduce noise from verbose modules in normal mode
    if level != logging.DEBUG:
        logging.getLogger('bruteforce_detector.parsers').setLevel(logging.WARNING)
        logging.getLogger('bruteforce_detector.detectors').setLevel(logging.WARNING)