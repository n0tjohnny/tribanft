"""
TribanFT Logging Configuration

Centralized logging setup for the application.

Configures:
- File logging to XDG state directory or fallback location
- Console output to stdout
- Log level management (INFO/DEBUG)
- Module-specific filtering to reduce noise

Simplifies logging setup across all modules with consistent formatting
and appropriate verbosity levels.

Author: TribanFT Project
License: GNU GPL v3
"""

import logging
import sys
import os
from pathlib import Path


def setup_logging(level=logging.INFO):
    """
    Configure application-wide logging with file and console handlers.
    
    Sets up dual logging:
    - File handler: Uses XDG_STATE_HOME or falls back to /tmp if no write permissions
    - Console handler: stdout
    
    In non-DEBUG mode, reduces verbosity for parsers and detectors
    to minimize log noise during normal operation.
    
    Args:
        level: Logging level (logging.INFO, logging.DEBUG, etc.)
        
    Example:
        >>> setup_logging(level=logging.DEBUG)  # Verbose mode
        >>> setup_logging()  # Normal mode (INFO)
    """
    # Determine log file location
    log_file = None
    
    # Try config-based path first
    try:
        from ..config import get_config
        config = get_config()
        log_file = Path(config.state_dir) / 'tribanft.log'
        log_file.parent.mkdir(parents=True, exist_ok=True)
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
    
    # Add file handler if we have a writable location
    try:
        handlers.append(logging.FileHandler(str(log_file)))
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