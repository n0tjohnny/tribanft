"""
TribanFT Logging Configuration

Centralized logging setup for the application.

Configures:
- File logging to /var/log/tribanft.log
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


def setup_logging(level=logging.INFO):
    """
    Configure application-wide logging with file and console handlers.
    
    Sets up dual logging:
    - File handler: /var/log/tribanft.log
    - Console handler: stdout
    
    In non-DEBUG mode, reduces verbosity for parsers and detectors
    to minimize log noise during normal operation.
    
    Args:
        level: Logging level (logging.INFO, logging.DEBUG, etc.)
        
    Example:
        >>> setup_logging(level=logging.DEBUG)  # Verbose mode
        >>> setup_logging()  # Normal mode (INFO)
    """
    # Clean formatter for readable logs
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    
    # Dual output: file + console
    handlers = [
        logging.FileHandler('/var/log/tribanft.log'),
        logging.StreamHandler(sys.stdout)
    ]
    
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