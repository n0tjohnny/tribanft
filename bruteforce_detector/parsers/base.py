"""
TribanFT Base Log Parser

Abstract base class for all log parsing modules.

Provides common functionality for file reading with error handling
and standardized parsing interface. All parsers must inherit and
implement the parse() method.

Author: TribanFT Project
License: GNU GPL v3
"""

from abc import ABC, abstractmethod
from typing import List, Iterator
from pathlib import Path
import logging

from ..models import SecurityEvent


class BaseLogParser(ABC):
    """Base class for log parsers"""
    
    def __init__(self, log_path: str):
        """
        Initialize parser with log file path.
        
        Args:
            log_path: Path to log file to parse
        """
        self.log_path = Path(log_path)
        self.logger = logging.getLogger(self.__class__.__name__)
    
    @abstractmethod
    def parse(self, since_timestamp=None, max_lines=None) -> List[SecurityEvent]:
        """
        Parse log file and return security events.
        
        Must be implemented by subclasses.
        
        Args:
            since_timestamp: Only return events after this time
            max_lines: Maximum lines to process
            
        Returns:
            List of SecurityEvent objects
        """
        pass
    
    def read_lines(self) -> Iterator[str]:
        """
        Read lines from log file with error handling.
        
        Yields:
            Lines from log file as strings
        """
        if not self.log_path.exists():
            self.logger.error(f"Log file not found: {self.log_path}")
            return iter(())
        
        try:
            with open(self.log_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    yield line.strip()
        except Exception as e:
            self.logger.error(f"Error reading log file {self.log_path}: {e}")
            return iter(())