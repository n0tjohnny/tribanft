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
from typing import List, Iterator, Optional, Tuple
from pathlib import Path
import logging
import re

from ..models import SecurityEvent


class BaseLogParser(ABC):
    """Base class for log parsers"""

    # Class-level pattern loader (shared across all parser instances)
    _pattern_loader: Optional['ParserPatternLoader'] = None

    def __init__(self, log_path: str):
        """
        Initialize parser with log file path.

        Args:
            log_path: Path to log file to parse
        """
        self.log_path = Path(log_path)
        self.logger = logging.getLogger(self.__class__.__name__)

        # Initialize pattern loader if not already done (singleton pattern)
        if BaseLogParser._pattern_loader is None:
            try:
                from ..core.parser_pattern_loader import ParserPatternLoader
                patterns_dir = Path(__file__).parent.parent / "rules" / "parsers"
                BaseLogParser._pattern_loader = ParserPatternLoader(patterns_dir)
                self.logger.debug(f"Initialized ParserPatternLoader with directory: {patterns_dir}")
            except Exception as e:
                self.logger.error(f"Failed to initialize ParserPatternLoader: {e}")
                BaseLogParser._pattern_loader = None

        # Load patterns for this parser if METADATA exists
        if hasattr(self, 'METADATA') and BaseLogParser._pattern_loader is not None:
            self._load_patterns()
        elif not hasattr(self, 'METADATA'):
            self.logger.warning(
                f"{self.__class__.__name__} does not have METADATA attribute. "
                "Pattern loading requires METADATA with 'name' field."
            )

    def _load_patterns(self):
        """
        Load YAML patterns for this parser.

        Called automatically during __init__ if METADATA exists.
        Loads patterns based on METADATA['name'].
        """
        if BaseLogParser._pattern_loader is None:
            self.logger.warning("Pattern loader not initialized, patterns will not be available")
            return

        if not hasattr(self, 'METADATA') or 'name' not in self.METADATA:
            self.logger.warning(
                f"{self.__class__.__name__} missing METADATA['name'], cannot load patterns"
            )
            return

        parser_name = self.METADATA['name']
        patterns = BaseLogParser._pattern_loader.load_patterns(parser_name)

        if patterns:
            available_groups = BaseLogParser._pattern_loader.get_available_groups(parser_name)
            self.logger.debug(
                f"Loaded patterns for parser '{parser_name}': "
                f"{len(available_groups)} groups available"
            )
        else:
            self.logger.warning(
                f"No patterns found for parser '{parser_name}'. "
                f"Expected YAML file: {parser_name}.yaml"
            )

    def _get_compiled_patterns(self, group: str) -> List[Tuple[re.Pattern, str]]:
        """
        Get pre-compiled regex patterns for a pattern group.

        Returns list of tuples: (compiled_regex, description)

        Args:
            group: Name of the pattern group (e.g., 'sql_injection', 'wordpress')

        Returns:
            List of tuples (compiled_pattern, description)
            Returns empty list if pattern group not found or loader not initialized
        """
        if BaseLogParser._pattern_loader is None:
            self.logger.debug(f"Pattern loader not initialized, returning empty pattern list for group '{group}'")
            return []

        if not hasattr(self, 'METADATA') or 'name' not in self.METADATA:
            self.logger.warning(f"Cannot get patterns: METADATA['name'] not found")
            return []

        parser_name = self.METADATA['name']
        return BaseLogParser._pattern_loader.get_compiled_patterns(parser_name, group)
    
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