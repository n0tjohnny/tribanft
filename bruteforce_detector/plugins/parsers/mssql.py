"""
TribanFT MSSQL Parser

Extracts security events from Microsoft SQL Server error logs.

Parses MSSQL errorlog for:
- Failed login attempts
- Authentication errors with IP addresses

Log format: 2025-11-20 13:22:32.99 Logon Login failed for user 'sa'. [CLIENT: 1.2.3.4]

Author: TribanFT Project
License: GNU GPL v3
"""

import re
from datetime import datetime
from typing import List, Optional
import ipaddress
import logging

from ...parsers.base import BaseLogParser
from ...models import SecurityEvent, EventType
from ...utils.validators import validate_ip


class MSSQLParser(BaseLogParser):
    """Parser for MSSQL error logs"""

    # Plugin metadata for auto-discovery
    METADATA = {
        'name': 'mssql_parser',
        'version': '1.0.0',
        'author': 'TribanFT Project',
        'description': 'Parses Microsoft SQL Server error logs for failed logins',
        'log_format': 'mssql_errorlog',
        'enabled_by_default': True
    }

    def __init__(self, log_path: str):
        """Initialize MSSQL parser with log path."""
        super().__init__(log_path)
        # Pattern loading handled by BaseLogParser
        # Patterns are loaded from mssql.yaml and pre-compiled
    
    def parse(self, since_timestamp: Optional[datetime] = None, max_lines: Optional[int] = None) -> List[SecurityEvent]:
        """
        Parse MSSQL log file and extract security events.
        
        Args:
            since_timestamp: Only return events after this time
            max_lines: Maximum lines to process
            
        Returns:
            List of SecurityEvent objects
        """
        events = []
        line_count = 0
        
        self.logger.info(f"Starting to parse MSSQL log file: {self.log_path}")
        self.logger.info(f"Time filter: since_timestamp = {since_timestamp}")
        
        for line in self.read_lines():
            if max_lines and line_count >= max_lines:
                break
            line_count += 1
            
            event = self._parse_line(line, since_timestamp)
            if event:
                events.append(event)
                self.logger.debug(f"Found security event: {event.event_type} from {event.source_ip}")
        
        self.logger.info(f"Parsed {len(events)} security events from MSSQL log (processed {line_count} lines)")
        return events
    
    def _parse_line(self, line: str, since_timestamp: Optional[datetime]) -> Optional[SecurityEvent]:
        """
        Parse single MSSQL log line for failed logins.
        
        Args:
            line: Log line to parse
            since_timestamp: Skip events older than this
            
        Returns:
            SecurityEvent if pattern matched, None otherwise
        """
        try:
            # Load failed login patterns from YAML
            failed_login_patterns = self._get_compiled_patterns('failed_login')

            for pattern, description in failed_login_patterns:
                match = pattern.search(line)
                if match:
                    ip_str = match.group(1).strip()
                    if validate_ip(ip_str):
                        timestamp = self._parse_timestamp(line) or datetime.now()

                        if since_timestamp and timestamp < since_timestamp:
                            self.logger.debug(f"Skipping old event from {ip_str} at {timestamp}")
                            return None

                        self.logger.debug(f"Found failed login event from {ip_str} at {timestamp}: {description}")
                        return SecurityEvent(
                            source_ip=ipaddress.ip_address(ip_str),
                            event_type=EventType.FAILED_LOGIN,
                            timestamp=timestamp,
                            source="mssql",
                            raw_message=line
                        )
                    else:
                        self.logger.warning(f"Invalid IP in failed login event: {ip_str}")
            
            return None
            
        except Exception as e:
            self.logger.warning(f"Failed to parse MSSQL log line: {line[:100]}... Error: {e}")
            return None
    
    def _parse_timestamp(self, line: str) -> Optional[datetime]:
        """
        Parse timestamp from MSSQL log line.
        
        Args:
            line: Log line containing timestamp
            
        Returns:
            Parsed datetime or None
        """
        match = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
        if match:
            timestamp_str = match.group(1)
            try:
                return datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                self.logger.warning(f"Failed to parse MSSQL timestamp: {timestamp_str}")
        
        return None