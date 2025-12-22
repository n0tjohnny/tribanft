"""
TribanFT Syslog Parser

Extracts security events from syslog files.

Parses /var/log/syslog for:
- MSSQL prelogin invalid packets
- Port scan detection markers
- System firewall drops

Log format expected:
    Nov 23 14:12:51 hostname sqlservr: prelogin packet used to open a connection CLIENT: 1.2.3.4

Author: TribanFT Project
License: GNU GPL v3
"""

import re
from datetime import datetime, timedelta
from typing import List, Optional
import ipaddress
import logging

from ...parsers.base import BaseLogParser
from ...models import SecurityEvent, EventType
from ...utils.validators import validate_ip


class SyslogParser(BaseLogParser):
    """
    Parser for syslog files (typically /var/log/syslog).

    Extracts security events using regex patterns for:
    - MSSQL prelogin reconnaissance attempts
    - Port scanning activity
    """

    # Plugin metadata for auto-discovery
    METADATA = {
        'name': 'syslog_parser',
        'version': '1.0.0',
        'author': 'TribanFT Project',
        'description': 'Parses syslog files for security events',
        'log_format': 'syslog',
        'enabled_by_default': True
    }

    def __init__(self, log_path: str):
        """
        Initialize syslog parser.

        Args:
            log_path: Path to syslog file (e.g., /var/log/syslog)
        """
        super().__init__(log_path)
        self.current_year = datetime.now().year
        # Pattern loading handled by BaseLogParser
        # Patterns are loaded from syslog.yaml and pre-compiled
    
    def parse(self, since_timestamp: Optional[datetime] = None, max_lines: Optional[int] = None) -> List[SecurityEvent]:
        """
        Parse syslog file and extract security events.
        
        Args:
            since_timestamp: Only return events after this time (for incremental parsing)
            max_lines: Maximum lines to process (None = all)
            
        Returns:
            List of SecurityEvent objects representing threats found in logs
        """
        events = []
        line_count = 0
        
        self.logger.info(f"Starting to parse syslog file: {self.log_path}")
        self.logger.info(f"Time filter: since_timestamp = {since_timestamp}")
        
        for line in self.read_lines():
            if max_lines and line_count >= max_lines:
                break
            line_count += 1
            
            # Try to parse this line as a security event
            event = self._parse_line(line, since_timestamp)
            if event:
                events.append(event)
                self.logger.debug(f"Found security event: {event.event_type} from {event.source_ip}")
        
        self.logger.info(f"Parsed {len(events)} security events from syslog (processed {line_count} lines)")
        return events
    
    def _parse_line(self, line: str, since_timestamp: Optional[datetime]) -> Optional[SecurityEvent]:
        """
        Parse a single syslog line for security events.
        
        Tries each pattern in order until a match is found.
        
        Args:
            line: Single line from syslog file
            since_timestamp: Skip events older than this
            
        Returns:
            SecurityEvent if pattern matched, None otherwise
        """
        try:
            # Try prelogin patterns first
            prelogin_patterns = self._get_compiled_patterns('prelogin')
            for pattern, description in prelogin_patterns:
                match = pattern.search(line)
                if match:
                    timestamp_str, ip_str = match.groups()
                    timestamp = self._parse_timestamp(timestamp_str)

                    # Skip old events
                    if since_timestamp and timestamp < since_timestamp:
                        self.logger.debug(f"Skipping old event from {ip_str} at {timestamp}")
                        return None

                    # Validate IP address
                    if validate_ip(ip_str):
                        self.logger.debug(f"Found prelogin event from {ip_str} at {timestamp}: {description}")
                        return SecurityEvent(
                            source_ip=ipaddress.ip_address(ip_str),
                            event_type=EventType.PRELOGIN_INVALID,
                            timestamp=timestamp,
                            source="syslog",
                            raw_message=line
                        )
                    else:
                        self.logger.warning(f"Invalid IP in prelogin event: {ip_str}")

            # Try port scan patterns
            port_scan_patterns = self._get_compiled_patterns('port_scan')
            for pattern, description in port_scan_patterns:
                match = pattern.search(line)
                if match:
                    timestamp_str, ip_str = match.groups()
                    timestamp = self._parse_timestamp(timestamp_str)

                    # Skip old events
                    if since_timestamp and timestamp < since_timestamp:
                        self.logger.debug(f"Skipping old event from {ip_str} at {timestamp}")
                        return None

                    # Validate IP address
                    if validate_ip(ip_str):
                        self.logger.debug(f"Found port scan event from {ip_str} at {timestamp}: {description}")
                        return SecurityEvent(
                            source_ip=ipaddress.ip_address(ip_str),
                            event_type=EventType.PORT_SCAN,
                            timestamp=timestamp,
                            source="syslog",
                            raw_message=line
                        )
                    else:
                        self.logger.warning(f"Invalid IP in port scan event: {ip_str}")

            return None
            
        except Exception as e:
            self.logger.warning(f"Failed to parse syslog line: {line[:100]}... Error: {e}")
            return None
    
    def _parse_timestamp(self, timestamp_str: str) -> datetime:
        """
        Parse syslog timestamp with proper year handling.
        
        Syslog format doesn't include year, so we infer it from current date.
        Handles year boundary correctly (Dec 31 → Jan 1 transitions).
        
        Args:
            timestamp_str: Timestamp string like "Nov 23 14:12:51"
            
        Returns:
            datetime object with inferred year
        """
        try:
            # Add current year and parse
            timestamp_with_year = f"{timestamp_str} {self.current_year}"
            parsed_time = datetime.strptime(timestamp_with_year, "%b %d %H:%M:%S %Y")
            
            # Better year boundary handling
            now = datetime.now()
            time_diff = (parsed_time - now).total_seconds()
            
            # If parsed time is more than 6 months in the future, assume previous year
            if time_diff > 15552000:  # 6 months in seconds
                parsed_time = parsed_time.replace(year=self.current_year - 1)
            # If parsed time is more than 6 months in the past, assume next year  
            elif time_diff < -15552000:
                parsed_time = parsed_time.replace(year=self.current_year + 1)
                
            return parsed_time
        except ValueError as e:
            self.logger.warning(f"Failed to parse timestamp: {timestamp_str}, using current time. Error: {e}")
            return datetime.now()
