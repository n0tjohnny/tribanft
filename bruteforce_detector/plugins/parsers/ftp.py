"""
TribanFT FTP Parser

Extracts security events from FTP server logs.

Parses FTP logs for:
- Failed login attempts
- Authentication errors with IP addresses

Supports: vsftpd, ProFTPD, Pure-FTPd

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


class FTPParser(BaseLogParser):
    """Parser for FTP server logs"""

    # Plugin metadata for auto-discovery
    METADATA = {
        'name': 'ftp',
        'version': '1.0.0',
        'author': 'TribanFT Project',
        'description': 'Parses FTP server logs for failed login attempts',
        'log_format': 'ftp_log',
        'enabled_by_default': True
    }

    def __init__(self, log_path: str):
        """Initialize FTP parser with log path."""
        super().__init__(log_path)
        # Pattern loading handled by BaseLogParser
        # Patterns are loaded from ftp.yaml and pre-compiled

    def parse(self, since_timestamp: Optional[datetime] = None, max_lines: Optional[int] = None) -> List[SecurityEvent]:
        """
        Parse FTP log file and extract security events.

        Args:
            since_timestamp: Only return events after this time
            max_lines: Maximum lines to process

        Returns:
            List of SecurityEvent objects
        """
        events = []
        line_count = 0

        self.logger.info(f"Starting to parse FTP log file: {self.log_path}")
        self.logger.info(f"Time filter: since_timestamp = {since_timestamp}")

        for line in self.read_lines():
            if max_lines and line_count >= max_lines:
                break
            line_count += 1

            event = self._parse_line(line, since_timestamp)
            if event:
                events.append(event)
                self.logger.debug(f"Found security event: {event.event_type} from {event.source_ip}")

        self.logger.info(f"Parsed {len(events)} security events from FTP log (processed {line_count} lines)")
        return events

    def _parse_line(self, line: str, since_timestamp: Optional[datetime]) -> Optional[SecurityEvent]:
        """
        Parse single FTP log line for failed logins.

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

                        self.logger.debug(f"Found FTP attack event from {ip_str} at {timestamp}: {description}")
                        return SecurityEvent(
                            source_ip=ipaddress.ip_address(ip_str),
                            event_type=EventType.FTP_ATTACK,
                            timestamp=timestamp,
                            source="ftp",
                            raw_message=line,
                            metadata={'attack_type': description}
                        )
                    else:
                        self.logger.warning(f"Invalid IP in FTP event: {ip_str}")

            return None

        except Exception as e:
            self.logger.warning(f"Failed to parse FTP log line: {line[:100]}... Error: {e}")
            return None

    def _parse_timestamp(self, line: str) -> Optional[datetime]:
        """
        Parse timestamp from FTP log line.

        Supports multiple FTP server formats:
        - vsftpd: "Mon Dec 23 10:15:42 2025"
        - ProFTPD: "2025-12-23 10:15:42"
        - Pure-FTPd: "Dec 23 10:15:42"

        Args:
            line: Log line containing timestamp

        Returns:
            Parsed datetime or None
        """
        # Try vsftpd/Pure-FTPd syslog format: "Mon Dec 23 10:15:42 2025"
        match = re.search(r'([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\d{4})', line)
        if match:
            timestamp_str = f"{match.group(1)} {match.group(2)}"
            try:
                return datetime.strptime(timestamp_str, "%b %d %H:%M:%S %Y")
            except ValueError:
                pass

        # Try ProFTPD format: "2025-12-23 10:15:42"
        match = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
        if match:
            timestamp_str = match.group(1)
            try:
                return datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                pass

        # Try syslog format without year: "Dec 23 10:15:42"
        match = re.search(r'([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', line)
        if match:
            timestamp_str = match.group(1)
            try:
                dt = datetime.strptime(timestamp_str, "%b %d %H:%M:%S")
                # Assign current year
                return dt.replace(year=datetime.now().year)
            except ValueError:
                pass

        return None
