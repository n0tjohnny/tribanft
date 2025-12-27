"""
TribanFT DNS Parser

Extracts security events from DNS server logs.

Detects:
- DNS amplification attacks (ANY queries with small request/large response)
- DNS tunneling (suspicious subdomain patterns, high query rates)
- Subdomain brute force (rapid NXDOMAIN responses)
- Zone transfer attempts (AXFR/IXFR queries from unauthorized IPs)

Supports: BIND9, dnsmasq, Unbound, systemd-resolved

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


class DNSParser(BaseLogParser):
    """Parser for DNS server logs"""

    # Plugin metadata for auto-discovery
    METADATA = {
        'name': 'dns',
        'version': '1.0.0',
        'author': 'TribanFT Project',
        'description': 'Parses DNS server logs for attacks (amplification, tunneling, brute force)',
        'log_format': 'dns_log',
        'enabled_by_default': True
    }

    def __init__(self, log_path: str):
        """Initialize DNS parser with log path."""
        super().__init__(log_path)
        # Pattern loading handled by BaseLogParser
        # Patterns are loaded from dns.yaml and pre-compiled

    def parse(self, since_timestamp: Optional[datetime] = None, max_lines: Optional[int] = None) -> List[SecurityEvent]:
        """
        Parse DNS log file and extract security events.

        Args:
            since_timestamp: Only return events after this time
            max_lines: Maximum lines to process

        Returns:
            List of SecurityEvent objects
        """
        events = []
        line_count = 0

        self.logger.info(f"Starting to parse DNS log file: {self.log_path}")
        self.logger.info(f"Time filter: since_timestamp = {since_timestamp}")

        for line in self.read_lines():
            if max_lines and line_count >= max_lines:
                break
            line_count += 1

            event = self._parse_line(line, since_timestamp)
            if event:
                events.append(event)
                self.logger.debug(f"Found security event: {event.event_type} from {event.source_ip}")

        self.logger.info(f"Parsed {len(events)} security events from DNS log (processed {line_count} lines)")
        return events

    def _parse_line(self, line: str, since_timestamp: Optional[datetime]) -> Optional[SecurityEvent]:
        """
        Parse single DNS log line for attack patterns.

        Args:
            line: DNS log line
            since_timestamp: Only return events after this timestamp

        Returns:
            SecurityEvent if attack pattern found, None otherwise
        """
        # Try to parse timestamp first
        timestamp = self._parse_timestamp(line)
        if timestamp and since_timestamp and timestamp < since_timestamp:
            return None

        # Check DNS attack patterns
        attack_patterns = self._get_compiled_patterns('dns_attacks')

        for pattern, description in attack_patterns:
            match = pattern.search(line)
            if match:
                # Extract IP address from match groups
                # Pattern should have IP as first capture group
                ip_str = match.group(1).strip()

                if not validate_ip(ip_str):
                    continue

                try:
                    source_ip = ipaddress.ip_address(ip_str)

                    return SecurityEvent(
                        source_ip=source_ip,
                        event_type=EventType.DNS_ATTACK,
                        timestamp=timestamp or datetime.now(),
                        source="dns",
                        raw_message=line,
                        metadata={'attack_type': description}
                    )

                except ValueError as e:
                    self.logger.debug(f"Invalid IP address in DNS log: {ip_str}: {e}")
                    continue

        return None

    def _parse_timestamp(self, line: str) -> Optional[datetime]:
        """
        Extract timestamp from DNS log line.

        Supports multiple DNS server log formats:
        - BIND9: 22-Dec-2025 10:30:15.123
        - dnsmasq: Dec 22 10:30:15
        - Unbound: [2025-12-22 10:30:15]
        - systemd-resolved: Dec 22 10:30:15

        Args:
            line: DNS log line

        Returns:
            datetime object or None if parsing fails
        """
        # BIND9 format: 22-Dec-2025 10:30:15.123
        bind_pattern = r'(\d{2})-(\w{3})-(\d{4}) (\d{2}):(\d{2}):(\d{2})'
        match = re.search(bind_pattern, line)
        if match:
            try:
                day, month_str, year, hour, minute, second = match.groups()
                month_map = {
                    'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
                    'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
                }
                month = month_map.get(month_str)
                if month:
                    return datetime(int(year), month, int(day), int(hour), int(minute), int(second))
            except (ValueError, AttributeError):
                pass

        # Unbound format: [2025-12-22 10:30:15]
        unbound_pattern = r'\[(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})\]'
        match = re.search(unbound_pattern, line)
        if match:
            try:
                year, month, day, hour, minute, second = match.groups()
                return datetime(int(year), int(month), int(day), int(hour), int(minute), int(second))
            except (ValueError, AttributeError):
                pass

        # dnsmasq/systemd-resolved format: Dec 22 10:30:15
        syslog_pattern = r'(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})'
        match = re.search(syslog_pattern, line)
        if match:
            try:
                month_str, day, hour, minute, second = match.groups()
                month_map = {
                    'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
                    'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
                }
                month = month_map.get(month_str)
                if month:
                    # Use current year since syslog format doesn't include year
                    year = datetime.now().year
                    return datetime(year, month, int(day), int(hour), int(minute), int(second))
            except (ValueError, AttributeError):
                pass

        # If no timestamp found, return None (will use current time)
        return None
