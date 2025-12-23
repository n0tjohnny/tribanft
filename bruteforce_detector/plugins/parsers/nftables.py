"""
TribanFT NFTables/IPTables Log Parser

Extracts security events from firewall logs (nftables, iptables).

Parses kernel firewall logs for:
- Port scanning activity (multiple connections to different ports)
- Network scanning (multiple connection attempts)
- Connection attempts to blocked/dropped packets

Log formats supported:
- NFTables: [nftables] IN=eth0 SRC=1.2.3.4 DST=10.0.0.1 PROTO=TCP DPT=22
- IPTables: [iptables] IN=eth0 SRC=1.2.3.4 DST=10.0.0.1 PROTO=TCP DPT=22

Author: TribanFT Project
License: GNU GPL v3
"""

import re
from datetime import datetime
from typing import List, Optional, Dict
from collections import defaultdict
import ipaddress
import logging

from ...parsers.base import BaseLogParser
from ...models import SecurityEvent, EventType
from ...utils.validators import validate_ip


class NFTablesParser(BaseLogParser):
    """
    Parser for NFTables/IPTables firewall logs.

    Detects:
    - Port scanning (multiple ports from same source)
    - Network scanning (connection attempts pattern)
    - Blocked connection attempts
    """

    # Plugin metadata for auto-discovery
    METADATA = {
        'name': 'nftables',
        'version': '1.0.0',
        'author': 'TribanFT Project',
        'description': 'Parses NFTables/IPTables firewall logs for port scans and network activity',
        'log_format': 'kernel_firewall',
        'enabled_by_default': True
    }

    def __init__(self, log_path: str):
        """
        Initialize NFTables/IPTables parser.

        Args:
            log_path: Path to firewall log (usually /var/log/kern.log or /var/log/messages)
        """
        super().__init__(log_path)

        # Load configuration from YAML
        self._load_configuration()

        # Track connection attempts per IP for port scan detection
        # Format: {source_ip: {port1, port2, port3, ...}}
        self._port_attempts: Dict[str, set] = defaultdict(set)

        # Track connection timestamps for temporal analysis
        # Format: {source_ip: [timestamp1, timestamp2, ...]}
        self._timestamps: Dict[str, list] = defaultdict(list)

    def _load_configuration(self):
        """
        Load configuration thresholds from nftables.yaml.

        Sets instance variables for detection thresholds.
        Falls back to sensible defaults if YAML not found.
        """
        # Default thresholds (fallback if YAML not found)
        self.port_scan_threshold = 5
        self.network_scan_threshold = 10

        # Try to load from YAML configuration
        if self._pattern_loader:
            pattern_data = self._pattern_loader.load_patterns('nftables')
            if pattern_data:
                config = pattern_data.get('configuration', {})
                self.port_scan_threshold = config.get('port_scan_threshold', 5)
                self.network_scan_threshold = config.get('network_scan_threshold', 10)

                self.logger.info(
                    f"NFTables parser configuration loaded: "
                    f"port_scan_threshold={self.port_scan_threshold}, "
                    f"network_scan_threshold={self.network_scan_threshold}"
                )
            else:
                self.logger.warning(
                    "NFTables YAML configuration not found, using defaults: "
                    f"port_scan_threshold={self.port_scan_threshold}, "
                    f"network_scan_threshold={self.network_scan_threshold}"
                )

    def parse(self, since_timestamp: Optional[datetime] = None, max_lines: Optional[int] = None) -> List[SecurityEvent]:
        """
        Parse firewall log file and extract security events.

        Args:
            since_timestamp: Only return events after this time (for incremental parsing)
            max_lines: Maximum lines to process (None = all)

        Returns:
            List of SecurityEvent objects representing threats found in logs
        """
        events = []
        line_count = 0

        # Reset tracking state
        self._port_attempts.clear()
        self._timestamps.clear()

        self.logger.info(f"Starting to parse NFTables/IPTables log: {self.log_path}")
        self.logger.info(f"Time filter: since_timestamp = {since_timestamp}")

        # First pass: collect connection attempts
        for line in self.read_lines():
            if max_lines and line_count >= max_lines:
                break
            line_count += 1

            # Parse this line
            self._analyze_line(line, since_timestamp)

        # Second pass: generate events based on patterns
        events = self._generate_events()

        self.logger.info(f"Parsed {len(events)} security events from firewall log (processed {line_count} lines)")
        return events

    def _analyze_line(self, line: str, since_timestamp: Optional[datetime]) -> None:
        """
        Analyze a single firewall log line and track connection attempts.

        Args:
            line: Single line from firewall log
            since_timestamp: Skip events older than this
        """
        try:
            # Check if it's a firewall log line
            if not (('[nftables]' in line.lower() or '[iptables]' in line.lower() or
                     'nft:' in line.lower() or 'ipt:' in line.lower())):
                return

            # Extract timestamp (kernel log format: "Jan 22 10:30:15")
            timestamp = self._parse_timestamp(line)
            if since_timestamp and timestamp < since_timestamp:
                return

            # Extract connection details
            conn_details = self._parse_connection_details(line)
            if not conn_details:
                return

            source_ip = conn_details.get('src')
            dest_port = conn_details.get('dpt')
            proto = conn_details.get('proto')

            if not source_ip or not validate_ip(source_ip):
                return

            # Track this connection attempt
            if dest_port:
                self._port_attempts[source_ip].add(dest_port)

            self._timestamps[source_ip].append(timestamp)

        except Exception as e:
            self.logger.debug(f"Failed to analyze firewall line: {line[:100]}... Error: {e}")

    def _parse_connection_details(self, line: str) -> Optional[Dict[str, str]]:
        """
        Extract connection details from firewall log line.

        Args:
            line: Firewall log line

        Returns:
            Dict with 'src', 'dst', 'dpt', 'spt', 'proto' or None if parsing fails
        """
        details = {}

        # Extract source IP
        src_match = re.search(r'SRC=([0-9a-fA-F\.:]+)', line)
        if src_match:
            details['src'] = src_match.group(1)

        # Extract destination IP
        dst_match = re.search(r'DST=([0-9a-fA-F\.:]+)', line)
        if dst_match:
            details['dst'] = dst_match.group(1)

        # Extract destination port
        dpt_match = re.search(r'DPT=(\d+)', line)
        if dpt_match:
            details['dpt'] = dpt_match.group(1)

        # Extract source port
        spt_match = re.search(r'SPT=(\d+)', line)
        if spt_match:
            details['spt'] = spt_match.group(1)

        # Extract protocol
        proto_match = re.search(r'PROTO=(\w+)', line)
        if proto_match:
            details['proto'] = proto_match.group(1)

        return details if details else None

    def _generate_events(self) -> List[SecurityEvent]:
        """
        Generate SecurityEvent objects based on tracked connection patterns.

        Returns:
            List of SecurityEvent objects
        """
        events = []
        current_time = datetime.now()

        for source_ip_str, ports in self._port_attempts.items():
            try:
                ip_address_obj = ipaddress.ip_address(source_ip_str)
                timestamps = self._timestamps[source_ip_str]

                if not timestamps:
                    continue

                # Use most recent timestamp
                latest_timestamp = max(timestamps)

                # PORT SCAN detection: Multiple different ports from same IP
                # Threshold configured in nftables.yaml (default: 5 ports)
                if len(ports) >= self.port_scan_threshold:
                    events.append(SecurityEvent(
                        source_ip=ip_address_obj,
                        event_type=EventType.PORT_SCAN,
                        timestamp=latest_timestamp,
                        source='nftables',
                        raw_message=f"Port scan: {len(ports)} ports scanned by {source_ip_str}",
                        metadata={
                            'ports_scanned': sorted(list(ports)),
                            'port_count': len(ports),
                            'scan_duration_seconds': (max(timestamps) - min(timestamps)).total_seconds() if len(timestamps) > 1 else 0,
                            'attempts': len(timestamps)
                        }
                    ))
                    self.logger.info(f"Port scan detected: {source_ip_str} scanned {len(ports)} ports")

                # NETWORK SCAN detection: High frequency of connection attempts
                # Threshold configured in nftables.yaml (default: 10 attempts)
                elif len(timestamps) >= self.network_scan_threshold:
                    events.append(SecurityEvent(
                        source_ip=ip_address_obj,
                        event_type=EventType.NETWORK_SCAN,
                        timestamp=latest_timestamp,
                        source='nftables',
                        raw_message=f"Network scan: {len(timestamps)} connection attempts from {source_ip_str}",
                        metadata={
                            'connection_attempts': len(timestamps),
                            'unique_ports': len(ports),
                            'scan_duration_seconds': (max(timestamps) - min(timestamps)).total_seconds() if len(timestamps) > 1 else 0
                        }
                    ))
                    self.logger.info(f"Network scan detected: {source_ip_str} made {len(timestamps)} attempts")

            except (ValueError, ipaddress.AddressValueError) as e:
                self.logger.warning(f"Invalid IP address: {source_ip_str} - {e}")
                continue

        return events

    def _parse_timestamp(self, line: str) -> datetime:
        """
        Parse timestamp from kernel log line.

        Format: "Jan 22 10:30:15" or "2025-01-22T10:30:15"

        Args:
            line: Log line

        Returns:
            datetime object
        """
        try:
            # Try kernel syslog format: "Jan 22 10:30:15"
            timestamp_match = re.search(r'([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', line)
            if timestamp_match:
                timestamp_str = timestamp_match.group(1)
                # Add current year (kernel logs don't include year)
                current_year = datetime.now().year
                timestamp_str = f"{current_year} {timestamp_str}"
                return datetime.strptime(timestamp_str, "%Y %b %d %H:%M:%S")

            # Try ISO format: "2025-01-22T10:30:15"
            iso_match = re.search(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})', line)
            if iso_match:
                return datetime.fromisoformat(iso_match.group(1))

        except ValueError as e:
            self.logger.debug(f"Failed to parse timestamp from line: {line[:50]}... Error: {e}")

        # Fallback to current time
        return datetime.now()


# Alias for IPTables (same parser, different name)
class IPTablesParser(NFTablesParser):
    """
    Parser for IPTables firewall logs.

    Alias for NFTablesParser (same log format).
    """

    METADATA = {
        'name': 'iptables',
        'version': '1.0.0',
        'author': 'TribanFT Project',
        'description': 'Parses IPTables firewall logs for port scans and network activity',
        'log_format': 'kernel_firewall',
        'enabled_by_default': True
    }
