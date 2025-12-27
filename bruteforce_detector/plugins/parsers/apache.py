"""
TribanFT Apache/Nginx Log Parser

Extracts security events from Apache and Nginx access logs.

Parses combined log format for:
- HTTP requests (all traffic)
- HTTP errors (4xx client errors, 5xx server errors)
- SQL injection attempts
- WordPress attacks (login, xmlrpc, plugin scanning)
- Failed login attempts (401/403 on login pages)
- XSS attacks (script injection, event handlers)
- Path traversal attacks (directory traversal, LFI/RFI)
- Command injection attempts (shell command execution)
- Malicious file uploads (executable uploads, double extensions)

Log format expected (combined):
    1.2.3.4 - - [20/Jan/2025:14:30:00 +0000] "GET /path HTTP/1.1" 200 1234 "referer" "user-agent"

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


class ApacheParser(BaseLogParser):
    """
    Parser for Apache/Nginx access logs in combined format.

    Detects:
    - SQL injection patterns in URIs
    - WordPress attack patterns
    - Failed login attempts
    - XSS attacks (script tags, event handlers)
    - Path traversal attempts (directory traversal, LFI/RFI)
    - Command injection (shell commands in parameters)
    - Malicious file uploads (executable files, double extensions)
    - HTTP errors (4xx client errors, 5xx server errors)
    - All HTTP requests for general monitoring
    """

    # Plugin metadata for auto-discovery
    METADATA = {
        'name': 'apache',
        'version': '1.0.0',
        'author': 'TribanFT Project',
        'description': 'Parses Apache/Nginx combined log format for security events',
        'log_format': 'apache_combined',
        'enabled_by_default': True
    }

    def __init__(self, log_path: str):
        """
        Initialize Apache/Nginx parser.

        Args:
            log_path: Path to Apache/Nginx access log
        """
        super().__init__(log_path)
        # Pattern loading handled by BaseLogParser
        # Patterns are loaded from apache.yaml and pre-compiled

    def parse(self, since_timestamp: Optional[datetime] = None, max_lines: Optional[int] = None) -> List[SecurityEvent]:
        """
        Parse Apache/Nginx log file and extract security events.

        Args:
            since_timestamp: Only return events after this time (for incremental parsing)
            max_lines: Maximum lines to process (None = all)

        Returns:
            List of SecurityEvent objects representing threats found in logs
        """
        events = []
        line_count = 0

        self.logger.info(f"Starting to parse Apache/Nginx log: {self.log_path}")
        self.logger.info(f"Time filter: since_timestamp = {since_timestamp}")

        for line in self.read_lines():
            if max_lines and line_count >= max_lines:
                break
            line_count += 1

            # Parse this line and extract event(s)
            line_events = self._parse_line(line, since_timestamp)
            if line_events:
                events.extend(line_events)

        self.logger.info(f"Parsed {len(events)} security events from Apache/Nginx log (processed {line_count} lines)")
        return events

    def _parse_line(self, line: str, since_timestamp: Optional[datetime]) -> List[SecurityEvent]:
        """
        Parse a single Apache/Nginx log line for security events.

        A single log line can generate multiple events:
        - HTTP_REQUEST (always)
        - HTTP_ERROR_4XX (if status 400-499)
        - HTTP_ERROR_5XX (if status 500-599)
        - SQL_INJECTION (if SQL pattern detected)
        - WORDPRESS_ATTACK (if WP pattern detected)
        - FAILED_LOGIN (if 401/403 on login page)
        - XSS_ATTACK (if XSS pattern detected)
        - PATH_TRAVERSAL (if path traversal pattern detected)
        - COMMAND_INJECTION (if command injection pattern detected)
        - FILE_UPLOAD_MALICIOUS (if malicious upload pattern detected)

        Args:
            line: Single line from access log
            since_timestamp: Skip events older than this

        Returns:
            List of SecurityEvent objects (0 or more)
        """
        try:
            # Get log format pattern from YAML
            log_format_patterns = self._get_compiled_patterns('log_format')
            if not log_format_patterns:
                self.logger.error("No log_format pattern found in apache.yaml")
                return []

            # Parse the log line using the first (and only) log format pattern
            combined_log_pattern, _ = log_format_patterns[0]
            match = combined_log_pattern.match(line)
            if not match:
                return []

            # Extract fields
            fields = match.groupdict()
            ip_str = fields['ip']
            timestamp_str = fields['timestamp']
            method = fields['method']
            uri = fields['uri']
            status = int(fields['status'])
            user_agent = fields['user_agent']

            # Parse timestamp
            timestamp = self._parse_timestamp(timestamp_str)

            # Skip old events
            if since_timestamp and timestamp < since_timestamp:
                return []

            # Validate IP
            if not validate_ip(ip_str):
                self.logger.warning(f"Invalid IP in log line: {ip_str}")
                return []

            ip_address = ipaddress.ip_address(ip_str)

            # Full request line for raw_message
            request_line = f"{method} {uri}"

            # Build metadata
            metadata = {
                'log_file': str(self.log_path),
                'method': method,
                'uri': uri,
                'status': status,
                'user_agent': user_agent,
            }

            events = []

            # 1. Always generate HTTP_REQUEST event
            events.append(SecurityEvent(
                source_ip=ip_address,
                event_type=EventType.HTTP_REQUEST,
                timestamp=timestamp,
                source='apache',
                raw_message=line,
                metadata=metadata.copy()
            ))

            # 2. Generate HTTP error events based on status code
            if 400 <= status < 500:
                events.append(SecurityEvent(
                    source_ip=ip_address,
                    event_type=EventType.HTTP_ERROR_4XX,
                    timestamp=timestamp,
                    source='apache',
                    raw_message=line,
                    metadata={**metadata, 'error_category': 'client_error'}
                ))
                self.logger.debug(f"HTTP 4XX error detected: {status} from {ip_str}")
            elif 500 <= status < 600:
                events.append(SecurityEvent(
                    source_ip=ip_address,
                    event_type=EventType.HTTP_ERROR_5XX,
                    timestamp=timestamp,
                    source='apache',
                    raw_message=line,
                    metadata={**metadata, 'error_category': 'server_error'}
                ))
                self.logger.debug(f"HTTP 5XX error detected: {status} from {ip_str}")

            # 3. Check for SQL injection patterns
            sql_detected = False
            sql_patterns = self._get_compiled_patterns('sql_injection')
            for pattern, description in sql_patterns:
                if pattern.search(uri) or pattern.search(line):
                    if not sql_detected:  # Only create one SQL_INJECTION event per line
                        events.append(SecurityEvent(
                            source_ip=ip_address,
                            event_type=EventType.SQL_INJECTION,
                            timestamp=timestamp,
                            source='apache',
                            raw_message=line,
                            metadata={**metadata, 'attack_type': description}
                        ))
                        sql_detected = True
                        self.logger.debug(f"SQL injection detected: {description} from {ip_str}")
                    break

            # 4. Check for WordPress attack patterns
            wp_detected = False
            wp_patterns = self._get_compiled_patterns('wordpress')
            for pattern, description in wp_patterns:
                if pattern.search(uri) or pattern.search(line):
                    if not wp_detected:  # Only create one WORDPRESS_ATTACK event per line
                        events.append(SecurityEvent(
                            source_ip=ip_address,
                            event_type=EventType.WORDPRESS_ATTACK,
                            timestamp=timestamp,
                            source='apache',
                            raw_message=line,
                            metadata={**metadata, 'attack_type': description}
                        ))
                        wp_detected = True
                        self.logger.debug(f"WordPress attack detected: {description} from {ip_str}")
                    break

            # 5. Check for failed login attempts (401/403 on login pages)
            if status in [401, 403]:
                login_patterns = self._get_compiled_patterns('login_pages')
                for login_pattern, description in login_patterns:
                    if login_pattern.search(uri):
                        events.append(SecurityEvent(
                            source_ip=ip_address,
                            event_type=EventType.FAILED_LOGIN,
                            timestamp=timestamp,
                            source='apache',
                            raw_message=line,
                            metadata={**metadata, 'login_failure_type': 'HTTP auth failure', 'page': description}
                        ))
                        self.logger.debug(f"Failed login detected: {status} on {uri} from {ip_str}")
                        break

            # 6. Check for XSS attack patterns
            xss_detected = False
            xss_patterns = self._get_compiled_patterns('xss_attack')
            for pattern, description in xss_patterns:
                if pattern.search(uri) or pattern.search(line):
                    if not xss_detected:
                        events.append(SecurityEvent(
                            source_ip=ip_address,
                            event_type=EventType.XSS_ATTACK,
                            timestamp=timestamp,
                            source='apache',
                            raw_message=line,
                            metadata={**metadata, 'attack_type': description}
                        ))
                        xss_detected = True
                        self.logger.debug(f"XSS attack detected: {description} from {ip_str}")
                    break

            # 7. Check for path traversal patterns
            pt_detected = False
            pt_patterns = self._get_compiled_patterns('path_traversal')
            for pattern, description in pt_patterns:
                if pattern.search(uri) or pattern.search(line):
                    if not pt_detected:
                        events.append(SecurityEvent(
                            source_ip=ip_address,
                            event_type=EventType.PATH_TRAVERSAL,
                            timestamp=timestamp,
                            source='apache',
                            raw_message=line,
                            metadata={**metadata, 'attack_type': description}
                        ))
                        pt_detected = True
                        self.logger.debug(f"Path traversal detected: {description} from {ip_str}")
                    break

            # 8. Check for command injection patterns
            cmd_detected = False
            cmd_patterns = self._get_compiled_patterns('command_injection')
            for pattern, description in cmd_patterns:
                if pattern.search(uri) or pattern.search(line):
                    if not cmd_detected:
                        events.append(SecurityEvent(
                            source_ip=ip_address,
                            event_type=EventType.COMMAND_INJECTION,
                            timestamp=timestamp,
                            source='apache',
                            raw_message=line,
                            metadata={**metadata, 'attack_type': description}
                        ))
                        cmd_detected = True
                        self.logger.debug(f"Command injection detected: {description} from {ip_str}")
                    break

            # 9. Check for malicious file upload patterns
            upload_detected = False
            upload_patterns = self._get_compiled_patterns('file_upload')
            for pattern, description in upload_patterns:
                if pattern.search(uri) or pattern.search(line):
                    if not upload_detected:
                        events.append(SecurityEvent(
                            source_ip=ip_address,
                            event_type=EventType.FILE_UPLOAD_MALICIOUS,
                            timestamp=timestamp,
                            source='apache',
                            raw_message=line,
                            metadata={**metadata, 'attack_type': description}
                        ))
                        upload_detected = True
                        self.logger.debug(f"Malicious file upload detected: {description} from {ip_str}")
                    break

            return events

        except Exception as e:
            self.logger.warning(f"Failed to parse Apache/Nginx line: {line[:100]}... Error: {e}")
            return []

    def _parse_timestamp(self, timestamp_str: str) -> datetime:
        """
        Parse Apache/Nginx timestamp.

        Format: 20/Jan/2025:14:30:00 +0000

        Args:
            timestamp_str: Timestamp string from log

        Returns:
            datetime object
        """
        try:
            # Remove timezone for simplicity (handle it in future if needed)
            timestamp_str = timestamp_str.split()[0]  # "20/Jan/2025:14:30:00"
            return datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S")
        except ValueError as e:
            self.logger.warning(f"Failed to parse timestamp: {timestamp_str}, using current time. Error: {e}")
            return datetime.now()
