"""
TribanFT Log Searcher

Searches system logs for IP activity and suspicious patterns.

Analyzes logs to find:
- Port scanning activity
- Brute force attempts (failed logins, prelogin patterns)
- Suspicious activity patterns
- MSSQL-specific security events

Searches multiple sources:
- Syslog (/var/log/syslog) including rotated logs
- MSSQL errorlog
- Auth logs
- Compressed archives (.gz files)

Author: TribanFT Project
License: GNU GPL v3
"""

from typing import List, Dict, Tuple
from pathlib import Path
from datetime import datetime, timedelta
import logging
import re
import gzip
import glob


class LogSearcher:
    """Searches for malicious IP activity in system logs"""
    
    def __init__(self, config):
        """Initialize log searcher with configuration and threat patterns."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Port scan patterns
        self.port_scan_patterns = [
            'port scan', 'scan detected', 'connection attempts',
            'possible scan', 'repeated attempts', 'firewall:',
            'dropped:', 'blocked:'
        ]
        
        # Brute force patterns
        self.bruteforce_patterns = [
            'failed password', 'authentication failure', 'invalid user',
            'prelogin', 'login failed', 'breach attempt'
        ]
    
    def search_ip_activity(self, ip_str: str, search_window_hours: int = 72) -> Dict:
        """
        Search all logs for IP activity within time window.
        
        Args:
            ip_str: IP address to search
            search_window_hours: Time window in hours (default: 72)
            
        Returns:
            Dict with events found, statistics, and recent events
        """
        log_events = []
        total_files_searched = 0
        
        try:
            # Search syslog and rotated logs
            log_files = self._find_all_log_files()
            for log_path, file_type in log_files:
                try:
                    if file_type == 'gzip':
                        with gzip.open(log_path, 'rt', encoding='utf-8', errors='ignore') as f:
                            events = self._search_file_for_ip(f, ip_str, log_path.name, search_window_hours)
                            log_events.extend(events)
                    else:
                        with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                            events = self._search_file_for_ip(f, ip_str, log_path.name, search_window_hours)
                            log_events.extend(events)
                    
                    total_files_searched += 1
                except Exception as e:
                    self.logger.warning(f"Error searching {log_path}: {e}")
            
            # Search MSSQL logs
            if Path(self.config.mssql_error_log_path).exists():
                try:
                    with open(self.config.mssql_error_log_path, 'r', encoding='utf-8', errors='ignore') as f:
                        events = self._search_mssql_logs(f, ip_str)
                        log_events.extend(events)
                        total_files_searched += 1
                except Exception as e:
                    self.logger.warning(f"Error searching MSSQL log: {e}")
        
        except Exception as e:
            self.logger.error(f"Error during log search for {ip_str}: {e}")
        
        # Sort by timestamp, return top 10 recent
        recent_events = sorted(log_events, key=lambda x: x.get('timestamp', ''), reverse=True)[:10]
        
        return {
            'ip': ip_str,
            'events_found': len(log_events),
            'files_searched': total_files_searched,
            'recent_events': recent_events,
            'event_types': list(set(event['type'] for event in log_events)),
            'sources': list(set(event['source'] for event in log_events)),
            'search_window_hours': search_window_hours
        }
    
    def _find_all_log_files(self) -> List[Tuple[Path, str]]:
        """Find all log files including rotated and compressed archives."""
        log_files = []
        base_log_path = Path(self.config.syslog_path)
        
        if base_log_path.exists():
            log_files.append((base_log_path, 'text'))
        
        # Rotated log patterns
        log_patterns = [
            f"{base_log_path}.*",
            f"{base_log_path}.*.gz",
            f"{base_log_path}-*",
            f"{base_log_path}-*.gz",
            "/var/log/messages*",
            "/var/log/auth.log*",
        ]
        
        for pattern in log_patterns:
            for file_path in glob.glob(pattern):
                path = Path(file_path)
                if path.exists() and path not in [f[0] for f in log_files]:
                    file_type = 'gzip' if path.suffix == '.gz' else 'text'
                    log_files.append((path, file_type))
        
        self.logger.debug(f"Found {len(log_files)} log files")
        return log_files
    
    def _search_file_for_ip(self, file_obj, ip_str: str, source_name: str, 
                           search_window_hours: int) -> List[Dict]:
        """Search single log file for IP within time window."""
        events = []
        cutoff_time = datetime.now() - timedelta(hours=search_window_hours)
        
        for line in file_obj:
            if ip_str in line:
                event = self._analyze_log_line(line, ip_str, source_name)
                if event:
                    event_time = self._parse_timestamp(event.get('timestamp'))
                    if event_time and event_time >= cutoff_time:
                        events.append(event)
        
        return events
    
    def _analyze_log_line(self, line: str, ip_str: str, source: str) -> Dict:
        """Analyze log line and categorize security event."""
        line_lower = line.lower()
        
        # Port scan detection
        if any(pattern in line_lower for pattern in self.port_scan_patterns):
            return {
                'source': source,
                'type': 'port_scan',
                'message': line.strip(),
                'timestamp': self._extract_timestamp(line),
                'confidence': 'high' if 'dropped' in line_lower or 'blocked' in line_lower else 'medium'
            }
        
        # Brute force detection
        if any(pattern in line_lower for pattern in self.bruteforce_patterns):
            event_type = 'prelogin_bruteforce' if 'prelogin' in line_lower else 'failed_login'
            return {
                'source': source,
                'type': event_type,
                'message': line.strip(),
                'timestamp': self._extract_timestamp(line),
                'confidence': 'high'
            }
        
        # MSSQL-specific patterns
        if 'mssql' in source.lower() or 'sql' in source.lower():
            if 'login failed' in line_lower:
                return {
                    'source': source,
                    'type': 'mssql_failed_login',
                    'message': line.strip(),
                    'timestamp': self._extract_mssql_timestamp(line),
                    'confidence': 'high'
                }
        
        # Generic suspicious activity
        if any(word in line_lower for word in ['warning', 'error', 'alert', 'intrusion']):
            return {
                'source': source,
                'type': 'suspicious_activity',
                'message': line.strip(),
                'timestamp': self._extract_timestamp(line),
                'confidence': 'medium'
            }
        
        return None
    
    def _search_mssql_logs(self, file_obj, ip_str: str) -> List[Dict]:
        """MSSQL-specific log search."""
        events = []
        
        for line in file_obj:
            if ip_str in line and 'login failed' in line.lower():
                events.append({
                    'source': 'mssql',
                    'type': 'mssql_failed_login',
                    'message': line.strip(),
                    'timestamp': self._extract_mssql_timestamp(line),
                    'confidence': 'high'
                })
        
        return events
    
    def _parse_timestamp(self, timestamp_str: str) -> datetime:
        """Parse various timestamp formats."""
        if not timestamp_str or timestamp_str == "Unknown":
            return None
        
        try:
            # Syslog format: "Nov 23 14:12:51"
            if re.match(r'\w+\s+\d+\s+\d+:\d+:\d+', timestamp_str):
                current_year = datetime.now().year
                return datetime.strptime(f"{current_year} {timestamp_str}", "%Y %b %d %H:%M:%S")
            
            # ISO format: "2024-12-23 14:12:51"
            elif re.match(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}', timestamp_str):
                return datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass
        
        return None
    
    def _extract_timestamp(self, line: str) -> str:
        """Extract timestamp from syslog line."""
        match = re.search(r'(\w+\s+\d+\s+\d+:\d+:\d+)', line)
        return match.group(1) if match else "Unknown"
    
    def _extract_mssql_timestamp(self, line: str) -> str:
        """Extract timestamp from MSSQL log line."""
        match = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
        return match.group(1) if match else "Unknown"