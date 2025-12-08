"""
bruteforce_detector/managers/log_searcher.py

Módulo responsável por buscar atividades de IPs nos logs do sistema
"""

from typing import List, Dict, Tuple
from pathlib import Path
from datetime import datetime, timedelta
import logging
import re
import gzip
import glob


class LogSearcher:
    """Busca atividades maliciosas de IPs nos logs do sistema"""
    
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Padrões de port scan
        self.port_scan_patterns = [
            'port scan', 'scan detected', 'connection attempts',
            'possible scan', 'repeated attempts', 'firewall:',
            'dropped:', 'blocked:'
        ]
        
        # Padrões de brute force
        self.bruteforce_patterns = [
            'failed password', 'authentication failure', 'invalid user',
            'prelogin', 'login failed', 'breach attempt'
        ]
    
    def search_ip_activity(self, ip_str: str, search_window_hours: int = 72) -> Dict:
        """
        Busca atividades de um IP em todos os logs
        
        Args:
            ip_str: IP a ser buscado
            search_window_hours: Janela de tempo em horas para buscar
            
        Returns:
            Dict com eventos encontrados e estatísticas
        """
        log_events = []
        total_files_searched = 0
        
        try:
            # Busca em syslog
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
            
            # Busca em MSSQL logs
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
        
        # Ordena por timestamp e pega eventos recentes
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
        """Encontra todos os arquivos de log incluindo rotacionados"""
        log_files = []
        base_log_path = Path(self.config.syslog_path)
        
        if base_log_path.exists():
            log_files.append((base_log_path, 'text'))
        
        # Padrões de logs rotacionados
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
        
        self.logger.debug(f"Found {len(log_files)} log files to search")
        return log_files
    
    def _search_file_for_ip(self, file_obj, ip_str: str, source_name: str, 
                           search_window_hours: int) -> List[Dict]:
        """Busca IP em um único arquivo de log"""
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
        """Analisa uma linha de log e categoriza o evento"""
        line_lower = line.lower()
        
        # Detecção de port scan
        if any(pattern in line_lower for pattern in self.port_scan_patterns):
            return {
                'source': source,
                'type': 'port_scan',
                'message': line.strip(),
                'timestamp': self._extract_timestamp(line),
                'confidence': 'high' if 'dropped' in line_lower or 'blocked' in line_lower else 'medium'
            }
        
        # Detecção de brute force
        if any(pattern in line_lower for pattern in self.bruteforce_patterns):
            event_type = 'prelogin_bruteforce' if 'prelogin' in line_lower else 'failed_login'
            return {
                'source': source,
                'type': event_type,
                'message': line.strip(),
                'timestamp': self._extract_timestamp(line),
                'confidence': 'high'
            }
        
        # Padrões específicos do MSSQL
        if 'mssql' in source.lower() or 'sql' in source.lower():
            if 'login failed' in line_lower:
                return {
                    'source': source,
                    'type': 'mssql_failed_login',
                    'message': line.strip(),
                    'timestamp': self._extract_mssql_timestamp(line),
                    'confidence': 'high'
                }
        
        # Atividade suspeita genérica
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
        """Busca específica em logs do MSSQL"""
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
        """Parse de vários formatos de timestamp"""
        if not timestamp_str or timestamp_str == "Unknown":
            return None
        
        try:
            # Formato syslog: "Nov 23 14:12:51"
            if re.match(r'\w+\s+\d+\s+\d+:\d+:\d+', timestamp_str):
                current_year = datetime.now().year
                return datetime.strptime(f"{current_year} {timestamp_str}", "%Y %b %d %H:%M:%S")
            
            # Formato ISO: "2024-12-23 14:12:51"
            elif re.match(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}', timestamp_str):
                return datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass
        
        return None
    
    def _extract_timestamp(self, line: str) -> str:
        """Extrai timestamp de linha do syslog"""
        match = re.search(r'(\w+\s+\d+\s+\d+:\d+:\d+)', line)
        return match.group(1) if match else "Unknown"
    
    def _extract_mssql_timestamp(self, line: str) -> str:
        """Extrai timestamp de linha do MSSQL"""
        match = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
        return match.group(1) if match else "Unknown"
