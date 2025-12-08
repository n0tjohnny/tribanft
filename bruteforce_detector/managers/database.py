"""
bruteforce_detector/managers/database.py

SQLite database manager for blacklist storage
Substitui arquivos de texto com banco de dados relacional
"""

import sqlite3
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Set
import ipaddress
from contextlib import contextmanager


class BlacklistDatabase:
    """Gerencia blacklist usando SQLite"""
    
    SCHEMA_VERSION = 1
    
    def __init__(self, db_path: str = "/var/lib/tribanft/blacklist.db"):
        self.db_path = Path(db_path)
        self.logger = logging.getLogger(__name__)
        self._ensure_database()
    
    def _ensure_database(self):
        """Cria database e schema se não existir"""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        with self._get_connection() as conn:
            # Tabela principal de IPs
            conn.execute("""
                CREATE TABLE IF NOT EXISTS blacklisted_ips (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT UNIQUE NOT NULL,
                    ip_version INTEGER NOT NULL,
                    reason TEXT,
                    confidence TEXT,
                    event_count INTEGER DEFAULT 0,
                    geo_country TEXT,
                    geo_city TEXT,
                    geo_isp TEXT,
                    first_seen TIMESTAMP,
                    last_seen TIMESTAMP,
                    date_added TIMESTAMP NOT NULL,
                    source TEXT,
                    is_active BOOLEAN DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Índices para performance
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_ip ON blacklisted_ips(ip)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_is_active ON blacklisted_ips(is_active)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_source ON blacklisted_ips(source)
            """)
            
            # Tabela de event types
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ip_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_id INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (ip_id) REFERENCES blacklisted_ips(id) ON DELETE CASCADE
                )
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_ip_id ON ip_events(ip_id)
            """)
            
            # Tabela de metadados
            conn.execute("""
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Armazena versão do schema
            conn.execute("""
                INSERT OR IGNORE INTO metadata (key, value) 
                VALUES ('schema_version', ?)
            """, (str(self.SCHEMA_VERSION),))
            
            conn.commit()
    
    @contextmanager
    def _get_connection(self):
        """Context manager para conexões thread-safe"""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    
    def add_ip(self, ip_str: str, info: Dict) -> bool:
        """
        Adiciona ou atualiza IP no blacklist
        
        Args:
            ip_str: IP address string
            info: Dict com informações do IP
            
        Returns:
            True se sucesso
        """
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            geo = info.get('geolocation', {})
            
            with self._get_connection() as conn:
                # Insere ou atualiza IP
                conn.execute("""
                    INSERT INTO blacklisted_ips 
                    (ip, ip_version, reason, confidence, event_count,
                     geo_country, geo_city, geo_isp,
                     first_seen, last_seen, date_added, source)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(ip) DO UPDATE SET
                        reason = excluded.reason,
                        confidence = excluded.confidence,
                        event_count = excluded.event_count,
                        geo_country = excluded.geo_country,
                        geo_city = excluded.geo_city,
                        geo_isp = excluded.geo_isp,
                        last_seen = excluded.last_seen,
                        source = excluded.source,
                        updated_at = CURRENT_TIMESTAMP
                """, (
                    ip_str,
                    ip_obj.version,
                    info.get('reason'),
                    info.get('confidence'),
                    info.get('event_count', 0),
                    geo.get('country') if geo else None,
                    geo.get('city') if geo else None,
                    geo.get('isp') if geo else None,
                    self._format_datetime(info.get('first_seen')),
                    self._format_datetime(info.get('last_seen')),
                    self._format_datetime(info.get('date_added', datetime.now())),
                    info.get('source', 'automatic')
                ))
                
                # Obtém IP ID
                cursor = conn.execute("SELECT id FROM blacklisted_ips WHERE ip = ?", (ip_str,))
                ip_id = cursor.fetchone()[0]
                
                # Adiciona event types
                event_types = info.get('event_types', [])
                if event_types:
                    # Remove events antigos
                    conn.execute("DELETE FROM ip_events WHERE ip_id = ?", (ip_id,))
                    
                    # Adiciona novos
                    for event_type in event_types:
                        conn.execute("""
                            INSERT INTO ip_events (ip_id, event_type)
                            VALUES (?, ?)
                        """, (ip_id, event_type))
                
                conn.commit()
                return True
                
        except Exception as e:
            self.logger.error(f"Error adding IP {ip_str}: {e}")
            return False
    
    def bulk_add(self, ips_info: Dict[str, Dict]) -> int:
        """
        Adiciona múltiplos IPs em batch (mais eficiente)
        
        Returns:
            Número de IPs adicionados
        """
        added = 0
        
        with self._get_connection() as conn:
            for ip_str, info in ips_info.items():
                try:
                    ip_obj = ipaddress.ip_address(ip_str)
                    geo = info.get('geolocation', {})
                    date_added = info.get("date_added") or info.get("first_seen") or datetime.now()
                    # Use('geolocation', {})
                    
                    conn.execute("""
                        INSERT INTO blacklisted_ips 
                        (ip, ip_version, reason, confidence, event_count,
                         geo_country, geo_city, geo_isp,
                         first_seen, last_seen, date_added, source)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(ip) DO UPDATE SET
                            reason = excluded.reason,
                            confidence = excluded.confidence,
                            event_count = excluded.event_count,
                            geo_country = excluded.geo_country,
                            geo_city = excluded.geo_city,
                            geo_isp = excluded.geo_isp,
                            last_seen = excluded.last_seen,
                            source = excluded.source,
                            updated_at = CURRENT_TIMESTAMP
                    """, (
                        ip_str,
                        ip_obj.version,
                        info.get('reason'),
                        info.get('confidence'),
                        info.get('event_count', 0),
                        geo.get('country') if geo else None,
                        geo.get('city') if geo else None,
                        geo.get('isp') if geo else None,
                        self._format_datetime(info.get('first_seen')),
                        self._format_datetime(info.get('last_seen')),
                        self._format_datetime(date_added),
                        info.get('source', 'automatic')
                    ))
                    
                    added += 1
                    
                except Exception as e:
                    self.logger.warning(f"Error adding IP {ip_str}: {e}")
                    continue
            
            conn.commit()
        
        self.logger.info(f"Bulk add: {added}/{len(ips_info)} IPs")
        return added
    
    def get_ip(self, ip_str: str) -> Optional[Dict]:
        """Obtém informações de um IP"""
        with self._get_connection() as conn:
            cursor = conn.execute("""
                SELECT * FROM blacklisted_ips WHERE ip = ? AND is_active = 1
            """, (ip_str,))
            
            row = cursor.fetchone()
            if not row:
                return None
            
            # Obtém event types
            cursor = conn.execute("""
                SELECT event_type FROM ip_events WHERE ip_id = ?
            """, (row['id'],))
            event_types = [r['event_type'] for r in cursor.fetchall()]
            
            return self._row_to_dict(row, event_types)
    
    def get_all_ips(self, ip_version: Optional[int] = None) -> Dict[str, Dict]:
        """
        Obtém todos os IPs ativos
        
        Args:
            ip_version: 4 ou 6 para filtrar, None para todos
        """
        ips_info = {}
        
        with self._get_connection() as conn:
            query = "SELECT * FROM blacklisted_ips WHERE is_active = 1"
            params = []
            
            if ip_version:
                query += " AND ip_version = ?"
                params.append(ip_version)
            
            cursor = conn.execute(query, params)
            
            for row in cursor.fetchall():
                # Obtém event types para este IP
                event_cursor = conn.execute("""
                    SELECT event_type FROM ip_events WHERE ip_id = ?
                """, (row['id'],))
                event_types = [r['event_type'] for r in event_cursor.fetchall()]
                
                ip_str = row['ip']
                ips_info[ip_str] = self._row_to_dict(row, event_types)
        
        return ips_info
    
    def remove_ip(self, ip_str: str) -> bool:
        """Remove IP (soft delete)"""
        try:
            with self._get_connection() as conn:
                conn.execute("""
                    UPDATE blacklisted_ips 
                    SET is_active = 0, updated_at = CURRENT_TIMESTAMP
                    WHERE ip = ?
                """, (ip_str,))
                conn.commit()
                return True
        except Exception as e:
            self.logger.error(f"Error removing IP {ip_str}: {e}")
            return False
    
    def get_statistics(self) -> Dict:
        """Retorna estatísticas do blacklist"""
        with self._get_connection() as conn:
            stats = {}
            
            # Total IPs
            cursor = conn.execute("SELECT COUNT(*) FROM blacklisted_ips WHERE is_active = 1")
            stats['total_ips'] = cursor.fetchone()[0]
            
            # Por versão
            cursor = conn.execute("""
                SELECT ip_version, COUNT(*) as count 
                FROM blacklisted_ips WHERE is_active = 1
                GROUP BY ip_version
            """)
            for row in cursor.fetchall():
                stats[f'ipv{row["ip_version"]}'] = row['count']
            
            # Por confidence
            cursor = conn.execute("""
                SELECT confidence, COUNT(*) as count 
                FROM blacklisted_ips WHERE is_active = 1
                GROUP BY confidence
            """)
            stats['by_confidence'] = {row['confidence']: row['count'] for row in cursor.fetchall()}
            
            # Por source
            cursor = conn.execute("""
                SELECT source, COUNT(*) as count 
                FROM blacklisted_ips WHERE is_active = 1
                GROUP BY source
            """)
            stats['by_source'] = {row['source']: row['count'] for row in cursor.fetchall()}
            
            # Total events
            cursor = conn.execute("""
                SELECT SUM(event_count) FROM blacklisted_ips WHERE is_active = 1
            """)
            stats['total_events'] = cursor.fetchone()[0] or 0
            
            # Com geolocalização
            cursor = conn.execute("""
                SELECT COUNT(*) FROM blacklisted_ips 
                WHERE is_active = 1 AND geo_country IS NOT NULL
            """)
            stats['with_geolocation'] = cursor.fetchone()[0]
            
            return stats
    
    def backup(self, backup_path: Optional[str] = None) -> str:
        """
        Cria backup do database
        
        Returns:
            Path do backup criado
        """
        if not backup_path:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_path = f"{self.db_path}.backup.{timestamp}"
        
        import shutil
        shutil.copy2(self.db_path, backup_path)
        
        self.logger.info(f"Backup created: {backup_path}")
        return backup_path
    
    def _row_to_dict(self, row: sqlite3.Row, event_types: List[str]) -> Dict:
        """Converte row do DB para dict compatível com formato antigo"""
        return {
            'ip': ipaddress.ip_address(row['ip']),
            'reason': row['reason'],
            'confidence': row['confidence'],
            'event_count': row['event_count'],
            'geolocation': {
                'country': row['geo_country'],
                'city': row['geo_city'],
                'isp': row['geo_isp']
            } if row['geo_country'] else None,
            'first_seen': self._parse_datetime(row['first_seen']),
            'last_seen': self._parse_datetime(row['last_seen']),
            'date_added': self._parse_datetime(row['date_added']),
            'source': row['source'],
            'event_types': event_types
        }
    
    def _format_datetime(self, dt) -> Optional[str]:
        """Formata datetime para SQLite"""
        if dt is None:
            return None
        if isinstance(dt, datetime):
            return dt.isoformat()
        if isinstance(dt, str):
            return dt
        return None
    
    def _parse_datetime(self, dt_str: Optional[str]) -> Optional[datetime]:
        """Parse datetime do SQLite"""
        if not dt_str:
            return None
        try:
            return datetime.fromisoformat(dt_str)
        except:
            return None
