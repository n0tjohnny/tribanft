"""
TribanFT SQLite Database Manager

SQLite backend for blacklist storage at scale (10k+ IPs).

Provides:
- Efficient IP storage with metadata
- Atomic bulk operations with UPSERT logic (preserves existing data)
- Historical tracking with timestamps
- Event type storage
- Geolocation caching
- Statistics aggregation

Database schema:
- blacklist table: IP, version, reason, confidence, events, source, geo, timestamps, metadata

Author: TribanFT Project
License: GNU GPL v3
"""

import sqlite3
from typing import Dict, Optional
from pathlib import Path
from datetime import datetime
import json
import logging
import ipaddress


class BlacklistDatabase:
    """SQLite database manager for blacklist storage"""
    
    def __init__(self, db_path: str = "/var/lib/tribanft/blacklist.db"):
        """
        Initialize database connection and create tables.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger(__name__)
        self._init_db()
    
    def _init_db(self):
        """Create database tables and indexes if they don't exist."""
        with sqlite3.connect(self.db_path) as conn:
            # Main blacklist table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS blacklist (
                    ip TEXT PRIMARY KEY,
                    ip_version INTEGER,
                    reason TEXT,
                    confidence TEXT,
                    event_count INTEGER,
                    source TEXT,
                    country TEXT,
                    city TEXT,
                    isp TEXT,
                    first_seen TEXT,
                    last_seen TEXT,
                    date_added TEXT,
                    metadata TEXT
                )
            """)
            
            # Indexes for performance
            conn.execute("CREATE INDEX IF NOT EXISTS idx_source ON blacklist(source)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_country ON blacklist(country)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_version ON blacklist(ip_version)")
            
            conn.commit()
    
    def bulk_add(self, ips_info: Dict[str, Dict]) -> int:
        """
        Bulk add/update IPs com UPSERT correto.
        
        Se IP existe: UPDATE apenas campos fornecidos (preserva existentes)
        Se IP novo: INSERT completo
        
        Converts datetime objects to ISO strings for SQLite storage.
        Stores event_types in metadata JSON field.
        
        Args:
            ips_info: Dict mapping IP string to metadata dict
            
        Returns:
            Number of IPs successfully added/updated
        """
        added = 0
        
        with sqlite3.connect(self.db_path) as conn:
            for ip_str, info in ips_info.items():
                try:
                    ip = ipaddress.ip_address(ip_str)
                    
                    # Verificar se IP já existe
                    existing = conn.execute(
                        "SELECT * FROM blacklist WHERE ip = ?", 
                        (ip_str,)
                    ).fetchone()
                    
                    if existing:
                        # UPDATE: atualizar apenas campos fornecidos
                        self._update_existing_ip(conn, ip_str, info, existing)
                    else:
                        # INSERT: novo IP completo
                        self._insert_new_ip(conn, ip_str, ip, info)
                    
                    added += 1
                    
                except Exception as e:
                    self.logger.warning(f"Skipped {ip_str}: {e}")
                    continue
            
            conn.commit()
        
        return added
    
    def _update_existing_ip(self, conn, ip_str: str, new_info: Dict, existing_row):
        """
        Update apenas campos fornecidos, preserva existentes.
        
        Args:
            conn: SQLite connection
            ip_str: IP address string
            new_info: New data to merge
            existing_row: Existing database row
        """
        # Parse existing data
        (_, ip_version, reason, confidence, event_count, source,
         country, city, isp, first_seen, last_seen, date_added, metadata_json) = existing_row
        
        # Merge geolocation (prioridade: new_info se fornecido)
        geo = new_info.get('geolocation')
        if geo:
            country = geo.get('country') or country
            city = geo.get('city') or city
            isp = geo.get('isp') or isp
        
        # Merge outros campos (prioridade: new_info se fornecido e não-None)
        if new_info.get('reason'):
            reason = new_info.get('reason')
        if new_info.get('confidence'):
            confidence = new_info.get('confidence')
        if new_info.get('event_count') is not None:
            event_count = new_info.get('event_count')
        if new_info.get('source'):
            source = new_info.get('source')
        
        # Timestamps: manter first_seen original, atualizar last_seen se fornecido
        first_seen_new = new_info.get('first_seen')
        last_seen_new = new_info.get('last_seen')
        
        # Manter first_seen original (não sobrescrever)
        first_str = first_seen
        
        # Atualizar last_seen apenas se fornecido
        if last_seen_new:
            last_str = last_seen_new.isoformat() if hasattr(last_seen_new, 'isoformat') else last_seen_new
        else:
            last_str = last_seen
        
        # Metadata: merge JSON
        try:
            existing_metadata = json.loads(metadata_json) if metadata_json else {}
        except:
            existing_metadata = {}
        
        new_metadata = new_info.get('metadata', {})
        
        # Adicionar event_types se fornecido e não existe
        if 'event_types' not in existing_metadata and new_info.get('event_types'):
            new_metadata['event_types'] = new_info['event_types']
        
        merged_metadata = {**existing_metadata, **new_metadata}
        
        # UPDATE query
        conn.execute("""
            UPDATE blacklist SET
                reason = ?,
                confidence = ?,
                event_count = ?,
                source = ?,
                country = ?,
                city = ?,
                isp = ?,
                last_seen = ?,
                metadata = ?
            WHERE ip = ?
        """, (
            reason,
            confidence,
            event_count,
            source,
            country,
            city,
            isp,
            last_str,
            json.dumps(merged_metadata),
            ip_str
        ))
    
    def _insert_new_ip(self, conn, ip_str: str, ip, info: Dict):
        """
        Insert novo IP completo.
        
        Args:
            conn: SQLite connection
            ip_str: IP address string
            ip: IP address object
            info: Complete IP metadata
        """
        geo = info.get('geolocation', {})
        
        # Convert datetime objects to ISO strings for SQLite
        first_seen = info.get('first_seen')
        last_seen = info.get('last_seen')
        date_added = info.get('date_added')
        
        first_str = first_seen.isoformat() if hasattr(first_seen, 'isoformat') else None
        last_str = last_seen.isoformat() if hasattr(last_seen, 'isoformat') else None
        added_str = date_added.isoformat() if hasattr(date_added, 'isoformat') else datetime.now().isoformat()
        
        # Prepare metadata with event_types
        metadata = info.get('metadata', {}).copy() if info.get('metadata') else {}
        
        # Add event_types to metadata if not already present
        if 'event_types' not in metadata and info.get('event_types'):
            metadata['event_types'] = info['event_types']
        
        # Insert or replace IP entry
        conn.execute("""
            INSERT INTO blacklist VALUES 
            (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            ip_str,
            ip.version,
            info.get('reason'),
            info.get('confidence'),
            info.get('event_count', 0),
            info.get('source'),
            geo.get('country') if geo else None,
            geo.get('city') if geo else None,
            geo.get('isp') if geo else None,
            first_str,
            last_str,
            added_str,
            json.dumps(metadata)
        ))
    
    def get_all_ips(self, ip_version: Optional[int] = None) -> Dict[str, Dict]:
        """
        Retrieve all IPs from database with full metadata.
        
        Parses timestamps back to datetime objects and extracts event_types.
        
        Args:
            ip_version: Optional filter for IPv4 (4) or IPv6 (6)
            
        Returns:
            Dict mapping IP string to metadata dict
        """
        query = "SELECT * FROM blacklist"
        if ip_version:
            query += f" WHERE ip_version = {ip_version}"
        
        ips = {}
        
        with sqlite3.connect(self.db_path) as conn:
            for row in conn.execute(query):
                try:
                    # Parse timestamps back to datetime objects
                    first_seen = datetime.fromisoformat(row[9]) if row[9] else None
                    last_seen = datetime.fromisoformat(row[10]) if row[10] else None
                    date_added = datetime.fromisoformat(row[11]) if row[11] else None
                    
                    # Parse metadata JSON to extract event_types
                    metadata = {}
                    event_types = []
                    
                    try:
                        if row[12]:
                            metadata = json.loads(row[12])
                            event_types = metadata.get('event_types', [])
                    except json.JSONDecodeError:
                        pass
                    
                    # Build complete IP info dict
                    ips[row[0]] = {
                        'ip': row[0],
                        'reason': row[2],
                        'confidence': row[3],
                        'event_count': row[4],
                        'source': row[5],
                        'first_seen': first_seen,
                        'last_seen': last_seen,
                        'date_added': date_added,
                        'event_types': event_types,
                        'metadata': metadata,
                        'geolocation': {
                            'country': row[6],
                            'city': row[7],
                            'isp': row[8]
                        } if row[6] else None
                    }
                    
                except Exception as e:
                    self.logger.warning(f"Error parsing row for {row[0]}: {e}")
                    continue
        
        return ips
    
    def get_statistics(self) -> Dict:
        """
        Calculate database statistics.
        
        Returns:
            Dict with IP counts, geolocation coverage, event totals
        """
        with sqlite3.connect(self.db_path) as conn:
            stats = {
                'total_ips': conn.execute(
                    "SELECT COUNT(*) FROM blacklist"
                ).fetchone()[0],
                
                'ipv4': conn.execute(
                    "SELECT COUNT(*) FROM blacklist WHERE ip_version=4"
                ).fetchone()[0],
                
                'ipv6': conn.execute(
                    "SELECT COUNT(*) FROM blacklist WHERE ip_version=6"
                ).fetchone()[0],
                
                'with_geolocation': conn.execute(
                    "SELECT COUNT(*) FROM blacklist WHERE country IS NOT NULL"
                ).fetchone()[0],
                
                'total_events': conn.execute(
                    "SELECT SUM(event_count) FROM blacklist"
                ).fetchone()[0] or 0
            }
            
            # Count by source
            by_source = {}
            for row in conn.execute("SELECT source, COUNT(*) FROM blacklist GROUP BY source"):
                by_source[row[0] or 'unknown'] = row[1]
            
            stats['by_source'] = by_source
            
            return stats
    
    def backup(self):
        """Create daily database backup."""
        backup_path = Path(str(self.db_path) + f".backup.{datetime.now().strftime('%Y%m%d')}")
        
        try:
            import shutil
            shutil.copy2(self.db_path, backup_path)
            self.logger.info(f"Database backup created: {backup_path.name}")
        except Exception as e:
            self.logger.error(f"Backup failed: {e}")