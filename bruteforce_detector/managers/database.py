"""
TribanFT SQLite Database

SQLite backend for blacklist storage at scale.

Provides efficient storage for 10k+ IPs with atomic operations,
historical tracking, and optimized queries.

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
    """SQLite database for blacklist storage"""
    
    def __init__(self, db_path: str = "/var/lib/tribanft/blacklist.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger(__name__)
        self._init_db()
    
    def _init_db(self):
        """Create tables and indexes."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS blacklist (
                ip TEXT PRIMARY KEY, ip_version INTEGER, reason TEXT,
                confidence TEXT, event_count INTEGER, source TEXT,
                country TEXT, city TEXT, isp TEXT,
                first_seen TEXT, last_seen TEXT, date_added TEXT, metadata TEXT)""")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_source ON blacklist(source)")
            conn.commit()
    
    def bulk_add(self, ips_info: Dict[str, Dict]) -> int:
        """Bulk add IPs for performance with proper datetime handling."""
        added = 0
        with sqlite3.connect(self.db_path) as conn:
            for ip_str, info in ips_info.items():
                try:
                    ip = ipaddress.ip_address(ip_str)
                    geo = info.get('geolocation', {})
                    
                    # Convert datetime objects to ISO strings
                    first_seen = info.get('first_seen')
                    last_seen = info.get('last_seen')
                    date_added = info.get('date_added')
                    
                    first_str = first_seen.isoformat() if hasattr(first_seen, 'isoformat') else None
                    last_str = last_seen.isoformat() if hasattr(last_seen, 'isoformat') else None
                    added_str = date_added.isoformat() if hasattr(date_added, 'isoformat') else datetime.now().isoformat()
                    
                    conn.execute("""INSERT OR REPLACE INTO blacklist VALUES 
                        (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", (
                        ip_str, ip.version, info.get('reason'), info.get('confidence'),
                        info.get('event_count', 0), info.get('source'),
                        geo.get('country') if geo else None,
                        geo.get('city') if geo else None,
                        geo.get('isp') if geo else None,
                        first_str,
                        last_str,
                        added_str,
                        json.dumps(info.get('metadata', {}))))
                    added += 1
                except Exception as e:
                    self.logger.warning(f"Skipped {ip_str}: {e}")
            conn.commit()
        return added
    
    def get_all_ips(self, ip_version: Optional[int] = None) -> Dict[str, Dict]:
        """Get all IPs from database with datetime parsing."""
        query = "SELECT * FROM blacklist"
        if ip_version: 
            query += f" WHERE ip_version = {ip_version}"
        
        ips = {}
        with sqlite3.connect(self.db_path) as conn:
            for row in conn.execute(query):
                # Parse timestamps back to datetime
                first_seen = datetime.fromisoformat(row[9]) if row[9] else None
                last_seen = datetime.fromisoformat(row[10]) if row[10] else None
                date_added = datetime.fromisoformat(row[11]) if row[11] else None
                
                ips[row[0]] = {
                    'ip': row[0], 
                    'reason': row[2], 
                    'confidence': row[3],
                    'event_count': row[4], 
                    'source': row[5],
                    'first_seen': first_seen,
                    'last_seen': last_seen,
                    'date_added': date_added,
                    'geolocation': {'country': row[6], 'city': row[7], 'isp': row[8]} if row[6] else None
                }
        return ips
    
    def get_statistics(self) -> Dict:
        """Get database statistics."""
        with sqlite3.connect(self.db_path) as conn:
            return {
                'total_ips': conn.execute("SELECT COUNT(*) FROM blacklist").fetchone()[0],
                'ipv4': conn.execute("SELECT COUNT(*) FROM blacklist WHERE ip_version=4").fetchone()[0],
                'with_geolocation': conn.execute("SELECT COUNT(*) FROM blacklist WHERE country IS NOT NULL").fetchone()[0],
                'total_events': conn.execute("SELECT SUM(event_count) FROM blacklist").fetchone()[0] or 0
            }
    
    def backup(self):
        """Create database backup."""
        backup_path = Path(str(self.db_path) + f".backup.{datetime.now().strftime('%Y%m%d')}")
        try:
            import shutil
            shutil.copy2(self.db_path, backup_path)
        except Exception as e:
            self.logger.error(f"Backup failed: {e}")