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
import time


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
            # Enable WAL mode for better concurrent read/write performance
            conn.execute("PRAGMA journal_mode=WAL")
            
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
        Bulk add/update IPs with correct UPSERT logic.

        If IP exists: UPDATE only provided fields (preserves existing data)
        If IP is new: INSERT complete record

        Converts datetime objects to ISO strings for SQLite storage.
        Stores event_types in metadata JSON field.

        Implements retry logic with exponential backoff for concurrent access.

        Args:
            ips_info: Dict mapping IP string to metadata dict

        Returns:
            Number of IPs successfully added/updated

        Raises:
            sqlite3.OperationalError: If database remains locked after max retries
        """
        max_retries = 5
        retry_delay = 0.1  # Start with 100ms
        
        for attempt in range(max_retries):
            try:
                added = 0
                
                # Use timeout and IMMEDIATE transaction for write lock
                with sqlite3.connect(self.db_path, timeout=10.0) as conn:
                    # Begin IMMEDIATE transaction to acquire write lock immediately
                    conn.execute("BEGIN IMMEDIATE")
                    
                    for ip_str, info in ips_info.items():
                        try:
                            ip = ipaddress.ip_address(ip_str)

                            # Check if IP already exists
                            existing = conn.execute(
                                "SELECT * FROM blacklist WHERE ip = ?",
                                (ip_str,)
                            ).fetchone()

                            if existing:
                                # UPDATE: update only provided fields
                                self._update_existing_ip(conn, ip_str, info, existing)
                            else:
                                # INSERT: new complete IP record
                                self._insert_new_ip(conn, ip_str, ip, info)
                            
                            added += 1
                            
                        except Exception as e:
                            self.logger.warning(f"Skipped {ip_str}: {e}")
                            continue
                    
                    conn.commit()
                
                # Success - return result
                return added
                
            except sqlite3.OperationalError as e:
                error_msg = str(e).lower()
                
                # Check if it's a lock-related error (more robust error detection)
                # Check both the error message string and errno if available
                is_lock_error = (
                    "database is locked" in error_msg or
                    "locked" in error_msg
                )
                
                if is_lock_error and attempt < max_retries - 1:
                    self.logger.warning(
                        f"Database locked on attempt {attempt + 1}/{max_retries}, "
                        f"retrying in {retry_delay:.2f}s..."
                    )
                    time.sleep(retry_delay)
                    retry_delay *= 2  # Exponential backoff
                    continue
                else:
                    # Non-lock error or max retries exceeded
                    self.logger.error(f"ERROR: Database operation failed: {e}")
                    raise
        
        # Should not reach here, but just in case
        raise sqlite3.OperationalError("Failed to complete bulk_add after all retries")
    
    def _update_existing_ip(self, conn, ip_str: str, new_info: Dict, existing_row):
        """
        Update only provided fields, preserves existing data.

        Args:
            conn: SQLite connection
            ip_str: IP address string
            new_info: New data to merge
            existing_row: Existing database row
        """
        # Parse existing data
        (_, ip_version, reason, confidence, event_count, source,
         country, city, isp, first_seen, last_seen, date_added, metadata_json) = existing_row

        # Merge geolocation (priority: new_info if provided, ALWAYS preserves existing)
        # CRITICAL: Only update geo if new data provides non-empty values
        # This prevents enrichment updates from accidentally clearing geolocation
        geo = new_info.get('geolocation')
        if geo and isinstance(geo, dict):
            # Only update individual fields if new value is non-empty
            new_country = geo.get('country')
            new_city = geo.get('city')
            new_isp = geo.get('isp')

            # Preserve existing values unless new data provides better info
            if new_country and not country:
                self.logger.debug(f"Adding geo for {ip_str}: {new_country}")
                country = new_country
            elif new_country and new_country != country:
                self.logger.debug(f"Updating geo for {ip_str}: {country} → {new_country}")
                country = new_country

            city = new_city if new_city else city
            isp = new_isp if new_isp else isp
        # If geo is None or not provided, existing values remain unchanged

        # Merge other fields (priority: new_info if provided and not None)
        if new_info.get('reason'):
            reason = new_info.get('reason')
        if new_info.get('confidence'):
            confidence = new_info.get('confidence')
        if new_info.get('event_count') is not None:
            event_count = new_info.get('event_count')
        if new_info.get('source'):
            source = new_info.get('source')

        # Timestamps: keep original first_seen, update last_seen if provided
        first_seen_new = new_info.get('first_seen')
        last_seen_new = new_info.get('last_seen')

        # Keep original first_seen (don't overwrite)
        first_str = first_seen

        # Update last_seen only if provided
        if last_seen_new:
            last_str = last_seen_new.isoformat() if hasattr(last_seen_new, 'isoformat') else last_seen_new
        else:
            last_str = last_seen

        # Metadata: merge JSON
        try:
            existing_metadata = json.loads(metadata_json) if metadata_json else {}
        except (json.JSONDecodeError, TypeError):
            existing_metadata = {}

        new_metadata = new_info.get('metadata', {})

        # Add event_types if provided and doesn't exist
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
        Insert new complete IP record.

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
        params = ()

        if ip_version:
            query += " WHERE ip_version = ?"
            params = (ip_version,)

        ips = {}

        with sqlite3.connect(self.db_path) as conn:
            for row in conn.execute(query, params):
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
                        'ip': ipaddress.ip_address(row[0]),
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

    def delete_ip(self, ip_str: str) -> bool:
        """
        Delete IP from blacklist database.

        Args:
            ip_str: IP address to remove

        Returns:
            True if IP was deleted, False if not found
        """
        try:
            with sqlite3.connect(self.db_path, timeout=30) as conn:
                cursor = conn.cursor()

                # Check if IP exists
                cursor.execute("SELECT ip FROM blacklist WHERE ip = ?", (ip_str,))
                if not cursor.fetchone():
                    self.logger.warning(f"IP {ip_str} not found in database")
                    return False

                # Delete the IP
                cursor.execute("DELETE FROM blacklist WHERE ip = ?", (ip_str,))
                conn.commit()

                self.logger.info(f"Deleted {ip_str} from database")
                return True

        except sqlite3.Error as e:
            self.logger.error(f"Database error deleting {ip_str}: {e}")
            return False