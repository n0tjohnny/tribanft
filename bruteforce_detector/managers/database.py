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
from contextlib import contextmanager


class BlacklistDatabase:
    """SQLite database manager for blacklist storage"""

    def __init__(self, db_path: str):
        """
        Initialize database connection and create tables.

        Args:
            db_path: Path to SQLite database file (from config)
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger(__name__)

        # Check SQLite version for json_patch support (available in SQLite 3.38+)
        conn = sqlite3.connect(self.db_path)
        sqlite_version = conn.execute("SELECT sqlite_version()").fetchone()[0]
        version_tuple = tuple(map(int, sqlite_version.split('.')))
        self.has_json_patch = version_tuple >= (3, 38, 0)
        conn.close()

        if self.has_json_patch:
            self.logger.debug(f"SQLite {sqlite_version}: json_patch available for metadata merge")
        else:
            self.logger.warning(f"SQLite {sqlite_version}: json_patch NOT available, using fallback merge")

        self._init_db()

    @contextmanager
    def _query_timer(self, operation: str):
        """
        Context manager for query performance logging (debug mode only).

        Usage:
            with self._query_timer("get_all_ips"):
                result = conn.execute(query)

        Args:
            operation: Description of the operation being timed
        """
        start_time = time.perf_counter()
        try:
            yield
        finally:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            if self.logger.isEnabledFor(logging.DEBUG):
                self.logger.debug(f"[PERF] {operation}: {elapsed_ms:.2f}ms")
    
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
            conn.execute("CREATE INDEX IF NOT EXISTS idx_event_count ON blacklist(event_count DESC)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_date_added ON blacklist(date_added DESC)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_last_seen ON blacklist(last_seen DESC)")

            conn.commit()
    
    def bulk_add(self, ips_info: Dict[str, Dict]) -> int:
        """
        Bulk add/update IPs using UPSERT for deadlock-free operation.

        Uses INSERT ... ON CONFLICT UPDATE to avoid row-by-row SELECT checks
        that can cause deadlocks under concurrent load.

        If IP exists: UPDATE with intelligent field merging
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

                # Use longer timeout with IMMEDIATE transaction for write lock
                with sqlite3.connect(self.db_path, timeout=30.0) as conn:
                    with self._query_timer(f"bulk_add({len(ips_info)} IPs)"):
                        # Begin IMMEDIATE transaction to acquire write lock immediately
                        conn.execute("BEGIN IMMEDIATE")

                        for ip_str, info in ips_info.items():
                            try:
                                ip = ipaddress.ip_address(ip_str)

                                # Prepare values
                                geo = info.get('geolocation', {})

                                # Convert datetime objects to ISO strings
                                first_seen = info.get('first_seen')
                                last_seen = info.get('last_seen')
                                date_added = info.get('date_added')

                                first_str = first_seen.isoformat() if hasattr(first_seen, 'isoformat') else first_seen
                                last_str = last_seen.isoformat() if hasattr(last_seen, 'isoformat') else last_seen
                                added_str = date_added.isoformat() if hasattr(date_added, 'isoformat') else datetime.now().isoformat()

                                # Prepare metadata with event_types
                                metadata = info.get('metadata', {}).copy() if info.get('metadata') else {}
                                if 'event_types' not in metadata and info.get('event_types'):
                                    metadata['event_types'] = info['event_types']
                                metadata_json = json.dumps(metadata)

                                # UPSERT: Insert new or update existing
                                # Uses ON CONFLICT to avoid SELECT-then-UPDATE deadlock
                                conn.execute("""
                                    INSERT INTO blacklist (
                                        ip, ip_version, reason, confidence, event_count,
                                        source, country, city, isp,
                                        first_seen, last_seen, date_added, metadata
                                    )
                                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                                    ON CONFLICT(ip) DO UPDATE SET
                                        event_count = event_count + excluded.event_count,
                                        last_seen = COALESCE(excluded.last_seen, last_seen),
                                        reason = COALESCE(excluded.reason, reason),
                                        confidence = COALESCE(excluded.confidence, confidence),
                                        source = COALESCE(excluded.source, source),
                                        country = COALESCE(excluded.country, country),
                                        city = COALESCE(excluded.city, city),
                                        isp = COALESCE(excluded.isp, isp),
                                        metadata = CASE
                                            WHEN ? THEN json_patch(metadata, excluded.metadata)
                                            ELSE excluded.metadata
                                        END
                                """, (
                                    ip_str,
                                    ip.version,
                                    info.get('reason'),
                                    info.get('confidence'),
                                    info.get('event_count', 1),
                                    info.get('source'),
                                    geo.get('country') if geo else None,
                                    geo.get('city') if geo else None,
                                    geo.get('isp') if geo else None,
                                    first_str,
                                    last_str,
                                    added_str,
                                    metadata_json,
                                    1 if self.has_json_patch else 0  # Boolean for CASE statement
                                ))

                                added += 1

                            except Exception as e:
                                self.logger.warning(f"Skipped {ip_str}: {e}")
                                continue

                        conn.commit()

                # Success - return result
                return added

            except sqlite3.OperationalError as e:
                error_msg = str(e).lower()

                # Check if it's a lock-related error
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
            with self._query_timer(f"get_all_ips(ip_version={ip_version})"):
                rows = conn.execute(query, params).fetchall()

            for row in rows:
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
            with self._query_timer("get_statistics"):
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

    def query_by_attack_type(self, event_type: str) -> Dict[str, Dict]:
        """
        Query IPs by attack/event type.

        Uses the event_types stored in metadata JSON field.

        Args:
            event_type: EventType to filter by (e.g., "sql_injection", "ssh_attack")

        Returns:
            Dict mapping IP string to metadata dict
        """
        ips = {}

        with sqlite3.connect(self.db_path) as conn:
            with self._query_timer(f"query_by_attack_type({event_type})"):
                # Query all IPs and filter by event_type in metadata
                for row in conn.execute("SELECT * FROM blacklist"):
                    try:
                        # Parse metadata JSON
                        metadata_json = row[12]
                        if metadata_json:
                            metadata = json.loads(metadata_json)
                            event_types = metadata.get('event_types', [])

                            # Check if event_type matches (case-insensitive)
                            if any(et.lower() == event_type.lower() for et in event_types):
                                # Parse timestamps
                                first_seen = datetime.fromisoformat(row[9]) if row[9] else None
                                last_seen = datetime.fromisoformat(row[10]) if row[10] else None
                                date_added = datetime.fromisoformat(row[11]) if row[11] else None

                                # Build IP info dict
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

                    except (json.JSONDecodeError, Exception) as e:
                        self.logger.debug(f"Error parsing row for {row[0]}: {e}")
                        continue

        return ips

    def query_by_timerange(self, start_date: Optional[datetime] = None,
                          end_date: Optional[datetime] = None) -> Dict[str, Dict]:
        """
        Query IPs by time range (date_added field).

        Args:
            start_date: Start of time range (inclusive)
            end_date: End of time range (inclusive)

        Returns:
            Dict mapping IP string to metadata dict
        """
        query = "SELECT * FROM blacklist WHERE 1=1"
        params = []

        if start_date:
            query += " AND date_added >= ?"
            params.append(start_date.isoformat())

        if end_date:
            query += " AND date_added <= ?"
            params.append(end_date.isoformat())

        # Order by date_added DESC (uses idx_date_added index)
        query += " ORDER BY date_added DESC"

        ips = {}

        with sqlite3.connect(self.db_path) as conn:
            with self._query_timer(f"query_by_timerange({start_date} to {end_date})"):
                rows = conn.execute(query, params).fetchall()

            for row in rows:
                try:
                    # Parse timestamps
                    first_seen = datetime.fromisoformat(row[9]) if row[9] else None
                    last_seen = datetime.fromisoformat(row[10]) if row[10] else None
                    date_added = datetime.fromisoformat(row[11]) if row[11] else None

                    # Parse metadata JSON
                    metadata = {}
                    event_types = []

                    try:
                        if row[12]:
                            metadata = json.loads(row[12])
                            event_types = metadata.get('event_types', [])
                    except json.JSONDecodeError:
                        pass

                    # Build IP info dict
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

    def query_top_ips(self, limit: int = 100, order_by: str = 'event_count') -> Dict[str, Dict]:
        """
        Query top IPs ordered by event_count or date_added.

        Args:
            limit: Maximum number of IPs to return
            order_by: Field to order by ('event_count' or 'date_added')

        Returns:
            Dict mapping IP string to metadata dict
        """
        # Validate order_by parameter
        if order_by not in ['event_count', 'date_added']:
            order_by = 'event_count'

        # Use appropriate index (idx_event_count or idx_date_added)
        query = f"SELECT * FROM blacklist ORDER BY {order_by} DESC LIMIT ?"

        ips = {}

        with sqlite3.connect(self.db_path) as conn:
            with self._query_timer(f"query_top_ips(limit={limit}, order_by={order_by})"):
                rows = conn.execute(query, (limit,)).fetchall()

            for row in rows:
                try:
                    # Parse timestamps
                    first_seen = datetime.fromisoformat(row[9]) if row[9] else None
                    last_seen = datetime.fromisoformat(row[10]) if row[10] else None
                    date_added = datetime.fromisoformat(row[11]) if row[11] else None

                    # Parse metadata JSON
                    metadata = {}
                    event_types = []

                    try:
                        if row[12]:
                            metadata = json.loads(row[12])
                            event_types = metadata.get('event_types', [])
                    except json.JSONDecodeError:
                        pass

                    # Build IP info dict
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