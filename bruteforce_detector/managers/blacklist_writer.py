"""
TribanFT Blacklist File Writer

Manages reading and writing of blacklist text files with comprehensive metadata preservation.

This module handles file-based blacklist storage with:
- Rich metadata extraction from comment blocks (geolocation, events, timestamps)
- Anti-corruption protection (prevents accidental data loss)
- Automatic backups before modifications
- FILE LOCKING to prevent race conditions
- Formatted output with statistics and organization

File format includes detailed comments for each IP with geolocation, reason,
confidence level, event counts, and timestamps for human readability and analysis.

Author: TribanFT Project
License: GNU GPL v3
"""

from typing import Dict, Set, List
from pathlib import Path
from datetime import datetime, timezone, timedelta
from collections import defaultdict
import logging
import ipaddress
import re
import fcntl
import os
import tempfile
from contextlib import contextmanager


class BlacklistWriter:
    """Manages blacklist file I/O with metadata preservation and corruption protection."""
    
    def __init__(self, config):
        """
        Initialize writer with configuration.
        
        Args:
            config: Configuration object with file paths
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Initialize backup manager for rotating backups
        try:
            from ..utils.backup_manager import get_backup_manager
            self.backup_manager = get_backup_manager()
        except Exception as e:
            self.logger.warning(f"Failed to initialize backup manager: {e}")
            self.backup_manager = None
    
    @contextmanager
    def _file_lock(self, filepath: Path):
        """
        Context manager for file locking during writes.

        Prevents race conditions when multiple processes write
        simultaneously (tribanft, ipinfo-batch, recover).

        Args:
            filepath: Path of the file to be locked

        Yields:
            None (file is locked during context)
        """
        lock_file = Path(str(filepath) + '.lock')
        
        lock_fd = None
        try:
            # Create lock file with secure permissions
            old_umask = os.umask(0o077)  # Ensure restrictive permissions (0600)
            try:
                lock_fd = open(lock_file, 'w')
            finally:
                os.umask(old_umask)  # Restore original umask

            # Acquire exclusive lock (blocks until acquired)
            self.logger.debug(f"Acquiring lock for {filepath.name}...")
            fcntl.flock(lock_fd.fileno(), fcntl.LOCK_EX)
            self.logger.debug(f"Lock acquired for {filepath.name}")

            yield

        finally:
            # Liberar lock
            if lock_fd is not None:
                try:
                    fcntl.flock(lock_fd.fileno(), fcntl.LOCK_UN)
                    lock_fd.close()
                except Exception as e:
                    self.logger.debug(f"Error releasing lock: {e}")

            # Remover arquivo de lock
            if lock_file.exists():
                lock_file.unlink()

            self.logger.debug(f"Lock released for {filepath.name}")

    def _should_create_backup(self, path: Path) -> bool:
        """
        Check if file has changed since last backup.

        Uses checksum comparison and time threshold to avoid redundant backups.
        Backups are skipped if:
        - Backups are disabled globally
        - Last backup was less than backup_interval_days ago
        - File content is identical to last backup (checksum match)

        Args:
            path: Path to file to check

        Returns:
            True if backup should be created, False if redundant
        """
        if not self.backup_manager:
            return False

        # Check if backups are enabled
        if not self.backup_manager.enabled:
            self.logger.debug("Backups disabled globally")
            return False

        # Get most recent backup for this file
        backups = self.backup_manager.list_backups(path.name)
        if not backups:
            return True  # No backup exists yet

        latest_backup_time, latest_backup_path = backups[0]

        # Calculate time threshold based on backup_interval_days
        # If interval_days = 0, use 5 minutes (backward compatibility)
        # Otherwise use the configured interval
        if self.backup_manager.interval_days == 0:
            min_interval = timedelta(minutes=5)
            interval_desc = "5 minutes"
        else:
            min_interval = timedelta(days=self.backup_manager.interval_days)
            interval_desc = f"{self.backup_manager.interval_days} day(s)"

        time_since_backup = datetime.now() - latest_backup_time
        if time_since_backup < min_interval:
            self.logger.debug(
                f"Skipping backup - last backup was {time_since_backup.total_seconds()/3600:.1f}h ago "
                f"(threshold: {interval_desc})"
            )
            return False

        # Compare checksums (fast for text files)
        import hashlib

        def file_checksum(filepath):
            """Calculate SHA256 checksum of file"""
            sha256 = hashlib.sha256()
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()

        try:
            current_checksum = file_checksum(path)

            # Decompress backup if needed for comparison
            if latest_backup_path.suffix == '.gz':
                import gzip
                import tempfile as tmp
                with tmp.NamedTemporaryFile(delete=True) as tmpf:
                    with gzip.open(latest_backup_path, 'rb') as gz:
                        tmpf.write(gz.read())
                    tmpf.flush()
                    backup_checksum = file_checksum(tmpf.name)
                    # File auto-deleted on context exit
            else:
                backup_checksum = file_checksum(latest_backup_path)

            if current_checksum == backup_checksum:
                self.logger.debug(f"Skipping backup - file unchanged since last backup")
                return False

            self.logger.debug(f"File has changed - checksum mismatch")
            return True  # File has changed
        except Exception as e:
            self.logger.warning(f"Checksum comparison failed: {e}, creating backup anyway")
            return True

    def read_blacklist(self, filename: str) -> Dict[str, Dict]:
        """
        Read and parse blacklist file preserving all metadata.
        
        Extracts from comment blocks:
        - Geolocation (country, city, ISP)
        - Block reason and confidence
        - Event counts and types
        - Timestamps (first/last seen, date added)
        - Detection source
        
        Args:
            filename: Path to blacklist file
            
        Returns:
            Dict mapping IP strings to metadata dicts
        """
        path = Path(filename)
        existing_info = {}
        
        if not path.exists():
            self.logger.debug(f"Blacklist file not found: {filename}")
            return existing_info
        
        current_ip = None
        current_comment_lines = []
        
        with open(path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                
                # IP line (no comment marker)
                if line and not line.startswith('#'):
                    # Process previous IP's comments
                    if current_ip and current_comment_lines:
                        parsed_info = self._parse_comment_block(current_comment_lines)
                        if parsed_info:
                            existing_info[current_ip].update(parsed_info)
                        current_comment_lines = []
                    
                    # Initialize new IP entry
                    current_ip = line
                    if current_ip not in existing_info:
                        existing_info[current_ip] = {
                            'reason': 'Previously blocked',
                            'confidence': 'unknown',
                            'event_count': 0,
                            'geolocation': None,
                            'first_seen': None,
                            'last_seen': None,
                            'date_added': None,
                            'source': 'legacy',
                            'event_types': []
                        }
                
                # Comment line for current IP
                elif line.startswith('# IP:') or line.startswith('#   '):
                    if current_ip:
                        current_comment_lines.append(line)
        
        # Process final IP
        if current_ip and current_comment_lines:
            parsed_info = self._parse_comment_block(current_comment_lines)
            if parsed_info:
                existing_info[current_ip].update(parsed_info)
        
        # Log statistics
        with_geo = sum(1 for info in existing_info.values() if info.get('geolocation'))
        with_events = sum(1 for info in existing_info.values() if info.get('event_count', 0) > 0)
        
        self.logger.info(f"Read {len(existing_info)} IPs from blacklist")
        self.logger.info(f"   {with_geo} with geolocation ({with_geo/len(existing_info)*100:.1f}%)")
        self.logger.info(f"   {with_events} with events ({with_events/len(existing_info)*100:.1f}%)")
        
        return existing_info
    
    def _parse_comment_block(self, comment_lines: List[str]) -> Dict:
        """
        Extract metadata from comment block using robust regex patterns.
        
        Parses geolocation, reason, confidence, events, timestamps from
        structured comment format.
        
        Args:
            comment_lines: List of comment lines for one IP
            
        Returns:
            Dict with extracted metadata
        """
        info = {}
        
        try:
            full_comment = ' '.join(comment_lines)
            
            # Extract GEOLOCATION (Country, City | ISP)
            geo_match = re.search(r'# IP:\s*[\d.]+\s*\|\s*([^|#]+?)\s*\|\s*([^|#]+?)(?:\s*#|$)', full_comment)
            if geo_match:
                location_str = geo_match.group(1).strip()
                isp_str = geo_match.group(2).strip()
                
                if location_str and location_str not in ['Unknown Location', 'Unknown']:
                    location_parts = location_str.split(',', 1)
                    country = location_parts[0].strip()
                    city = location_parts[1].strip() if len(location_parts) > 1 else ''
                    
                    if country and country not in ['Unknown', 'Unknown Location']:
                        info['geolocation'] = {
                            'country': country,
                            'city': city,
                            'isp': isp_str if isp_str != 'Unknown ISP' else ''
                        }
            
            # Extract remaining fields
            for field, pattern in [
                ('reason', r'Reason:\s*([^|]+?)(?:\||#|$)'),
                ('confidence', r'Confidence:\s*(\w+)'),
                ('event_count', r'Events:\s*(\d+)'),
                ('event_types', r'EventTypes:\s*([^|#\n]+)'),
                ('source', r'Source:\s*(\w+)')
            ]:
                match = re.search(pattern, full_comment)
                if match:
                    value = match.group(1).strip()
                    if field == 'event_count':
                        info[field] = int(value)
                    elif field == 'event_types':
                        if value != 'N/A':
                            info[field] = [et.strip() for et in value.split(',')]
                    else:
                        info[field] = value
            
            # Extract timestamps
            for ts_field, pattern in [
                ('first_seen', r'First:\s*([\d\-: ]+)'),
                ('last_seen', r'Last:\s*([\d\-: ]+)'),
                ('date_added', r'Added:\s*([\d\-: ]+)')
            ]:
                match = re.search(pattern, full_comment)
                if match:
                    ts_str = match.group(1).strip()
                    if ts_str and ts_str != 'Unknown':
                        try:
                            info[ts_field] = datetime.strptime(ts_str, '%Y-%m-%d %H:%M').replace(tzinfo=timezone.utc)
                        except ValueError:
                            pass
        
        except Exception as e:
            self.logger.debug(f"Error parsing comment block: {e}")
        
        return info
    
    def write_blacklist(self, filename: str, ips_info: Dict[str, Dict], new_count: int = 0):
        """
        Write blacklist with comprehensive metadata and corruption protection.
        
        NOW WITH FILE LOCKING to prevent race conditions.
        
        Safety features:
        - Validates write would not lose >50% of IPs
        - Automatic backup before modifications
        - File locking to serialize concurrent writes
        - Keeps last 5 backups
        - Detailed statistics in header
        
        Args:
            filename: Output file path
            ips_info: Dict of IP addresses with metadata
            new_count: Number of new IPs in this update
            
        Raises:
            ValueError: If write would cause significant data loss
        """
        path = Path(filename)

        # Whitelist precedence check - NEVER block whitelisted IPs
        whitelist = self._load_whitelist()
        if whitelist:
            original_count = len(ips_info)
            ips_info = {
                ip: info for ip, info in ips_info.items()
                if ip not in whitelist
            }
            filtered_count = original_count - len(ips_info)
            if filtered_count > 0:
                self.logger.warning(
                    f"Filtered {filtered_count} whitelisted IPs from blacklist write"
                )

        # Anti-corruption protection
        min_expected_ips = getattr(self.config, 'min_expected_ips', 1000)

        if len(ips_info) < min_expected_ips:
            existing_count = self._count_existing_ips(path)

            if existing_count > min_expected_ips and len(ips_info) < existing_count * 0.5:
                loss = existing_count - len(ips_info)
                loss_pct = 100 - (len(ips_info) / existing_count * 100)
                
                error_msg = (
                    f"CRITICAL PROTECTION TRIGGERED:\n"
                    f"   Current: {existing_count} IPs\n"
                    f"   Proposed: {len(ips_info)} IPs\n"
                    f"   Loss: {loss} IPs ({loss_pct:.1f}%)\n"
                    f"   BLOCKED to prevent corruption"
                )
                self.logger.error(error_msg)
                raise ValueError(f"Blacklist corruption prevented: would lose {loss} IPs")
            
            elif len(ips_info) < 10:
                self.logger.error(f"ERROR: Only {len(ips_info)} IPs - possible corruption")
                raise ValueError(f"Blacklist too small: {len(ips_info)} IPs")
        
        # FILE LOCKING: Previne escrita concorrente
        with self._file_lock(path):
            # Automatic backup using BackupManager (only if file changed)
            if self.backup_manager:
                try:
                    # Smart backup: only create if file has changed
                    if self._should_create_backup(path):
                        self.backup_manager.create_backup(str(path))
                        # Prune old backups according to retention policy
                        self.backup_manager.prune_old_backups()
                    else:
                        self.logger.debug(f"Skipped redundant backup for {path.name}")
                except FileNotFoundError:
                    self.logger.debug(f"File disappeared before backup: {path}")
                except Exception as e:
                    self.logger.warning(f"Backup manager failed: {e}")
            else:
                # Fallback to old backup method
                try:
                    if path.exists():
                        backup_path = Path(str(path) + f".backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}")
                        import shutil
                        shutil.copy2(path, backup_path)
                        self.logger.info(f"Backup: {backup_path.name}")
                        self._cleanup_old_backups(path, keep=5)
                except FileNotFoundError:
                    self.logger.debug(f"File disappeared before backup: {path}")
                except Exception as e:
                    self.logger.warning(f"Backup failed: {e}")
            
            # Calculate statistics
            total_ips = len(ips_info)
            high_conf = sum(1 for info in ips_info.values() if info.get('confidence') == 'high')
            medium_conf = sum(1 for info in ips_info.values() if info.get('confidence') == 'medium')
            total_events = sum(info.get('event_count', 0) for info in ips_info.values())
            with_geo = sum(1 for info in ips_info.values() if info.get('geolocation'))
            
            # ATOMIC WRITE: Write to temp file first, then rename
            try:
                # Create temp file in same directory as target (ensures same filesystem)
                fd, temp_path = tempfile.mkstemp(
                    dir=path.parent,
                    prefix=f".{path.name}.",
                    suffix='.tmp'
                )
                
                try:
                    # Write to temp file
                    with os.fdopen(fd, 'w') as f:
                        f.write(f"# {'='*118}\n")
                        f.write(f"# ENHANCED BLACKLIST - COMPREHENSIVE THREAT INTELLIGENCE\n")
                        f.write(f"# {'='*118}\n")
                        f.write(f"# Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n#\n")
                        f.write(f"# STATISTICS:\n")
                        f.write(f"#   Total IPs: {total_ips} (New: {new_count})\n")
                        f.write(f"#   High Confidence: {high_conf} | Medium: {medium_conf}\n")
                        f.write(f"#   Total Events: {total_events}\n")
                        f.write(f"#   With Geolocation: {with_geo} ({with_geo/total_ips*100:.1f}%)\n")
                        f.write(f"# {'='*118}\n\n")
                        
                        # Group by source
                        by_source = self._group_by_source(ips_info)
                        
                        for source, ips in by_source.items():
                            if ips:
                                f.write(f"\n# {'-'*118}\n")
                                f.write(f"# SOURCE: {source.upper()} ({len(ips)} IPs)\n")
                                f.write(f"# {'-'*118}\n\n")
                                
                                for ip_str in sorted(ips.keys(), key=lambda x: ipaddress.ip_address(x)):
                                    self._write_ip_entry(f, ip_str, ips[ip_str])
                    
                    # Atomic rename: replaces old file with new one
                    try:
                        os.replace(temp_path, path)
                    except OSError as e:
                        self.logger.error(f"Failed to rename temp file to {path}: {e}")
                        raise
                    
                except Exception as e:
                    # Clean up temp file on error
                    if os.path.exists(temp_path):
                        os.unlink(temp_path)
                    raise
                    
            except Exception as e:
                self.logger.error(f"Failed to write {path}: {e}")
                raise
        
        # Log after releasing the lock
        if new_count > 0:
            self.logger.info(f"Blacklist updated: {total_ips} IPs (+{new_count} new)")
    
    def _load_whitelist(self) -> Set[str]:
        """Load whitelisted IPs from whitelist file."""
        whitelist = set()
        whitelist_path = Path(self.config.whitelist_file)

        if whitelist_path.exists():
            try:
                with open(whitelist_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            try:
                                # Validate IP address
                                ipaddress.ip_address(line)
                                whitelist.add(line)
                            except ValueError:
                                pass
            except Exception as e:
                self.logger.warning(f"Failed to load whitelist: {e}")

        return whitelist

    def get_manual_ips(self, manual_blacklist_file: str) -> Set[str]:
        """Extract IP addresses from manual blacklist file."""
        manual_ips = set()
        manual_path = Path(manual_blacklist_file)

        if manual_path.exists():
            with open(manual_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        manual_ips.add(line)

        return manual_ips
    
    def _count_existing_ips(self, filepath: Path) -> int:
        """Count valid IPs in existing blacklist for corruption detection."""
        if not filepath.exists():
            return 0
        
        count = 0
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        try:
                            ipaddress.ip_address(line)
                            count += 1
                        except ValueError:
                            pass
        except Exception:
            pass
        
        return count
    
    def _cleanup_old_backups(self, original_path: Path, keep: int = 5):
        """Keep only N most recent backups."""
        try:
            backup_pattern = f"{original_path.name}.backup.*"
            backups = sorted(
                original_path.parent.glob(backup_pattern),
                key=lambda p: p.stat().st_mtime,
                reverse=True
            )
            
            for old_backup in backups[keep:]:
                old_backup.unlink()
        except Exception as e:
            self.logger.debug(f"Backup cleanup error: {e}")
    
    def _group_by_source(self, ips_info: Dict[str, Dict]) -> Dict[str, Dict]:
        """
        Organize IPs by detection source with dynamic source support.
        
        Uses defaultdict to automatically handle new source types without
        schema updates. This prevents KeyError when enrichment adds sources
        like 'crowdsec_alerts' that aren't in the predefined whitelist.
        
        Args:
            ips_info: Dict mapping IP strings to metadata
            
        Returns:
            Dict mapping source names to dicts of {ip: metadata}
        """
        by_source = defaultdict(dict)
        
        for ip_str, info in ips_info.items():
            source = info.get('source') or 'legacy'
            by_source[source][ip_str] = info
        
        return dict(by_source)  # Convert to regular dict for consistent output
    
    def _write_ip_entry(self, file_obj, ip_str: str, info: Dict):
        """Write formatted IP entry with metadata."""
        geo = info.get('geolocation', {})
        if geo:
            country = geo.get('country', 'Unknown')
            city = geo.get('city', '')
            isp = geo.get('isp', 'Unknown ISP')
            location = f"{country}, {city}" if city else country
        else:
            location = "Unknown Location"
            isp = "Unknown ISP"
        
        first_seen = self._format_timestamp(info.get('first_seen'))
        last_seen = self._format_timestamp(info.get('last_seen'))
        date_added = self._format_timestamp(info.get('date_added', datetime.now()))
        
        event_types = info.get('event_types', [])
        event_types_str = ','.join(event_types) if event_types else 'N/A'
        
        file_obj.write(f"# IP: {ip_str} | {location} | {isp}\n")
        file_obj.write(f"#   Reason: {info.get('reason', 'Unknown')}\n")
        file_obj.write(f"#   Events: {info.get('event_count', 0)}\n")
        file_obj.write(f"#   EventTypes: {event_types_str}\n")
        file_obj.write(f"#   First: {first_seen} | ")
        file_obj.write(f"Last: {last_seen} | ")
        file_obj.write(f"Added: {date_added}\n")
        file_obj.write(f"#   Source: {info.get('source', 'automatic')}\n")
        file_obj.write(f"{ip_str}\n\n")
    
    def _format_timestamp(self, timestamp) -> str:
        """Format timestamp consistently."""
        if timestamp is None:
            return "Unknown"
        if isinstance(timestamp, datetime):
            return timestamp.strftime('%Y-%m-%d %H:%M')
        return str(timestamp) if isinstance(timestamp, str) else "Unknown"