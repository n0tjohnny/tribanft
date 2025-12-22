"""
TribanFT Blacklist Storage Adapter

Provides unified interface for blacklist storage supporting both file and SQLite backends.

This adapter enables seamless migration between storage systems without changing
consumer code. It maintains API compatibility with BlacklistWriter while adding
database support for improved performance at scale.

Key features:
- Transparent backend switching (file vs SQLite)
- Data integrity protection during writes
- Migration utilities from file to database
- Export/backup functionality
- Statistics aggregation

Use file backend for <10k IPs, database for larger deployments.

Author: TribanFT Project
License: GNU GPL v3
"""

import logging
from pathlib import Path
from typing import Dict, Set, Optional
from datetime import datetime
import ipaddress

from .database import BlacklistDatabase
from .blacklist_writer import BlacklistWriter


class BlacklistAdapter:
    """
    Storage adapter providing unified interface for file and database backends.
    
    Maintains backward compatibility with BlacklistWriter while enabling
    SQLite database for better performance and features.
    """
    
    def __init__(self, config, use_database: bool = True):
        """
        Initialize adapter with selected backend.

        Args:
            config: Configuration object with file paths
            use_database: If True, use SQLite; if False, use file backend
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.use_database = use_database

        # Always create file writer for sync capability
        self.file_writer = BlacklistWriter(config)

        if use_database:
            self.db = BlacklistDatabase(config.database_path)
            self.logger.info("Using SQLite backend for blacklist")
            if getattr(config, 'sync_to_file', True):
                self.logger.info("File sync ENABLED (database to/from file)")
        else:
            self.logger.warning("Using file backend for blacklist (database mode DISABLED)")
            self.logger.warning("   WARNING: If this is unexpected, check config.conf use_database setting")
    
    def read_blacklist(self, filename: str) -> Dict[str, Dict]:
        """
        Read blacklist from storage (file or database).
        
        Args:
            filename: File path (used to determine IP version for database queries)
            
        Returns:
            Dict mapping IP strings to metadata dictionaries
        """
        if self.use_database:
            # Extract IP version from filename
            ip_version = None
            if 'ipv4' in filename.lower():
                ip_version = 4
            elif 'ipv6' in filename.lower():
                ip_version = 6
            
            return self.db.get_all_ips(ip_version=ip_version)
        else:
            return self.file_writer.read_blacklist(filename)
    
    def write_blacklist(self, filename: str, ips_info: Dict[str, Dict], new_count: int = 0):
        """
        Write blacklist to storage with corruption protection.
        
        Validates data before write to prevent accidental data loss.
        Performs automatic backup before large modifications.
        
        Args:
            filename: Target file path
            ips_info: Dict of IP addresses with metadata
            new_count: Number of new IPs in this update
            
        Raises:
            ValueError: If write would cause significant data loss
        """
        if self.use_database:
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
                        f"Filtered {filtered_count} whitelisted IPs from database write"
                    )

            # Anti-corruption protection
            min_expected_ips = getattr(self.config, 'min_expected_ips', 1000)

            if len(ips_info) < min_expected_ips:
                stats = self.db.get_statistics()
                existing_count = stats.get('total_ips', 0)

                if existing_count > min_expected_ips and len(ips_info) < existing_count * 0.5:
                    loss = existing_count - len(ips_info)
                    loss_pct = 100 - (len(ips_info) / existing_count * 100)
                    
                    error_msg = (
                        f"CRITICAL PROTECTION TRIGGERED (DATABASE):\n"
                        f"   Current DB: {existing_count} IPs\n"
                        f"   Proposed write: {len(ips_info)} IPs\n"
                        f"   Data loss: {loss} IPs ({loss_pct:.1f}%)\n"
                        f"   Operation BLOCKED to prevent corruption"
                    )
                    self.logger.error(error_msg)
                    raise ValueError(
                        f"Database corruption prevented: "
                        f"Proposed {len(ips_info)} IPs would lose {loss} IPs"
                    )
            
            # Automatic backup before large changes
            if new_count > 100:
                self.db.backup()
            
            # Bulk add for performance
            added = self.db.bulk_add(ips_info)
            
            # Log statistics
            stats = self.db.get_statistics()
            self.logger.info(f"Database updated:")
            self.logger.info(f"   Total IPs: {stats['total_ips']} (+{new_count} new)")
            self.logger.info(f"   IPv4: {stats.get('ipv4', 0)} | IPv6: {stats.get('ipv6', 0)}")
            self.logger.info(f"   Total Events: {stats['total_events']}")
            
            with_geo = stats.get('with_geolocation', 0)
            if stats['total_ips'] > 0:
                geo_pct = (with_geo / stats['total_ips']) * 100
                self.logger.info(f"   With Geo: {with_geo} ({geo_pct:.1f}%)")
                
                # SYNC TO FILE WHEN ENABLED
                if getattr(self.config, 'sync_to_file', True):
                    self.logger.debug(f"Syncing {len(ips_info)} IPs to {filename}")
                    try:
                        self.file_writer.write_blacklist(filename, ips_info, new_count)
                        self.logger.debug(f"SUCCESS: File sync completed for {filename}")
                    except Exception as e:
                        self.logger.warning(f"WARNING: File sync failed: {e}")
        else:
            self.file_writer.write_blacklist(filename, ips_info, new_count)
    
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
        """
        Retrieve manually added IPs.

        Args:
            manual_blacklist_file: Path to manual blacklist file

        Returns:
            Set of IP address strings
        """
        if self.use_database:
            # Query IPs with source='manual'
            all_ips = self.db.get_all_ips()
            return {
                ip_str for ip_str, info in all_ips.items()
                if info.get('source') == 'manual'
            }
        else:
            return self.file_writer.get_manual_ips(manual_blacklist_file)
    
    def migrate_from_files(self):
        """
        Migrate existing file-based blacklists to SQLite database.
        
        Reads all blacklist files and imports them into database with
        proper source attribution. Idempotent - safe to run multiple times.
        
        Usage:
            adapter = BlacklistAdapter(config, use_database=True)
            adapter.migrate_from_files()
        """
        if not self.use_database:
            self.logger.warning("WARNING: Database not enabled, cannot migrate")
            return
        
        self.logger.info("Starting migration from files to SQLite...")
        
        files_to_migrate = [
            self.config.blacklist_ipv4_file,
            self.config.blacklist_ipv6_file,
            self.config.prelogin_bruteforce_file,
            self.config.manual_blacklist_file
        ]
        
        total_migrated = 0
        
        for filepath in files_to_migrate:
            path = Path(filepath)
            if not path.exists():
                self.logger.debug(f"Skipping non-existent: {filepath}")
                continue
            
            self.logger.info(f"Migrating: {path.name}")
            
            # Read using BlacklistWriter
            writer = BlacklistWriter(self.config)
            ips_info = writer.read_blacklist(str(path))
            
            if ips_info:
                # Determine source from filename
                source = 'automatic'
                if 'manual' in path.name:
                    source = 'manual'
                elif 'prelogin' in path.name:
                    source = 'prelogin'
                
                # Update source for all IPs from this file
                for ip_str, info in ips_info.items():
                    if not info.get('source') or info.get('source') == 'legacy':
                        info['source'] = source
                
                # Bulk add for performance
                added = self.db.bulk_add(ips_info)
                total_migrated += added
                
                self.logger.info(f"   Migrated {added} IPs from {path.name}")
        
        # Final statistics
        stats = self.db.get_statistics()
        self.logger.info(f"\n{'='*70}")
        self.logger.info("MIGRATION COMPLETED")
        self.logger.info(f"{'='*70}")
        self.logger.info(f"Total IPs migrated: {total_migrated}")
        self.logger.info(f"Database statistics:")
        self.logger.info(f"  Total IPs: {stats['total_ips']}")
        self.logger.info(f"  IPv4: {stats.get('ipv4', 0)} | IPv6: {stats.get('ipv6', 0)}")
        self.logger.info(f"  With geolocation: {stats.get('with_geolocation', 0)}")
        self.logger.info(f"  Total events: {stats['total_events']}")
        self.logger.info(f"\nBy source:")
        for source, count in stats.get('by_source', {}).items():
            self.logger.info(f"  {source}: {count}")
        self.logger.info(f"{'='*70}\n")
    
    def export_to_file(self, output_file: str, ip_version: int = 4, create_backup: bool = False):
        """
        Export database to text file for backup or compatibility.
        
        Args:
            output_file: Destination file path
            ip_version: 4 for IPv4, 6 for IPv6
            create_backup: Create timestamped backup before overwriting
        """
        if not self.use_database:
            self.logger.warning("WARNING: Not using database, nothing to export")
            return
        
        self.logger.info(f"Exporting IPv{ip_version} to {output_file}")
        
        # Create backup if requested
        if create_backup:
            self.create_backup(Path(output_file))
        
        ips_info = self.db.get_all_ips(ip_version=ip_version)
        
        # Use BlacklistWriter for formatting
        writer = BlacklistWriter(self.config)
        writer.write_blacklist(output_file, ips_info, len(ips_info))
        
        self.logger.info(f"   Exported {len(ips_info)} IPs")
    
    def create_backup(self, file_path: Path) -> Optional[Path]:
        """
        Create timestamped backup of file.

        Args:
            file_path: Path to file to backup

        Returns:
            Path to backup file, or None if source doesn't exist
        """
        if not file_path.exists():
            return None

        backup_dir = self.config.get_backup_dir()
        backup_dir.mkdir(parents=True, exist_ok=True)
        
        from datetime import datetime
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_path = backup_dir / f"{file_path.name}.backup.{timestamp}"
        
        import shutil
        shutil.copy2(file_path, backup_path)
        self.logger.info(f"Backup: {backup_path.name}")
        
        # Keep only last 20 backups
        backups = sorted(backup_dir.glob(f"{file_path.name}.backup.*"))
        for old_backup in backups[:-20]:
            old_backup.unlink()
            self.logger.debug(f"Removed old backup: {old_backup.name}")
        
        return backup_path
    
    def print_stats(self):
        """Print database statistics in user-friendly format."""
        stats = self.get_statistics()
        
        if not self.use_database:
            self.logger.info("\n" + "="*70)
            self.logger.info("FILE STATISTICS")
            self.logger.info("="*70)
            self.logger.info(f"Total IPs: {stats.get('total_ips', 0)}")
            self.logger.info(f"IPv4: {stats.get('ipv4', 0)}")
            self.logger.info(f"IPv6: {stats.get('ipv6', 0)}")
            self.logger.info("="*70)
            return
        
        all_ips = self.db.get_all_ips()
        with_first = sum(1 for info in all_ips.values() if info.get('first_seen'))
        with_last = sum(1 for info in all_ips.values() if info.get('last_seen'))
        with_added = sum(1 for info in all_ips.values() if info.get('date_added'))
        
        self.logger.info("\n" + "="*70)
        self.logger.info("DATABASE STATISTICS")
        self.logger.info("="*70)
        self.logger.info(f"Total IPs: {stats['total_ips']}")
        self.logger.info(f"IPv4: {stats['ipv4']}")
        
        if stats.get('ipv6', 0) > 0:
            self.logger.info(f"IPv6: {stats['ipv6']}")
        
        self.logger.info(f"With Geolocation: {stats.get('with_geolocation', 0)}")
        self.logger.info(f"Total Events: {stats['total_events']}")
        
        if stats['total_ips'] > 0:
            self.logger.info(f"\nTimestamp Coverage:")
            self.logger.info(f"  With first_seen: {with_first} ({with_first/stats['total_ips']*100:.1f}%)")
            self.logger.info(f"  With last_seen: {with_last} ({with_last/stats['total_ips']*100:.1f}%)")
            self.logger.info(f"  With date_added: {with_added} ({with_added/stats['total_ips']*100:.1f}%)")
        
        # Show by source if available
        by_source = stats.get('by_source', {})
        if by_source:
            self.logger.info(f"\nBy Source:")
            for source, count in by_source.items():
                self.logger.info(f"  {source}: {count}")
        
        self.logger.info("="*70)
    
    def get_statistics(self) -> Dict:
        """
        Get storage statistics.
        
        Returns:
            Dict with IP counts and metadata statistics
        """
        if self.use_database:
            return self.db.get_statistics()
        else:
            # Calculate basic stats for file backend
            ipv4 = self.file_writer.read_blacklist(self.config.blacklist_ipv4_file)
            ipv6 = self.file_writer.read_blacklist(self.config.blacklist_ipv6_file)
            
            return {
                'total_ips': len(ipv4) + len(ipv6),
                'ipv4': len(ipv4),
                'ipv6': len(ipv6),
                'backend': 'file'
            }