"""
TribanFT Backup Manager

Rotating backup system for critical files with timestamp-based versioning.

Provides:
- Timestamped backups before file modifications
- Automatic backup pruning based on age and count
- Backup listing and restoration capabilities
- Corruption recovery support

Backup naming format: {original_filename}_YYYYMMDD_HHMMSS.backup
Storage location: {state_dir}/backups/

Author: TribanFT Project
License: GNU GPL v3
"""

import logging
import shutil
import gzip
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Optional, Tuple
import os

from .file_lock import file_lock, FileLockError


class BackupManager:
    """
    Manages rotating backups for critical files.
    
    Features:
    - Timestamped backup creation
    - Automatic pruning (retention policy)
    - Backup restoration
    - Backup enumeration
    """
    
    def __init__(self, backup_dir: Path, retention_days: int = 7, min_keep: int = 5, compress_age_days: int = 1, enabled: bool = True, interval_days: int = 1):
        """
        Initialize backup manager.

        Args:
            backup_dir: Directory to store backups
            retention_days: Maximum age of backups to keep (default: 7)
            min_keep: Minimum number of backups to keep regardless of age (default: 5)
            compress_age_days: Age in days after which to compress backups (default: 1)
            enabled: Enable automatic backups (default: True)
            interval_days: Backup interval in days (default: 1, 0 = every run)
        """
        self.backup_dir = Path(backup_dir)
        self.retention_days = retention_days
        self.min_keep = min_keep
        self.compress_age_days = compress_age_days
        self.enabled = enabled
        self.interval_days = interval_days
        self.logger = logging.getLogger(__name__)

        # In-memory cache to prevent duplicate backups in same process run
        # Maps filepath -> last backup timestamp
        self._backup_cache = {}

        # Ensure backup directory exists
        self.backup_dir.mkdir(parents=True, exist_ok=True)
    
    def create_backup(self, filepath: str) -> Optional[Path]:
        """
        Create timestamped backup of a file.

        Prevents duplicate backups within the same process run by caching
        backup timestamps in memory.

        Args:
            filepath: Path to file to backup

        Returns:
            Path to created backup file, or None if backup failed or skipped
        """
        # Check if backups are enabled
        if not self.enabled:
            self.logger.debug(f"Backups disabled - skipping backup for {filepath}")
            return None

        source = Path(filepath)

        # Skip if source doesn't exist
        if not source.exists():
            self.logger.debug(f"Skipping backup - file doesn't exist: {filepath}")
            return None

        # Check in-memory cache to prevent duplicate backups in same run
        now = datetime.now()
        cache_key = str(source.resolve())

        if cache_key in self._backup_cache:
            last_backup_time = self._backup_cache[cache_key]
            time_since = (now - last_backup_time).total_seconds()

            # Skip if backup was created less than 5 minutes ago in this run
            if time_since < 300:  # 5 minutes
                self.logger.debug(
                    f"Skipping backup - already created {time_since:.0f}s ago "
                    f"in this run: {source.name}"
                )
                return None

        # Generate timestamped backup filename
        timestamp = now.strftime('%Y%m%d_%H%M%S')
        backup_name = f"{source.name}_{timestamp}.backup"
        backup_path = self.backup_dir / backup_name

        # CRITICAL FIX #36: Lock source file during backup to prevent
        # concurrent modifications causing inconsistent backup
        lock_path = source.parent / f".{source.name}.lock"

        try:
            with file_lock(lock_path, timeout=10, description=f"backup {source.name}"):
                # File locked - safe to copy atomically
                shutil.copy2(source, backup_path)

                # Update cache to prevent duplicate backups
                self._backup_cache[cache_key] = now

                self.logger.info(f"Created backup: {backup_name}")
                return backup_path

        except FileLockError:
            self.logger.warning(
                f"Could not acquire lock for backup (file in use): {filepath}"
            )
            return None
        except Exception as e:
            self.logger.error(f"Backup failed for {filepath}: {e}")
            return None
    
    def compress_backup(self, backup_path: Path) -> Optional[Path]:
        """
        Compress a backup file using gzip.

        Args:
            backup_path: Path to uncompressed backup file

        Returns:
            Path to compressed file, or None if compression failed
        """
        if not backup_path.exists():
            self.logger.warning(f"Cannot compress - file doesn't exist: {backup_path}")
            return None

        # Skip if already compressed
        if backup_path.suffix == '.gz':
            return backup_path

        compressed_path = backup_path.with_suffix(backup_path.suffix + '.gz')

        try:
            # Compress file
            with open(backup_path, 'rb') as f_in:
                with gzip.open(compressed_path, 'wb', compresslevel=9) as f_out:
                    shutil.copyfileobj(f_in, f_out)

            # Get size reduction
            original_size = backup_path.stat().st_size
            compressed_size = compressed_path.stat().st_size
            reduction = (1 - compressed_size / original_size) * 100 if original_size > 0 else 0

            # Remove original uncompressed file
            backup_path.unlink()

            self.logger.info(
                f"Compressed {backup_path.name}: "
                f"{original_size:,} → {compressed_size:,} bytes "
                f"({reduction:.1f}% reduction)"
            )
            return compressed_path
        except Exception as e:
            self.logger.error(f"Compression failed for {backup_path}: {e}")
            # Clean up partial compressed file if it exists
            if compressed_path.exists():
                compressed_path.unlink()
            return None

    def list_backups(self, filename: str) -> List[Tuple[datetime, Path]]:
        """
        List all backups for a specific file (compressed and uncompressed).

        Args:
            filename: Original filename (without path) to find backups for

        Returns:
            List of (timestamp, path) tuples, sorted newest first
        """
        backups = []

        # Search for both .backup and .backup.gz files
        for pattern in [f"{filename}_*.backup", f"{filename}_*.backup.gz"]:
            for backup_file in self.backup_dir.glob(pattern):
                try:
                    # Extract timestamp from filename
                    # Format: {filename}_YYYYMMDD_HHMMSS.backup[.gz]
                    name = backup_file.stem
                    if name.endswith('.backup'):
                        name = name[:-7]  # Remove .backup

                    parts = name.rsplit('_', 2)
                    if len(parts) >= 3:
                        date_str = parts[-2]
                        time_str = parts[-1]
                        timestamp = datetime.strptime(f"{date_str}_{time_str}", '%Y%m%d_%H%M%S')
                        backups.append((timestamp, backup_file))
                except Exception as e:
                    self.logger.warning(f"Failed to parse backup timestamp for {backup_file}: {e}")

        # Sort by timestamp, newest first
        backups.sort(key=lambda x: x[0], reverse=True)
        return backups
    
    def restore_backup(self, backup_path: Path, target_path: Path) -> bool:
        """
        Restore a file from backup (decompresses if needed).

        Args:
            backup_path: Path to backup file (can be compressed)
            target_path: Destination path for restored file

        Returns:
            True if restoration successful, False otherwise
        """
        if not backup_path.exists():
            self.logger.error(f"Backup file not found: {backup_path}")
            return False

        try:
            # Create backup of current file before restoring
            if target_path.exists():
                self.create_backup(str(target_path))

            # Restore from backup (decompress if needed)
            if backup_path.suffix == '.gz':
                # Decompress gzip file
                with gzip.open(backup_path, 'rb') as f_in:
                    with open(target_path, 'wb') as f_out:
                        shutil.copyfileobj(f_in, f_out)
                self.logger.info(f"Restored {target_path} from compressed backup {backup_path}")
            else:
                # Direct copy for uncompressed backups
                shutil.copy2(backup_path, target_path)
                self.logger.info(f"Restored {target_path} from {backup_path}")
            return True
        except Exception as e:
            self.logger.error(f"Restoration failed: {e}")
            return False
    
    def restore_latest_backup(self, filename: str, target_path: Path) -> bool:
        """
        Restore the most recent backup of a file.
        
        Args:
            filename: Original filename to restore
            target_path: Destination path for restored file
            
        Returns:
            True if restoration successful, False otherwise
        """
        backups = self.list_backups(filename)
        
        if not backups:
            self.logger.error(f"No backups found for {filename}")
            return False
        
        # Restore from newest backup
        _, backup_path = backups[0]
        return self.restore_backup(backup_path, target_path)
    
    def compress_old_backups(self) -> Tuple[int, int]:
        """
        Compress uncompressed backups older than compress_age_days.

        Returns:
            Tuple of (compressed_count, total_bytes_saved)
        """
        compress_cutoff = datetime.now() - timedelta(days=self.compress_age_days)
        compressed_count = 0
        total_bytes_saved = 0

        # Find all uncompressed backups
        for backup_file in self.backup_dir.glob('*.backup'):
            try:
                # Extract timestamp
                parts = backup_file.stem.rsplit('_', 2)
                if len(parts) >= 3:
                    date_str = parts[-2]
                    time_str = parts[-1]
                    timestamp = datetime.strptime(f"{date_str}_{time_str}", '%Y%m%d_%H%M%S')

                    # Compress if older than threshold
                    if timestamp < compress_cutoff:
                        original_size = backup_file.stat().st_size
                        compressed_path = self.compress_backup(backup_file)
                        if compressed_path:
                            compressed_size = compressed_path.stat().st_size
                            total_bytes_saved += (original_size - compressed_size)
                            compressed_count += 1
            except Exception as e:
                self.logger.warning(f"Failed to process backup {backup_file}: {e}")

        if compressed_count > 0:
            self.logger.info(
                f"Compressed {compressed_count} old backups, "
                f"saved {total_bytes_saved:,} bytes ({total_bytes_saved / 1024 / 1024:.1f} MB)"
            )

        return compressed_count, total_bytes_saved

    def prune_old_backups(self) -> Tuple[int, int]:
        """
        Compress old backups, then remove very old ones based on retention policy.

        Process:
        1. Compress uncompressed backups older than compress_age_days
        2. Delete compressed backups older than retention_days (keeping min_keep)

        Keeps backups that are:
        - Younger than retention_days, OR
        - Among the min_keep most recent backups

        Returns:
            Tuple of (removed_count, kept_count)
        """
        # Step 1: Compress old uncompressed backups
        self.compress_old_backups()

        # Step 2: Remove very old backups
        cutoff_date = datetime.now() - timedelta(days=self.retention_days)
        removed_count = 0
        kept_count = 0

        # Group backups by original filename
        backup_groups = {}
        for pattern in ['*.backup', '*.backup.gz']:
            for backup_file in self.backup_dir.glob(pattern):
                try:
                    # Extract original filename (everything before the timestamp)
                    # Format: {filename}_YYYYMMDD_HHMMSS.backup[.gz]
                    name = backup_file.stem
                    if name.endswith('.backup'):
                        name = name[:-7]  # Remove .backup

                    parts = name.rsplit('_', 2)
                    if len(parts) >= 3:
                        original_name = '_'.join(parts[:-2])
                        date_str = parts[-2]
                        time_str = parts[-1]
                        timestamp = datetime.strptime(f"{date_str}_{time_str}", '%Y%m%d_%H%M%S')

                        if original_name not in backup_groups:
                            backup_groups[original_name] = []
                        backup_groups[original_name].append((timestamp, backup_file))
                except Exception as e:
                    self.logger.warning(f"Failed to parse backup {backup_file}: {e}")

        # Process each group
        for original_name, backups in backup_groups.items():
            # Sort by timestamp, newest first
            backups.sort(key=lambda x: x[0], reverse=True)

            for idx, (timestamp, backup_file) in enumerate(backups):
                # Keep if:
                # 1. Within retention period, OR
                # 2. Among the min_keep most recent backups
                if timestamp >= cutoff_date or idx < self.min_keep:
                    kept_count += 1
                else:
                    try:
                        backup_file.unlink()
                        self.logger.debug(f"Pruned old backup: {backup_file}")
                        removed_count += 1
                    except Exception as e:
                        self.logger.warning(f"Failed to remove backup {backup_file}: {e}")

        if removed_count > 0:
            self.logger.info(f"Pruned {removed_count} old backups, kept {kept_count}")

        return removed_count, kept_count
    
    def get_backup_info(self, filename: str) -> dict:
        """
        Get information about backups for a file.
        
        Args:
            filename: Original filename to query
            
        Returns:
            Dictionary with backup statistics
        """
        backups = self.list_backups(filename)
        
        if not backups:
            return {
                'count': 0,
                'newest': None,
                'oldest': None,
                'total_size': 0
            }
        
        total_size = sum(b[1].stat().st_size for b in backups if b[1].exists())
        
        return {
            'count': len(backups),
            'newest': backups[0][0] if len(backups) > 0 else None,
            'oldest': backups[-1][0] if len(backups) > 0 else None,
            'total_size': total_size
        }


def get_backup_manager() -> BackupManager:
    """
    Get BackupManager instance using application configuration.

    Returns:
        BackupManager configured with application settings
    """
    from ..config import get_config

    config = get_config()
    backup_dir = config.get_backup_dir()

    return BackupManager(
        backup_dir=backup_dir,
        retention_days=config.backup_retention_days,
        min_keep=config.backup_min_keep,
        compress_age_days=config.backup_compress_age_days,
        enabled=config.backup_enabled,
        interval_days=config.backup_interval_days
    )
