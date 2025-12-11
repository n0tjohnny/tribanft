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
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Optional, Tuple
import os


class BackupManager:
    """
    Manages rotating backups for critical files.
    
    Features:
    - Timestamped backup creation
    - Automatic pruning (retention policy)
    - Backup restoration
    - Backup enumeration
    """
    
    def __init__(self, backup_dir: Path, retention_days: int = 7, min_keep: int = 5):
        """
        Initialize backup manager.
        
        Args:
            backup_dir: Directory to store backups
            retention_days: Maximum age of backups to keep (default: 7)
            min_keep: Minimum number of backups to keep regardless of age (default: 5)
        """
        self.backup_dir = Path(backup_dir)
        self.retention_days = retention_days
        self.min_keep = min_keep
        self.logger = logging.getLogger(__name__)
        
        # Ensure backup directory exists
        self.backup_dir.mkdir(parents=True, exist_ok=True)
    
    def create_backup(self, filepath: str) -> Optional[Path]:
        """
        Create timestamped backup of a file.
        
        Args:
            filepath: Path to file to backup
            
        Returns:
            Path to created backup file, or None if backup failed
        """
        source = Path(filepath)
        
        # Skip if source doesn't exist
        if not source.exists():
            self.logger.debug(f"Skipping backup - file doesn't exist: {filepath}")
            return None
        
        # Generate timestamped backup filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_name = f"{source.name}_{timestamp}.backup"
        backup_path = self.backup_dir / backup_name
        
        try:
            # Copy file to backup location
            shutil.copy2(source, backup_path)
            self.logger.info(f"✅ Created backup: {backup_path}")
            return backup_path
        except Exception as e:
            self.logger.error(f"❌ Backup failed for {filepath}: {e}")
            return None
    
    def list_backups(self, filename: str) -> List[Tuple[datetime, Path]]:
        """
        List all backups for a specific file.
        
        Args:
            filename: Original filename (without path) to find backups for
            
        Returns:
            List of (timestamp, path) tuples, sorted newest first
        """
        backups = []
        pattern = f"{filename}_*.backup"
        
        for backup_file in self.backup_dir.glob(pattern):
            try:
                # Extract timestamp from filename
                # Format: {filename}_YYYYMMDD_HHMMSS.backup
                parts = backup_file.stem.rsplit('_', 2)
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
        Restore a file from backup.
        
        Args:
            backup_path: Path to backup file
            target_path: Destination path for restored file
            
        Returns:
            True if restoration successful, False otherwise
        """
        if not backup_path.exists():
            self.logger.error(f"❌ Backup file not found: {backup_path}")
            return False
        
        try:
            # Create backup of current file before restoring
            if target_path.exists():
                self.create_backup(str(target_path))
            
            # Restore from backup
            shutil.copy2(backup_path, target_path)
            self.logger.info(f"✅ Restored {target_path} from {backup_path}")
            return True
        except Exception as e:
            self.logger.error(f"❌ Restoration failed: {e}")
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
            self.logger.error(f"❌ No backups found for {filename}")
            return False
        
        # Restore from newest backup
        _, backup_path = backups[0]
        return self.restore_backup(backup_path, target_path)
    
    def prune_old_backups(self) -> Tuple[int, int]:
        """
        Remove old backups based on retention policy.
        
        Keeps backups that are:
        - Younger than retention_days, OR
        - Among the min_keep most recent backups
        
        Returns:
            Tuple of (removed_count, kept_count)
        """
        cutoff_date = datetime.now() - timedelta(days=self.retention_days)
        removed_count = 0
        kept_count = 0
        
        # Group backups by original filename
        backup_groups = {}
        for backup_file in self.backup_dir.glob('*.backup'):
            try:
                # Extract original filename (everything before the timestamp)
                # Format: {filename}_YYYYMMDD_HHMMSS.backup
                parts = backup_file.stem.rsplit('_', 2)
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
            self.logger.info(f"🗑️  Pruned {removed_count} old backups, kept {kept_count}")
        
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
        min_keep=config.backup_min_keep
    )
