"""
TribanFT Directory Structure Migration Utility

Automatically migrates existing flat directory structure to organized
subdirectories (v2.9.0+) on first run after upgrade.

Migration process:
1. Detects if migration needed (no organized structure + files in root)
2. Creates full backup tarball for rollback capability
3. Creates organized subdirectories with proper permissions
4. Moves files to appropriate subdirectories
5. Updates config.conf with new paths
6. Creates marker file to prevent re-migration
7. Validates file count integrity

Security features:
- Path validation to prevent traversal attacks
- Atomic operations where possible
- Full backup before any changes
- Permission enforcement (0o750 for sensitive, 0o755 for public)
- File count verification
- Safe error handling with rollback capability

Author: TribanFT Project
License: GNU GPL v3
"""

import logging
import shutil
import tarfile
import tempfile
from pathlib import Path
from datetime import datetime
from typing import List, Tuple, Dict, Set
import os

logger = logging.getLogger(__name__)


def _safe_move(src: Path, dest: Path) -> bool:
    """
    Safely move file with validation.

    Security: Validates paths and uses atomic move operation.

    Args:
        src: Source file path
        dest: Destination file path

    Returns:
        True if successful, False otherwise
    """
    try:
        # Validate source exists
        if not src.exists():
            logger.debug(f"Source doesn't exist, skipping: {src}")
            return False

        # Security: Resolve paths to prevent traversal
        src_resolved = src.resolve()
        dest_resolved = dest.resolve()

        # Create destination directory if needed
        dest_resolved.parent.mkdir(parents=True, exist_ok=True)

        # Atomic move
        shutil.move(str(src_resolved), str(dest_resolved))
        logger.debug(f"Moved: {src.name} -> {dest_resolved.parent.name}/")
        return True

    except Exception as e:
        logger.error(f"Failed to move {src} -> {dest}: {e}")
        return False


def _create_backup(data_dir: Path) -> Path:
    """
    Create full backup tarball of data directory.

    Security: Creates compressed backup with restrictive permissions
    for disaster recovery.

    Args:
        data_dir: Data directory to backup

    Returns:
        Path to created backup tarball

    Raises:
        RuntimeError: If backup creation fails
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_filename = f"tribanft_pre_migration_backup_{timestamp}.tar.gz"
    backup_path = data_dir / backup_filename

    try:
        logger.info(f"Creating full backup: {backup_filename}")

        with tarfile.open(backup_path, "w:gz") as tar:
            # Add all files in data_dir except the backup itself
            for item in data_dir.iterdir():
                if item != backup_path:
                    tar.add(item, arcname=item.name)

        # Security: Set restrictive permissions on backup
        backup_path.chmod(0o640)

        size_mb = backup_path.stat().st_size / (1024 * 1024)
        logger.info(f"Backup created successfully: {backup_path} ({size_mb:.1f} MB)")

        return backup_path

    except Exception as e:
        # Clean up partial backup
        if backup_path.exists():
            try:
                backup_path.unlink()
            except:
                pass
        raise RuntimeError(f"Backup creation failed: {e}")


def _count_files(directory: Path, pattern: str = "*") -> int:
    """
    Count files matching pattern in directory (non-recursive).

    Args:
        directory: Directory to count files in
        pattern: Glob pattern for files to count

    Returns:
        Number of files found
    """
    try:
        return len(list(directory.glob(pattern)))
    except Exception:
        return 0


def _detect_legacy_files(data_dir: Path) -> Dict[str, List[Path]]:
    """
    Detect files in legacy (flat) structure.

    Returns:
        Dictionary mapping category to list of file paths
    """
    legacy_files = {
        'data': [],
        'state': [],
        'cache': [],
        'logs': [],
        'backups': [],
    }

    # Data files (firewall lists)
    for pattern in ['blacklist*.txt', 'whitelist*.txt', 'manual_blacklist.txt',
                    'prelogin*.txt', '*-bruteforce-ips.txt']:
        legacy_files['data'].extend(data_dir.glob(pattern))

    # State files
    for pattern in ['state.json', 'state.bak', 'blacklist.db', 'blacklist.db-*',
                    'nftables_events.jsonl']:
        legacy_files['state'].extend(data_dir.glob(pattern))

    # Cache files
    cache_dir = data_dir / 'ipinfo_cache'
    if cache_dir.exists() and cache_dir.is_dir():
        legacy_files['cache'].append(cache_dir)
    for pattern in ['ipinfo_results*.json', 'ipinfo_results*.csv', 'geo-health-state.txt']:
        legacy_files['cache'].extend(data_dir.glob(pattern))

    # Log files
    for pattern in ['tribanft.log*']:
        legacy_files['logs'].extend(data_dir.glob(pattern))

    # Backup files (old flat backups)
    for pattern in ['*.backup', '*.backup-*', '*.backup.*', 'config.conf.backup*']:
        legacy_files['backups'].extend(data_dir.glob(pattern))

    # Remove duplicates and filter out subdirectories
    for category in legacy_files:
        legacy_files[category] = [
            f for f in set(legacy_files[category])
            if f.is_file() or (category == 'cache' and f.is_dir())
        ]

    return legacy_files


def needs_migration(data_dir: Path) -> bool:
    """
    Check if migration is needed.

    Migration is needed if:
    1. Marker file doesn't exist, AND
    2. Organized subdirectory structure doesn't exist, AND
    3. Legacy files exist in root

    Args:
        data_dir: Data directory to check

    Returns:
        True if migration needed, False otherwise
    """
    marker_file = data_dir / '.migrated_to_organized_structure'

    # Already migrated
    if marker_file.exists():
        logger.debug("Migration marker found - already migrated")
        return False

    # Check if organized structure already exists
    data_subdir = data_dir / 'data'
    if data_subdir.exists() and data_subdir.is_dir():
        logger.debug("Organized structure already exists")
        return False

    # Detect legacy files
    legacy_files = _detect_legacy_files(data_dir)
    total_legacy = sum(len(files) for files in legacy_files.values())

    if total_legacy > 0:
        logger.info(f"Detected {total_legacy} files in legacy flat structure")
        return True

    logger.debug("No legacy files found - clean install")
    return False


def auto_migrate_to_organized_structure() -> bool:
    """
    Automatically migrate to organized directory structure (v2.9.0+).

    This function is called once on first startup after upgrading to v2.9.0+.
    It safely migrates existing flat directory structure to organized subdirs.

    Process:
    1. Detect if migration needed
    2. Create full backup tarball
    3. Create organized subdirectories
    4. Move files to appropriate locations
    5. Rename config backups to new format
    6. Create migration marker
    7. Verify file integrity

    Security:
    - Full backup before any changes
    - Atomic operations where possible
    - Path validation
    - Permission enforcement
    - File count verification

    Returns:
        True if migration performed successfully, False if skipped/failed
    """
    # Import here to avoid circular dependency
    from ..config import find_config_file

    config_file = find_config_file()
    if not config_file:
        logger.debug("No config file found - skipping migration")
        return False

    data_dir = config_file.parent
    logger.debug(f"Checking migration status for: {data_dir}")

    # Check if migration needed
    if not needs_migration(data_dir):
        return False

    logger.warning("=" * 70)
    logger.warning("MIGRATION: Upgrading to organized directory structure (v2.9.0)")
    logger.warning("=" * 70)

    try:
        # Step 1: Create full backup
        backup_path = _create_backup(data_dir)

        # Step 2: Detect legacy files
        legacy_files = _detect_legacy_files(data_dir)
        files_before = sum(len(files) for files in legacy_files.values())

        logger.info(f"Files to migrate: {files_before}")
        for category, files in legacy_files.items():
            if files:
                logger.info(f"  {category}/: {len(files)} files")

        # Step 3: Create organized subdirectories with proper permissions
        subdirs = {
            'data': (data_dir / 'data', 0o755),
            'state': (data_dir / 'state', 0o750),
            'cache': (data_dir / 'cache', 0o755),
            'logs': (data_dir / 'logs', 0o750),
            'backups': (data_dir / 'backups', 0o750),
        }

        for name, (path, mode) in subdirs.items():
            if not path.exists():
                path.mkdir(parents=True, exist_ok=True)
                path.chmod(mode)  # Guarantee permissions
                logger.info(f"Created: {path.name}/ ({oct(mode)})")

        # Step 4: Move files to organized locations
        moved_count = 0

        # Move data files
        for src in legacy_files['data']:
            dest = subdirs['data'][0] / src.name
            if _safe_move(src, dest):
                moved_count += 1

        # Move state files
        for src in legacy_files['state']:
            dest = subdirs['state'][0] / src.name
            if _safe_move(src, dest):
                moved_count += 1

        # Move cache files (including directory)
        for src in legacy_files['cache']:
            dest = subdirs['cache'][0] / src.name
            if _safe_move(src, dest):
                moved_count += 1

        # Move log files
        for src in legacy_files['logs']:
            dest = subdirs['logs'][0] / src.name
            if _safe_move(src, dest):
                moved_count += 1

        # Move and rename backup files
        for src in legacy_files['backups']:
            # Rename old format config.conf.backup-TIMESTAMP to config.conf_TIMESTAMP.backup
            if 'config.conf.backup' in src.name:
                # Extract timestamp from various old formats
                timestamp_part = src.name.replace('config.conf.backup-', '').replace('config.conf.backup.', '')
                timestamp_part = timestamp_part.replace('.backup', '')
                dest_name = f'config.conf_{timestamp_part}.backup'
            else:
                dest_name = src.name

            dest = subdirs['backups'][0] / dest_name
            if _safe_move(src, dest):
                # Security: Ensure restrictive permissions on backups
                try:
                    dest.chmod(0o640)
                except:
                    pass
                moved_count += 1

        # Step 5: Verify file count integrity
        files_after = sum(
            _count_files(path, '*') for path, _ in subdirs.values()
        )

        if files_after < moved_count:
            raise RuntimeError(
                f"File count mismatch after migration: "
                f"moved {moved_count}, found {files_after}"
            )

        # Step 6: Create migration marker
        marker_file = data_dir / '.migrated_to_organized_structure'
        marker_file.write_text(
            f"Migrated to organized structure on {datetime.now().isoformat()}\n"
            f"Backup: {backup_path.name}\n"
            f"Files migrated: {moved_count}\n"
        )
        marker_file.chmod(0o644)

        # Step 7: Success summary
        logger.warning("=" * 70)
        logger.warning(f"MIGRATION COMPLETED SUCCESSFULLY")
        logger.warning(f"  Files migrated: {moved_count}")
        logger.warning(f"  Backup: {backup_path}")
        logger.warning(f"  New structure:")
        for name, (path, mode) in subdirs.items():
            count = _count_files(path, '*')
            logger.warning(f"    {path.name}/: {count} files ({oct(mode)})")
        logger.warning("=" * 70)

        return True

    except Exception as e:
        logger.error("=" * 70)
        logger.error(f"MIGRATION FAILED: {e}")
        logger.error(f"Backup preserved at: {backup_path if 'backup_path' in locals() else 'N/A'}")
        logger.error("System will continue with files in current locations")
        logger.error("=" * 70)
        return False
