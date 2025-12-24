"""
TribanFT Migration Assistant

Helps users migrate from cron-based setup to systemd real-time monitoring.

Author: TribanFT Project
License: GNU GPL v3
"""

import os
import subprocess
import logging
from pathlib import Path
from typing import List, Tuple, Optional


def detect_old_setup() -> List[str]:
    """
    Detect legacy cron-based tribanFT setup.

    Returns:
        List of warnings about detected old setup
    """
    warnings = []

    # Check for cron jobs
    cron_locations = [
        '/etc/cron.d/tribanft',
        '/etc/cron.hourly/tribanft',
        '/var/spool/cron/crontabs/root',  # User crontab
    ]

    for cron_file in cron_locations:
        if os.path.exists(cron_file):
            # Check if tribanft is mentioned
            try:
                with open(cron_file, 'r') as f:
                    content = f.read()
                    if 'tribanft' in content:
                        warnings.append(f"Legacy cron job found: {cron_file}")
            except PermissionError:
                pass

    # Check user crontab
    try:
        result = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
        if result.returncode == 0 and 'tribanft' in result.stdout:
            warnings.append("Legacy cron job found in user crontab")
    except:
        pass

    return warnings


def show_migration_guide():
    """
    Display migration guide to user.
    """
    print("=" * 80)
    print("MIGRATION TO REAL-TIME MONITORING")
    print("=" * 80)
    print()
    print("TribanFT now uses real-time log monitoring instead of periodic cron jobs.")
    print()
    print("Benefits:")
    print("  - Immediate detection (<2s lag vs. 5 minutes)")
    print("  - Lower resource usage (event-driven vs. polling)")
    print("  - Automatic file rotation handling")
    print()
    print("Migration Steps:")
    print()
    print("1. Disable old cron job:")
    print("   sudo rm /etc/cron.d/tribanft")
    print("   crontab -e  # Remove tribanft entries")
    print()
    print("2. Install systemd service:")
    print("   sudo cp systemd/tribanft.service /etc/systemd/system/")
    print("   sudo systemctl daemon-reload")
    print("   sudo systemctl enable tribanft")
    print("   sudo systemctl start tribanft")
    print()
    print("3. Verify it's working:")
    print("   sudo systemctl status tribanft")
    print("   sudo journalctl -u tribanft -f")
    print()
    print("=" * 80)


def check_and_warn_migration(logger: logging.Logger):
    """
    Check for old setup and warn user about migration.

    Args:
        logger: Logger instance for warnings
    """
    warnings = detect_old_setup()

    if warnings:
        logger.warning("=" * 80)
        logger.warning("MIGRATION REQUIRED")
        logger.warning("=" * 80)

        for warning in warnings:
            logger.warning(f"  {warning}")

        logger.warning("")
        logger.warning("TribanFT now uses real-time monitoring (systemd service).")
        logger.warning("Your cron-based setup is deprecated.")
        logger.warning("")
        logger.warning("To migrate, run:")
        logger.warning("  tribanft --migrate")
        logger.warning("")
        logger.warning("Or see: docs/MIGRATION.md")
        logger.warning("=" * 80)


def migrate_to_systemd(dry_run: bool = False) -> bool:
    """
    Migrate from cron to systemd.

    Args:
        dry_run: If True, only show what would be done

    Returns:
        True if successful, False otherwise
    """
    logger = logging.getLogger(__name__)

    print()
    print("=" * 80)
    print("MIGRATING TO SYSTEMD")
    print("=" * 80)
    print()

    # Step 1: Detect old cron jobs
    warnings = detect_old_setup()

    if not warnings:
        print("No old cron jobs detected.")
        print("Nothing to migrate.")
        return True

    print("Detected legacy setup:")
    for warning in warnings:
        print(f"  - {warning}")
    print()

    # Step 2: Offer to disable cron
    if not dry_run:
        response = input("Disable cron jobs? [y/N]: ")
        if response.lower() == 'y':
            # Remove cron file
            cron_file = '/etc/cron.d/tribanft'
            if os.path.exists(cron_file):
                try:
                    os.remove(cron_file)
                    print(f"  Removed: {cron_file}")
                except Exception as e:
                    print(f"  ERROR: Failed to remove {cron_file}: {e}")
                    print(f"  Run manually: sudo rm {cron_file}")
    else:
        print("[DRY RUN] Would disable cron jobs")

    # Step 3: Install systemd service
    print()
    print("To install systemd service, run:")
    print("  sudo cp systemd/tribanft.service /etc/systemd/system/")
    print("  sudo systemctl daemon-reload")
    print("  sudo systemctl enable tribanft")
    print("  sudo systemctl start tribanft")
    print()

    # Step 4: Show verification
    print("Verify with:")
    print("  sudo systemctl status tribanft")
    print()
    print("=" * 80)

    return True
