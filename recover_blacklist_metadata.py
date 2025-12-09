#!/usr/bin/env python3
"""
recover_blacklist_metadata.py

Syncs database to blacklist_ipv4.txt file when using SQLite backend.
Creates automatic backups in /root/backup/lists before modifying files.
"""

import sys
import os
import argparse
import logging
import shutil
from pathlib import Path
from datetime import datetime

sys.path.insert(0, '/root/bruteforce_detector')

from bruteforce_detector.config import get_config
from bruteforce_detector.managers.database import BlacklistDatabase
from bruteforce_detector.managers.blacklist_writer import BlacklistWriter


class DatabaseToFileSync:
    """Syncs database to text file with backups"""
    
    def __init__(self):
        self.config = get_config()
        self.logger = logging.getLogger(__name__)
        self.db = BlacklistDatabase()
        self.writer = BlacklistWriter(self.config)
        self.backup_dir = Path("/root/backup/lists")
        self.backup_dir.mkdir(parents=True, exist_ok=True)
    
    def create_backup(self, file_path: Path) -> Path:
        """Create timestamped backup"""
        if not file_path.exists():
            return None
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_path = self.backup_dir / f"{file_path.name}.backup.{timestamp}"
        
        shutil.copy2(file_path, backup_path)
        self.logger.info(f"💾 Backup: {backup_path.name}")
        
        # Keep only last 20 backups
        backups = sorted(self.backup_dir.glob(f"{file_path.name}.backup.*"))
        for old_backup in backups[:-20]:
            old_backup.unlink()
        
        return backup_path
    
    def sync_database_to_file(self, output_file: str):
        """Export database to text file with metadata"""
        self.logger.info(f"📊 Reading database...")
        
        # Get all IPs from database
        all_ips = self.db.get_all_ips(ip_version=4)
        
        self.logger.info(f"   Found {len(all_ips)} IPv4 addresses")
        
        # Create backup
        output_path = Path(output_file)
        if output_path.exists():
            self.create_backup(output_path)
        
        # Write to file using BlacklistWriter
        self.logger.info(f"📝 Writing to {output_file}...")
        self.writer.write_blacklist(output_file, all_ips, new_count=0)
        
        self.logger.info(f"✅ Sync complete!")
    
    def print_stats(self):
        """Print database statistics"""
        stats = self.db.get_statistics()
        
        all_ips = self.db.get_all_ips()
        with_first = sum(1 for info in all_ips.values() if info.get('first_seen'))
        with_last = sum(1 for info in all_ips.values() if info.get('last_seen'))
        with_added = sum(1 for info in all_ips.values() if info.get('date_added'))
        
        self.logger.info("\n" + "="*70)
        self.logger.info("📊 DATABASE STATISTICS")
        self.logger.info("="*70)
        self.logger.info(f"Total IPs: {stats['total_ips']}")
        self.logger.info(f"IPv4: {stats['ipv4']}")
        self.logger.info(f"With Geolocation: {stats['with_geolocation']}")
        self.logger.info(f"Total Events: {stats['total_events']}")
        self.logger.info(f"\nTimestamp Coverage:")
        self.logger.info(f"  With first_seen: {with_first} ({with_first/stats['total_ips']*100:.1f}%)")
        self.logger.info(f"  With last_seen: {with_last} ({with_last/stats['total_ips']*100:.1f}%)")
        self.logger.info(f"  With date_added: {with_added} ({with_added/stats['total_ips']*100:.1f}%)")
        self.logger.info("="*70)


def main():
    parser = argparse.ArgumentParser(
        description='Sync database to blacklist_ipv4.txt file',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Sync database to default file
  %(prog)s --stats                  # Show database statistics
  %(prog)s --output /tmp/test.txt   # Sync to custom file
        """
    )
    
    parser.add_argument(
        '--output', '-o',
        default='/root/blacklist_ipv4.txt',
        help='Output file path (default: /root/blacklist_ipv4.txt)'
    )
    
    parser.add_argument(
        '--stats', '-s',
        action='store_true',
        help='Show statistics only (no sync)'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Verbose output'
    )
    
    args = parser.parse_args()
    
    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    logger = logging.getLogger(__name__)
    
    logger.info("="*70)
    logger.info("🔄 TribanFT Database → File Sync")
    logger.info("="*70)
    
    sync = DatabaseToFileSync()
    
    if args.stats:
        sync.print_stats()
    else:
        sync.print_stats()
        logger.info("")
        sync.sync_database_to_file(args.output)
    
    logger.info("\n🏁 Done!")


if __name__ == "__main__":
    main()