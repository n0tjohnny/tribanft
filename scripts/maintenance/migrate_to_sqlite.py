#!/usr/bin/env python3
"""
migrate_to_sqlite.py

Migra blacklists de arquivos texto para SQLite
"""

import sys
import argparse
import logging
from pathlib import Path

sys.path.insert(0, '/root/bruteforce_detector')

from bruteforce_detector.config import get_config
from bruteforce_detector.managers.blacklist_adapter import BlacklistAdapter


def main():
    parser = argparse.ArgumentParser(
        description='Migrate TribanFT blacklists from text files to SQLite',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --migrate              # Migrate all files to SQLite
  %(prog)s --export ipv4.txt      # Export SQLite to text file
  %(prog)s --stats                # Show database statistics
  %(prog)s --test                 # Test database without migrating
        """
    )
    
    parser.add_argument(
        '--migrate',
        action='store_true',
        help='Migrate text files to SQLite database'
    )
    
    parser.add_argument(
        '--export',
        metavar='FILE',
        help='Export database to text file'
    )
    
    parser.add_argument(
        '--stats',
        action='store_true',
        help='Show database statistics'
    )
    
    parser.add_argument(
        '--test',
        action='store_true',
        help='Test database creation without migrating'
    )
    
    parser.add_argument(
        '--db-path',
        default='/var/lib/tribanft/blacklist.db',
        help='Database path (default: /var/lib/tribanft/blacklist.db)'
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
    
    # Config
    config = get_config()
    
    # Inicializa adapter com database
    adapter = BlacklistAdapter(config, use_database=True)
    
    if args.test:
        logger.info("🧪 Testing database creation...")
        stats = adapter.get_statistics()
        logger.info(f"✅ Database initialized successfully")
        logger.info(f"   Current IPs: {stats.get('total_ips', 0)}")
        return
    
    if args.migrate:
        logger.info("="*70)
        logger.info("🚀 Starting Migration to SQLite")
        logger.info("="*70)
        
        # Pergunta confirmação
        response = input("\nThis will migrate all blacklist files to SQLite.\nContinue? [y/N]: ")
        if response.lower() != 'y':
            logger.info("Migration cancelled")
            return
        
        adapter.migrate_from_files()
        
        logger.info("\n✅ Migration completed successfully!")
        logger.info("\nNext steps:")
        logger.info("1. Update config to use database: BFD_USE_DATABASE=true")
        logger.info("2. Test with: tribanft --show-blacklist")
        logger.info("3. Backup old files: mv /root/blacklist_ipv4.txt /root/blacklist_ipv4.txt.backup")
        
    elif args.stats:
        stats = adapter.get_statistics()
        
        print("\n" + "="*70)
        print("📊 BLACKLIST DATABASE STATISTICS")
        print("="*70)
        print(f"Total IPs:        {stats.get('total_ips', 0):,}")
        print(f"IPv4:             {stats.get('ipv4', 0):,}")
        print(f"IPv6:             {stats.get('ipv6', 0):,}")
        print(f"Total Events:     {stats.get('total_events', 0):,}")
        print(f"With Geolocation: {stats.get('with_geolocation', 0):,}")
        
        print("\nBy Confidence:")
        for conf, count in stats.get('by_confidence', {}).items():
            print(f"  {conf:15s}: {count:,}")
        
        print("\nBy Source:")
        for source, count in stats.get('by_source', {}).items():
            print(f"  {source:15s}: {count:,}")
        
        print("="*70 + "\n")
        
    elif args.export:
        ip_version = 4 if 'ipv6' not in args.export.lower() else 6
        adapter.export_to_file(args.export, ip_version=ip_version)
        logger.info(f"✅ Exported to {args.export}")
        
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
