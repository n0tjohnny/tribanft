#!/usr/bin/env python3
"""
recover_blacklist_metadata.py

DEPRECATED: This script is deprecated. Use 'tribanft' command instead.

Argument Mapping:
  OLD: ./recover_blacklist_metadata.py --stats
  NEW: tribanft --stats-only

  OLD: ./recover_blacklist_metadata.py
  NEW: tribanft --sync-files --sync-stats

  OLD: ./recover_blacklist_metadata.py --output /tmp/test.txt
  NEW: tribanft --sync-files --sync-stats --sync-output /tmp/test.txt

This wrapper maintains backward compatibility but will be removed in future versions.
"""

import sys
import os
import argparse
import subprocess

def show_deprecation_warning():
    """Display deprecation notice to stderr."""
    print("", file=sys.stderr)
    print("="*70, file=sys.stderr)
    print("⚠️  DEPRECATION WARNING", file=sys.stderr)
    print("="*70, file=sys.stderr)
    print("This script (recover_blacklist_metadata.py) is DEPRECATED.", file=sys.stderr)
    print("", file=sys.stderr)
    print("Please use the 'tribanft' command instead:", file=sys.stderr)
    print("  • tribanft --stats-only", file=sys.stderr)
    print("  • tribanft --sync-files", file=sys.stderr)
    print("  • tribanft --sync-files --sync-output <file>", file=sys.stderr)
    print("  • tribanft --sync-files --sync-stats", file=sys.stderr)
    print("", file=sys.stderr)
    print("This wrapper will be removed in a future version.", file=sys.stderr)
    print("="*70, file=sys.stderr)
    print("", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description='[DEPRECATED] Sync database to blacklist_ipv4.txt file',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
DEPRECATION NOTICE:
  This script is deprecated. Use 'tribanft' command instead.
  
Examples (NEW COMMANDS):
  tribanft --stats-only                               # Show database statistics (replaces --stats)
  tribanft --sync-files --sync-stats                  # Sync database to default file with stats
  tribanft --sync-files --sync-output /tmp/test.txt   # Sync to custom file
  tribanft --sync-files --sync-stats --sync-output /tmp/test.txt   # Custom file with stats
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
    
    # Show deprecation warning
    show_deprecation_warning()
    
    # Build tribanft command
    cmd = ['tribanft']
    
    if args.stats:
        # Map --stats to --stats-only
        cmd.append('--stats-only')
    else:
        # Map default behavior to --sync-files with stats
        # Note: old script always showed stats before sync
        cmd.append('--sync-files')
        cmd.append('--sync-stats')  # Show stats to match old behavior
        
        # Map --output to --sync-output (only if not default)
        if args.output != '/root/blacklist_ipv4.txt':
            cmd.extend(['--sync-output', args.output])
    
    if args.verbose:
        cmd.append('--verbose')
    
    # Execute tribanft command
    print(f"🔄 Executing: {' '.join(cmd)}", file=sys.stderr)
    print("", file=sys.stderr)
    
    try:
        result = subprocess.run(cmd, check=False)
        sys.exit(result.returncode)
    except Exception as e:
        print(f"❌ Error executing tribanft: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
