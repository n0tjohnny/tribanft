#!/usr/bin/env python3
"""
tribanft-ipinfo-batch.py

Batch geolocation service for tribanft
- Runs periodically to geolocate IPs from the blacklist
- Respects ipinfo.io API limits
- Can be run as a systemd service
"""

import sys
import os
import argparse
import logging
import time
from pathlib import Path
from datetime import datetime

# Add project directory to path (auto-detected via config)
# The config module will find the project directory from config.conf or auto-detect it
script_dir = Path(__file__).parent.parent
sys.path.insert(0, str(script_dir))

from bruteforce_detector.config import get_config
from bruteforce_detector.managers.ipinfo_batch_manager import IPInfoBatchManager
from bruteforce_detector.utils.logging import setup_logging
from bruteforce_detector.utils.file_lock import FileLockError


def run_batch_service(config, args):
    """Runs the batch geolocation service"""
    logger = logging.getLogger(__name__)

    logger.info("="*70)
    logger.info("Starting Batch Geolocation Service - TribanFT")
    logger.info("="*70)

    # Initialize the manager
    ipinfo_manager = IPInfoBatchManager(config, api_token=args.token)

    # Display initial statistics
    if args.show_stats:
        ipinfo_manager.print_stats()
    
    iteration = 0
    
    try:
        while True:
            iteration += 1
            logger.info(f"\n{'='*70}")
            logger.info(f"Iteration #{iteration} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            logger.info("="*70)

            try:
                # Process IP batch
                processed = ipinfo_manager.process_blacklist_batch(
                    max_requests=args.batch_size
                )

                # Display statistics
                stats = ipinfo_manager.get_stats_summary()
                logger.info(f"\nStatistics:")
                logger.info(f"   IPs processed in this iteration: {processed}")
                logger.info(f"   Requests today: {stats['requests_today']}/{stats['daily_limit']}")
                logger.info(f"   Available today: {stats['remaining_today']}")
                logger.info(f"   Cache size: {stats['cache_size']} IPs")
                
            except FileLockError as e:
                logger.error(
                    f"File lock error in iteration {iteration}: {e}\n"
                    f"   Lock file: {ipinfo_manager.lock_file}\n"
                    "   This is non-critical - service will continue with next iteration"
                )
                # Log diagnostic info but don't crash
                if ipinfo_manager.lock_file.exists():
                    try:
                        stat = ipinfo_manager.lock_file.stat()
                        logger.info(
                            f"   Lock file diagnostic:\n"
                            f"     - Size: {stat.st_size} bytes\n"
                            f"     - Age: {time.time() - stat.st_mtime:.1f}s"
                        )
                    except Exception:
                        pass
                processed = 0  # Mark as no processing done
                stats = ipinfo_manager.get_stats_summary()  # Get stats even on error
            
            # If no more IPs to process or daily limit reached
            if processed == 0:
                logger.info("No new IPs to process or limit reached")

                if not args.daemon:
                    logger.info("Single mode: terminating service")
                    break

            # In daemon mode, wait before next iteration
            if args.daemon:
                if stats['remaining_today'] == 0:
                    # If daily limit reached, wait until midnight
                    logger.info(f"Daily limit reached. Waiting for reset at midnight...")
                    time.sleep(3600)  # Wait 1 hour and check again
                else:
                    # Wait configured interval
                    logger.info(f"Waiting {args.interval} seconds until next iteration...")
                    time.sleep(args.interval)
            else:
                # Single mode: terminate after processing
                logger.info("Single mode: terminating service")
                break
                
    except KeyboardInterrupt:
        logger.info("\nService interrupted by user")
    except Exception as e:
        logger.error(f"Service error: {e}", exc_info=True)
        sys.exit(1)
    finally:
        logger.info("\n" + "="*70)
        logger.info("FINAL STATISTICS")
        logger.info("="*70)
        ipinfo_manager.print_stats()
        logger.info("Batch Geolocation Service completed")


def main():
    parser = argparse.ArgumentParser(
        description='Batch Geolocation Service for TribanFT',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
USAGE EXAMPLES:
  %(prog)s                                    # Run once
  %(prog)s --daemon                           # Run continuously
  %(prog)s --daemon --interval 3600           # Run every 1 hour
  %(prog)s --batch-size 200                   # Process 200 IPs at a time
  %(prog)s --show-stats                       # Display statistics
  %(prog)s --token YOUR_TOKEN                 # Use custom token

TOKEN CONFIGURATION:
  Configure in config.conf or save to: <config_dir>/ipinfo_token.txt
  (run ./setup.sh to create config.conf)

INSTALLATION AS SERVICE:
  sudo ./scripts/install-ipinfo-batch-service.sh
  sudo systemctl status tribanft-ipinfo-batch.service
        """
    )
    
    parser.add_argument(
        '--daemon', '-d',
        action='store_true',
        help='Run as daemon (continuous mode)'
    )

    parser.add_argument(
        '--interval', '-i',
        type=int,
        default=3600,
        help='Interval between iterations in seconds (default: 3600 = 1 hour)'
    )

    parser.add_argument(
        '--batch-size', '-b',
        type=int,
        default=100,
        help='Maximum number of IPs to process per iteration (default: 100)'
    )

    parser.add_argument(
        '--token', '-t',
        type=str,
        help='ipinfo.io API token (or save to /etc/tribanft/ipinfo_token.txt)'
    )

    parser.add_argument(
        '--show-stats', '-s',
        action='store_true',
        help='Display statistics before starting'
    )

    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Verbose mode (debug)'
    )
    
    args = parser.parse_args()

    # Validate interval
    if args.interval < 60:
        print("ERROR: Minimum interval: 60 seconds")
        sys.exit(1)

    if args.batch_size < 1 or args.batch_size > 1000:
        print("ERROR: Batch size must be between 1 and 1000")
        sys.exit(1)

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    setup_logging(level=log_level)

    # Get configuration
    config = get_config()

    # Create config directory if it doesn't exist
    config_dir = Path("/etc/tribanft")
    config_dir.mkdir(parents=True, exist_ok=True)

    # Execute service
    run_batch_service(config, args)


if __name__ == "__main__":
    main()
