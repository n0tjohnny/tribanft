#!/usr/bin/env python3
"""
TribanFT - IP Visibility & Intelligent Blacklist Management

Main entry point for the threat detection and IP blocking system.

This module orchestrates the complete detection cycle:
- Parses security events from system logs (syslog, MSSQL)
- Runs detection algorithms (prelogin, failed login, port scan, CrowdSec)
- Updates blacklists with geolocation and threat intelligence
- Synchronizes with NFTables for immediate firewall blocking

Usage:
    tribanft --detect                    # Run detection cycle
    tribanft --show-blacklist           # Display current blacklist
    tribanft --blacklist-add <ip>       # Manually block IP
    tribanft --blacklist-remove <ip>    # Remove IP from blacklist
    tribanft --whitelist-add <ip>       # Whitelist IP

Author: TribanFT Project
License: GNU GPL v3
Repository: https://github.com/n0tjohnny/tribanft
"""

import sys
import os
import argparse
import logging
import signal
from typing import List
from pathlib import Path
from datetime import datetime, timedelta
from bruteforce_detector.managers.geolocation import IPGeolocationManager

# Add the current directory to Python path so imports work
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Now import your modules
from bruteforce_detector.config import get_config
from bruteforce_detector.models import SecurityEvent, DetectionResult, ProcessingState
from bruteforce_detector.managers.whitelist import WhitelistManager
from bruteforce_detector.managers.blacklist import BlacklistManager
from bruteforce_detector.managers.nftables_manager import NFTablesManager
from bruteforce_detector.managers.state import StateManager
from bruteforce_detector.utils.logging import setup_logging

# Plugin system imports
from bruteforce_detector.core.plugin_manager import PluginManager
from bruteforce_detector.core.rule_engine import RuleEngine
from bruteforce_detector.detectors.base import BaseDetector
from bruteforce_detector.parsers.base import BaseLogParser

# Real-time monitoring
from bruteforce_detector.core.realtime_engine import RealtimeDetectionMixin


class BruteForceDetectorEngine(RealtimeDetectionMixin):
    """
    Core detection engine that coordinates all components.
    
    Responsibilities:
    - Initialize and manage all detection modules (parsers, detectors, managers)
    - Orchestrate the detection cycle workflow
    - Handle log parsing from multiple sources
    - Run detection algorithms across collected events
    - Update blacklists and synchronize with firewall
    """

    def __init__(self):
        """
        Initialize the detection engine with all required components.
        
        Sets up:
        - Configuration from environment/files
        - Whitelist/blacklist managers
        - NFTables integration
        - Log parsers (syslog, MSSQL)
        - Detection modules (prelogin, failed login, port scan, CrowdSec)
        - State management for tracking processing history
        """
        self.logger = logging.getLogger(__name__)
        self.config = get_config()
        self.geolocation_manager = IPGeolocationManager()

        # CRITICAL FIX #35: Graceful shutdown flag for signal handlers
        self._shutdown_requested = False

        try:
            # Initialize managers
            self.whitelist_manager = WhitelistManager()
            self.blacklist_manager = BlacklistManager(self.whitelist_manager, self.geolocation_manager)
            self.nftables_manager = NFTablesManager()
            self.state_manager = StateManager()

            # Initialize plugin manager
            self.plugin_manager = PluginManager(self.config)

            # Auto-discover and load parsers
            parser_dir = Path(__file__).parent / "plugins" / "parsers"
            parser_classes = self.plugin_manager.discover_plugins(parser_dir, BaseLogParser)

            # Instantiate parsers with log paths from config
            self.parsers = []
            for parser_class in parser_classes:
                parser_name = parser_class.__name__.lower()

                # Map parser classes to their config log paths
                if 'syslog' in parser_name:
                    if self.config.syslog_path and Path(self.config.syslog_path).exists():
                        self.parsers.append(parser_class(self.config.syslog_path))
                    else:
                        self.logger.warning(f"Syslog file not found: {self.config.syslog_path}")

                elif 'mssql' in parser_name:
                    if (self.config.mssql_error_log_path and
                        Path(self.config.mssql_error_log_path).exists()):
                        self.parsers.append(parser_class(self.config.mssql_error_log_path))
                    else:
                        self.logger.warning(f"MSSQL log file not found: {self.config.mssql_error_log_path}")

                elif 'apache' in parser_name:
                    if (self.config.apache_access_log_path and
                        Path(self.config.apache_access_log_path).exists()):
                        self.parsers.append(parser_class(self.config.apache_access_log_path))
                        self.logger.info(f"Apache parser loaded: {self.config.apache_access_log_path}")
                    else:
                        if self.config.apache_access_log_path:
                            self.logger.warning(f"Apache log file not found: {self.config.apache_access_log_path}")

                elif 'nginx' in parser_name:
                    if (self.config.nginx_access_log_path and
                        Path(self.config.nginx_access_log_path).exists()):
                        self.parsers.append(parser_class(self.config.nginx_access_log_path))
                        self.logger.info(f"Nginx parser loaded: {self.config.nginx_access_log_path}")
                    else:
                        if self.config.nginx_access_log_path:
                            self.logger.warning(f"Nginx log file not found: {self.config.nginx_access_log_path}")

            self.logger.info(f"Loaded {len(self.parsers)} parser plugins")

            # Auto-discover and load detectors
            detector_dir = Path(__file__).parent / "plugins" / "detectors"
            detector_classes = self.plugin_manager.discover_plugins(detector_dir, BaseDetector)

            # Prepare dependencies for detector instantiation
            detector_dependencies = {
                'config': self.config,
                'blacklist_manager': self.blacklist_manager
            }

            # Instantiate detectors with dependency injection
            self.detectors = self.plugin_manager.instantiate_plugins(
                detector_classes,
                detector_dependencies
            )

            self.logger.info(f"Loaded {len(self.detectors)} detector plugins")

            # Initialize YAML rule engine
            rules_dir = Path(__file__).parent / "rules" / "detectors"
            if getattr(self.config, 'enable_yaml_rules', True):
                self.rule_engine = RuleEngine(rules_dir)
                rule_summary = self.rule_engine.get_rule_summary()
                self.logger.info(
                    f"YAML Rule Engine: Loaded {rule_summary['enabled_rules']}/"
                    f"{rule_summary['total_rules']} rules"
                )
            else:
                self.rule_engine = None
                self.logger.info("YAML rule engine disabled in config")

            # Initialize real-time monitoring (with automatic fallback)
            self._init_realtime()

            # CRITICAL FIX #34: Setup signal handlers for hot-reload
            self._setup_signal_handlers()

        except Exception as e:
            self.logger.error(f"Failed to initialize detector engine: {e}")
            raise

    def _setup_signal_handlers(self):
        """
        Setup signal handlers for graceful operation and shutdown.

        CRITICAL FIX #34: Allows reloading whitelist without service restart.
        CRITICAL FIX #35: Graceful shutdown on SIGTERM/SIGINT.

        Signals:
            SIGHUP: Reload whitelist from disk
            SIGTERM: Graceful shutdown
            SIGINT: Graceful shutdown (Ctrl+C)
        """
        def handle_sighup(signum, frame):
            """Handle SIGHUP signal by reloading whitelist."""
            self.logger.info("Received SIGHUP signal - reloading whitelist...")
            try:
                self.whitelist_manager.reload()
                self.logger.info("✓ Whitelist reloaded successfully")
            except Exception as e:
                self.logger.error(f"Failed to reload whitelist: {e}")

        def handle_shutdown(signum, frame):
            """Handle SIGTERM/SIGINT signal for graceful shutdown."""
            sig_name = "SIGTERM" if signum == signal.SIGTERM else "SIGINT"
            self.logger.info(f"Received {sig_name} - initiating graceful shutdown...")
            self._shutdown_requested = True

            # Stop realtime monitoring if running
            if hasattr(self, '_stop_event'):
                self._stop_event.set()

        # Register SIGHUP handler (Unix only)
        if hasattr(signal, 'SIGHUP'):
            signal.signal(signal.SIGHUP, handle_sighup)
            self.logger.info("✓ SIGHUP signal handler registered (whitelist hot-reload)")
        else:
            self.logger.debug("SIGHUP not available on this platform (Windows)")

        # Register SIGTERM handler (Unix/Windows)
        if hasattr(signal, 'SIGTERM'):
            signal.signal(signal.SIGTERM, handle_shutdown)
            self.logger.info("✓ SIGTERM signal handler registered (graceful shutdown)")

        # Register SIGINT handler (Ctrl+C - Unix/Windows)
        if hasattr(signal, 'SIGINT'):
            signal.signal(signal.SIGINT, handle_shutdown)
            self.logger.info("✓ SIGINT signal handler registered (Ctrl+C shutdown)")
    
    def run_detection(self) -> List[DetectionResult]:
        """
        Execute the complete detection cycle.
        
        Process:
        1. Load last processing state (timestamp of last run)
        2. Parse logs from all sources since last run
        3. Run all enabled detectors on collected events
        4. Process detections (deduplicate, enrich with geolocation)
        5. Update blacklists and NFTables
        6. Enrich metadata from authoritative sources (NFTables, CrowdSec)
        7. Save current state for next run
        
        Returns:
            List of DetectionResult objects representing detected threats
        """
        self.logger.info("=" * 60)
        self.logger.info("Starting advanced brute force detection")
        self.logger.info("=" * 60)
        
        # Get last processing state
        last_state = self.state_manager.get_state()
        since_timestamp = last_state.last_processed_timestamp if last_state else None
        
        # Collect events from all parsers
        all_events: List[SecurityEvent] = []
        for parser in self.parsers:
            try:
                events = parser.parse(since_timestamp=since_timestamp)
                all_events.extend(events)
                self.logger.info(f"Parser {parser.__class__.__name__} found {len(events)} events")
            except Exception as e:
                self.logger.error(f"Parser {parser.__class__.__name__} failed: {e}")
        
        # Run all detectors
        # CRITICAL FIX #19: Track failed detectors for optional fail-fast mode
        all_detections: List[DetectionResult] = []
        failed_detectors = []

        for detector in self.detectors:
            if not detector.enabled:
                self.logger.info(f"Detector {detector.name} is disabled, skipping")
                continue

            try:
                detections = detector.detect(all_events)
                all_detections.extend(detections)
                self.logger.info(f"Detector {detector.name} found {len(detections)} detections")
            except Exception as e:
                self.logger.error(f"Detector {detector.name} failed: {e}", exc_info=True)
                failed_detectors.append(detector.name)

        # CRITICAL FIX #19: Optional fail-fast on detector errors
        if failed_detectors:
            failure_msg = f"Detection completed with {len(failed_detectors)} failed detectors: {', '.join(failed_detectors)}"

            # Check config for strict mode
            if getattr(self.config, 'fail_on_detector_error', False):
                self.logger.error(failure_msg)
                raise RuntimeError(f"Critical detectors failed: {', '.join(failed_detectors)}")
            else:
                self.logger.warning(failure_msg)

        # Apply YAML rules
        if self.rule_engine:
            try:
                rule_detections = self.rule_engine.apply_rules(all_events)
                all_detections.extend(rule_detections)
                self.logger.info(f"YAML Rule Engine found {len(rule_detections)} detections")
            except Exception as e:
                self.logger.error(f"YAML Rule Engine failed: {e}", exc_info=True)

        # Process detections
        if all_detections:
            self._process_detections(all_detections)

            # Enrich metadata from authoritative sources (when detections found)
            if self.config.enable_auto_enrichment:
                self._enrich_metadata_from_sources()
                # Update enrichment timestamp
                last_state.last_enrichment_timestamp = datetime.now()
        else:
            self.logger.info("No new detections found")

            # Periodic enrichment: run once every 24 hours even without detections
            if self.config.enable_auto_enrichment:
                should_enrich = self._should_run_periodic_enrichment(last_state)
                if should_enrich:
                    self.logger.info("Running periodic metadata enrichment (last run >24h ago)")
                    self._enrich_metadata_from_sources()
                    # Update enrichment timestamp
                    last_state.last_enrichment_timestamp = datetime.now()
                else:
                    self.logger.debug("Skipping metadata enrichment - no detections and last enrichment recent (saves ~90s)")

        # Update processing state
        self.state_manager.update_state(last_state)
        
        self.logger.info("Brute force detection completed")
        self.logger.info("=" * 60)
        
        return all_detections

    def _process_detections(self, detections: List[DetectionResult]):
        """
        Process detected threats and update security systems.
        
        Steps:
        1. Deduplicate detections by IP address
        2. Enrich with geolocation data (country, ISP)
        3. Update blacklist files with comprehensive metadata
        4. Sync with NFTables for immediate firewall blocking
        
        Args:
            detections: List of DetectionResult objects to process
        """
        # Deduplicate by IP
        unique_detections = {}
        for detection in detections:
            ip_str = str(detection.ip)
            if ip_str not in unique_detections:
                unique_detections[ip_str] = detection
        
        unique_list = list(unique_detections.values())
        
        if unique_list:
            self.logger.warning(f"SECURITY ALERT: Found {len(unique_list)} malicious IPs to block")
            
            # Enhance with geolocation (only for new detections)
            for detection in unique_list:
                if hasattr(self, 'geolocation_manager'):
                    # Only enrich geolocation if not already present (preserves CrowdSec data)
                    if detection.geolocation is None:
                        geo_info = self.geolocation_manager.get_ip_info(detection.ip)
                        detection.geolocation = geo_info
        
        # Update blacklists (handles logging internally)
        self.blacklist_manager.update_blacklists(unique_list)

        # Update nftables if enabled
        # FIX #4 FOLLOW-UP: Handle exceptions from NFTables update (Fix #4 added exception propagation)
        # Storage is already updated, so graceful degradation on NFTables failure
        if self.config.enable_nftables_update:
            try:
                self.nftables_manager.update_blacklists(
                    self.blacklist_manager.get_all_blacklisted_ips()
                )
            except Exception as e:
                self.logger.error(f"NFTables update failed after storage update: {e}")
                self.logger.warning("Blacklist updated in storage but NOT synced to firewall - manual sync may be needed")
                # Continue execution - storage is consistent, just not synced to firewall

    def _should_run_periodic_enrichment(self, state) -> bool:
        """
        Determine if periodic enrichment should run (even without detections).

        Runs enrichment if it's been more than 24 hours since last enrichment.
        This ensures metadata stays fresh from NFTables/CrowdSec.

        Args:
            state: ProcessingState with last_enrichment_timestamp

        Returns:
            True if enrichment should run, False otherwise
        """
        if not state or not state.last_enrichment_timestamp:
            # Never enriched before - run it
            return True

        time_since_enrichment = datetime.now() - state.last_enrichment_timestamp

        # Run if last enrichment was more than 24 hours ago
        if time_since_enrichment > timedelta(hours=24):
            return True

        return False

    def _enrich_metadata_from_sources(self):
        """
        Automatically enrich blacklist metadata from authoritative sources.
        
        Runs periodically during detection cycle:
        1. Import port_scanners from NFTables with calculated timestamps
        2. Import NEW IPs from CrowdSec historical alerts
        3. Enrich existing IPs with CrowdSec historical alert data
        4. Update database/files with enriched metadata
        5. Auto-sync to maintain consistency
        
        Prevents metadata loss by constantly refreshing from sources.
        This ensures IPs never lose their context, geolocation, or detection reason.
        """
        self.logger.info("Enriching metadata from authoritative sources...")
        
        try:
            # Get existing IPs
            existing = self.blacklist_manager.get_all_blacklisted_ips()
            existing_ipv4 = {str(ip) for ip in existing.get('ipv4', set())}
            
            enriched_data = {}
            
            # 1. NFTables Discovery (v2.4)
            if self.config.enable_nftables_update:
                # Auto-discover NFTables sets if enabled
                if self.config.nftables_auto_discovery:
                    try:
                        discovered_sets = self.blacklist_manager.nft_sync.discover_nftables_sets()
                        if discovered_sets:
                            self.logger.info(f"   Discovered {len(discovered_sets)} NFTables sets:")
                            for key, info in discovered_sets.items():
                                # Get IP count from each set
                                family, table, set_name = key.split(':')
                                try:
                                    ips = self.blacklist_manager.nft_sync.import_from_set(
                                        table=table,
                                        set_name=set_name,
                                        family=family,
                                        reason=f"Discovery from {key}"
                                    )
                                    ip_count = len(ips) if ips else 0
                                    self.logger.info(f"      - {key}: {ip_count} IPs (type={info['type']})")
                                    if ips:
                                        enriched_data.update(ips)
                                except Exception as e:
                                    self.logger.debug(f"      - {key}: Could not import ({e})")
                        else:
                            self.logger.debug("   No NFTables sets discovered")
                    except Exception as e:
                        self.logger.warning(f"   WARNING: NFTables discovery failed: {e}")

                # Import from configured custom sets
                if self.config.nftables_import_sets:
                    try:
                        import_sets_str = self.config.nftables_import_sets.strip()
                        if import_sets_str:
                            import_specs = [s.strip() for s in import_sets_str.split(',') if s.strip()]
                            for spec in import_specs:
                                # Parse format: family:table:set_name
                                parts = spec.split(':')
                                if len(parts) == 3:
                                    family, table, set_name = parts
                                    imported_ips = self.blacklist_manager.nft_sync.import_from_set(
                                        table=table,
                                        set_name=set_name,
                                        family=family,
                                        reason=f"NFTables import from {spec}"
                                    )
                                    if imported_ips:
                                        enriched_data.update(imported_ips)
                                        self.logger.info(f"   Imported {len(imported_ips)} IPs from {spec}")
                                else:
                                    self.logger.warning(f"   Invalid set spec '{spec}' (use family:table:set)")
                    except Exception as e:
                        self.logger.warning(f"   WARNING: Custom set import failed: {e}")

                # Import from NFTables port_scanners set (fallback if auto-discovery disabled)
                if not self.config.nftables_auto_discovery:
                    try:
                        port_scanner_ips = self.blacklist_manager.nft_sync.get_port_scanners()
                        if port_scanner_ips:
                            enriched_data.update(port_scanner_ips)
                            self.logger.info(f"   Found {len(port_scanner_ips)} IPs in port_scanners")
                    except Exception as e:
                        self.logger.warning(f"   WARNING: Port scanner import failed: {e}")
            
            # 2. Enrich from CrowdSec historical alerts
            if self.config.enable_crowdsec_integration:
                try:
                    # Find the CrowdSec detector
                    crowdsec_detector = None
                    for detector in self.detectors:
                        if isinstance(detector, CrowdSecDetector):
                            crowdsec_detector = detector
                            break
                    
                    if crowdsec_detector:
                        crowdsec_data = crowdsec_detector.enrich_from_historical_alerts(existing_ipv4)
                        if crowdsec_data:
                            # Separate new imports from enrichment updates
                            new_imports = {}
                            enrichment_updates = {}
                            
                            for ip_str, metadata in crowdsec_data.items():
                                if ip_str in existing_ipv4:
                                    # Existing IP - enrich metadata
                                    if ip_str not in enriched_data:
                                        enrichment_updates[ip_str] = metadata
                                else:
                                    # New IP - import to blacklist
                                    new_imports[ip_str] = metadata
                            
                            # Log results
                            if new_imports:
                                self.logger.info(f"   Importing {len(new_imports)} NEW IPs from CrowdSec alerts")
                            if enrichment_updates:
                                self.logger.info(f"   Enriching {len(enrichment_updates)} existing IPs from CrowdSec alerts")
                                enriched_data.update(enrichment_updates)
                            
                            # Import new IPs to blacklist
                            if new_imports:
                                self._import_crowdsec_alerts(new_imports)
                                
                except Exception as e:
                    self.logger.warning(f"   WARNING: CrowdSec enrichment failed: {e}")
            
            # 3. Update database/files with enriched metadata
            if enriched_data:
                self.blacklist_manager.bulk_update_metadata(enriched_data)
                self.logger.info(f"   Updated {len(enriched_data)} IPs with enriched metadata")
            else:
                self.logger.info("   INFO: No new metadata to enrich")
        
        except Exception as e:
            self.logger.error(f"   ERROR: Metadata enrichment failed: {e}")
            import traceback
            self.logger.debug(traceback.format_exc())
    
    def _import_crowdsec_alerts(self, new_ips_data: dict):
        """
        Import new IPs discovered in CrowdSec alerts but not yet in blacklist.
        
        These are IPs that:
        - Were detected by CrowdSec (not by tribanFT's own detectors)
        - Attacked services we don't monitor (e.g., HTTP-only attacks)
        - Were blocked before tribanFT saw them
        
        Args:
            new_ips_data: Dict mapping IP strings to metadata
                Format: {'1.2.3.4': {'ip': IPv4Address, 'reason': '...', ...}}
        """
        if not new_ips_data:
            return
        
        try:
            # Split by IP version for proper blacklist file routing
            ipv4_imports = {}
            ipv6_imports = {}
            
            for ip_str, metadata in new_ips_data.items():
                ip_obj = metadata.get('ip')
                if ip_obj:
                    if ip_obj.version == 4:
                        ipv4_imports[ip_str] = metadata
                    else:
                        ipv6_imports[ip_str] = metadata
            
            # Import to blacklist files using existing infrastructure
            if ipv4_imports:
                self.blacklist_manager._update_blacklist_file(
                    self.config.blacklist_ipv4_file,
                    ipv4_imports
                )
                self.logger.info(f"   Imported {len(ipv4_imports)} IPv4 from CrowdSec alerts")
            
            if ipv6_imports:
                self.blacklist_manager._update_blacklist_file(
                    self.config.blacklist_ipv6_file,
                    ipv6_imports
                )
                self.logger.info(f"   Imported {len(ipv6_imports)} IPv6 from CrowdSec alerts")
                
        except Exception as e:
            self.logger.error(f"   ERROR: Failed to import CrowdSec alerts: {e}")
            import traceback
            self.logger.debug(traceback.format_exc())


def main():
    """
    CLI entry point with argument parsing.
    
    Supported operations:
    - Detection cycle (--detect)
    - Whitelist management (--whitelist-add/remove)
    - Blacklist management (--blacklist-add/remove, --show-blacklist)
    - Log search (--blacklist-search)
    - Manual IP investigation (--no-log-search to skip)
    """
    parser = argparse.ArgumentParser(description='TribanFT - IP Visibility & Intelligent Blacklist Management')
    parser.add_argument('--detect', action='store_true', help='Run brute force detection')
    parser.add_argument('--whitelist-add', type=str, help='Add IP to whitelist')
    parser.add_argument('--whitelist-remove', type=str, help='Remove IP from whitelist')
    parser.add_argument('--blacklist-add', type=str, help='Add IP to manual blacklist')
    parser.add_argument('--blacklist-remove', type=str, help='Remove IP from blacklist')
    parser.add_argument('--blacklist-reason', type=str, help='Reason for manual blacklisting')
    parser.add_argument('--no-log-search', action='store_true', help='Skip log search when adding manual IP')
    parser.add_argument('--blacklist-search', type=str, help='Search logs for IP activity before adding')
    parser.add_argument('--show-whitelist', action='store_true', help='Show current whitelist')
    parser.add_argument('--show-blacklist', action='store_true', help='Show current blacklist')
    parser.add_argument('--show-manual', action='store_true', help='Show manual blacklist only')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')
    parser.add_argument('--daemon', action='store_true', help='Run as daemon service (real-time monitoring with auto-fallback)')
    # Removed --migrate argument (obsolete cron-to-systemd migration from v2.8.x)
    parser.add_argument('--sync-files', action='store_true', help='Force sync database to blacklist files')
    parser.add_argument('--sync-output', type=str, help='Custom output file for sync (default: config file)')
    parser.add_argument('--sync-stats', action='store_true', help='Show database statistics with sync')
    parser.add_argument('--stats-only', action='store_true', help='Show database statistics without syncing')
    
    # Integrity and backup management commands
    parser.add_argument('--verify', action='store_true', help='Run integrity checks on blacklist files and database')
    parser.add_argument('--skip-verify', action='store_true', help='Skip automatic integrity verification on startup')
    parser.add_argument('--list-backups', type=str, metavar='FILE', help='List available backups for a file (e.g., blacklist_ipv4.txt)')
    parser.add_argument('--restore-backup', type=str, metavar='BACKUP_PATH', help='Restore from a specific backup file')
    parser.add_argument('--restore-target', type=str, metavar='TARGET_PATH', help='Target path for backup restoration (required with --restore-backup)')

    # CrowdSec integration commands
    parser.add_argument('--import-crowdsec-csv', type=str, metavar='CSV_FILE', help='Import and replace blacklist with trusted CrowdSec CSV data')

    # Query and statistics commands
    parser.add_argument('--query-ip', type=str, metavar='IP', help='Query detailed information about a specific IP')
    parser.add_argument('--query-country', type=str, metavar='COUNTRY', help='List IPs from a specific country')
    parser.add_argument('--query-reason', type=str, metavar='REASON', help='Search IPs by block reason (partial match)')
    parser.add_argument('--query-attack-type', type=str, metavar='TYPE', help='Filter IPs by attack/event type (e.g., sql_injection, ssh_attack)')
    parser.add_argument('--query-timerange', type=str, metavar='RANGE', help='Filter IPs by time range (format: "2025-12-01 to 2025-12-24" or "last 7 days")')
    parser.add_argument('--list-countries', action='store_true', help='List all countries with IP counts')
    parser.add_argument('--list-sources', action='store_true', help='List all detection sources with counts')
    parser.add_argument('--top-threats', type=int, metavar='N', help='Show top N IPs by event count')
    parser.add_argument('--export-csv', type=str, metavar='FILE', help='Export blacklist to CSV file')
    parser.add_argument('--export-json', type=str, metavar='FILE', help='Export blacklist to JSON file')
    parser.add_argument('--live-monitor', action='store_true', help='Monitor threats in real-time (live stream)')

    args = parser.parse_args()
    
    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    setup_logging(level=log_level)

    # Removed --migrate command (obsolete cron-to-systemd migration from v2.8.x)
    # Directory structure migration happens automatically via config.py

    # Handle integrity and backup commands first (don't need full engine)
    if args.verify:
        from bruteforce_detector.utils.integrity_checker import IntegrityChecker
        from bruteforce_detector.config import get_config
        
        config = get_config()
        checker = IntegrityChecker()
        
        print("Running Integrity Checks...")
        print("=" * 80)
        
        results = checker.verify_all(config)
        
        for result in results:
            print(result)
            print()
        
        # Overall summary
        passed = sum(1 for r in results if r.passed)
        failed = len(results) - passed
        
        print("=" * 80)
        print(f"Summary: {passed} passed, {failed} failed")
        
        sys.exit(0 if failed == 0 else 1)
    
    elif args.list_backups:
        from bruteforce_detector.utils.backup_manager import get_backup_manager
        from bruteforce_detector.config import get_config
        
        config = get_config()
        backup_mgr = get_backup_manager()
        
        filename = args.list_backups
        backups = backup_mgr.list_backups(filename)
        
        if not backups:
            print(f"No backups found for {filename}")
            sys.exit(0)
        
        print(f"Available Backups for {filename}")
        print("=" * 80)
        
        for timestamp, backup_path in backups:
            size = backup_path.stat().st_size
            size_kb = size / 1024
            print(f"  {timestamp.strftime('%Y-%m-%d %H:%M:%S')} - {backup_path.name} ({size_kb:.1f} KB)")
        
        print(f"\nTotal: {len(backups)} backups")
        sys.exit(0)
    
    elif args.restore_backup:
        if not args.restore_target:
            print("ERROR: --restore-target is required with --restore-backup")
            sys.exit(1)

        from bruteforce_detector.utils.backup_manager import get_backup_manager

        backup_mgr = get_backup_manager()
        backup_path = Path(args.restore_backup)
        target_path = Path(args.restore_target)

        print(f"Restoring from backup...")
        print(f"   Backup: {backup_path}")
        print(f"   Target: {target_path}")

        success = backup_mgr.restore_backup(backup_path, target_path)

        if success:
            print(f"SUCCESS: Restoration completed successfully")
            sys.exit(0)
        else:
            print(f"ERROR: Restoration failed")
            sys.exit(1)

    # Query commands
    elif (args.query_ip or args.query_country or args.query_reason or args.query_attack_type or
          args.query_timerange or args.list_countries or args.list_sources or args.top_threats or
          args.export_csv or args.export_json):
        from bruteforce_detector.config import get_config
        from bruteforce_detector.managers.database import BlacklistDatabase
        from bruteforce_detector.utils.query_tool import QueryTool

        config = get_config()

        if not config.use_database:
            print("ERROR: Query commands require database mode (use_database = true in config)")
            sys.exit(1)

        db = BlacklistDatabase(config.database_path)
        query = QueryTool(db)

        if args.query_ip:
            query.query_ip(args.query_ip)
        elif args.query_country:
            query.query_country(args.query_country)
        elif args.query_reason:
            query.query_reason(args.query_reason)
        elif args.query_attack_type:
            query.query_attack_type(args.query_attack_type)
        elif args.query_timerange:
            query.query_timerange(args.query_timerange)
        elif args.list_countries:
            query.list_countries()
        elif args.list_sources:
            query.list_sources()
        elif args.top_threats:
            query.top_threats(args.top_threats)
        elif args.export_csv:
            query.export_csv(args.export_csv)
        elif args.export_json:
            query.export_json(args.export_json)

        sys.exit(0)

    # Live monitor command
    elif args.live_monitor:
        from bruteforce_detector.config import get_config
        from bruteforce_detector.managers.database import BlacklistDatabase
        from bruteforce_detector.utils.live_monitor import LiveMonitor

        config = get_config()

        if not config.use_database:
            print("ERROR: Live monitor requires database mode (use_database = true in config)")
            sys.exit(1)

        db = BlacklistDatabase(config.database_path)
        monitor = LiveMonitor(db)

        print("Starting live threat monitor...")
        print("Press Ctrl+C to stop")
        print()

        try:
            monitor.run()
        except KeyboardInterrupt:
            print("\nStopping live monitor...")
            sys.exit(0)

    engine = BruteForceDetectorEngine()
    
    # Run automatic integrity check on startup (unless skipped)
    if not args.skip_verify and args.detect:
        from bruteforce_detector.utils.integrity_checker import IntegrityChecker
        
        logger = logging.getLogger(__name__)
        checker = IntegrityChecker()
        config = engine.config
        
        logger.info("Running startup integrity checks...")
        
        # Quick check on main blacklist file
        if Path(config.blacklist_ipv4_file).exists():
            result = checker.verify_blacklist_file(config.blacklist_ipv4_file)
            if not result.passed:
                logger.warning("WARNING: Integrity check found issues:")
                for error in result.errors[:3]:
                    logger.warning(f"   • {error}")
                logger.warning("   Use --verify for full report")
        
        logger.info("Startup checks complete")

    # Handle CrowdSec CSV import
    if args.import_crowdsec_csv:
        from bruteforce_detector.detectors.crowdsec import CrowdSecDetector

        logger = logging.getLogger(__name__)
        logger.info(f"Importing CrowdSec data from CSV: {args.import_crowdsec_csv}")

        # Initialize CrowdSec detector
        crowdsec = CrowdSecDetector(engine.config)

        # Import CSV data
        imported_data = crowdsec.import_from_csv(args.import_crowdsec_csv)

        if imported_data:
            # Split by IP version
            ipv4_data = {}
            ipv6_data = {}

            for ip_str, metadata in imported_data.items():
                ip_obj = metadata.get('ip')
                if ip_obj.version == 4:
                    ipv4_data[ip_str] = metadata
                else:
                    ipv6_data[ip_str] = metadata

            # Replace blacklist data with CSV imports (replace=True to overwrite existing entries)
            if ipv4_data:
                logger.info(f"Replacing IPv4 blacklist with {len(ipv4_data)} trusted CrowdSec entries")
                engine.blacklist_manager._update_blacklist_file(
                    engine.config.blacklist_ipv4_file,
                    ipv4_data,
                    replace=True  # Force replacement instead of merge
                )

            if ipv6_data:
                logger.info(f"Replacing IPv6 blacklist with {len(ipv6_data)} trusted CrowdSec entries")
                engine.blacklist_manager._update_blacklist_file(
                    engine.config.blacklist_ipv6_file,
                    ipv6_data,
                    replace=True  # Force replacement instead of merge
                )

            # Update NFTables if enabled
            # FIX #4 FOLLOW-UP: Handle exceptions from NFTables update (Fix #4 added exception propagation)
            if engine.config.enable_nftables_update:
                logger.info("Updating NFTables firewall rules...")
                all_ips = engine.blacklist_manager.get_all_blacklisted_ips()
                try:
                    engine.nftables_manager.update_blacklists(all_ips)
                    logger.info("SUCCESS: NFTables updated successfully")
                except Exception as e:
                    logger.error(f"NFTables update failed after CrowdSec import: {e}")
                    logger.warning("IPs imported to storage but NOT synced to firewall - run 'tribanft --sync-files' to retry")
                    # Continue - import succeeded, just firewall sync failed

            logger.info(f"SUCCESS: Successfully imported {len(imported_data)} IPs from CrowdSec CSV")
        else:
            logger.error("ERROR: Failed to import any IPs from CSV")
            sys.exit(1)

        sys.exit(0)

    if args.whitelist_add:
        success = engine.whitelist_manager.add_to_whitelist(args.whitelist_add)
        sys.exit(0 if success else 1)
    elif args.whitelist_remove:
        success = engine.whitelist_manager.remove_from_whitelist(args.whitelist_remove)
        sys.exit(0 if success else 1)
    elif args.blacklist_add:
        reason = args.blacklist_reason or "Manually added by administrator"
        search_logs = not args.no_log_search  # Search logs unless explicitly disabled
        success = engine.blacklist_manager.add_manual_ip(args.blacklist_add, reason, search_logs)
        sys.exit(0 if success else 1)
    elif args.blacklist_remove:
        try:
            success = engine.blacklist_manager.remove_ip(args.blacklist_remove)
            sys.exit(0 if success else 1)
        except RuntimeError as e:
            logger.error(f"Failed to remove IP: {e}")
            logger.warning("Try disabling NFTables updates or fix firewall configuration")
            sys.exit(1)
    elif args.blacklist_search:
        log_analysis = engine.blacklist_manager._search_logs_for_ip(args.blacklist_search)
        print(f"Log Analysis for {args.blacklist_search}:")
        print(f"   Events Found: {log_analysis['events_found']}")
        print(f"   Event Types: {', '.join(log_analysis['event_types'])}")
        if log_analysis['recent_events']:
            print("   Recent Events:")
            for event in log_analysis['recent_events'][:3]:
                print(f"     - {event['source']}: {event['type']} at {event['timestamp']}")
        else:
            print("   No recent events found in logs")
        sys.exit(0)
    elif args.show_whitelist:
        entries = engine.whitelist_manager.get_whitelist_entries()
        if entries:
            print("Current whitelist:")
            for entry in entries:
                print(f"  - {entry}")
        else:
            print("Whitelist is empty")
        sys.exit(0)
    elif args.show_blacklist:
        engine.blacklist_manager.show_blacklist()
        sys.exit(0)
    elif args.show_manual:
        manual_path = Path(engine.config.manual_blacklist_file)
        if manual_path.exists():
            print("MANUAL BLACKLIST")
            print("=" * 80)
            with open(manual_path, 'r') as f:
                for line in f:
                    if line.strip() and not line.startswith('#'):
                        print(f"  - {line.strip()}")
                    elif line.startswith('# IP:'):
                        print(f"    {line.strip()}")
        else:
            print("No manual blacklist file found")
        sys.exit(0)
    elif args.stats_only:
        # Show database statistics without syncing
        if engine.config.use_database:
            from bruteforce_detector.managers.blacklist_adapter import BlacklistAdapter
            adapter = BlacklistAdapter(engine.config, use_database=True)
            adapter.print_stats()
        else:
            engine.logger.warning("WARNING: Not using database, statistics unavailable")
        sys.exit(0)
    elif args.sync_files:
        engine.logger.info("Manual database to file sync requested")
        
        try:
            if not engine.config.use_database:
                engine.logger.warning("WARNING: Not using database, sync not needed")
                sys.exit(0)
            
            from bruteforce_detector.managers.database import BlacklistDatabase
            from bruteforce_detector.managers.blacklist_adapter import BlacklistAdapter
            
            db = BlacklistDatabase(engine.config.database_path)
            adapter = BlacklistAdapter(engine.config, use_database=True)
            
            # Show stats before sync if requested
            if args.sync_stats:
                engine.logger.info("\nBEFORE SYNC:")
                adapter.print_stats()
                engine.logger.info("")
            
            # Determine output file(s)
            if args.sync_output:
                # Custom output file - single file sync
                output_file = args.sync_output
                engine.logger.info(f"Syncing to custom file: {output_file}")
                
                # Determine IP version from filename or default to IPv4
                ip_version = 4
                if 'ipv6' in output_file.lower():
                    ip_version = 6
                
                # Export with backup
                adapter.export_to_file(output_file, ip_version=ip_version, create_backup=True)
            else:
                # Default behavior - sync to configured files
                engine.logger.info("Syncing to configured files...")
                
                # Export IPv4 with backup
                adapter.export_to_file(
                    engine.config.blacklist_ipv4_file,
                    ip_version=4,
                    create_backup=True
                )
                
                # Export IPv6 if any exist
                stats = db.get_statistics()
                if stats.get('ipv6', 0) > 0:
                    adapter.export_to_file(
                        engine.config.blacklist_ipv6_file,
                        ip_version=6,
                        create_backup=True
                    )
            
            # Show stats after sync if requested
            if args.sync_stats:
                engine.logger.info("\nAFTER SYNC:")
                adapter.print_stats()
            
            engine.logger.info("\nSUCCESS: Database to file sync completed successfully")
            
        except Exception as e:
            engine.logger.error(f"ERROR: Sync failed: {e}")
            import traceback
            engine.logger.debug(traceback.format_exc())
            sys.exit(1)
    else:
        # Default action: run detection
        if not args.detect and not args.daemon:
            print("No action specified. Running detection (use --detect to explicitly run)")

        if args.daemon:
            # Daemon mode: real-time monitoring with automatic fallback
            logger = logging.getLogger(__name__)

            # Removed obsolete cron-to-systemd migration check (v2.8.x feature)
            # v2.9.0+ uses auto_migrate_to_organized_structure() instead (automatic in config.py)

            if engine.realtime_available:
                # Real-time monitoring mode
                logger.info("Starting TribanFT in real-time mode")
                try:
                    engine.run_realtime()
                except Exception as e:
                    logger.error(f"Real-time monitoring failed: {e}")
                    logger.info("Switching to periodic fallback...")
                    engine.run_periodic_fallback()
            else:
                # Periodic fallback mode
                logger.info("Real-time not available, using periodic mode")
                engine.run_periodic_fallback()

        else:
            # Single detection run
            engine.run_detection()

if __name__ == "__main__":
    main()