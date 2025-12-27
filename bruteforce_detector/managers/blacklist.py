"""
TribanFT Blacklist Manager

Orchestrates blacklist operations and coordinates all blacklist-related components.

This module is the central controller for IP blacklisting, managing:
- Automatic IP blocking from detection results with timestamps
- Manual IP addition with comprehensive investigation
- Bidirectional synchronization with NFTables firewall
- Integration with geolocation and log analysis
- Coordination between file/database storage backends

Architecture:
Uses a modular design where specialized components handle specific tasks:
- BlacklistAdapter: Storage abstraction (file or SQLite)
- NFTablesManager: Firewall synchronization
- IPInvestigator: IP analysis and geolocation
- LogSearcher: Historical log analysis

Author: TribanFT Project
License: GNU GPL v3
"""

from typing import Set, List, Dict, Tuple
import ipaddress
from pathlib import Path
import logging
import threading
from datetime import datetime, timezone

from ..models import DetectionResult
from ..config import get_config
from .whitelist import WhitelistManager
from .geolocation import IPGeolocationManager
from .nftables_manager import NFTablesManager
from .log_searcher import LogSearcher
from .blacklist_writer import BlacklistWriter
from .blacklist_adapter import BlacklistAdapter
from .ip_investigator import IPInvestigator


class BlacklistManager:
    """
    Central orchestrator for all blacklist operations.
    
    Coordinates between detection results, storage systems, firewall rules,
    and threat intelligence to maintain a comprehensive IP blacklist.
    """
    
    def __init__(self, whitelist_manager: WhitelistManager,
                 geolocation_manager: IPGeolocationManager = None):
        """
        Initialize blacklist manager with required dependencies.

        Args:
            whitelist_manager: WhitelistManager for filtering trusted IPs
            geolocation_manager: Optional IPGeolocationManager for threat intelligence
        """
        self.whitelist_manager = whitelist_manager
        self.geolocation_manager = geolocation_manager
        self.config = get_config()
        self.logger = logging.getLogger(__name__)
        self.manual_blacklist_file = self.config.manual_blacklist_file

        # RACE CONDITION FIX (C8): Lock for atomic read-modify-write operations
        self._update_lock = threading.Lock()

        # Initialize specialized modules
        self.log_searcher = LogSearcher(self.config)
        self.writer = BlacklistAdapter(self.config, use_database=self.config.use_database)
        self.investigator = IPInvestigator(geolocation_manager, self.log_searcher)
        self.nft_sync = NFTablesManager(self.config, whitelist_manager, geolocation_manager)
    
    # ========================================================================
    # CORE OPERATIONS
    # ========================================================================
    
    def update_blacklists(self, detections: List[DetectionResult]):
        """
        Process new detections and update blacklist storage.

        Workflow:
        1. Prepare detection data with metadata and timestamps
        2. Write to blacklist files/database
        3. Synchronize with NFTables firewall
        4. Import any new IPs found in NFTables

        NOTE: NFTables export is handled by caller (main.py) after this method returns.
        This allows caller to batch multiple updates before exporting to firewall.

        Args:
            detections: List of DetectionResult objects from detectors
        """
        new_ips_info = self._prepare_detection_ips(detections)

        if new_ips_info:
            self.logger.warning(f"SECURITY ALERT: Detected {len(new_ips_info)} new malicious IPs")
            self._update_blacklist_file(self.config.blacklist_ipv4_file, new_ips_info)
            self._log_new_ips(new_ips_info)

            # Sync with NFTables (C3 fix: graceful degradation on error)
            try:
                self.logger.info("Synchronizing with NFTables...")
                new_to_blacklist, new_to_nft = self.sync_from_nftables()
                if new_to_blacklist > 0:
                    self.logger.info(f"SUCCESS: {new_to_blacklist} IPs imported from NFTables")
            except Exception as e:
                self.logger.error(f"NFTables sync failed: {e}")
                self.logger.warning("Continuing blacklist operation without NFTables sync")
                # Blacklist is still updated in file/database, just not synced to firewall
    
    def add_manual_ip(self, ip_str: str, reason: str = "Manually added", 
                     search_logs: bool = True) -> bool:
        """
        Manually add IP with comprehensive investigation and logging.
        
        Process:
        1. Validate IP address format
        2. Check whitelist (prevent blocking trusted IPs)
        3. Investigate IP (geolocation + log analysis)
        4. Add to manual blacklist file with timestamps
        5. Propagate to main blacklist files
        6. Generate investigation report
        
        Args:
            ip_str: IP address string to block
            reason: Human-readable reason for blocking
            search_logs: Whether to analyze historical logs for this IP
            
        Returns:
            True if successful, False if invalid IP or whitelisted
        """
        try:
            ip = ipaddress.ip_address(ip_str)
            
            if self.whitelist_manager.is_whitelisted(ip):
                self.logger.error(f"ERROR: Cannot blacklist {ip_str} - it's in whitelist")
                return False
            
            # Investigate IP with full context
            investigation = self.investigator.investigate_ip(ip_str, search_logs)
            investigation['ip'] = ip
            
            # Ensure all timestamps are set
            now = datetime.now()
            if not investigation.get('first_seen'):
                investigation['first_seen'] = now
            if not investigation.get('last_seen'):
                investigation['last_seen'] = investigation.get('first_seen', now)
            investigation['date_added'] = now  # Always set when adding to blacklist
            
            # Add to blacklist files
            self._add_to_manual_blacklist(ip_str, investigation)
            self._add_to_main_blacklists({ip_str: investigation})
            self.investigator.format_investigation_log(ip_str, investigation)
            
            return True
                
        except ValueError:
            self.logger.error(f"ERROR: Invalid IP address: {ip_str}")
            return False

    def remove_ip(self, ip_str: str) -> bool:
        """
        Remove IP from blacklist (database and files).

        Process:
        1. Validate IP address format
        2. Remove from database/files (atomic)
        3. Remove from NFTables (if sync enabled, atomic with step 2)
        4. Log removal

        THREAD SAFETY: Uses _update_lock for atomic read-modify-write operations.
        Prevents race conditions during concurrent IP removal.

        Args:
            ip_str: IP address to remove

        Returns:
            True if successful, False if invalid IP or not found
        """
        try:
            ip = ipaddress.ip_address(ip_str)

            # RACE CONDITION FIX: Acquire lock for atomic removal
            # Entire operation (file + NFTables) under lock for complete atomicity
            with self._update_lock:
                # TWO-PHASE COMMIT: Remove from NFTables FIRST, then storage
                # This prevents inconsistent state where IP is removed from storage
                # but still blocked in firewall (Fix #9)

                if self.config.enable_nftables_update:
                    try:
                        # Get all current IPs
                        all_ips = self.blacklist_adapter.get_all_ips()

                        # Create remaining IP sets (without the IP to remove)
                        remaining_ips = {x for x in all_ips if str(x) != ip_str}

                        # Full NFTables update without this IP
                        # Use existing instance, not new one (Fix #10)
                        ipv4_set = {x for x in remaining_ips if x.version == 4}
                        ipv6_set = {x for x in remaining_ips if x.version == 6}

                        self.nft_sync.update_blacklists({
                            'ipv4': ipv4_set,
                            'ipv6': ipv6_set
                        })
                        self.logger.info(f"Removed {ip_str} from NFTables")

                    except Exception as e:
                        self.logger.error(f"NFTables removal failed for {ip_str}: {e}")
                        raise RuntimeError(f"Cannot remove {ip_str}: NFTables update failed") from e

                # Phase 2: Remove from storage (only if NFTables succeeded or disabled)
                success = self.blacklist_adapter.remove_ip(ip_str)

                if success:
                    self.logger.info(f"Successfully removed {ip_str} from blacklist storage")
                    return True
                else:
                    self.logger.warning(f"IP {ip_str} was not in blacklist storage")
                    return False

        except ValueError:
            self.logger.error(f"ERROR: Invalid IP address: {ip_str}")
            return False

    def sync_from_nftables(self, sync_to_nftables: bool = False, 
                          add_geolocation: bool = False) -> Tuple[int, int]:
        """
        Bidirectional sync between blacklist and NFTables firewall.
        
        Modes:
        - Import only (default): Fetch IPs from NFTables sets
        - Bidirectional: Also push blacklist IPs to NFTables
        - With geolocation: Add location data (slow, manual use only)
        
        Args:
            sync_to_nftables: If True, push blacklist IPs to NFTables
            add_geolocation: If True, fetch geolocation (rate limited, slow)
            
        Returns:
            Tuple of (IPs added to blacklist, IPs added to NFTables)
        """
        try:
            return self.nft_sync.run_sync(
                sync_to_nftables=sync_to_nftables,
                add_geolocation=add_geolocation,
                max_geo_requests=0
            )
        except Exception as e:
            self.logger.error(f"ERROR: NFTables sync error: {e}")
            return 0, 0
    
    def _normalize_datetime(self, dt) -> datetime:
        """
        Ensure datetime is timezone-aware (UTC).
        
        Converts naive datetimes to UTC and preserves aware datetimes.
        Required for consistent timestamp comparisons across sources.
        """
        if dt is None:
            return None
        if isinstance(dt, datetime):
            if dt.tzinfo is None:
                # Naive datetime - assume UTC
                return dt.replace(tzinfo=timezone.utc)
            return dt
        return None
    
    def bulk_update_metadata(self, metadata_updates: Dict[str, Dict]):
        """
        Bulk update metadata for existing IPs.
        
        Used by automatic enrichment to update IPs with data from
        NFTables port_scanners and CrowdSec historical alerts.
        
        Intelligently merges new metadata with existing entries:
        - Preserves original detection reason and timestamps
        - Updates geolocation if missing
        - Increments event counts
        - Uses most recent timestamps
        
        Args:
            metadata_updates: Dict mapping IP to metadata updates
                Format: {'1.2.3.4': {'reason': '...', 'first_seen': datetime, ...}}
        """
        if not metadata_updates:
            return
        
        # Split by IP version
        ipv4_updates = {}
        ipv6_updates = {}
        
        for ip_str, metadata in metadata_updates.items():
            ip_obj = metadata.get('ip')
            if not ip_obj:
                try:
                    ip_obj = ipaddress.ip_address(ip_str)
                except ValueError:
                    self.logger.warning(f"Invalid IP in metadata update: {ip_str}")
                    continue
            
            if ip_obj.version == 4:
                ipv4_updates[ip_str] = metadata
            else:
                ipv6_updates[ip_str] = metadata
        
        # Update IPv4
        if ipv4_updates:
            self._bulk_update_file(self.config.blacklist_ipv4_file, ipv4_updates)
        
        # Update IPv6
        if ipv6_updates:
            self._bulk_update_file(self.config.blacklist_ipv6_file, ipv6_updates)
        
        self.logger.info(f"Bulk updated {len(metadata_updates)} IPs with enriched metadata")
    
    def _bulk_update_file(self, filename: str, updates: Dict[str, Dict]):
        """
        Internal helper to merge metadata updates with existing blacklist file.

        RACE CONDITION FIX (C8): Protected with lock for atomic read-modify-write.

        Reads existing data, merges with updates, writes back.
        """
        # RACE CONDITION FIX: Acquire lock for atomic read-modify-write
        with self._update_lock:
            existing = self.writer.read_blacklist(filename)

            for ip_str, new_metadata in updates.items():
                if ip_str in existing:
                    # Merge with existing entry - preserve original data
                    existing_entry = existing[ip_str]

                    # Update geolocation only if missing
                    if not existing_entry.get('geolocation') and new_metadata.get('geolocation'):
                        existing_entry['geolocation'] = new_metadata['geolocation']

                    # Use earliest first_seen
                    existing_first = self._normalize_datetime(existing_entry.get('first_seen'))
                    new_first = self._normalize_datetime(new_metadata.get('first_seen'))
                    if new_first and (not existing_first or new_first < existing_first):
                        existing_entry['first_seen'] = new_first

                    # Use most recent last_seen
                    existing_last = self._normalize_datetime(existing_entry.get('last_seen'))
                    new_last = self._normalize_datetime(new_metadata.get('last_seen'))
                    if new_last and (not existing_last or new_last > existing_last):
                        existing_entry['last_seen'] = new_last

                    # For enrichment updates (from NFTables/CrowdSec), use max event count
                    # rather than incrementing to avoid inflation from repeated enrichment
                    new_count = new_metadata.get('event_count', 0)
                    existing_count = existing_entry.get('event_count', 0)
                    if new_count > existing_count:
                        existing_entry['event_count'] = new_count
                else:
                    # New IP - add it
                    existing[ip_str] = new_metadata

            # Write back (use 0 for new_count since this is an update, not detection)
            self.writer.write_blacklist(filename, existing, 0)
            # Lock automatically released here
    
    def get_all_blacklisted_ips(self) -> Dict[str, Set[ipaddress.IPv4Address | ipaddress.IPv6Address]]:
        """
        Retrieve all blocked IPs from all sources.
        
        Aggregates IPs from:
        - IPv4 blacklist file
        - IPv6 blacklist file
        - Prelogin-specific blacklist
        - Manual blacklist
        
        Returns:
            Dict with 'ipv4' and 'ipv6' keys containing IP sets
        """
        ipv4_ips = set()
        ipv6_ips = set()
        
        # Read from main blacklist files
        for filename in [self.config.blacklist_ipv4_file, self.config.blacklist_ipv6_file, 
                        self.config.prelogin_bruteforce_file]:
            ips = self._read_ips_from_file(filename)
            for ip in ips:
                (ipv4_ips if ip.version == 4 else ipv6_ips).add(ip)
        
        # Add manual IPs
        manual_ips = self.writer.get_manual_ips(self.manual_blacklist_file)
        for ip_str in manual_ips:
            try:
                ip = ipaddress.ip_address(ip_str)
                (ipv4_ips if ip.version == 4 else ipv6_ips).add(ip)
            except ValueError:
                pass
        
        return {'ipv4': ipv4_ips, 'ipv6': ipv6_ips}
    
    def show_blacklist(self):
        """
        Display formatted blacklist with geolocation and threat intelligence.
        
        Shows:
        - IP addresses with country/ISP information
        - Block reason and confidence level
        - Event counts and detection source
        - Statistics (total IPs, manual IPs)
        """
        print("TRIBANFT BLACKLIST INFORMATION")
        print("=" * 120)
        print(f"{'IP':<18} {'Country':<15} {'ISP':<20} {'Reason':<25} {'Confidence':<12} {'Source'}")
        print("-" * 120)
        
        # Use adapter for storage abstraction
        all_ips = self.writer.read_blacklist(self.config.blacklist_ipv4_file)
        
        for ip_str, info in list(sorted(all_ips.items()))[:50]:
            geo = info.get('geolocation', {})
            country = geo.get('country', 'Unknown') if geo else 'Unknown'
            isp = geo.get('isp', 'Unknown ISP') if geo else 'Unknown ISP'
            reason = info.get('reason', 'Unknown')[:25]
            conf = info.get('confidence', 'unknown')
            source = info.get('source', 'unknown')
            print(f"{ip_str:<18} {country:<15} {isp:<20} {reason:<25} {conf:<12} {source}")
        
        if len(all_ips) > 50:
            print(f"... and {len(all_ips) - 50} more IPs")
        
        # Statistics
        blacklisted_ips = self.get_all_blacklisted_ips()
        total = len(blacklisted_ips['ipv4']) + len(blacklisted_ips['ipv6'])
        manual = len(self.writer.get_manual_ips(self.manual_blacklist_file))
        
        print("-" * 120)
        print(f"Total: {total} (IPv4: {len(blacklisted_ips['ipv4'])}, IPv6: {len(blacklisted_ips['ipv6'])})")
        print(f"Manual IPs: {manual}")

    def sync_database_to_files(self):
        """
        Force synchronization from database to blacklist files.

        RACE CONDITION FIX (C8): Protected with lock to prevent concurrent modifications.

        Useful for manual sync or recovery scenarios.
        Returns True if sync successful.
        """
        if not self.config.use_database:
            self.logger.warning("WARNING: Not using database, nothing to sync")
            return True

        self.logger.info("Forcing database to file sync...")

        try:
            # RACE CONDITION FIX: Acquire lock to prevent concurrent modifications during sync
            with self._update_lock:
                # Get all IPv4 entries from database
                ipv4_data = self.writer.read_blacklist(self.config.blacklist_ipv4_file)

                # Write to file using the adapter's sync logic
                self.writer.write_blacklist(self.config.blacklist_ipv4_file, ipv4_data, 0)

                # Also sync IPv6
                ipv6_data = self.writer.read_blacklist(self.config.blacklist_ipv6_file)
                if ipv6_data:
                    self.writer.write_blacklist(self.config.blacklist_ipv6_file, ipv6_data, 0)

                self.logger.info(f"SUCCESS: Database sync complete: {len(ipv4_data)} IPv4, {len(ipv6_data)} IPv6")
                return True

        except Exception as e:
            self.logger.error(f"ERROR: Database sync failed: {e}")
            return False
    
    # ========================================================================
    # INTERNAL HELPERS
    # ========================================================================
    
    def _prepare_detection_ips(self, detections: List[DetectionResult]) -> Dict:
        """
        Convert DetectionResult objects to blacklist entry format.
        
        Extracts and structures all metadata from detections for storage.
        Filters out whitelisted IPs before preparation.
        NOW INCLUDES: Guaranteed timestamps + event_types extraction
        """
        now = datetime.now()
        
        return {
            str(d.ip): {
                'ip': d.ip,
                'reason': d.reason,
                'confidence': d.confidence.value,
                'event_count': d.event_count,
                'geolocation': d.geolocation,
                'first_seen': d.first_seen or now,
                'last_seen': d.last_seen or now,
                'date_added': now,
                'timestamp': now,
                'source': 'automatic',
                'event_types': list(set(e.event_type.value for e in d.source_events)) if d.source_events else []
            }
            for d in detections if not self.whitelist_manager.is_whitelisted(d.ip)
        }
    
    def _update_blacklist_file(self, filename: str, new_ips_info: Dict, replace: bool = False):
        """
        Merge new IPs with existing blacklist and write to storage atomically.

        RACE CONDITION FIX (C8): Holds lock across entire read-modify-write cycle.
        Prevents concurrent updates from overwriting each other's changes.

        Without lock:
        - Thread A reads, Thread B reads (same data)
        - Thread A modifies, Thread B modifies (different changes)
        - Thread A writes, Thread B writes (B overwrites A - DATA LOSS!)

        With lock:
        - Thread A acquires lock, reads, modifies, writes, releases
        - Thread B waits, then reads updated data, modifies, writes
        - All changes preserved, no data loss

        Handles merging of automatic detections, manual additions, and
        existing entries while preserving metadata and timestamps.

        Args:
            filename: Path to blacklist file
            new_ips_info: Dict of new IP metadata
            replace: If True, replace existing entries with new data (for CSV import).
                     If False, preserve existing metadata and only update timestamps (default).

        FIXED: Preserves existing metadata when re-detecting IPs.
        Only updates timestamps and increments event counts.
        """
        # RACE CONDITION FIX: Acquire lock for entire read-modify-write operation
        with self._update_lock:
            existing = self.writer.read_blacklist(filename)
            manual = self._get_manual_ips_info()

            # INTELLIGENT MERGE: Preserve existing metadata (unless replace=True)
            merged = existing.copy()

            for ip_str, new_info in new_ips_info.items():
                if ip_str in existing:
                    if replace:
                        # REPLACE mode: Overwrite existing entry with new trusted data
                        merged[ip_str] = new_info
                    else:
                        # MERGE mode: IP already exists - UPDATE only timestamps and events
                        existing_entry = merged[ip_str]

                        # Preserve original metadata (reason, confidence, source, first_seen, date_added)
                        # Update last_seen to most recent timestamp (use max to ensure forward progression)
                        # Normalize datetimes to handle timezone-aware/naive comparison
                        new_last_seen = self._normalize_datetime(new_info.get('last_seen'))
                        existing_last_seen = self._normalize_datetime(existing_entry.get('last_seen'))
                        if new_last_seen and existing_last_seen:
                            existing_entry['last_seen'] = max(new_last_seen, existing_last_seen)
                        elif new_last_seen:
                            existing_entry['last_seen'] = new_last_seen

                        # Increment event count (accumulate total events seen)
                        # Note: This counts total detection events, not unique incidents
                        existing_entry['event_count'] = existing_entry.get('event_count', 0) + new_info.get('event_count', 0)

                        # Merge event_types (union of both sets)
                        existing_types = set(existing_entry.get('event_types', []))
                        new_types = set(new_info.get('event_types', []))
                        existing_entry['event_types'] = list(existing_types | new_types)

                        # Keep original first_seen, date_added, reason, confidence, source
                        # (Don't overwrite with new_info values)

                else:
                    # New IP - add completely
                    merged[ip_str] = new_info

            # Add manual IPs (they take precedence over automatic)
            # Manual entries completely override any existing automatic detections
            for ip_str, manual_info in manual.items():
                merged[ip_str] = manual_info

            # Filter whitelisted
            all_ips = self._filter_whitelisted_ips(merged)
            new_count = len(set(new_ips_info.keys()) - set(existing.keys()))
            self.writer.write_blacklist(filename, all_ips, new_count)
            # Lock automatically released here by context manager
    
    def _get_manual_ips_info(self) -> Dict:
        """Retrieve manual IPs with enriched metadata and timestamps."""
        now = datetime.now()
        manual_ips = self.writer.get_manual_ips(self.manual_blacklist_file)
        
        return {
            ip_str: {
                'ip': ipaddress.ip_address(ip_str),
                'reason': 'Manually added (from manual blacklist)',
                'confidence': 'manual',
                'event_count': 0,
                'geolocation': self.geolocation_manager.get_ip_info(ipaddress.ip_address(ip_str)) if self.geolocation_manager else None,
                'first_seen': now,
                'last_seen': now,
                'date_added': now,
                'source': 'manual'
            }
            for ip_str in manual_ips
            if not self.whitelist_manager.is_whitelisted(ipaddress.ip_address(ip_str))
        }
    
    def _filter_whitelisted_ips(self, ips_info: Dict) -> Dict:
        """Remove whitelisted IPs from blacklist data."""
        filtered = {}
        for ip_str, info in ips_info.items():
            try:
                if not self.whitelist_manager.is_whitelisted(ipaddress.ip_address(ip_str)):
                    filtered[ip_str] = info
            except ValueError:
                continue
        return filtered
    
    def _add_to_manual_blacklist(self, ip_str: str, info: Dict):
        """
        Add IP to manual blacklist file with formatted metadata.
        
        Preserves existing entries and appends new IP with comprehensive
        information including geolocation, reason, and timestamps.
        """
        manual_path = Path(self.manual_blacklist_file)
        entries = {}
        
        if manual_path.exists():
            current_ip = None
            with open(manual_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        current_ip = line
                        entries[current_ip] = {'ip': current_ip}
        
        entries[ip_str] = info
        self._write_manual_blacklist(manual_path, entries)
    
    def _write_manual_blacklist(self, path: Path, entries: Dict):
        """Write manual blacklist file with enhanced formatting and timestamps."""
        with open(path, 'w') as f:
            f.write(f"# Enhanced Manual Blacklist - Updated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("#" + "="*100 + "\n")
            
            for ip_str, info in sorted(entries.items()):
                geo = info.get('geolocation', {})
                country = geo.get('country', 'Unknown') if geo else 'Unknown'
                isp = geo.get('isp', 'Unknown ISP') if geo else 'Unknown ISP'
                city = geo.get('city', '') if geo else ''
                location = f"{country}, {city}" if city else country
                
                # Format timestamps
                first_seen = info.get('first_seen', datetime.now())
                last_seen = info.get('last_seen', datetime.now())
                date_added = info.get('date_added', datetime.now())
                
                first_str = first_seen.strftime('%Y-%m-%d %H:%M') if isinstance(first_seen, datetime) else 'Unknown'
                last_str = last_seen.strftime('%Y-%m-%d %H:%M') if isinstance(last_seen, datetime) else 'Unknown'
                added_str = date_added.strftime('%Y-%m-%d %H:%M') if isinstance(date_added, datetime) else 'Unknown'
                
                f.write(f"# IP: {ip_str} | {location} | {isp} | ")
                f.write(f"Reason: {info.get('reason', 'Unknown')} | ")
                f.write(f"Confidence: {info.get('confidence', 'unknown')} | ")
                f.write(f"Events: {info.get('event_count', 0)} | ")
                f.write(f"First: {first_str} | Last: {last_str} | Added: {added_str}\n")
                f.write(f"{ip_str}\n")
    
    def _add_to_main_blacklists(self, new_ips_info: Dict):
        """Distribute IPs to appropriate IPv4/IPv6 blacklist files."""
        ipv4 = {ip: info for ip, info in new_ips_info.items() if info['ip'].version == 4}
        ipv6 = {ip: info for ip, info in new_ips_info.items() if info['ip'].version == 6}
        
        if ipv4:
            self._update_blacklist_file(self.config.blacklist_ipv4_file, ipv4)
        if ipv6:
            self._update_blacklist_file(self.config.blacklist_ipv6_file, ipv6)
    
    def _log_new_ips(self, new_ips_info: Dict):
        """Log newly blocked IPs with geolocation context."""
        for ip_str, info in new_ips_info.items():
            geo = info.get('geolocation', {})
            location = f"{geo.get('country', 'Unknown')} ({geo.get('isp', 'Unknown ISP')})" if geo else "Unknown"
            
            # Format timestamps for logging
            first_seen = info.get('first_seen')
            last_seen = info.get('last_seen')
            first_str = first_seen.strftime('%Y-%m-%d %H:%M') if isinstance(first_seen, datetime) else 'Unknown'
            last_str = last_seen.strftime('%Y-%m-%d %H:%M') if isinstance(last_seen, datetime) else 'Unknown'
            
            self.logger.warning(
                f"Blocking {ip_str} - {info['reason']} - {location} "
                f"(First: {first_str}, Last: {last_str})"
            )
    
    def _read_ips_from_file(self, filename: str) -> Set:
        """Parse IP addresses from blacklist file, ignoring comments."""
        ips = set()
        path = Path(filename)
        if path.exists():
            with open(path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        try:
                            ips.add(ipaddress.ip_address(line))
                        except ValueError:
                            pass
        return ips
    
    def _print_blacklist_entry(self, line: str):
        """Parse and display formatted blacklist comment line."""
        parts = line.split('|')
        if len(parts) >= 4:
            ip = parts[0].replace('# IP:', '').strip()
            country = parts[1].strip() if len(parts) > 1 else 'Unknown'
            isp = parts[2].strip() if len(parts) > 2 else 'Unknown ISP'
            reason = parts[3].strip() if len(parts) > 3 else 'Unknown'
            
            confidence = source = 'unknown'
            for part in parts:
                if 'Confidence:' in part:
                    confidence = part.split('Confidence:')[1].strip().split()[0]
                if 'Source:' in part:
                    source = part.split('Source:')[1].strip()
            
            print(f"{ip:<18} {country:<15} {isp:<20} {reason:<25} {confidence:<12} {source}")
    
    def _search_logs_for_ip(self, ip_str: str, search_window_hours: int = 72) -> Dict:
        """Compatibility wrapper for log searching functionality."""
        return self.log_searcher.search_ip_activity(ip_str, search_window_hours)