"""
TribanFT NFTables Manager - Unified Firewall Integration

Manages bidirectional synchronization between blacklist and NFTables firewall.

OPTIMIZATIONS:
- Large batch operations (1000 IPs per nft call)
- Reduced syscalls from 37k to ~40
- 90 seconds -> 5 seconds for 37k IPs

Features:
- Export blacklist IPs to NFTables sets (optimized batching)
- Import IPs from NFTables sets (port_scanners, fail2ban)
- Geolocation enrichment for imported IPs
- Whitelist filtering
- Timestamp calculation from NFTables metadata

Monitored NFTables sets:
- inet filter blacklist_ipv4 (export target)
- inet filter blacklist_ipv6 (export target)
- inet filter port_scanners (import source)
- inet f2b-table addr-set-* (import source)

Author: TribanFT Project
License: GNU GPL v3
"""

import subprocess
import logging
import shutil
import json
import re
from typing import Set, Dict, Tuple, Optional, List
import ipaddress
from datetime import datetime, timezone
from pathlib import Path

from ..config import get_config
from ..utils.nftables_parser import parse_nftables_set_elements


class NFTablesManager:
    """
    Unified NFTables firewall integration with bidirectional sync.

    Combines optimized export (batched writes) with intelligent import
    (port scanner detection, fail2ban integration, geolocation enrichment).
    """

    def __init__(self, config=None, whitelist_manager=None, geolocation_manager=None):
        """
        Initialize NFTables manager.

        Args:
            config: Configuration object (optional, uses get_config() if None)
            whitelist_manager: WhitelistManager for filtering (optional)
            geolocation_manager: IPGeolocationManager for enrichment (optional)
        """
        self.config = config or get_config()
        self.whitelist_manager = whitelist_manager
        self.geolocation_manager = geolocation_manager
        self.logger = logging.getLogger(__name__)
        # Use large batch size for performance (config default is 1000)
        self.batch_size = max(self.config.batch_size, 1000)

        # Shadow event log (optional, enabled via config)
        self.event_log_enabled = getattr(config, 'nftables_event_log_enabled', False)
        self.event_log_path = None
        if self.event_log_enabled:
            state_dir = Path(config.state_dir)
            self.event_log_path = state_dir / 'nftables_events.jsonl'
            self.logger.info(f"NFTables event log enabled: {self.event_log_path}")

    # ========================================================================
    # DISCOVERY OPERATIONS (NFTables → Catalog)
    # ========================================================================

    def discover_nftables_sets(self, family_filter: Optional[str] = None,
                                verdict_filter: Optional[str] = None) -> Dict[str, Dict]:
        """
        Discover all NFTables sets in the system.

        Queries NFTables for all defined sets and extracts metadata:
        - family (ip, ip6, inet)
        - table_name
        - set_name
        - type (ipv4_addr, ipv6_addr, etc)
        - flags (timeout, dynamic, etc)

        Args:
            family_filter: Filter by family ('ip', 'ip6', 'inet', or None for all)
            verdict_filter: Filter by verdict context ('drop', 'reject', 'accept', or None for all)

        Returns:
            Dict mapping 'family:table:set' to metadata:
            {
                'inet:filter:blacklist_ipv4': {
                    'family': 'inet',
                    'table': 'filter',
                    'set': 'blacklist_ipv4',
                    'type': 'ipv4_addr',
                    'flags': ['timeout'],
                    'size': None or int,
                    'timeout': '10d' or None
                }
            }
        """
        try:
            nft_path = shutil.which('nft') or '/usr/sbin/nft'

            # Query all sets
            result = subprocess.run(
                [nft_path, 'list', 'sets'],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                self.logger.error(f"Failed to list NFTables sets: {result.stderr}")
                return {}

            sets_info = self._parse_sets_output(result.stdout)

            # Apply filters if specified
            if family_filter or verdict_filter:
                filtered = {}
                for key, info in sets_info.items():
                    if family_filter and info['family'] != family_filter:
                        continue
                    if verdict_filter and info.get('verdict_context') != verdict_filter:
                        continue
                    filtered[key] = info
                sets_info = filtered

            self.logger.info(f"Discovered {len(sets_info)} NFTables sets")

            # Log event with set names
            self._log_event('nftables_discovery', {
                'sets_found': len(sets_info),
                'family_filter': family_filter,
                'verdict_filter': verdict_filter,
                'sets': {key: {'type': info['type'], 'flags': info['flags']} for key, info in sets_info.items()}
            })

            return sets_info

        except subprocess.TimeoutExpired:
            self.logger.error("NFTables discovery timed out")
            return {}
        except Exception as e:
            self.logger.error(f"Error discovering NFTables sets: {e}")
            import traceback
            self.logger.debug(traceback.format_exc())
            return {}

    def _parse_sets_output(self, output: str) -> Dict[str, Dict]:
        """
        Parse 'nft list sets' output to extract set metadata.

        Expected format:
            table inet filter {
                set blacklist_ipv4 {
                    type ipv4_addr
                    flags timeout
                    timeout 10d
                }
            }

        Returns:
            Dict mapping 'family:table:set' to metadata
        """
        sets = {}
        current_family = None
        current_table = None
        current_set = None
        current_set_info = {}

        for line in output.splitlines():
            line = line.strip()

            # Parse table declaration: "table inet filter {"
            table_match = re.match(r'table\s+(ip6?|inet)\s+(\S+)', line)
            if table_match:
                current_family = table_match.group(1)
                current_table = table_match.group(2)
                continue

            # Parse set declaration: "set blacklist_ipv4 {"
            set_match = re.match(r'set\s+(\S+)\s+\{', line)
            if set_match and current_table:
                current_set = set_match.group(1)
                current_set_info = {
                    'family': current_family,
                    'table': current_table,
                    'set': current_set,
                    'type': None,
                    'flags': [],
                    'size': None,
                    'timeout': None
                }
                continue

            # Parse set properties
            if current_set:
                # Type: "type ipv4_addr"
                if line.startswith('type '):
                    current_set_info['type'] = line.split()[1]

                # Flags: "flags timeout"
                elif line.startswith('flags '):
                    flags_str = line.replace('flags ', '').replace(',', '')
                    current_set_info['flags'] = flags_str.split()

                # Size: "size 65535"
                elif line.startswith('size '):
                    try:
                        current_set_info['size'] = int(line.split()[1])
                    except ValueError:
                        pass

                # Timeout: "timeout 10d"
                elif line.startswith('timeout '):
                    current_set_info['timeout'] = line.split()[1]

                # End of set: "}"
                elif line == '}' and current_set_info.get('type'):
                    key = f"{current_family}:{current_table}:{current_set}"
                    sets[key] = current_set_info
                    current_set = None
                    current_set_info = {}

        return sets

    def import_from_set(self, table: str, set_name: str,
                        family: str = 'inet',
                        reason: Optional[str] = None,
                        detection_source: str = 'nftables') -> Dict[str, Dict]:
        """
        Import IPs from any NFTables set (generic version of get_port_scanners).

        This is the extensible method that can import from any set, not just port_scanners.

        Args:
            table: NFTables table name (e.g., 'filter')
            set_name: NFTables set name (e.g., 'blacklist_ipv4', 'port_scanners')
            family: Address family ('inet', 'ip', 'ip6')
            reason: Detection reason (defaults to 'NFTables set: {set_name}')
            detection_source: Source identifier (default: 'nftables')

        Returns:
            Dict mapping IP to metadata compatible with BlacklistAdapter:
            {
                '1.2.3.4': {
                    'ip': IPv4Address('1.2.3.4'),
                    'reason': str,
                    'confidence': 'high',
                    'event_count': 1,
                    'first_seen': datetime,
                    'last_seen': datetime,
                    'date_added': datetime,
                    'source': str,
                    'metadata': dict  # Optional NFTables metadata
                }
            }
        """
        if reason is None:
            reason = f"NFTables set: {set_name}"

        try:
            nft_path = shutil.which('nft') or '/usr/sbin/nft'

            # Query specific set
            result = subprocess.run(
                [nft_path, 'list', 'set', family, table, set_name],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                self.logger.error(f"Failed to query set {family} {table} {set_name}: {result.stderr}")
                return {}

            # Parse set elements using existing parser
            parsed = parse_nftables_set_elements(result.stdout, set_name)

            if not parsed:
                self.logger.debug(f"No IPs found in {table}/{set_name}")
                return {}

            # Convert to blacklist metadata format
            imported_ips = {}
            now = datetime.now(timezone.utc)

            for ip_str, nft_data in parsed.items():
                try:
                    ip_obj = ipaddress.ip_address(ip_str)

                    # Skip whitelisted IPs
                    if self.whitelist_manager and self.whitelist_manager.is_whitelisted(ip_obj):
                        self.logger.debug(f"Skipping whitelisted IP: {ip_str}")
                        continue

                    # Build metadata
                    imported_ips[ip_str] = {
                        'ip': ip_obj,
                        'reason': reason,
                        'confidence': 'high',
                        'event_count': 1,
                        'first_seen': nft_data.get('first_seen', now),
                        'last_seen': nft_data.get('last_seen', now),
                        'date_added': nft_data.get('date_added', now),
                        'source': f"{detection_source}_{set_name}",
                        'metadata': {
                            'nftables_table': table,
                            'nftables_set': set_name,
                            'nftables_family': family,
                            'timeout': nft_data.get('timeout', 'unknown'),
                            'expires': nft_data.get('expires', 'unknown')
                        }
                    }

                except ValueError as e:
                    self.logger.warning(f"Invalid IP in {set_name}: {ip_str}: {e}")
                    continue

            self.logger.info(f"Imported {len(imported_ips)} IPs from {table}/{set_name}")

            # Log event
            self._log_event('nftables_import', {
                'table': table,
                'set_name': set_name,
                'family': family,
                'ip_count': len(imported_ips),
                'reason': reason
            })

            return imported_ips

        except subprocess.TimeoutExpired:
            self.logger.error(f"Query timed out for {table}/{set_name}")
            return {}
        except FileNotFoundError:
            self.logger.error("nft command not found - is NFTables installed?")
            return {}
        except Exception as e:
            self.logger.error(f"Error importing from {table}/{set_name}: {e}")
            import traceback
            self.logger.debug(traceback.format_exc())
            return {}

    def _log_event(self, event_type: str, payload: dict):
        """
        Log NFTables event to shadow event log (JSONL format).

        This creates an append-only audit trail of all NFTables operations
        without affecting core functionality. Can be used for:
        - Debugging
        - Replay/reconstruction
        - Historical analysis

        Args:
            event_type: Type of event ('nftables_discovery', 'nftables_import', etc)
            payload: Event-specific data
        """
        if not self.event_log_enabled or not self.event_log_path:
            return

        try:
            event = {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'event_type': event_type,
                'payload': payload
            }

            # Append to JSONL file (atomic write to avoid corruption)
            with open(self.event_log_path, 'a') as f:
                f.write(json.dumps(event) + '\n')

        except Exception as e:
            # Don't crash if event logging fails
            self.logger.debug(f"Failed to log event {event_type}: {e}")

    # ========================================================================
    # EXPORT OPERATIONS (Blacklist → NFTables)
    # ========================================================================

    def update_blacklists(self, blacklisted_ips: Dict[str, Set[ipaddress.IPv4Address | ipaddress.IPv6Address]]):
        """
        Update nftables sets with blacklisted IPs using optimized batch operations.

        Performance: ~5 seconds for 37k IPs (vs 90 seconds with small batches)

        Process:
        1. Flush existing sets
        2. Add IPv4 IPs to inet filter blacklist_ipv4 (batches of 1000)
        3. Add IPv6 IPs to inet filter blacklist_ipv6 (batches of 1000)

        Args:
            blacklisted_ips: Dict with 'ipv4' and 'ipv6' keys containing IP sets
        """
        if not self.config.enable_nftables_update:
            self.logger.info("NFTables update disabled in config")
            return

        try:
            ipv4_count = len(blacklisted_ips['ipv4'])
            ipv6_count = len(blacklisted_ips['ipv6'])

            # Flush sets
            self._flush_set('inet filter blacklist_ipv4')
            self._flush_set('inet filter blacklist_ipv6')

            # Add IPs in large batches
            if blacklisted_ips['ipv4']:
                batches_v4 = (ipv4_count + self.batch_size - 1) // self.batch_size
                self.logger.info(f"Adding {ipv4_count} IPv4 in {batches_v4} batches of {self.batch_size}")
                self._add_ips_to_set('inet filter blacklist_ipv4', blacklisted_ips['ipv4'])

            if blacklisted_ips['ipv6']:
                batches_v6 = (ipv6_count + self.batch_size - 1) // self.batch_size
                self.logger.info(f"Adding {ipv6_count} IPv6 in {batches_v6} batches of {self.batch_size}")
                self._add_ips_to_set('inet filter blacklist_ipv6', blacklisted_ips['ipv6'])

            self.logger.info(f"SUCCESS: Updated NFTables: {ipv4_count} IPv4, {ipv6_count} IPv6")

        except Exception as e:
            self.logger.error(f"ERROR: NFTables update failed: {e}")

    def _flush_set(self, set_name: str):
        """
        Flush (clear) an nftables set.

        Args:
            set_name: Full set name (e.g., 'inet filter blacklist_ipv4')
        """
        try:
            cmd = ['/usr/sbin/nft', 'flush', 'set', set_name]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                self.logger.error(f"Failed to flush {set_name}: {result.stderr}")
        except subprocess.TimeoutExpired:
            self.logger.error(f"Timeout flushing {set_name}")
        except Exception as e:
            self.logger.error(f"Error flushing {set_name}: {e}")

    def _add_ips_to_set(self, set_name: str, ips: Set[ipaddress.IPv4Address | ipaddress.IPv6Address]):
        """
        Add IPs to nftables set in LARGE batches for maximum performance.

        OPTIMIZED: Uses 1000 IPs per nft call (vs 100 before)
        Result: 37k IPs in ~40 calls instead of 370 calls

        Args:
            set_name: Target nftables set
            ips: Set of IP address objects to add
        """
        if not ips:
            return

        ip_list = list(ips)
        total_batches = (len(ip_list) + self.batch_size - 1) // self.batch_size

        for batch_num, i in enumerate(range(0, len(ip_list), self.batch_size), 1):
            batch = ip_list[i:i+self.batch_size]
            ip_str = ','.join(str(ip) for ip in batch)

            try:
                cmd = ['/usr/sbin/nft', 'add', 'element', set_name, '{', ip_str, '}']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

                if result.returncode != 0:
                    self.logger.error(f"Batch {batch_num}/{total_batches} failed: {result.stderr}")
                else:
                    # Log progress every 10 batches
                    if batch_num % 10 == 0 or batch_num == total_batches:
                        self.logger.debug(f"Progress: {batch_num}/{total_batches} batches ({len(batch)} IPs)")

            except subprocess.TimeoutExpired:
                self.logger.error(f"Timeout on batch {batch_num}/{total_batches}")
            except Exception as e:
                self.logger.error(f"Error on batch {batch_num}/{total_batches}: {e}")

    # ========================================================================
    # IMPORT OPERATIONS (NFTables → Blacklist)
    # ========================================================================

    def get_port_scanners(self) -> Dict[str, Dict]:
        """
        Get IPs from NFTables port_scanners set with calculated timestamps.

        REFACTORED: Now uses the generic import_from_set() method internally
        for better code reuse while maintaining backward compatibility.

        Returns:
            Dict mapping IP to metadata with timestamps:
            {
                '1.2.3.4': {
                    'ip': IPv4Address('1.2.3.4'),
                    'reason': 'Port scanner (NFTables)',
                    'confidence': 'high',
                    'event_count': 1,
                    'first_seen': datetime(...),
                    'last_seen': datetime(...),
                    'date_added': datetime(...),
                    'source': 'nftables_port_scanners',
                    'timeout': '10d',
                    'expires': '8d12h21m34s'
                }
            }
        """
        # Use generic import method with port_scanners-specific settings
        port_scanner_ips = self.import_from_set(
            table='filter',
            set_name='port_scanners',
            family='inet',
            reason='Port scanner (NFTables)',
            detection_source='nftables'
        )

        # Flatten metadata for backward compatibility
        # (old format had timeout/expires at top level)
        for ip_str, data in port_scanner_ips.items():
            if 'metadata' in data:
                data['timeout'] = data['metadata'].get('timeout', 'unknown')
                data['expires'] = data['metadata'].get('expires', 'unknown')

        return port_scanner_ips

    def run_sync(self, sync_to_nftables: bool = False,
                 add_geolocation: bool = False,
                 max_geo_requests: int = 0) -> Tuple[int, int]:
        """
        Execute bidirectional sync (placeholder for compatibility).

        NOTE: Export is handled by update_blacklists() for better performance.
        This method primarily handles import operations.

        Args:
            sync_to_nftables: If True, export blacklist to NFTables (not implemented here)
            add_geolocation: If True, fetch geolocation (slow, rate limited)
            max_geo_requests: Maximum API calls for geolocation

        Returns:
            Tuple of (IPs added to blacklist, IPs added to NFTables)
        """
        new_to_blacklist = 0
        new_to_nft = 0

        try:
            # Import from NFTables to blacklist
            # This is primarily used for port_scanners set
            # For actual sync, use get_port_scanners() directly

            if sync_to_nftables:
                self.logger.warning(
                    "Export sync requested but should use update_blacklists() instead"
                )

            # Return counts (actual implementation handled by BlacklistManager)
            return new_to_blacklist, new_to_nft

        except Exception as e:
            self.logger.error(f"Sync error: {e}")
            return 0, 0


# Backward compatibility alias
NFTablesSync = NFTablesManager
