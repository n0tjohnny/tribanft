"""
TribanFT NFTables Sync Manager

Bidirectional synchronization between blacklist and NFTables firewall.

Manages:
- Importing IPs from NFTables sets to blacklist
- Exporting blacklist IPs to NFTables sets
- Geolocation enrichment for imported IPs
- Rate limiting for API calls

Monitored NFTables sets:
- inet filter blacklist_ipv4
- inet filter port_scanners
- inet f2b-table addr-set-*

Author: TribanFT Project
License: GNU GPL v3
"""

import subprocess
import logging
from typing import Set, Tuple
import ipaddress
from datetime import datetime

from ..config import get_config


class NFTablesSync:
    """Bidirectional sync between blacklist and NFTables"""
    
    def __init__(self, config, whitelist_manager, geolocation_manager=None):
        """
        Initialize NFTables sync manager.
        
        Args:
            config: Configuration object
            whitelist_manager: WhitelistManager for filtering
            geolocation_manager: Optional geolocation service
        """
        self.config = config
        self.whitelist_manager = whitelist_manager
        self.geolocation_manager = geolocation_manager
        self.logger = logging.getLogger(__name__)
    
    def run_sync(self, sync_to_nftables: bool = False, 
                 add_geolocation: bool = False,
                 max_geo_requests: int = 0) -> Tuple[int, int]:
        """
        Execute bidirectional sync.
        
        Args:
            sync_to_nftables: If True, export blacklist to NFTables
            add_geolocation: If True, fetch geolocation (slow, rate limited)
            max_geo_requests: Maximum API calls for geolocation
            
        Returns:
            Tuple of (IPs added to blacklist, IPs added to NFTables)
        """
        new_to_blacklist = 0
        new_to_nft = 0
        
        try:
            # Import from NFTables to blacklist
            nft_ips = self._get_nftables_ips()
            self.logger.info(f"Found {len(nft_ips)} IPs in NFTables")
            
            # Filter and process
            filtered = self._filter_ips(nft_ips)
            new_to_blacklist = len(filtered)
            
            if filtered and add_geolocation:
                self._add_geolocation(filtered, max_geo_requests)
            
            # Export to NFTables (if enabled)
            if sync_to_nftables:
                new_to_nft = self._sync_to_nftables()
            
        except Exception as e:
            self.logger.error(f"Sync error: {e}")
        
        return new_to_blacklist, new_to_nft
    
    def _get_nftables_ips(self) -> Set[str]:
        """
        Query NFTables for all blocked IPs.
        
        Returns:
            Set of IP address strings
        """
        ips = set()
        
        try:
            result = subprocess.run(
                ['/usr/sbin/nft', 'list', 'sets'],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode == 0:
                # Parse output for IP addresses
                for line in result.stdout.split('\n'):
                    if 'elements' in line:
                        # Extract IPs from elements line
                        pass  # Implementation depends on nft output format
        except Exception as e:
            self.logger.error(f"NFTables query failed: {e}")
        
        return ips
    
    def _filter_ips(self, ips: Set[str]) -> Set[str]:
        """
        Filter IPs removing whitelisted ones.
        
        Args:
            ips: Set of IP strings
            
        Returns:
            Filtered set excluding whitelisted IPs
        """
        filtered = set()
        for ip_str in ips:
            try:
                ip = ipaddress.ip_address(ip_str)
                if not self.whitelist_manager.is_whitelisted(ip):
                    filtered.add(ip_str)
            except ValueError:
                continue
        return filtered
    
    def _add_geolocation(self, ips: Set[str], max_requests: int):
        """
        Add geolocation data to IPs (rate limited).
        
        Args:
            ips: Set of IP strings
            max_requests: Maximum API calls to make
        """
        if not self.geolocation_manager:
            return
        
        count = 0
        for ip_str in ips:
            if count >= max_requests:
                break
            try:
                ip = ipaddress.ip_address(ip_str)
                self.geolocation_manager.get_ip_info(ip)
                count += 1
            except Exception as e:
                self.logger.warning(f"Geolocation failed for {ip_str}: {e}")
    
    def _sync_to_nftables(self) -> int:
        """
        Export blacklist IPs to NFTables.
        
        Returns:
            Number of IPs added to NFTables
        """
        # Implementation would read blacklist and add to nft
        return 0