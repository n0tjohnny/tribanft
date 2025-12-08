"""
TribanFT NFTables Manager

Manages nftables firewall integration for IP blocking.

Synchronizes blacklisted IPs with nftables sets for immediate network-level blocking.
Supports both IPv4 and IPv6 with batch operations for performance.

Key operations:
- Flush and rebuild nftables blacklist sets
- Batch IP additions (configurable batch size)
- Separate IPv4/IPv6 set management

Requires root/sudo access to nft command.

Author: TribanFT Project
License: GNU GPL v3
"""

import subprocess
import logging
from typing import Set, Dict
import ipaddress
from pathlib import Path

from ..config import get_config


class NFTablesManager:
    """Manages nftables firewall blacklist sets."""
    
    def __init__(self):
        """Initialize nftables manager with configuration."""
        self.config = get_config()
        self.logger = logging.getLogger(__name__)
    
    def update_blacklists(self, blacklisted_ips: Dict[str, Set[ipaddress.IPv4Address | ipaddress.IPv6Address]]):
        """
        Update nftables sets with blacklisted IPs.
        
        Process:
        1. Flush existing sets
        2. Add IPv4 IPs to inet filter blacklist_ipv4
        3. Add IPv6 IPs to inet filter blacklist_ipv6
        
        Args:
            blacklisted_ips: Dict with 'ipv4' and 'ipv6' keys containing IP sets
        """
        if not self.config.enable_nftables_update:
            self.logger.info("NFTables update disabled in config")
            return
        
        try:
            # Flush sets
            self._flush_set('inet filter blacklist_ipv4')
            self._flush_set('inet filter blacklist_ipv6')
            
            # Add IPs
            if blacklisted_ips['ipv4']:
                self._add_ips_to_set('inet filter blacklist_ipv4', blacklisted_ips['ipv4'])
            
            if blacklisted_ips['ipv6']:
                self._add_ips_to_set('inet filter blacklist_ipv6', blacklisted_ips['ipv6'])
            
            self.logger.info(
                f"Updated nftables: {len(blacklisted_ips['ipv4'])} IPv4, "
                f"{len(blacklisted_ips['ipv6'])} IPv6"
            )
            
        except Exception as e:
            self.logger.error(f"NFTables update failed: {e}")
    
    def _flush_set(self, set_name: str):
        """
        Flush (clear) an nftables set.
        
        Args:
            set_name: Full set name (e.g., 'inet filter blacklist_ipv4')
        """
        cmd = ['/usr/sbin/nft', 'flush', 'set', set_name]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            self.logger.error(f"Failed to flush {set_name}: {result.stderr}")
    
    def _add_ips_to_set(self, set_name: str, ips: Set[ipaddress.IPv4Address | ipaddress.IPv6Address]):
        """
        Add IPs to nftables set in batches for performance.
        
        Args:
            set_name: Target nftables set
            ips: Set of IP address objects to add
        """
        batch_size = self.config.batch_size
        ip_list = list(ips)
        
        for i in range(0, len(ip_list), batch_size):
            batch = ip_list[i:i+batch_size]
            ip_str = ','.join(str(ip) for ip in batch)
            cmd = ['/usr/sbin/nft', 'add', 'element', set_name, '{', ip_str, '}']
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                self.logger.error(f"Failed adding batch to {set_name}: {result.stderr}")