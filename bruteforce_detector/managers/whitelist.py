"""
TribanFT Whitelist Manager

Manages trusted IPs and networks that should never be blocked.

Supports:
- Individual IP addresses (IPv4/IPv6)
- Network ranges in CIDR notation (e.g., 192.168.0.0/24)
- Hot-reloading from configuration file
- Efficient membership testing

The whitelist is checked before any IP is blacklisted to prevent blocking
trusted infrastructure like admin IPs, monitoring systems, or internal networks.

Author: TribanFT Project
License: GNU GPL v3
"""

from typing import Set, List, Optional
import ipaddress
from pathlib import Path
import logging
import threading
import tempfile
import os
from datetime import datetime

from ..config import get_config
from ..utils.validators import validate_ip, validate_cidr


class WhitelistManager:
    """Manages whitelisted IPs and networks with hot-reload support"""

    def __init__(self):
        """Initialize whitelist manager and load entries from file."""
        self.individual_ips: Set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
        self.networks: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self.last_loaded: Optional[datetime] = None
        self.logger = logging.getLogger(__name__)
        self.config = get_config()

        # CRITICAL FIX #34: Thread-safe whitelist reloading
        self._reload_lock = threading.Lock()

        self._load_whitelist()
    
    def _load_whitelist(self):
        """
        Load whitelist from configuration file.
        
        Parses both individual IPs and CIDR notation networks.
        Creates default file if missing.
        """
        whitelist_file = Path(self.config.whitelist_file)
        
        if not whitelist_file.exists():
            self._create_default_whitelist()
            return
        
        try:
            with open(whitelist_file, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    if '/' in line:
                        # CIDR notation
                        if validate_cidr(line):
                            network = ipaddress.ip_network(line, strict=False)
                            self.networks.append(network)
                        else:
                            self.logger.warning(f"Invalid CIDR (line {line_num}): {line}")
                    else:
                        # Individual IP
                        if validate_ip(line):
                            ip = ipaddress.ip_address(line)
                            self.individual_ips.add(ip)
                        else:
                            self.logger.warning(f"Invalid IP (line {line_num}): {line}")
            
            self.last_loaded = datetime.now()
            self.logger.info(f"Loaded {len(self.individual_ips)} IPs and {len(self.networks)} networks")
            
        except Exception as e:
            self.logger.error(f"Error loading whitelist: {e}")
    
    def _create_default_whitelist(self):
        """Create default whitelist file with examples."""
        whitelist_file = Path(self.config.whitelist_file)
        whitelist_file.parent.mkdir(parents=True, exist_ok=True)
        
        default_content = """# IP Whitelist
# Add one IP or network per line to whitelist
# Examples:
# 192.168.1.100
# 10.0.0.0/24
# 2001:db8::/32
"""
        with open(whitelist_file, 'w') as f:
            f.write(default_content)
        self.logger.info(f"Created default whitelist: {whitelist_file}")
    
    def is_whitelisted(self, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        """
        Check if IP is whitelisted.

        THREAD SAFETY FIX #34: Protected by lock to prevent reading during reload.

        Args:
            ip: IP address object to check

        Returns:
            True if IP is in whitelist or belongs to whitelisted network
        """
        # CRITICAL FIX #34: Acquire lock to prevent race condition where
        # reload() clears whitelist while is_whitelisted() checks it
        with self._reload_lock:
            # Check individual IPs (faster)
            if ip in self.individual_ips:
                return True

            # Check networks
            for network in self.networks:
                if ip in network:
                    return True

            return False
    
    def add_to_whitelist(self, ip_or_network: str) -> bool:
        """
        Add IP or network to whitelist and persist to file.
        
        Args:
            ip_or_network: IP address or CIDR notation network
            
        Returns:
            True if successfully added, False on error
        """
        try:
            if '/' in ip_or_network:
                if not validate_cidr(ip_or_network):
                    return False
                network = ipaddress.ip_network(ip_or_network, strict=False)
                if network not in self.networks:
                    self.networks.append(network)
            else:
                if not validate_ip(ip_or_network):
                    return False
                ip = ipaddress.ip_address(ip_or_network)
                self.individual_ips.add(ip)
            
            # Append to file
            with open(self.config.whitelist_file, 'a') as f:
                f.write(f"{ip_or_network}\n")
            
            self.logger.info(f"Added {ip_or_network} to whitelist")
            return True
            
        except Exception as e:
            self.logger.error(f"Error adding to whitelist: {e}")
            return False
    
    def remove_from_whitelist(self, ip_or_network: str) -> bool:
        """
        Remove IP or network from whitelist.
        
        Args:
            ip_or_network: IP address or CIDR notation to remove
            
        Returns:
            True if removed, False if not found or error
        """
        try:
            removed = False
            
            if '/' in ip_or_network:
                network = ipaddress.ip_network(ip_or_network, strict=False)
                if network in self.networks:
                    self.networks.remove(network)
                    removed = True
            else:
                ip = ipaddress.ip_address(ip_or_network)
                if ip in self.individual_ips:
                    self.individual_ips.remove(ip)
                    removed = True
            
            if removed:
                # CRITICAL FIX #31: Atomic file rewrite using tempfile + rename
                # Prevents corruption if process killed during write
                whitelist_file = Path(self.config.whitelist_file)
                fd, temp_path = tempfile.mkstemp(
                    dir=whitelist_file.parent,
                    prefix=".whitelist.",
                    suffix=".tmp"
                )

                try:
                    with os.fdopen(fd, 'w') as f:
                        f.write("# IP Whitelist\n\n")
                        for ip in sorted(self.individual_ips):
                            f.write(f"{ip}\n")
                        for network in sorted(self.networks):
                            f.write(f"{network}\n")

                    # Atomic rename (all-or-nothing semantics)
                    os.replace(temp_path, self.config.whitelist_file)
                    self.logger.info(f"Removed {ip_or_network} from whitelist")

                except Exception as e:
                    # Clean up temp file on error
                    if os.path.exists(temp_path):
                        os.unlink(temp_path)
                    raise
            
            return removed
            
        except Exception as e:
            self.logger.error(f"Error removing from whitelist: {e}")
            return False
    
    def get_whitelist_entries(self) -> List[str]:
        """Get all whitelist entries as strings."""
        entries = [str(ip) for ip in sorted(self.individual_ips)]
        entries.extend(str(network) for network in sorted(self.networks))
        return entries

    def reload(self):
        """
        Hot-reload whitelist from disk.

        CRITICAL FIX #34: Allows updating whitelist without restarting service.
        Triggered by SIGHUP signal handler.

        Thread-safe: Uses lock to prevent race conditions with is_whitelisted() checks.

        Use case:
            1. Edit whitelist_ips.txt to add/remove trusted IPs
            2. Send SIGHUP signal: kill -HUP <pid>
            3. Whitelist reloads without service restart
        """
        with self._reload_lock:
            self.logger.info("Reloading whitelist from disk...")

            # Clear current whitelist
            self.individual_ips.clear()
            self.networks.clear()

            # Reload from file
            self._load_whitelist()

            self.logger.info(
                f"Whitelist reloaded: {len(self.individual_ips)} IPs, "
                f"{len(self.networks)} networks"
            )