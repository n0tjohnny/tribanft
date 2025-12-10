"""
TribanFT NFTables Ruleset Parser Utilities

Utilities for parsing NFTables output formats, particularly:
- Expiry time format (e.g., "8d12h21m34s564ms")
- Timeout values (e.g., "10d")
- Calculating original detection dates from timeout and expiry

Used by NFTablesSync to import IPs from port_scanners set with accurate timestamps.

Author: TribanFT Project
License: GNU GPL v3
"""

import re
import ipaddress
from datetime import datetime, timedelta, timezone
from typing import Optional
import logging


logger = logging.getLogger(__name__)


def parse_expiry_to_timedelta(expiry_str: str) -> Optional[timedelta]:
    """
    Parse NFTables expiry format to timedelta.
    
    NFTables uses formats like:
    - '8d12h21m34s564ms' → timedelta(days=8, hours=12, minutes=21, seconds=34)
    - '3h45m' → timedelta(hours=3, minutes=45)
    - '10d' → timedelta(days=10)
    
    Args:
        expiry_str: NFTables expiry string (e.g., from "expires 8d12h21m34s564ms")
        
    Returns:
        timedelta object or None if parsing fails
    """
    if not expiry_str:
        return None
    
    days = hours = minutes = seconds = 0
    
    try:
        # Parse days
        if 'd' in expiry_str:
            match = re.search(r'(\d+)d', expiry_str)
            if match:
                days = int(match.group(1))
        
        # Parse hours
        if 'h' in expiry_str:
            match = re.search(r'(\d+)h', expiry_str)
            if match:
                hours = int(match.group(1))
        
        # Parse minutes (exclude milliseconds 'ms')
        if 'm' in expiry_str:
            # Use negative lookahead to avoid matching 'ms' as minutes
            match = re.search(r'(\d+)m(?!s)', expiry_str)
            if match:
                minutes = int(match.group(1))
        
        # Parse seconds (exclude milliseconds)
        if 's' in expiry_str:
            # Match digits followed by 's' but not when 's' is part of 'ms' (milliseconds)
            match = re.search(r'(\d+)s(?!ms)', expiry_str)
            if match:
                seconds = int(match.group(1))
        
        return timedelta(days=days, hours=hours, minutes=minutes, seconds=seconds)
        
    except (ValueError, AttributeError) as e:
        logger.warning(f"Failed to parse expiry string '{expiry_str}': {e}")
        return None


def calculate_detection_date(timeout_str: str, expiry_str: str) -> Optional[datetime]:
    """
    Calculate original detection date from timeout and expiry.
    
    NFTables port_scanners set has:
    - timeout: Total time before expiry (e.g., "10d")
    - expires: Time remaining until expiry (e.g., "8d12h21m34s")
    
    Formula: detection_date = now - (timeout - expires)
    
    Example:
        timeout='10d', expires='8d12h21m34s'
        time_remaining = 8d12h21m34s
        time_elapsed = 10d - 8d12h21m34s = 1d11h38m26s
        detection_date = now - 1d11h38m26s
    
    Args:
        timeout_str: Total timeout (e.g., '10d')
        expiry_str: Time remaining (e.g., '8d12h21m34s564ms')
        
    Returns:
        datetime of original detection or None if parsing fails
    """
    timeout = parse_expiry_to_timedelta(timeout_str)
    expires = parse_expiry_to_timedelta(expiry_str)
    
    if not timeout or not expires:
        logger.debug(f"Cannot calculate date: timeout={timeout_str}, expires={expiry_str}")
        return None
    
    # Calculate how much time has elapsed since detection
    time_elapsed = timeout - expires
    
    # Detection date is current time minus elapsed time
    detection_date = datetime.now(timezone.utc) - time_elapsed
    
    return detection_date


def parse_nftables_set_elements(output: str, set_name: str = 'port_scanners') -> dict:
    """
    Parse NFTables set elements with timeout/expiry information.
    
    Parses output from: nft list ruleset | grep -A 1000 'set port_scanners'
    
    Expected format:
        set port_scanners {
            type ipv4_addr
            timeout 10d
            elements = {
                1.2.3.4 timeout 10d expires 8d12h21m34s,
                5.6.7.8 timeout 10d expires 9d1h5m12s
            }
        }
    
    Args:
        output: NFTables ruleset output containing set definition
        set_name: Name of the set to parse (default: 'port_scanners')
        
    Returns:
        Dict mapping IP to metadata with calculated timestamps:
        {
            '1.2.3.4': {
                'timeout': '10d',
                'expires': '8d12h21m34s',
                'date_added': datetime(...)
            }
        }
    """
    result = {}
    
    # Find the set definition - use a more robust approach
    # Look for "set port_scanners {" and find matching closing brace
    set_start = output.find(f'set {set_name}')
    if set_start == -1:
        logger.debug(f"Set '{set_name}' not found in output")
        return result
    
    # Find the opening brace
    brace_start = output.find('{', set_start)
    if brace_start == -1:
        logger.debug(f"Opening brace not found for set '{set_name}'")
        return result
    
    # Find matching closing brace (handle nested braces)
    brace_count = 1
    pos = brace_start + 1
    brace_end = -1
    while pos < len(output) and brace_count > 0:
        if output[pos] == '{':
            brace_count += 1
        elif output[pos] == '}':
            brace_count -= 1
            if brace_count == 0:
                brace_end = pos
                break
        pos += 1
    
    if brace_end == -1:
        logger.debug(f"Closing brace not found for set '{set_name}'")
        return result
    
    set_content = output[brace_start+1:brace_end]
    
    # Extract default timeout from set definition
    default_timeout = None
    timeout_match = re.search(r'timeout\s+(\S+)', set_content)
    if timeout_match:
        default_timeout = timeout_match.group(1)
    
    # Parse elements section
    elements_pattern = r'elements\s*=\s*\{([^}]+)\}'
    elements_match = re.search(elements_pattern, set_content, re.DOTALL)
    
    if not elements_match:
        logger.debug(f"No elements found in set '{set_name}'")
        return result
    
    elements_content = elements_match.group(1)
    
    # Parse individual IP entries
    # Format: IP [limit rate over X/minute] timeout Xd expires Xd...
    # Note: This regex permits octets 0-999; validation with ipaddress.ip_address() follows
    ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(?:limit\s+rate\s+over\s+\S+\s+)?(?:timeout\s+(\S+))?\s*(?:expires\s+(\S+))?'
    
    for match in re.finditer(ip_pattern, elements_content):
        ip = match.group(1)
        timeout = match.group(2) or default_timeout
        expires = match.group(3)
        
        # Validate IP address format
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            logger.debug(f"Invalid IP address: {ip}")
            continue
        
        # Clean up timeout and expires (remove trailing commas/spaces)
        if timeout:
            timeout = timeout.rstrip(',').strip()
        if expires:
            expires = expires.rstrip(',').strip()
        
        if not timeout or not expires:
            # If we don't have both timeout and expires, skip timestamp calculation
            logger.debug(f"Incomplete timeout/expires for {ip}: timeout={timeout}, expires={expires}")
            continue
        
        # Calculate detection date
        date_added = calculate_detection_date(timeout, expires)
        
        if date_added:
            result[ip] = {
                'timeout': timeout,
                'expires': expires,
                'date_added': date_added,
                'last_seen': date_added,  # Use detection date as last_seen
                'first_seen': date_added  # Use detection date as first_seen
            }
            logger.debug(f"Parsed {ip}: timeout={timeout}, expires={expires}, date_added={date_added}")
    
    return result
