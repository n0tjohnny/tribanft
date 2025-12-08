"""
TribanFT IP Validators

IP address and CIDR notation validation utilities.

Provides validation functions for:
- IPv4 and IPv6 address validation
- CIDR network notation validation
- Input sanitization for security operations

Used throughout the application to ensure IP addresses are properly
formatted before processing, storage, or firewall operations.

Author: TribanFT Project
License: GNU GPL v3
"""

import ipaddress
from typing import Union


def validate_ip(ip_str: str) -> bool:
    """
    Validate if string is a valid IP address (IPv4 or IPv6).
    
    Args:
        ip_str: String to validate as IP address
        
    Returns:
        True if valid IP address, False otherwise
        
    Example:
        >>> validate_ip("192.168.1.1")
        True
        >>> validate_ip("invalid")
        False
    """
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def validate_cidr(cidr_str: str) -> bool:
    """
    Validate if string is valid CIDR notation.
    
    Args:
        cidr_str: String to validate as CIDR (e.g., "192.168.1.0/24")
        
    Returns:
        True if valid CIDR notation, False otherwise
        
    Example:
        >>> validate_cidr("192.168.1.0/24")
        True
        >>> validate_cidr("192.168.1.1/33")
        False
    """
    try:
        ipaddress.ip_network(cidr_str, strict=False)
        return True
    except ValueError:
        return False