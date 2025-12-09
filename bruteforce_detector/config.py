"""
TribanFT Configuration Module

Centralized configuration management using Pydantic for validation.

Configuration sources (in order of precedence):
1. Environment variables (prefix: BFD_)
2. .env file
3. Default values defined in this module

Key configuration groups:
- Log paths (syslog, MSSQL errorlog)
- Blacklist/whitelist file locations
- Detection thresholds (failed login, prelogin, port scan)
- Time window for event correlation (default: 7 days)
- Feature flags (enable/disable detectors)
- Performance settings (batch size, state management)
- Storage backend (file vs SQLite database)

Environment variable examples:
    BFD_TIME_WINDOW_MINUTES=10080        # 7 days
    BFD_FAILED_LOGIN_THRESHOLD=20        # 20 failed attempts
    BFD_USE_DATABASE=true                # Enable SQLite backend

Author: TribanFT Project
License: GNU GPL v3
"""

from pydantic import BaseSettings
from typing import List, Set, Optional
from pathlib import Path
import ipaddress
import logging
import os


class DetectorConfig(BaseSettings):
    """
    Main configuration class with validation and environment variable support.
    
    All settings can be overridden via environment variables with BFD_ prefix.
    For example: BFD_TIME_WINDOW_MINUTES=10080
    """
    
    # Log paths - customize these for your environment
    syslog_path: str = "/var/log/syslog"
    mssql_error_log_path: str = "/var/opt/mssql/log/errorlog"
    
    # Blacklist files - primary storage for blocked IPs
    blacklist_ipv4_file: str = "/root/blacklist_ipv4.txt"
    blacklist_ipv6_file: str = "/root/blacklist_ipv6.txt"
    prelogin_bruteforce_file: str = "/root/prelogin-bruteforce-ips.txt"
    whitelist_file: str = "/root/whitelist_ips.txt"
    
    # Detection thresholds - balance between security and false positives
    # Threshold logic: N events within time_window_minutes triggers blocking
    brute_force_threshold: int = 20
    time_window_minutes: int = 10080  # 7 days default
    failed_login_threshold: int = 20
    prelogin_pattern_threshold: int = 20
    port_scan_threshold: int = 20
    
    # Feature flags - enable/disable specific detection modules
    enable_prelogin_detection: bool = True
    enable_failed_login_detection: bool = True
    enable_port_scan_detection: bool = True
    enable_crowdsec_integration: bool = True
    enable_nftables_update: bool = True
    
    # Performance settings
    batch_size: int = 1000  # NFTables batch operation size
    state_file: str = "/var/lib/tribanft/state.json"
    
    # Storage backend - file-based vs SQLite database
    # Database recommended for >10k IPs for better performance
    use_database: bool = False
    database_path: str = "/var/lib/tribanft/blacklist.db"

    class Config:
        """Pydantic configuration"""
        env_prefix = "BFD_"  # Environment variable prefix
        case_sensitive = False


# Global configuration instance - use lazy initialization
_config_instance = None


def get_config() -> DetectorConfig:
    """
    Get the global configuration instance (singleton pattern).
    
    Lazy initialization ensures configuration is loaded only once
    and shared across all modules.
    
    Returns:
        DetectorConfig: Configuration object with all settings
    """
    global _config_instance
    if _config_instance is None:
        _config_instance = DetectorConfig()
    return _config_instance


# Backward compatibility - allows 'from config import config'
config = get_config()
