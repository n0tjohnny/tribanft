"""
TribanFT Configuration Module

Centralized configuration management using Pydantic for validation.

Configuration sources (in order of precedence):
1. Environment variables (prefix: BFD_ or TRIBANFT_)
2. .env file
3. XDG Base Directory defaults
4. Legacy hardcoded paths (with deprecation warnings)

Key configuration groups:
- Path configuration (XDG compliant, configurable via environment)
- Log paths (syslog, MSSQL errorlog)
- Blacklist/whitelist file locations
- Detection thresholds (failed login, prelogin, port scan)
- Time window for event correlation (default: 7 days)
- Feature flags (enable/disable detectors)
- Performance settings (batch size, state management)
- Storage backend (file vs SQLite database)

Environment variable examples:
    TRIBANFT_DATA_DIR=/opt/tribanft/data
    TRIBANFT_CONFIG_DIR=/etc/tribanft
    TRIBANFT_STATE_DIR=/var/lib/tribanft
    BFD_TIME_WINDOW_MINUTES=10080        # 7 days
    BFD_FAILED_LOGIN_THRESHOLD=20        # 20 failed attempts
    BFD_USE_DATABASE=true                # Enable SQLite backend

Author: TribanFT Project
License: GNU GPL v3
"""

#from pydantic import BaseSettings, Field
from pydantic_settings import BaseSettings
from pydantic import Field, field_validator, model_validator
from typing import List, Set, Optional
from pathlib import Path
import ipaddress
import logging
import os
import warnings


def _get_xdg_dir(env_var: str, default_subdir: str) -> Path:
    """
    Get XDG Base Directory path with fallback to user home.
    
    Args:
        env_var: XDG environment variable name (e.g., 'XDG_CONFIG_HOME')
        default_subdir: Default subdirectory under home (e.g., '.config')
        
    Returns:
        Path object for the XDG directory
    """
    xdg_base = os.environ.get(env_var)
    if xdg_base:
        return Path(xdg_base) / 'tribanft'
    return Path.home() / default_subdir / 'tribanft'


def _resolve_path(
    override_env: str,
    xdg_dir: Optional[Path],
    legacy_path: Optional[str],
    filename: str,
    warn_legacy: bool = True
) -> str:
    """
    Resolve path with precedence: override > XDG > legacy.
    
    Args:
        override_env: Environment variable for direct override
        xdg_dir: XDG compliant directory path
        legacy_path: Legacy hardcoded path for backward compatibility
        filename: File name to append to directory
        warn_legacy: Whether to emit deprecation warning for legacy paths
        
    Returns:
        Resolved file path as string
    """
    # 1. Check for direct override (TRIBANFT_DATA_DIR, etc.)
    override = os.environ.get(override_env)
    if override:
        return str(Path(override) / filename)
    
    # 2. Check if legacy path exists (backward compatibility)
    # Wrap in try-except to handle permission errors gracefully
    if legacy_path:
        try:
            if Path(legacy_path).exists():
                if warn_legacy:
                    warnings.warn(
                        f"Using legacy path {legacy_path}. "
                        f"Please migrate to XDG paths using {override_env} environment variable.",
                        DeprecationWarning,
                        stacklevel=3
                    )
                return legacy_path
        except (PermissionError, OSError):
            # Legacy path not accessible, fall through to XDG
            pass
    
    # 3. Use XDG Base Directory path
    if xdg_dir:
        return str(xdg_dir / filename)
    
    # 4. Fall back to legacy path if XDG not available
    return legacy_path if legacy_path else str(Path.home() / filename)


class DetectorConfig(BaseSettings):
    """
    Main configuration class with validation and environment variable support.
    
    All settings can be overridden via environment variables with BFD_ prefix
    or TRIBANFT_ prefix for path configuration.
    
    Path resolution order:
    1. TRIBANFT_*_DIR environment variables (highest priority)
    2. Legacy hardcoded paths if they exist (with deprecation warning)
    3. XDG Base Directory specification (default)
    
    Example: BFD_TIME_WINDOW_MINUTES=10080
    """
    
    # ========================================================================
    # PATH CONFIGURATION (XDG Base Directory compliant)
    # ========================================================================
    
    # Directory paths - can be overridden via environment
    data_dir: str = Field(
        default_factory=lambda: str(_get_xdg_dir('XDG_DATA_HOME', '.local/share')),
        description="Data directory for blacklists, whitelists, etc."
    )
    config_dir: str = Field(
        default_factory=lambda: str(_get_xdg_dir('XDG_CONFIG_HOME', '.config')),
        description="Configuration directory for settings"
    )
    state_dir: str = Field(
        default_factory=lambda: str(_get_xdg_dir('XDG_STATE_HOME', '.local/state')),
        description="State directory for runtime state and backups"
    )
    
    # Log paths - customize these for your environment
    syslog_path: str = "/var/log/syslog"
    mssql_error_log_path: str = "/var/opt/mssql/log/errorlog"
    
    # Blacklist files - resolved using data_dir
    blacklist_ipv4_file: Optional[str] = None
    blacklist_ipv6_file: Optional[str] = None
    prelogin_bruteforce_file: Optional[str] = None
    whitelist_file: Optional[str] = None
    manual_blacklist_file: Optional[str] = None
    
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
    state_file: Optional[str] = None
    
    # Storage backend - file-based vs SQLite database
    # Database recommended for >10k IPs for better performance
    use_database: bool = False
    database_path: Optional[str] = None
    sync_to_file: bool = Field(
        default=True,
        description="When using database, also sync changes to blacklist files for compatibility"
    )
    
    # Metadata enrichment settings
    # Enrichment runs automatically during detection cycle to prevent metadata loss
    enable_auto_enrichment: bool = True
    
    # Backup settings
    backup_retention_days: int = Field(
        default=7,
        description="Number of days to retain backup files"
    )
    backup_min_keep: int = Field(
        default=5,
        description="Minimum number of backups to keep regardless of age"
    )

    class Config:
        """Pydantic configuration"""
        env_prefix = "BFD_"  # Environment variable prefix
        case_sensitive = False
        
    @model_validator(mode='after')
    def resolve_all_paths(self):
        """Resolve all file paths using directory configuration."""
        # Override data_dir if TRIBANFT_DATA_DIR is set
        data_override = os.environ.get('TRIBANFT_DATA_DIR')
        if data_override:
            self.data_dir = data_override
        
        # Override config_dir if TRIBANFT_CONFIG_DIR is set
        config_override = os.environ.get('TRIBANFT_CONFIG_DIR')
        if config_override:
            self.config_dir = config_override
        
        # Override state_dir if TRIBANFT_STATE_DIR is set
        state_override = os.environ.get('TRIBANFT_STATE_DIR')
        if state_override:
            self.state_dir = state_override
        
        # Ensure directories are Path objects
        data_dir = Path(self.data_dir)
        state_dir = Path(self.state_dir)
        
        # Resolve blacklist files if not explicitly set
        if self.blacklist_ipv4_file is None:
            self.blacklist_ipv4_file = _resolve_path(
                'TRIBANFT_DATA_DIR',
                data_dir,
                '/root/blacklist_ipv4.txt',
                'blacklist_ipv4.txt'
            )
        
        if self.blacklist_ipv6_file is None:
            self.blacklist_ipv6_file = _resolve_path(
                'TRIBANFT_DATA_DIR',
                data_dir,
                '/root/blacklist_ipv6.txt',
                'blacklist_ipv6.txt'
            )
        
        if self.prelogin_bruteforce_file is None:
            self.prelogin_bruteforce_file = _resolve_path(
                'TRIBANFT_DATA_DIR',
                data_dir,
                '/root/prelogin-bruteforce-ips.txt',
                'prelogin-bruteforce-ips.txt'
            )
        
        if self.whitelist_file is None:
            self.whitelist_file = _resolve_path(
                'TRIBANFT_DATA_DIR',
                data_dir,
                '/root/whitelist_ips.txt',
                'whitelist_ips.txt'
            )
        
        if self.manual_blacklist_file is None:
            self.manual_blacklist_file = _resolve_path(
                'TRIBANFT_DATA_DIR',
                data_dir,
                '/root/manual_blacklist.txt',
                'manual_blacklist.txt'
            )
        
        # Resolve state file if not explicitly set
        if self.state_file is None:
            self.state_file = _resolve_path(
                'TRIBANFT_STATE_DIR',
                state_dir,
                '/var/lib/tribanft/state.json',
                'state.json'
            )
        
        # Resolve database path if not explicitly set
        if self.database_path is None:
            self.database_path = _resolve_path(
                'TRIBANFT_STATE_DIR',
                state_dir,
                '/var/lib/tribanft/blacklist.db',
                'blacklist.db'
            )
        
        return self
    
    def ensure_directories(self):
        """
        Create required directories if they don't exist.
        
        Creates data, config, and state directories with appropriate permissions.
        Also creates backup directory under state_dir.
        """
        logger = logging.getLogger(__name__)
        
        for dir_path in [self.data_dir, self.config_dir, self.state_dir]:
            path = Path(dir_path)
            if not path.exists():
                try:
                    path.mkdir(parents=True, exist_ok=True, mode=0o755)
                    logger.info(f"Created directory: {path}")
                except PermissionError:
                    logger.error(f"Permission denied creating directory: {path}")
                    raise
                except Exception as e:
                    logger.error(f"Failed to create directory {path}: {e}")
                    raise
        
        # Create backup directory
        backup_dir = Path(self.state_dir) / 'backups'
        if not backup_dir.exists():
            try:
                backup_dir.mkdir(parents=True, exist_ok=True, mode=0o755)
                logger.info(f"Created backup directory: {backup_dir}")
            except Exception as e:
                logger.warning(f"Failed to create backup directory {backup_dir}: {e}")
    
    def get_backup_dir(self) -> Path:
        """Get the backup directory path."""
        return Path(self.state_dir) / 'backups'


# Global configuration instance - use lazy initialization
_config_instance = None


def get_config() -> DetectorConfig:
    """
    Get the global configuration instance (singleton pattern).
    
    Lazy initialization ensures configuration is loaded only once
    and shared across all modules.
    
    Automatically ensures required directories exist on first access.
    
    Returns:
        DetectorConfig: Configuration object with all settings
    """
    global _config_instance
    if _config_instance is None:
        _config_instance = DetectorConfig()
        try:
            _config_instance.ensure_directories()
        except Exception as e:
            logging.getLogger(__name__).warning(
                f"Failed to create directories: {e}. "
                "Some operations may fail if directories don't exist."
            )
    return _config_instance


# Backward compatibility - allows 'from config import config'
config = get_config()
