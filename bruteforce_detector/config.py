"""
TribanFT Configuration Module

Centralized configuration management using Pydantic for validation.

Configuration precedence (highest to lowest):
1. Environment variables (TRIBANFT_* for paths, BFD_* for settings)
2. Legacy hardcoded paths (if they exist, with deprecation warning)
3. XDG Base Directory specification (default)

Author: TribanFT Project
License: GNU GPL v3
"""

from pydantic_settings import BaseSettings
from pydantic import Field, model_validator
from typing import Optional
from pathlib import Path
import logging
import os
import warnings


def _xdg_base(env_var: str, home_subdir: str) -> Path:
    """Get XDG directory, falling back to ~/.{subdir}/tribanft"""
    base = os.environ.get(env_var)
    return Path(base) / 'tribanft' if base else Path.home() / home_subdir / 'tribanft'


def _resolve_file_path(env_var: str, xdg_dir: Path, legacy_path: str, filename: str) -> str:
    """
    Resolve file path with precedence: env override > legacy (if exists) > XDG
    
    Args:
        env_var: Environment variable for directory override (e.g., TRIBANFT_DATA_DIR)
        xdg_dir: XDG-compliant directory
        legacy_path: Legacy hardcoded path (for backward compatibility)
        filename: File name to append
    """
    # Priority 1: Environment variable override
    override = os.environ.get(env_var)
    if override:
        return str(Path(override) / filename)
    
    # Priority 2: Legacy path (if exists, warn)
    try:
        if Path(legacy_path).exists():
            warnings.warn(
                f"Using legacy path {legacy_path}. Migrate to XDG using {env_var}.",
                DeprecationWarning,
                stacklevel=3
            )
            return legacy_path
    except (PermissionError, OSError):
        pass
    
    # Priority 3: XDG default
    return str(xdg_dir / filename)


class DetectorConfig(BaseSettings):
    """
    Main configuration with validation and environment variable support.
    
    All settings accept environment variables:
    - BFD_* prefix for feature flags and thresholds
    - TRIBANFT_* prefix for directory paths
    """
    
    # === Directory Paths (XDG-compliant) ===
    data_dir: str = Field(
        default_factory=lambda: str(_xdg_base('XDG_DATA_HOME', '.local/share')),
        description="Data directory for blacklists/whitelists"
    )
    config_dir: str = Field(
        default_factory=lambda: str(_xdg_base('XDG_CONFIG_HOME', '.config')),
        description="Configuration directory"
    )
    state_dir: str = Field(
        default_factory=lambda: str(_xdg_base('XDG_STATE_HOME', '.local/state')),
        description="State directory for runtime data"
    )
    
    # === Log Paths ===
    syslog_path: str = "/var/log/syslog"
    mssql_error_log_path: str = "/var/opt/mssql/log/errorlog"
    
    # === Data Files (resolved from data_dir) ===
    blacklist_ipv4_file: Optional[str] = None
    blacklist_ipv6_file: Optional[str] = None
    prelogin_bruteforce_file: Optional[str] = None
    whitelist_file: Optional[str] = None
    manual_blacklist_file: Optional[str] = None
    
    # === Detection Thresholds ===
    brute_force_threshold: int = 20
    time_window_minutes: int = 10080  # 7 days
    failed_login_threshold: int = 20
    prelogin_pattern_threshold: int = 20
    port_scan_threshold: int = 20
    
    # === Feature Flags ===
    enable_prelogin_detection: bool = True
    enable_failed_login_detection: bool = True
    enable_port_scan_detection: bool = True
    enable_crowdsec_integration: bool = True
    enable_nftables_update: bool = True
    enable_auto_enrichment: bool = True
    
    # === Performance Settings ===
    batch_size: int = 1000
    state_file: Optional[str] = None
    
    # === Storage Backend ===
    use_database: bool = False
    database_path: Optional[str] = None
    sync_to_file: bool = Field(
        default=True,
        description="Sync database changes to blacklist files"
    )
    
    # === Backup Settings ===
    backup_retention_days: int = 7
    backup_min_keep: int = 5

    model_config = {
        'env_prefix': 'BFD_',
        'case_sensitive': False
    }
        
    @model_validator(mode='after')
    def resolve_all_paths(self):
        """Resolve all file paths using directory configuration"""
        # Apply environment variable overrides to directories
        for env_var, attr in [
            ('TRIBANFT_DATA_DIR', 'data_dir'),
            ('TRIBANFT_CONFIG_DIR', 'config_dir'),
            ('TRIBANFT_STATE_DIR', 'state_dir')
        ]:
            override = os.environ.get(env_var)
            if override:
                setattr(self, attr, override)
        
        data_dir = Path(self.data_dir)
        state_dir = Path(self.state_dir)
        
        # Resolve data files
        if self.blacklist_ipv4_file is None:
            self.blacklist_ipv4_file = _resolve_file_path(
                'TRIBANFT_DATA_DIR', data_dir, '/root/blacklist_ipv4.txt', 'blacklist_ipv4.txt'
            )
        if self.blacklist_ipv6_file is None:
            self.blacklist_ipv6_file = _resolve_file_path(
                'TRIBANFT_DATA_DIR', data_dir, '/root/blacklist_ipv6.txt', 'blacklist_ipv6.txt'
            )
        if self.prelogin_bruteforce_file is None:
            self.prelogin_bruteforce_file = _resolve_file_path(
                'TRIBANFT_DATA_DIR', data_dir, '/root/prelogin-bruteforce-ips.txt', 'prelogin-bruteforce-ips.txt'
            )
        if self.whitelist_file is None:
            self.whitelist_file = _resolve_file_path(
                'TRIBANFT_DATA_DIR', data_dir, '/root/whitelist_ips.txt', 'whitelist_ips.txt'
            )
        if self.manual_blacklist_file is None:
            self.manual_blacklist_file = _resolve_file_path(
                'TRIBANFT_DATA_DIR', data_dir, '/root/manual_blacklist.txt', 'manual_blacklist.txt'
            )
        
        # Resolve state files
        if self.state_file is None:
            self.state_file = _resolve_file_path(
                'TRIBANFT_STATE_DIR', state_dir, '/var/lib/tribanft/state.json', 'state.json'
            )
        if self.database_path is None:
            self.database_path = _resolve_file_path(
                'TRIBANFT_STATE_DIR', state_dir, '/var/lib/tribanft/blacklist.db', 'blacklist.db'
            )
        
        return self
    
    def ensure_directories(self):
        """Create required directories if they don't exist"""
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
        """Get backup directory path"""
        return Path(self.state_dir) / 'backups'


# Global configuration instance (singleton pattern)
_config_instance = None


def get_config() -> DetectorConfig:
    """
    Get global configuration instance with lazy initialization.
    
    Ensures configuration is loaded once and shared across modules.
    Automatically creates required directories on first access.
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


# Backward compatibility
config = get_config()
