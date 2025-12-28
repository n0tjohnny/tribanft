"""
TribanFT Configuration Module

Centralized configuration management using INI-style config.conf file.

Configuration precedence (highest to lowest):
1. Environment variables (BFD_* for settings, TRIBANFT_* for paths)
2. config.conf file (INI format)
3. Default values

Config file search locations (first found wins):
1. Path specified in TRIBANFT_CONFIG_FILE environment variable
2. /etc/tribanft/config.conf (system-wide)
3. ~/.local/share/tribanft/config.conf (user-specific, XDG standard)
4. ./config.conf (current directory)
5. Built-in defaults (if no config file found)

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
import configparser


def find_config_file() -> Optional[Path]:
    """
    Search for config.conf in standard locations.

    Returns:
        Path to config file if found, None otherwise
    """
    # Priority 1: Environment variable override
    env_config = os.environ.get('TRIBANFT_CONFIG_FILE')
    if env_config:
        path = Path(env_config)
        if path.exists():
            return path
        warnings.warn(f"TRIBANFT_CONFIG_FILE={env_config} does not exist")

    # Priority 2-4: Standard locations
    search_paths = [
        Path('/etc/tribanft/config.conf'),
        Path.home() / '.local' / 'share' / 'tribanft' / 'config.conf',
        Path('config.conf'),
    ]

    for path in search_paths:
        if path.exists():
            return path

    return None


def load_config_file() -> dict:
    """
    Load configuration from config.conf file.

    Returns:
        Dictionary with configuration values
    """
    config_file = find_config_file()

    logger = logging.getLogger(__name__)

    if not config_file:
        logger.warning("DEBUG: CONFIG: No config.conf file found!")
        logger.info(
            "No config.conf file found. Using environment variables and defaults. "
            "Run setup.sh to create a configuration file."
        )
        return {}

    logger.info(f"DEBUG: CONFIG: Loading config from: {config_file}")

    parser = configparser.ConfigParser(
        interpolation=configparser.ExtendedInterpolation()
    )

    try:
        parser.read(config_file)
        logging.getLogger(__name__).info(f"Loaded configuration from: {config_file}")
    except Exception as e:
        logging.getLogger(__name__).warning(
            f"Failed to parse {config_file}: {e}. Using defaults."
        )
        return {}

    # Convert INI sections to flat dictionary with BFD_ and TRIBANFT_ prefixes
    config = {}

    # Paths section -> TRIBANFT_* environment variables
    if parser.has_section('paths'):
        for key, value in parser.items('paths'):
            # Strip inline comments (anything after #)
            value = value.split('#')[0].strip()
            # Expand tilde in paths
            expanded_value = os.path.expanduser(value)
            config[f'TRIBANFT_{key.upper()}'] = expanded_value

    # All other sections -> BFD_* environment variables
    for section in ['detection', 'features', 'storage', 'performance',
                    'logs', 'data_files', 'state_files', 'ipinfo',
                    'nftables', 'advanced', 'realtime', 'threat_intelligence']:
        if parser.has_section(section):
            for key, value in parser.items(section):
                # Strip inline comments (anything after #)
                value = value.split('#')[0].strip()
                # Expand tilde in paths
                expanded_value = os.path.expanduser(value)
                env_key = f'BFD_{key.upper()}'
                config[env_key] = expanded_value

                # DEBUG: Log storage section specifically
                if section == 'storage':
                    logging.getLogger(__name__).info(
                        f"DEBUG: CONFIG: [{section}] {key} = {value} -> {env_key} = {expanded_value}"
                    )

    return config


def _parse_bool(value: str, field_name: str = "field") -> bool:
    """
    Parse boolean value from string with validation.

    Args:
        value: String value to parse
        field_name: Name of field for error messages

    Returns:
        Boolean value

    Raises:
        ValueError: If value is not a valid boolean string
    """
    value_lower = value.lower().strip()
    if value_lower in ('true', '1', 'yes', 'on'):
        return True
    elif value_lower in ('false', '0', 'no', 'off', ''):
        return False
    else:
        raise ValueError(
            f"Invalid boolean value for {field_name}: '{value}'. "
            f"Use: true/false, 1/0, yes/no, on/off"
        )


def _get_from_sources(key: str, config_dict: dict, env_prefix: str = 'BFD_') -> Optional[str]:
    """
    Get configuration value from multiple sources with precedence.

    Args:
        key: Configuration key (lowercase with underscores)
        config_dict: Configuration from config.conf file
        env_prefix: Environment variable prefix

    Returns:
        Configuration value or None
    """
    env_key = f"{env_prefix}{key.upper()}"

    # Priority 1: Environment variable
    env_value = os.environ.get(env_key)
    if env_value is not None:
        return env_value

    # Priority 2: Config file
    file_value = config_dict.get(env_key)
    if file_value is not None:
        return file_value

    # Priority 3: None (will use pydantic default)
    return None


def _xdg_base(env_var: str, home_subdir: str, config_dict: dict) -> Path:
    """Get XDG directory with config.conf override support"""
    # Check config.conf first
    config_key = env_var.lower().replace('xdg_', '').replace('_home', '') + '_dir'
    config_value = config_dict.get(f'TRIBANFT_{config_key.upper()}')
    if config_value:
        return Path(config_value)

    # Then environment variable
    base = os.environ.get(env_var)
    if base:
        return Path(base) / 'tribanft'

    # Finally default
    return Path.home() / home_subdir / 'tribanft'


def _resolve_file_path(
    env_var: str,
    xdg_dir: Path,
    legacy_path: str,
    filename: str,
    config_dict: dict
) -> str:
    """
    Resolve file path with precedence: env override > config.conf > legacy (if exists) > XDG

    Args:
        env_var: Environment variable for directory override
        xdg_dir: XDG-compliant directory
        legacy_path: Legacy hardcoded path (for backward compatibility)
        filename: File name to append
        config_dict: Configuration from config.conf
    """
    # Priority 1: Environment variable override
    env_override = os.environ.get(env_var)
    if env_override:
        return str(Path(env_override) / filename)

    # Priority 2: Config file directory override
    config_dir = config_dict.get(env_var)
    if config_dir:
        return str(Path(config_dir) / filename)

    # Priority 3: Legacy path (if exists, warn)
    try:
        if Path(legacy_path).exists():
            warnings.warn(
                f"Using legacy path {legacy_path}. "
                f"Migrate to config.conf or set {env_var}.",
                DeprecationWarning,
                stacklevel=3
            )
            return legacy_path
    except (PermissionError, OSError):
        pass

    # Priority 4: XDG default
    return str(xdg_dir / filename)


class DetectorConfig(BaseSettings):
    """
    Main configuration with validation.

    Configuration is loaded from:
    1. Environment variables (highest priority)
    2. config.conf file
    3. Default values (lowest priority)
    """

    # === Directory Paths ===
    data_dir: str = Field(
        default="",
        description="Data directory for blacklists/whitelists"
    )
    config_dir: str = Field(
        default="",
        description="Configuration directory"
    )
    state_dir: str = Field(
        default="",
        description="State directory for runtime data"
    )
    project_dir: str = Field(
        default="",
        description="Project root directory"
    )
    python_bin: str = Field(
        default="/usr/bin/python3",
        description="Python interpreter path"
    )
    tribanft_bin: str = Field(
        default="tribanft",
        description="TribanFT binary path"
    )

    # === Organized Subdirectories (v2.9.0+) ===
    data_subdir: str = Field(
        default="",
        description="Subdirectory for firewall data files"
    )
    state_subdir: str = Field(
        default="",
        description="Subdirectory for runtime state files"
    )
    cache_subdir: str = Field(
        default="",
        description="Subdirectory for temporary cache files"
    )
    logs_subdir: str = Field(
        default="",
        description="Subdirectory for application logs"
    )
    backup_subdir: str = Field(
        default="",
        description="Subdirectory for backup files"
    )

    # === Log Rotation Settings (v2.9.0+) ===
    log_max_bytes: int = 10485760  # 10MB default
    log_backup_count: int = 5  # Keep 5 rotated files

    # === Log Paths ===
    syslog_path: str = "/var/log/syslog"
    mssql_error_log_path: str = "/var/opt/mssql/log/errorlog"
    apache_access_log_path: Optional[str] = None
    nginx_access_log_path: Optional[str] = None
    ftp_log_path: Optional[str] = None
    smtp_log_path: Optional[str] = None
    dns_log_path: Optional[str] = None

    # === Data Files ===
    blacklist_ipv4_file: Optional[str] = None
    blacklist_ipv6_file: Optional[str] = None
    prelogin_bruteforce_file: Optional[str] = None
    whitelist_file: Optional[str] = None
    manual_blacklist_file: Optional[str] = None

    # === State Files ===
    state_file: Optional[str] = None
    database_path: Optional[str] = None

    # === IPInfo Settings ===
    ipinfo_token_file: Optional[str] = None
    ipinfo_cache_dir: Optional[str] = None
    ipinfo_results_file: Optional[str] = None
    ipinfo_csv_cache_file: Optional[str] = None
    ipinfo_batch_interval: int = 3600
    ipinfo_batch_size: int = 2000
    ipinfo_daily_limit: int = 2000
    ipinfo_rate_limit_per_minute: int = 15

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

    # === Storage Backend ===
    use_database: bool = False
    sync_to_file: bool = True

    # === Backup Settings ===
    backup_enabled: bool = True  # Enable automatic backups
    backup_interval_days: int = 1  # Backup interval in days (0 = every run)
    backup_retention_days: int = 3  # Days to keep backups (reduced from 7 for less storage)
    backup_min_keep: int = 3  # Minimum backups to keep regardless of age (reduced from 5)
    backup_compress_age_days: int = 0  # Compress immediately (reduced from 1 for space savings)

    # === Advanced ===
    verbose: bool = False
    skip_verify: bool = False
    min_expected_ips: int = 1000  # Anti-corruption protection threshold

    # === Real-Time Monitoring (NEW in v2.3) ===
    monitor_syslog: bool = True
    monitor_mssql: bool = True
    monitor_apache: bool = True
    monitor_nginx: bool = True
    monitor_files: Optional[str] = None  # Comma-separated list of custom files
    debounce_interval: float = 1.0
    max_events_per_second: int = 1000
    rate_limit_backoff: int = 30
    fallback_interval: int = 60
    nftables_discovery_interval: int = 3600  # NFTables auto-discovery interval in real-time mode (seconds)

    # === NFTables Discovery (NEW in v2.4) ===
    nftables_event_log_enabled: bool = False
    nftables_auto_discovery: bool = False
    nftables_import_sets: Optional[str] = None  # Comma-separated sets (family:table:set)

    # === Threat Intelligence (NEW in v2.5) ===
    threat_feeds_enabled: bool = False
    threat_feed_sources: str = "spamhaus"
    threat_feed_cache_hours: int = 24

    model_config = {
        'env_prefix': 'BFD_',
        'case_sensitive': False
    }

    @model_validator(mode='after')
    def resolve_all_paths(self):
        """Resolve all file paths using configuration sources"""
        # Initialize logger for this validator
        logger = logging.getLogger(__name__)

        # Load config.conf file
        config_dict = load_config_file()

        # Resolve directory paths with config.conf support
        if not self.data_dir:
            value = _get_from_sources('data_dir', config_dict, 'TRIBANFT_')
            self.data_dir = value if value else str(
                _xdg_base('XDG_DATA_HOME', '.local/share', config_dict)
            )

        if not self.config_dir:
            value = _get_from_sources('config_dir', config_dict, 'TRIBANFT_')
            self.config_dir = value if value else str(
                _xdg_base('XDG_CONFIG_HOME', '.config', config_dict)
            )

        if not self.state_dir:
            value = _get_from_sources('state_dir', config_dict, 'TRIBANFT_')
            self.state_dir = value if value else str(
                _xdg_base('XDG_STATE_HOME', '.local/state', config_dict)
            )

        if not self.project_dir:
            value = _get_from_sources('project_dir', config_dict, 'TRIBANFT_')
            if value:
                self.project_dir = value
            else:
                # Auto-detect project directory
                self.project_dir = str(Path(__file__).parent.parent.absolute())

        # Get paths from config
        python_bin = _get_from_sources('python_bin', config_dict, 'TRIBANFT_')
        if python_bin:
            self.python_bin = python_bin

        tribanft_bin = _get_from_sources('tribanft_bin', config_dict, 'TRIBANFT_')
        if tribanft_bin:
            self.tribanft_bin = tribanft_bin

        # Resolve organized subdirectories (v2.9.0+)
        # SECURITY: Validate paths to prevent directory traversal attacks
        base_dir = Path(self.data_dir).resolve()

        def _validate_subdir(path_str: str, default_name: str) -> str:
            """
            Validate subdirectory path prevents traversal outside base_dir.

            Security: Prevents path traversal attacks by ensuring configured
            subdirs resolve to paths within base_dir.

            Args:
                path_str: Configured subdirectory path
                default_name: Default subdirectory name if validation fails

            Returns:
                Validated absolute path string

            Raises:
                ValueError: If path escapes base_dir containment
            """
            if not path_str:
                return str(base_dir / default_name)

            # Resolve to absolute path and check containment
            subdir_path = Path(path_str).resolve()

            # Security check: Must be within base_dir
            try:
                subdir_path.relative_to(base_dir)
            except ValueError:
                logger.error(
                    f"Security: Subdirectory '{path_str}' is outside base directory "
                    f"'{base_dir}'. Using default '{default_name}' instead."
                )
                return str(base_dir / default_name)

            return str(subdir_path)

        if not self.data_subdir:
            value = _get_from_sources('data_subdir', config_dict, 'TRIBANFT_')
            self.data_subdir = _validate_subdir(value, 'data')

        if not self.state_subdir:
            value = _get_from_sources('state_subdir', config_dict, 'TRIBANFT_')
            self.state_subdir = _validate_subdir(value, 'state')

        if not self.cache_subdir:
            value = _get_from_sources('cache_subdir', config_dict, 'TRIBANFT_')
            self.cache_subdir = _validate_subdir(value, 'cache')

        if not self.logs_subdir:
            value = _get_from_sources('logs_subdir', config_dict, 'TRIBANFT_')
            self.logs_subdir = _validate_subdir(value, 'logs')

        if not self.backup_subdir:
            value = _get_from_sources('backup_subdir', config_dict, 'TRIBANFT_')
            self.backup_subdir = _validate_subdir(value, 'backups')

        # Load log rotation settings (v2.9.0+)
        log_max_str = _get_from_sources('log_max_bytes', config_dict)
        if log_max_str:
            try:
                self.log_max_bytes = int(log_max_str)
                logger.debug(f"DEBUG: CONFIG: log_max_bytes = {log_max_str}")
            except ValueError:
                logger.warning(f"Invalid integer value for log_max_bytes: {log_max_str}")

        log_count_str = _get_from_sources('log_backup_count', config_dict)
        if log_count_str:
            try:
                self.log_backup_count = int(log_count_str)
                logger.debug(f"DEBUG: CONFIG: log_backup_count = {log_count_str}")
            except ValueError:
                logger.warning(f"Invalid integer value for log_backup_count: {log_count_str}")

        # Resolve log paths
        syslog = _get_from_sources('syslog_path', config_dict)
        if syslog:
            self.syslog_path = syslog

        mssql_log = _get_from_sources('mssql_error_log_path', config_dict)
        if mssql_log:
            self.mssql_error_log_path = mssql_log

        apache_log = _get_from_sources('apache_access_log_path', config_dict)
        if apache_log:
            self.apache_access_log_path = apache_log

        nginx_log = _get_from_sources('nginx_access_log_path', config_dict)
        if nginx_log:
            self.nginx_access_log_path = nginx_log

        ftp_log = _get_from_sources('ftp_log_path', config_dict)
        if ftp_log:
            self.ftp_log_path = ftp_log

        smtp_log = _get_from_sources('smtp_log_path', config_dict)
        if smtp_log:
            self.smtp_log_path = smtp_log

        dns_log = _get_from_sources('dns_log_path', config_dict)
        if dns_log:
            self.dns_log_path = dns_log

        # === CRITICAL FIX: Load all settings from config.conf ===
        # Pydantic only reads from environment variables by default.
        # We must explicitly load values from config_dict for non-path settings.
        logger = logging.getLogger(__name__)

        # Storage backend settings
        use_db_str = _get_from_sources('use_database', config_dict)
        if use_db_str is not None:
            try:
                self.use_database = _parse_bool(use_db_str, 'use_database')
                logger.info(f"DEBUG: CONFIG: use_database = {use_db_str} -> {self.use_database}")
            except ValueError as e:
                logger.error(str(e))
                raise

        sync_file_str = _get_from_sources('sync_to_file', config_dict)
        if sync_file_str is not None:
            try:
                self.sync_to_file = _parse_bool(sync_file_str, 'sync_to_file')
                logger.info(f"DEBUG: CONFIG: sync_to_file = {sync_file_str} -> {self.sync_to_file}")
            except ValueError as e:
                logger.error(str(e))
                raise

        # Detection thresholds
        for field in ['brute_force_threshold', 'time_window_minutes', 'failed_login_threshold',
                      'prelogin_pattern_threshold', 'port_scan_threshold']:
            value_str = _get_from_sources(field, config_dict)
            if value_str is not None:
                try:
                    setattr(self, field, int(value_str))
                    logger.debug(f"DEBUG: CONFIG: {field} = {value_str}")
                except ValueError:
                    logger.warning(f"Invalid integer value for {field}: {value_str}")

        # Feature flags
        for field in ['enable_prelogin_detection', 'enable_failed_login_detection',
                      'enable_port_scan_detection', 'enable_crowdsec_integration',
                      'enable_nftables_update', 'enable_auto_enrichment']:
            value_str = _get_from_sources(field, config_dict)
            if value_str is not None:
                try:
                    setattr(self, field, _parse_bool(value_str, field))
                    logger.debug(f"DEBUG: CONFIG: {field} = {value_str}")
                except ValueError as e:
                    logger.warning(str(e))
                    # Keep default value on parse error

        # Performance settings
        batch_str = _get_from_sources('batch_size', config_dict)
        if batch_str is not None:
            try:
                self.batch_size = int(batch_str)
                logger.debug(f"DEBUG: CONFIG: batch_size = {batch_str}")
            except ValueError:
                logger.warning(f"Invalid integer value for batch_size: {batch_str}")

        # IPInfo settings
        for field in ['ipinfo_batch_interval', 'ipinfo_batch_size', 'ipinfo_daily_limit', 'ipinfo_rate_limit_per_minute']:
            # Handle mapping: config file uses shorter names (batch_interval → ipinfo_batch_interval)
            config_key = field.replace('ipinfo_', '')
            value_str = _get_from_sources(config_key, config_dict)
            if value_str is not None:
                try:
                    setattr(self, field, int(value_str))
                    logger.debug(f"DEBUG: CONFIG: {field} = {value_str}")
                except ValueError:
                    logger.warning(f"Invalid integer value for {field}: {value_str}")

        # Backup settings
        backup_enabled_str = _get_from_sources('backup_enabled', config_dict)
        if backup_enabled_str is not None:
            try:
                self.backup_enabled = _parse_bool(backup_enabled_str, 'backup_enabled')
                logger.debug(f"DEBUG: CONFIG: backup_enabled = {backup_enabled_str}")
            except ValueError as e:
                logger.warning(str(e))

        for field in ['backup_interval_days', 'backup_retention_days', 'backup_min_keep', 'backup_compress_age_days']:
            value_str = _get_from_sources(field, config_dict)
            if value_str is not None:
                try:
                    setattr(self, field, int(value_str))
                    logger.debug(f"DEBUG: CONFIG: {field} = {value_str}")
                except ValueError:
                    logger.warning(f"Invalid integer value for {field}: {value_str}")

        # Advanced settings - boolean flags
        for field in ['verbose', 'skip_verify']:
            value_str = _get_from_sources(field, config_dict)
            if value_str is not None:
                try:
                    setattr(self, field, _parse_bool(value_str, field))
                    logger.debug(f"DEBUG: CONFIG: {field} = {value_str}")
                except ValueError as e:
                    logger.warning(str(e))

        # Min expected IPs (anti-corruption threshold)
        min_ips_str = _get_from_sources('min_expected_ips', config_dict)
        if min_ips_str is not None:
            try:
                self.min_expected_ips = max(int(min_ips_str), 100)
                if int(min_ips_str) < 100:
                    logger.warning(f"min_expected_ips={min_ips_str} too low, enforcing minimum of 100")
                logger.debug(f"DEBUG: CONFIG: min_expected_ips = {self.min_expected_ips}")
            except ValueError:
                logger.warning(f"Invalid integer value for min_expected_ips: {min_ips_str}")

        # NFTables Discovery settings (NEW in v2.4)
        for field in ['nftables_event_log_enabled', 'nftables_auto_discovery']:
            value_str = _get_from_sources(field, config_dict)
            if value_str is not None:
                try:
                    setattr(self, field, _parse_bool(value_str, field))
                    logger.debug(f"DEBUG: CONFIG: {field} = {value_str}")
                except ValueError as e:
                    logger.warning(str(e))

        nftables_import_str = _get_from_sources('nftables_import_sets', config_dict)
        if nftables_import_str is not None:
            self.nftables_import_sets = nftables_import_str.strip()
            logger.debug(f"DEBUG: CONFIG: nftables_import_sets = {nftables_import_str}")

        # Threat Intelligence settings (NEW in v2.5)
        threat_enabled_str = _get_from_sources('threat_feeds_enabled', config_dict)
        if threat_enabled_str is not None:
            try:
                self.threat_feeds_enabled = _parse_bool(threat_enabled_str, 'threat_feeds_enabled')
                logger.debug(f"DEBUG: CONFIG: threat_feeds_enabled = {threat_enabled_str}")
            except ValueError as e:
                logger.warning(str(e))

        threat_sources_str = _get_from_sources('threat_feed_sources', config_dict)
        if threat_sources_str is not None:
            self.threat_feed_sources = threat_sources_str.strip()
            logger.debug(f"DEBUG: CONFIG: threat_feed_sources = {threat_sources_str}")

        threat_cache_str = _get_from_sources('threat_feed_cache_hours', config_dict)
        if threat_cache_str is not None:
            try:
                self.threat_feed_cache_hours = int(threat_cache_str)
                logger.debug(f"DEBUG: CONFIG: threat_feed_cache_hours = {threat_cache_str}")
            except ValueError:
                logger.warning(f"Invalid integer value for threat_feed_cache_hours: {threat_cache_str}")

        data_dir = Path(self.data_dir)
        state_dir = Path(self.state_dir)

        # Resolve data files with config.conf override support
        if self.blacklist_ipv4_file is None:
            override = _get_from_sources('blacklist_ipv4_file', config_dict)
            self.blacklist_ipv4_file = override if override else str(data_dir / 'blacklist_ipv4.txt')

        if self.blacklist_ipv6_file is None:
            override = _get_from_sources('blacklist_ipv6_file', config_dict)
            self.blacklist_ipv6_file = override if override else str(data_dir / 'blacklist_ipv6.txt')

        if self.prelogin_bruteforce_file is None:
            override = _get_from_sources('prelogin_bruteforce_file', config_dict)
            self.prelogin_bruteforce_file = override if override else str(data_dir / 'prelogin-bruteforce-ips.txt')

        if self.whitelist_file is None:
            override = _get_from_sources('whitelist_file', config_dict)
            self.whitelist_file = override if override else str(data_dir / 'whitelist_ips.txt')

        if self.manual_blacklist_file is None:
            override = _get_from_sources('manual_blacklist_file', config_dict)
            self.manual_blacklist_file = override if override else str(data_dir / 'manual_blacklist.txt')

        # Resolve state files
        if self.state_file is None:
            override = _get_from_sources('state_file', config_dict)
            self.state_file = override if override else str(state_dir / 'state.json')

        if self.database_path is None:
            override = _get_from_sources('database_path', config_dict)
            self.database_path = override if override else str(state_dir / 'blacklist.db')

        # Resolve IPInfo paths
        if self.ipinfo_token_file is None:
            override = _get_from_sources('token_file', config_dict)
            self.ipinfo_token_file = override if override else str(Path(self.config_dir) / 'ipinfo_token.txt')
            logger.info(f"DEBUG: CONFIG: ipinfo_token_file = {self.ipinfo_token_file}")

        if self.ipinfo_cache_dir is None:
            override = _get_from_sources('cache_dir', config_dict)
            self.ipinfo_cache_dir = override if override else str(state_dir / 'ipinfo_cache')
            logger.info(f"DEBUG: CONFIG: ipinfo_cache_dir = {self.ipinfo_cache_dir}")

        if self.ipinfo_results_file is None:
            override = _get_from_sources('results_file', config_dict)
            self.ipinfo_results_file = override if override else str(state_dir / 'ipinfo_results.json')
            logger.info(f"DEBUG: CONFIG: ipinfo_results_file = {self.ipinfo_results_file}")

        if self.ipinfo_csv_cache_file is None:
            override = _get_from_sources('csv_cache_file', config_dict)
            self.ipinfo_csv_cache_file = override if override else str(state_dir / 'ipinfo_results_legacy.csv')
            logger.info(f"DEBUG: CONFIG: ipinfo_csv_cache_file = {self.ipinfo_csv_cache_file}")

        return self

    def ensure_directories(self):
        """Create required directories if they don't exist"""
        logger = logging.getLogger(__name__)

        # Create main directories
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

        # Create organized subdirectories (v2.9.0+) using configured paths
        # Security: Different permissions based on data sensitivity
        # Note: mkdir(mode=X) doesn't guarantee permissions with parents=True
        # due to umask influence. We use explicit chmod() after creation.
        subdirs_with_perms = [
            (Path(self.data_subdir), 0o755, "data files (public IPs)"),
            (Path(self.state_subdir), 0o750, "state files (sensitive metadata)"),
            (Path(self.cache_subdir), 0o755, "cache files (public geolocation)"),
            (Path(self.logs_subdir), 0o750, "logs (may contain sensitive info)"),
            (Path(self.backup_subdir), 0o750, "backups (critical data)"),
        ]

        # Preserve user's scripts/ and systemd/ directories if they exist
        scripts_dir = Path(self.data_dir) / 'scripts'
        systemd_dir = Path(self.data_dir) / 'systemd'
        if scripts_dir.exists():
            subdirs_with_perms.append((scripts_dir, 0o755, "user scripts"))
        if systemd_dir.exists():
            subdirs_with_perms.append((systemd_dir, 0o755, "systemd overrides"))

        for subdir, mode, description in subdirs_with_perms:
            if not subdir.exists():
                try:
                    # Create directory first
                    subdir.mkdir(parents=True, exist_ok=True)
                    # Then explicitly set permissions (guaranteed to work)
                    subdir.chmod(mode)
                    logger.debug(f"Created subdirectory: {subdir} ({oct(mode)}) - {description}")
                except Exception as e:
                    logger.warning(f"Failed to create subdirectory {subdir}: {e}")

        # Create IPInfo cache directory
        if self.ipinfo_cache_dir:
            ipinfo_cache_path = Path(self.ipinfo_cache_dir)
            if not ipinfo_cache_path.exists():
                try:
                    # Security: mkdir(mode=X) doesn't guarantee with parents=True
                    ipinfo_cache_path.mkdir(parents=True, exist_ok=True)
                    ipinfo_cache_path.chmod(0o755)  # Public cache data, world-readable OK
                    logger.info(f"Created IPInfo cache directory: {ipinfo_cache_path} (0o755)")
                except Exception as e:
                    logger.warning(f"Failed to create IPInfo cache directory {ipinfo_cache_path}: {e}")

    def get_backup_dir(self) -> Path:
        """Get backup directory path (v2.9.0+: uses configured backup_subdir)"""
        return Path(self.backup_subdir)

    def get_logs_dir(self) -> Path:
        """Get logs directory path (v2.9.0+: uses configured logs_subdir)"""
        return Path(self.logs_subdir)


# Global configuration instance (singleton pattern)
_config_instance = None


def get_config() -> DetectorConfig:
    """
    Get global configuration instance with lazy initialization.

    Ensures configuration is loaded once and shared across modules.
    Automatically creates required directories on first access.

    Startup sequence (v2.9.0+):
    1. Auto-migrate to organized structure (one-time, if needed)
    2. Auto-sync config.conf with template (merge new options)
    3. Load configuration
    4. Ensure directories exist
    """
    global _config_instance
    if _config_instance is None:
        # MIGRATION (v2.9.0+): Auto-migrate to organized structure
        # This runs once on first startup after upgrading to v2.9.0+
        # Moves files from flat structure to organized subdirectories
        try:
            from .utils.migration import auto_migrate_to_organized_structure
            auto_migrate_to_organized_structure()
        except Exception as e:
            logging.getLogger(__name__).warning(f"Auto-migration failed: {e}")
            logging.getLogger(__name__).info("Continuing with files in current locations")

        # AUTO-SYNC: Merge new template options before loading
        # This ensures users automatically receive new configuration options
        # from template updates without losing their customized settings
        try:
            from .config_sync import auto_sync_on_startup
            auto_sync_on_startup()
        except Exception as e:
            logging.getLogger(__name__).warning(f"Config auto-sync failed: {e}")
            logging.getLogger(__name__).info("Continuing with existing config")

        # Load configuration
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
