# TribanFT Configuration Reference

Complete reference for config.conf settings.

---

## Quick Setup

```bash
# Interactive setup (recommended)
scripts/setup-config.sh --learning-mode

# Manual setup
cp config.conf.template ~/.local/share/tribanft/config.conf
vim ~/.local/share/tribanft/config.conf
```

---

## Configuration File Location

**Priority (highest first)**:
1. `TRIBANFT_CONFIG_FILE` environment variable
2. `~/.local/share/tribanft/config.conf`
3. `${XDG_DATA_HOME}/tribanft/config.conf`

**Override any setting**:
```bash
export TRIBANFT_DATA_DIR="/custom/path"
```

---

## Core Configuration Sections

### [paths] - File Locations

| Option | Default | Description |
|--------|---------|-------------|
| data_dir | `~/.local/share/tribanft` | Base directory for all data |
| state_dir | `${data_dir}` | State files location (legacy, deprecated) |
| project_dir | `${data_dir}/bruteforce_detector` | Project code directory |
| **data_subdir** | `${data_dir}/data` | **Firewall data files directory (v2.9.0+)** |
| **state_subdir** | `${data_dir}/state` | **Runtime state files directory (v2.9.0+)** |
| **cache_subdir** | `${data_dir}/cache` | **Temporary cache directory (v2.9.0+)** |
| **logs_subdir** | `${data_dir}/logs` | **Application logs directory (v2.9.0+)** |
| **backup_subdir** | `${data_dir}/backups` | **Backup files directory (v2.9.0+)** |

**Organized Directory Structure (v2.9.0+)**:
```
~/.local/share/tribanft/
├── config.conf
├── data/           # Firewall lists (0o755)
├── state/          # Runtime state (0o750)
├── cache/          # Temporary cache (0o755)
├── logs/           # Application logs (0o750)
└── backups/        # All backups (0o750)
```

**Common overrides**:
```ini
[paths]
data_dir = ~/.local/share/tribanft
data_subdir = ${data_dir}/data
state_subdir = ${data_dir}/state
logs_subdir = ${data_dir}/logs
```

**Auto-migration**: Existing installations automatically migrate to organized structure on first v2.9.0+ startup

### [logs] - Log File Paths

| Option | Default | Description |
|--------|---------|-------------|
| **app_log_filename** | `tribanft.log` | **Application log filename (v2.9.0+)** |
| **app_log_path** | `${paths:logs_subdir}/tribanft.log` | **Application log full path (v2.9.0+)** |
| **log_max_bytes** | `10485760` | **Max log file size (10MB, v2.9.0+)** |
| **log_backup_count** | `5` | **Number of rotated logs to keep (v2.9.0+)** |
| syslog_path | `/var/log/syslog` | System log file to monitor |
| mssql_errorlog_path | `/var/opt/mssql/log/errorlog` | MSSQL error log to monitor |
| apache_access_log_path | Not set | Apache access log (optional) |
| nginx_access_log_path | Not set | Nginx access log (optional) |

**Log Rotation (v2.9.0+)**:
- Automatic rotation when log reaches `log_max_bytes`
- Old logs compressed with gzip (90% space savings)
- Example: `tribanft.log` → `tribanft.log.1` → `tribanft.log.2.gz`

Add custom log paths:
```ini
[logs]
my_app_log_path = /var/log/myapp.log
log_max_bytes = 20971520  # 20MB
log_backup_count = 10     # Keep 10 rotated files
```

### [features] - Detection Toggles

| Option | Default | Description |
|--------|---------|-------------|
| enable_prelogin_detection | `true` | MSSQL prelogin attack detection |
| enable_failed_login_detection | `true` | Failed login detection |
| enable_port_scan_detection | `true` | Port scan detection |
| enable_crowdsec_integration | `false` | CrowdSec integration |
| enable_fail2ban_integration | `false` | Fail2Ban integration |
| **enable_nftables_update** | `false` | **NFTables blocking (Week 1: false)** |

**Learning mode (Week 1)**:
```ini
[features]
enable_nftables_update = false  # No blocking, log only
```

**Production mode (Week 3+)**:
```ini
[features]
enable_nftables_update = true  # Active blocking
```

### [nftables] - Firewall Integration

| Option | Default | Description |
|--------|---------|-------------|
| nft_bin | `/usr/sbin/nft` | NFTables binary path |
| blacklist_set | `inet filter blacklist_ipv4` | IPv4 blacklist set |
| port_scanners_set | `inet filter port_scanners` | Port scanner set |
| crowdsec_sets | `inet filter crowdsec` | CrowdSec set pattern |
| fail2ban_pattern | `inet f2b-table addr-set-*` | Fail2Ban set pattern |
| nftables_auto_discovery | `false` | Auto-discover all sets |
| nftables_event_log_enabled | `false` | Log NFTables events to JSONL |

**Setup NFTables**:
```bash
sudo scripts/setup_nftables.sh
```

### [data_files] - Firewall Data Files (v2.9.0+)

Configurable filenames and paths for firewall lists. Filenames separated from paths for full user control.

| Option | Default | Description |
|--------|---------|-------------|
| blacklist_ipv4_filename | `blacklist_ipv4.txt` | IPv4 blacklist filename |
| blacklist_ipv6_filename | `blacklist_ipv6.txt` | IPv6 blacklist filename |
| whitelist_filename | `whitelist_ips.txt` | Whitelist filename |
| manual_blacklist_filename | `manual_blacklist.txt` | Manual blacklist filename |
| prelogin_bruteforce_filename | `prelogin-bruteforce-ips.txt` | Prelogin attacks filename |
| blacklist_ipv4_file | `${paths:data_subdir}/${data_files:blacklist_ipv4_filename}` | IPv4 blacklist full path |
| blacklist_ipv6_file | `${paths:data_subdir}/${data_files:blacklist_ipv6_filename}` | IPv6 blacklist full path |
| whitelist_file | `${paths:data_subdir}/${data_files:whitelist_filename}` | Whitelist full path |

**Customization**:
```ini
[data_files]
blacklist_ipv4_filename = my-custom-blacklist-v4.txt
blacklist_ipv4_file = ${paths:data_subdir}/${data_files:blacklist_ipv4_filename}
```

### [state_files] - Runtime State Files (v2.9.0+)

Configurable filenames and paths for runtime state data.

| Option | Default | Description |
|--------|---------|-------------|
| state_filename | `state.json` | State file filename |
| database_filename | `blacklist.db` | SQLite database filename |
| nftables_event_log_filename | `nftables_events.jsonl` | NFTables events log filename |
| state_file | `${paths:state_subdir}/${state_files:state_filename}` | State file full path |
| database_path | `${paths:state_subdir}/${state_files:database_filename}` | Database full path |
| nftables_event_log | `${paths:state_subdir}/${state_files:nftables_event_log_filename}` | Events log full path |
| backup_dir | `${paths:backup_subdir}` | Backups directory |

### [storage] - Data Storage

| Option | Default | Description |
|--------|---------|-------------|
| use_database | `false` | Use SQLite database (recommended for >1000 IPs) |
| sync_to_file | `true` | Keep text files synced with database |

**Recommendations**:
- Small deployments (<1000 IPs): `use_database = false`
- Large deployments (>1000 IPs): `use_database = true`
- Maximum performance: `use_database = true, sync_to_file = false`

**Note**: File paths configured in [data_files] and [state_files] sections (v2.9.0+)

### [performance] - Backup & Performance

| Option | Default | Description |
|--------|---------|-------------|
| backup_enabled | `true` | Enable smart backups |
| backup_interval_days | `7` | Only backup if last backup >7 days |
| backup_retention_days | `30` | Keep backups for 30 days |
| backup_min_keep | `4` | Always keep at least 4 backups |
| backup_compress_age_days | `1` | Compress backups older than 1 day |
| batch_size | `1000` | Batch size for database operations |

**Smart backups** - Only create backup if:
- Last backup > `backup_interval_days` ago
- **OR** file changed since last backup

### [realtime] - Real-Time Monitoring (v2.3+)

| Option | Default | Description |
|--------|---------|-------------|
| monitor_syslog | `false` | Monitor syslog in real-time |
| monitor_mssql | `false` | Monitor MSSQL logs in real-time |
| monitor_apache | `false` | Monitor Apache logs in real-time |
| monitor_nginx | `false` | Monitor Nginx logs in real-time |
| debounce_interval | `1.0` | Batch rapid writes (seconds) |
| max_events_per_second | `1000` | Rate limit for DoS protection |
| rate_limit_backoff | `30` | Pause duration on rate limit (seconds) |
| fallback_interval | `60` | Periodic mode interval if watchdog unavailable |

**Enable real-time monitoring**:
```bash
pip3 install --user watchdog  # Required dependency
```

```ini
[realtime]
monitor_syslog = true
monitor_mssql = true
```

**Auto-fallback** - If watchdog unavailable, automatically falls back to periodic mode (60s intervals)

### [plugins] - Plugin System

| Option | Default | Description |
|--------|---------|-------------|
| enable_plugin_system | `true` | Enable plugin auto-discovery |
| detector_plugin_dir | `${project_dir}/plugins/detectors` | Detector plugins directory |
| parser_plugin_dir | `${project_dir}/plugins/parsers` | Parser plugins directory |
| enable_yaml_rules | `true` | Enable YAML-based detection rules |
| rules_dir | `${project_dir}/rules` | YAML rules directory |

See: `docs/PLUGIN_DEVELOPMENT.md`

### [ipinfo] - IP Geolocation (Optional)

| Option | Default | Description |
|--------|---------|-------------|
| token_filename | `ipinfo_token.txt` | IPInfo token filename (v2.9.0+) |
| results_filename | `ipinfo_results.json` | IPInfo results filename (v2.9.0+) |
| csv_cache_filename | `ipinfo_results_legacy.csv` | Legacy CSV cache filename (v2.9.0+) |
| token_file | `${paths:config_dir}/ipinfo_token.txt` | Token file full path (v2.9.0+) |
| cache_dir | `${paths:cache_subdir}/ipinfo_cache` | IPInfo cache directory (v2.9.0+) |
| results_file | `${paths:state_subdir}/${ipinfo:results_filename}` | Results file full path (v2.9.0+) |
| daily_limit | `2000` | IPInfo.io daily API limit |
| rate_limit_per_minute | `100` | Rate limit per minute |

**Enable geolocation**:
1. Get API key from ipinfo.io
2. Set environment variable: `export IPINFO_TOKEN="your-token"`

### [whitelist] - IP Whitelist

| Option | Default | Description |
|--------|---------|-------------|
| whitelist_filename | `whitelist_ips.txt` | Whitelist filename (v2.9.0+) |
| whitelist_file | `${paths:data_subdir}/${whitelist:whitelist_filename}` | Whitelist full path (v2.9.0+) |

**Add whitelisted IPs**:
```bash
tribanft --whitelist-add 10.0.0.5 --reason "Monitoring server"
```

### [advanced] - Debug Settings

| Option | Default | Description |
|--------|---------|-------------|
| verbose | `false` | Enable debug-level logging |
| log_level | `INFO` | Logging level (DEBUG, INFO, WARNING, ERROR) |

### [threat_intelligence] - Threat Feed Integration (v2.5+)

| Option | Default | Description |
|--------|---------|-------------|
| threat_feeds_enabled | `false` | Enable threat intelligence feed integration |
| threat_feed_sources | `spamhaus` | Comma-separated list of sources (spamhaus, abuseipdb, alienvault) |
| threat_feed_cache_hours | `24` | Cache duration for feed results (hours) |

**Enable threat intelligence**:
```ini
[threat_intelligence]
threat_feeds_enabled = true
threat_feed_sources = spamhaus
```

**Notes**:
- Spamhaus DROP/EDROP lists are free (no API key required)
- AbuseIPDB and AlienVault require free registration for API keys
- Feed results are cached to minimize API calls

---

## Environment Variables

Override any config option:

| Variable | Override | Example |
|----------|----------|---------|
| TRIBANFT_CONFIG_FILE | Config file path | `/etc/tribanft/config.conf` |
| TRIBANFT_DATA_DIR | data_dir | `~/.local/share/tribanft` |
| TRIBANFT_STATE_DIR | state_dir | `~/.local/share/tribanft/state` |
| IPINFO_TOKEN | IPInfo API token | `your-api-token` |
| BFD_ENABLE_NFTABLES_UPDATE | enable_nftables_update | `true` or `false` |

**Set environment variable**:
```bash
# Temporary
export TRIBANFT_DATA_DIR="/custom/path"

# Permanent (add to ~/.bashrc)
echo 'export TRIBANFT_DATA_DIR="/custom/path"' >> ~/.bashrc
```

---

## Service Management

```bash
# Setup and start
scripts/setup-config.sh --learning-mode
sudo systemctl start tribanft

# View logs
sudo journalctl -u tribanft -f

# Restart after config changes
sudo systemctl restart tribanft

# Check status
sudo systemctl status tribanft
```

---

## Migrations

### Migration: Organized Directory Structure (v2.9.0+)

**Automatic migration** on first startup after upgrading to v2.9.0+:

**What happens**:
1. System detects legacy flat directory structure
2. Creates timestamped backup tarball: `tribanft_pre_migration_backup_TIMESTAMP.tar.gz`
3. Creates organized subdirectories: `data/`, `state/`, `cache/`, `logs/`, `backups/`
4. Moves files to appropriate locations based on type
5. Renames old config backups to new format: `config.conf_TIMESTAMP.backup`
6. Logs migration summary with file counts
7. Creates marker file: `.migrated_to_organized_structure`

**Files moved**:
- Blacklist/whitelist files → `data/`
- State files (state.json, blacklist.db) → `state/`
- Cache files (ipinfo_cache/) → `cache/`
- Log files (tribanft.log*) → `logs/`
- All backup files → `backups/`

**Preserved**:
- `config.conf` stays in base directory
- User's `scripts/` and `systemd/` directories unchanged

**Rollback**:
```bash
# If issues occur, restore from backup tarball
cd ~/.local/share/tribanft
tar -xzf tribanft_pre_migration_backup_TIMESTAMP.tar.gz
rm .migrated_to_organized_structure
```

**Permissions**:
- data/ (0o755) - Public firewall lists
- state/ (0o750) - Sensitive runtime state
- cache/ (0o755) - Public cache data
- logs/ (0o750) - May contain sensitive info
- backups/ (0o750) - Critical backup data

### Migration: File → Database

```bash
# Edit config
vim ~/.local/share/tribanft/config.conf
```

Change:
```ini
[storage]
use_database = true  # Enable database
sync_to_file = true  # Keep files synced during migration
```

```bash
# Restart service - auto-migrates data
sudo systemctl restart tribanft

# Verify migration
tribanft --show-blacklist | head -20

# After verification, optionally disable file sync for performance
# [storage]
# sync_to_file = false
```

---

## Troubleshooting

```bash
# Validate config syntax
python3 -c "from bruteforce_detector.config import get_config; get_config()"

# Check current settings
tribanft --show-config  # If available

# Reset to defaults
cp config.conf.template ~/.local/share/tribanft/config.conf
scripts/setup-config.sh --learning-mode
```

---

## Example Configurations

### Learning Mode (Week 1 - No Blocking)

Complete configuration for initial deployment and tuning. Logging only, no firewall blocking.

```ini
[paths]
data_dir = ~/.local/share/tribanft
state_dir = ${data_dir}
project_dir = ${data_dir}/bruteforce_detector
data_subdir = ${paths:data_dir}/data
state_subdir = ${paths:data_dir}/state
cache_subdir = ${paths:data_dir}/cache
logs_subdir = ${paths:data_dir}/logs
backup_subdir = ${paths:data_dir}/backups

[logs]
syslog_path = /var/log/syslog
mssql_errorlog_path = /var/opt/mssql/log/errorlog
app_log_filename = tribanft.log
app_log_path = ${paths:logs_subdir}/${logs:app_log_filename}
log_max_bytes = 10485760
log_backup_count = 5

[storage]
use_database = false
sync_to_file = true

[features]
enable_prelogin_detection = true
enable_failed_login_detection = true
enable_port_scan_detection = true
enable_nftables_update = false
enable_crowdsec_integration = false
enable_fail2ban_integration = false

[detection]
failed_login_threshold = 20
time_window_minutes = 10080

[realtime]
monitor_syslog = true
monitor_mssql = false
monitor_apache = false
monitor_nginx = false
debounce_interval = 1.0

[plugins]
enable_plugin_system = true
enable_yaml_rules = true

[performance]
backup_enabled = true
backup_interval_days = 7

[advanced]
verbose = false
log_level = INFO
```

### Production (Active Blocking)

Complete configuration for production deployment with NFTables integration.

```ini
[paths]
data_dir = ~/.local/share/tribanft
state_dir = ${data_dir}/state
project_dir = ${data_dir}/bruteforce_detector
data_subdir = ${paths:data_dir}/data
state_subdir = ${paths:data_dir}/state
cache_subdir = ${paths:data_dir}/cache
logs_subdir = ${paths:data_dir}/logs
backup_subdir = ${paths:data_dir}/backups

[logs]
syslog_path = /var/log/syslog
mssql_errorlog_path = /var/opt/mssql/log/errorlog
apache_access_log_path = /var/log/apache2/access.log
nginx_access_log_path = /var/log/nginx/access.log
app_log_filename = tribanft.log
app_log_path = ${paths:logs_subdir}/${logs:app_log_filename}
log_max_bytes = 10485760
log_backup_count = 5

[storage]
use_database = true
sync_to_file = true

[features]
enable_prelogin_detection = true
enable_failed_login_detection = true
enable_port_scan_detection = true
enable_nftables_update = true
enable_crowdsec_integration = true
enable_fail2ban_integration = true

[nftables]
nft_bin = /usr/sbin/nft
blacklist_set = inet filter blacklist_ipv4
blacklist_set_ipv6 = inet filter blacklist_ipv6
port_scanners_set = inet filter port_scanners
crowdsec_sets = inet filter crowdsec
fail2ban_pattern = inet f2b-table addr-set-*
nftables_auto_discovery = true
nftables_event_log_enabled = false

[detection]
failed_login_threshold = 20
brute_force_threshold = 15
port_scan_threshold = 50
time_window_minutes = 10080
fail_on_detector_error = false

[realtime]
monitor_syslog = true
monitor_mssql = true
monitor_apache = true
monitor_nginx = true
debounce_interval = 1.0
max_events_per_second = 1000
rate_limit_backoff = 30
fallback_interval = 60

[plugins]
enable_plugin_system = true
enable_yaml_rules = true
detector_plugin_dir = ${paths:project_dir}/plugins/detectors
parser_plugin_dir = ${paths:project_dir}/plugins/parsers
rules_dir = ${paths:project_dir}/rules

[ipinfo]
daily_limit = 2000
rate_limit_per_minute = 100

[whitelist]
whitelist_path = ${paths:data_dir}/whitelist_ips.txt

[performance]
backup_enabled = true
backup_interval_days = 7
backup_retention_days = 30
backup_min_keep = 4
backup_compress_age_days = 1
batch_size = 1000

[threat_intelligence]
threat_feeds_enabled = true
threat_feed_sources = spamhaus
threat_feed_cache_hours = 24

[advanced]
verbose = false
log_level = INFO
```

### High-Performance (Large Scale)

Optimized configuration for high-traffic environments (>10k IPs, multiple services).

```ini
[paths]
data_dir = ~/.local/share/tribanft
state_dir = ${data_dir}/state
project_dir = ${data_dir}/bruteforce_detector
data_subdir = ${paths:data_dir}/data
state_subdir = ${paths:data_dir}/state
cache_subdir = ${paths:data_dir}/cache
logs_subdir = ${paths:data_dir}/logs
backup_subdir = ${paths:data_dir}/backups

[logs]
syslog_path = /var/log/syslog
mssql_errorlog_path = /var/opt/mssql/log/errorlog
apache_access_log_path = /var/log/apache2/access.log
nginx_access_log_path = /var/log/nginx/access.log
dns_log_path = /var/log/named/query.log
app_log_filename = tribanft.log
app_log_path = ${paths:logs_subdir}/${logs:app_log_filename}
log_max_bytes = 20971520
log_backup_count = 10

[storage]
use_database = true
sync_to_file = false

[features]
enable_prelogin_detection = true
enable_failed_login_detection = true
enable_port_scan_detection = true
enable_nftables_update = true
enable_crowdsec_integration = true
enable_fail2ban_integration = true

[nftables]
nft_bin = /usr/sbin/nft
blacklist_set = inet filter blacklist_ipv4
blacklist_set_ipv6 = inet filter blacklist_ipv6
port_scanners_set = inet filter port_scanners
crowdsec_sets = inet filter crowdsec
fail2ban_pattern = inet f2b-table addr-set-*
nftables_auto_discovery = true
nftables_event_log_enabled = true
batch_size = 2000

[detection]
failed_login_threshold = 15
brute_force_threshold = 10
port_scan_threshold = 30
time_window_minutes = 10080
fail_on_detector_error = false

[realtime]
monitor_syslog = true
monitor_mssql = true
monitor_apache = true
monitor_nginx = true
debounce_interval = 0.5
max_events_per_second = 2000
rate_limit_backoff = 30
fallback_interval = 60

[plugins]
enable_plugin_system = true
enable_yaml_rules = true
detector_plugin_dir = ${paths:project_dir}/plugins/detectors
parser_plugin_dir = ${paths:project_dir}/plugins/parsers
rules_dir = ${paths:project_dir}/rules

[ipinfo]
daily_limit = 2000
rate_limit_per_minute = 100

[whitelist]
whitelist_path = ${paths:data_dir}/whitelist_ips.txt

[performance]
backup_enabled = true
backup_interval_days = 3
backup_retention_days = 14
backup_min_keep = 4
backup_compress_age_days = 1
batch_size = 2000

[threat_intelligence]
threat_feeds_enabled = true
threat_feed_sources = spamhaus,abuseipdb,alienvault
threat_feed_cache_hours = 12

[advanced]
verbose = false
log_level = WARNING
```

---

## Configuration Template

Complete template: `config.conf.template` in project root

---

## Related Documentation

- **Deployment**: docs/DEPLOYMENT_GUIDE.md
- **Plugin System**: docs/PLUGIN_DEVELOPMENT.md
- **Rule Syntax**: docs/RULE_SYNTAX.md
- **Monitoring**: docs/MONITORING_AND_TUNING.md
