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
| state_dir | `${data_dir}` | State files location |
| project_dir | `${data_dir}/bruteforce_detector` | Project code directory |

**Common overrides**:
```ini
[paths]
data_dir = /var/lib/tribanft
state_dir = /var/lib/tribanft/state
```

### [logs] - Log File Paths

| Option | Default | Description |
|--------|---------|-------------|
| syslog_path | `/var/log/syslog` | System log file |
| mssql_errorlog_path | `/var/opt/mssql/log/errorlog` | MSSQL error log |
| apache_access_log_path | Not set | Apache access log (optional) |
| nginx_access_log_path | Not set | Nginx access log (optional) |

Add custom log paths:
```ini
[logs]
my_app_log_path = /var/log/myapp.log
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

### [storage] - Data Storage

| Option | Default | Description |
|--------|---------|-------------|
| use_database | `false` | Use SQLite database (recommended for >1000 IPs) |
| sync_to_file | `true` | Keep text files synced with database |
| database_path | `${data_dir}/blacklist.db` | SQLite database path |
| blacklist_ipv4_path | `${data_dir}/blacklist_ipv4.txt` | IPv4 text file |
| blacklist_ipv6_path | `${data_dir}/blacklist_ipv6.txt` | IPv6 text file |

**Recommendations**:
- Small deployments (<1000 IPs): `use_database = false`
- Large deployments (>1000 IPs): `use_database = true`
- Maximum performance: `use_database = true, sync_to_file = false`

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

See: docs/PLUGIN_DEVELOPMENT.md

### [ipinfo] - IP Geolocation (Optional)

| Option | Default | Description |
|--------|---------|-------------|
| daily_limit | `2000` | IPInfo.io daily API limit |
| rate_limit_per_minute | `100` | Rate limit per minute |

**Enable geolocation**:
1. Get API key from ipinfo.io
2. Set environment variable: `export IPINFO_TOKEN="your-token"`

### [whitelist] - IP Whitelist

| Option | Default | Description |
|--------|---------|-------------|
| whitelist_path | `${data_dir}/whitelist_ips.txt` | Whitelist file path |

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
| TRIBANFT_DATA_DIR | data_dir | `/var/lib/tribanft` |
| TRIBANFT_STATE_DIR | state_dir | `/var/lib/tribanft/state` |
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

## Migration: File → Database

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

### Minimal (Learning Mode)
```ini
[features]
enable_nftables_update = false

[storage]
use_database = false

[realtime]
monitor_syslog = true
```

### Production (High Traffic)
```ini
[features]
enable_nftables_update = true

[storage]
use_database = true
sync_to_file = false

[performance]
batch_size = 2000
backup_interval_days = 7

[realtime]
monitor_syslog = true
monitor_mssql = true
```

### Multi-Service Environment
```ini
[logs]
apache_access_log_path = /var/log/apache2/access.log
nginx_access_log_path = /var/log/nginx/access.log

[realtime]
monitor_syslog = true
monitor_mssql = true
monitor_apache = true
monitor_nginx = true

[features]
enable_crowdsec_integration = true
enable_fail2ban_integration = true
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
