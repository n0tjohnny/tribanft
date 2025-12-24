# TribanFT Configuration Guide

# Index

- [Overview](#overview)
- [Configuration File Location](#configuration-file-location)
- [Configuration Precedence](#configuration-precedence)
- [Quick Start](#quick-start)
- [Configuration Sections](#configuration-sections)
- [Systemd Service Configuration](#systemd-service-configuration)
- [Environment Variable Overrides](#environment-variable-overrides)
- [Performance Tuning Guide](#performance-tuning-guide)
- [Migration Scenarios](#migration-scenarios)
- [Troubleshooting](#troubleshooting-1)
- [Best Practices](#best-practices)
- [Complete Example Configuration](#complete-example-configuration)

---

## Overview

TribanFT uses a centralized configuration file (`config.conf`) in INI format. This guide explains all configuration options and best practices.

---

## Configuration File Location

**Primary location**: `~/.local/share/tribanft/config.conf`

The system searches in this order:
1. `$TRIBANFT_CONFIG_FILE` environment variable
2. `~/.local/share/tribanft/config.conf` (default)
3. `/etc/tribanft/config.conf` (system-wide alternative)
4. `./config.conf` (current directory)

If no config file exists, defaults are used.

---

## Configuration Precedence

Settings are loaded with this priority (highest to lowest):

1. **Environment variables** (`BFD_*` for settings, `TRIBANFT_*` for paths)
2. **config.conf file**
3. **Built-in defaults**

This allows flexible configuration:
- Use `config.conf` for permanent settings
- Use environment variables for temporary overrides
- Rely on sensible defaults

---

## Quick Start

### Initial Setup

```bash
# Copy template
cp config.conf.template ~/.local/share/tribanft/config.conf

# Edit configuration
nano ~/.local/share/tribanft/config.conf

# Install systemd service
cd scripts
sudo ./install-service.sh
```

### Minimal Configuration

For most users, only these paths need configuration:

```ini
[paths]
data_dir = ~/.local/share/tribanft
config_dir = ~/.local/share/tribanft
state_dir = ~/.local/share/tribanft

[logs]
syslog_path = /var/log/syslog
mssql_error_log_path = /var/opt/mssql/log/errorlog
```

Everything else uses sensible defaults.

---

## Configuration Sections

### [paths] - Directory Locations

Core directories for TribanFT operation:

```ini
[paths]
# Main directory (all-in-one approach)
data_dir = ~/.local/share/tribanft      # Blacklists, whitelists, data files
config_dir = ~/.local/share/tribanft    # Configuration files
state_dir = ~/.local/share/tribanft     # Database, logs, backups

# Optional: Project location (auto-detected if omitted)
project_dir = /path/to/tribanft

# Binaries (usually auto-detected)
python_bin = /usr/bin/python3
tribanft_bin = ~/.local/bin/tribanft
```

**Note**: Using the same directory for all three (`~/.local/share/tribanft`) is the recommended approach for simplicity.

---

### [logs] - Log File Paths

Specify system log files to monitor:

```ini
[logs]
# System log (SSH, FTP, auth events)
syslog_path = /var/log/syslog

# MSSQL error log (if running SQL Server)
mssql_error_log_path = /var/opt/mssql/log/errorlog

# Apache access log (for SQL injection and WordPress attack detection)
# Common paths: /var/log/apache2/access.log (Debian/Ubuntu)
#               /var/log/httpd/access_log (RedHat/CentOS/Fedora)
apache_access_log_path = /var/log/apache2/access.log

# Nginx access log (for SQL injection and WordPress attack detection)
nginx_access_log_path = /var/log/nginx/access.log

# TribanFT application log (auto-generated if omitted)
app_log_path = ${paths:state_dir}/tribanft.log
```

---

### [data_files] - Data File Locations

Override default data file locations:

```ini
[data_files]
# By default, these are auto-generated in data_dir
# Only uncomment to override specific files

# blacklist_ipv4_file = /custom/path/blacklist_ipv4.txt
# blacklist_ipv6_file = /custom/path/blacklist_ipv6.txt
# whitelist_file = /custom/path/whitelist_ips.txt
# manual_blacklist_file = /custom/path/manual_blacklist.txt
# prelogin_bruteforce_file = /custom/path/prelogin-bruteforce-ips.txt
```

**Recommended**: Leave commented to use defaults.

---

### [state_files] - Runtime State Files

Database and runtime state:

```ini
[state_files]
# State tracking (log positions, last run timestamp)
state_file = ${paths:state_dir}/state.json

# SQLite database (primary storage)
database_path = ${paths:state_dir}/blacklist.db

# Backup directory
backup_dir = ${paths:state_dir}/backups
```

**Note**: `${paths:state_dir}` references the `state_dir` from `[paths]` section.

---

### [detection] - Detection Thresholds

Configure sensitivity of threat detection:

```ini
[detection]
# Time window for event correlation (minutes)
time_window_minutes = 10080             # 7 days (default)

# Threshold = number of events within time window to trigger blacklist
brute_force_threshold = 20              # General threshold
failed_login_threshold = 20             # Failed login attempts
prelogin_pattern_threshold = 20         # MSSQL prelogin probes
port_scan_threshold = 20                # Port scan events
```

**Example**: With `failed_login_threshold = 20` and `time_window_minutes = 10080`, an IP is blacklisted after 20 failed login attempts within 7 days.

**Tuning**:
- **Lower thresholds** (e.g., 10) = More sensitive, may have false positives
- **Higher thresholds** (e.g., 50) = Less sensitive, catches only persistent attackers
- **Shorter time window** (e.g., 1440 = 24 hours) = Catch rapid attacks
- **Longer time window** (e.g., 20160 = 14 days) = Catch slow, distributed attacks

---

### [features] - Enable/Disable Features

Control which detection modules are active:

```ini
[features]
# Detection modules
enable_prelogin_detection = true        # MSSQL reconnaissance detection
enable_failed_login_detection = true    # SSH/MSSQL/FTP brute force
enable_port_scan_detection = true       # Port scanning activity
enable_crowdsec_integration = true      # Import CrowdSec blocks

# System integrations
enable_nftables_update = true           # Sync to NFTables firewall
enable_auto_enrichment = true           # Periodic metadata refresh from NFTables/CrowdSec
```

**Tip**: Disable unused detectors to improve performance.

---

### [plugins] - Plugin System Configuration

**New in Phase 1 & 2**: Configure the plugin auto-discovery system and YAML rule engine.

```ini
[plugins]
# Enable plugin auto-discovery system
# When enabled, detectors and parsers are automatically loaded from plugins/ directory
# When disabled, uses legacy hardcoded detector/parser initialization
enable_plugin_system = true

# Plugin directories (relative to project_dir)
# These directories are scanned for detector and parser plugins
detector_plugin_dir = ${paths:project_dir}/bruteforce_detector/plugins/detectors
parser_plugin_dir = ${paths:project_dir}/bruteforce_detector/plugins/parsers

# ┌───────────────────────────────────────────────────────────────────────┐
# │ YAML Rule Engine                                                      │
# │ Define detection patterns in YAML files - no code required!          │
# └───────────────────────────────────────────────────────────────────────┘

# Enable YAML-based detection rules
# When enabled, scans rules_dir for YAML rule files
enable_yaml_rules = true

# Rules directory for YAML-based detection patterns
# Place your custom .yaml rule files here
rules_dir = ${paths:project_dir}/bruteforce_detector/rules
```

**YAML Parser Patterns (NEW in v2.1)**:

Parser patterns are automatically loaded from `${rules_dir}/parsers/`

**Pattern files:**
- `apache.yaml` - Apache/Nginx SQL injection, WordPress attack patterns
- `syslog.yaml` - Syslog prelogin, port scan patterns
- `mssql.yaml` - MSSQL failed login patterns
- `nftables.yaml` - NFTables port scan and network scan thresholds
- `PARSER_TEMPLATE.yaml.example` - Template for custom patterns

**To add custom patterns:**
1. Copy `PARSER_TEMPLATE.yaml.example` to `custom_parser.yaml`
2. Edit `pattern_groups` section with your regex patterns
3. Restart tribanft or re-run detection

No restart required for pattern updates - loaded at parser initialization.

**Per-Plugin Configuration:**

Control individual plugins by adding sections like `[plugin:detector_name]` or `[plugin:parser_name]`:

```ini
# Example: Disable specific plugin
# enable_prelogin_detector_plugin = false
# enable_crowdsec_detector_plugin = false

# Example: Custom plugin configuration (for future custom plugins)
# [plugin:custom_detector]
# threshold = 15
# time_window = 120
# custom_parameter = value
```

**Plugin System Features:**

1. **Auto-Discovery**: Automatically loads detector and parser plugins from configured directories
2. **YAML Rules**: Define detection patterns using YAML configuration files
3. **Drop-in Architecture**: Add new detectors/parsers without modifying core code
4. **Metadata-Driven**: Plugins use METADATA dictionaries for version control and dependencies

**Directory Structure:**
```
${project_dir}/bruteforce_detector/
├── core/
│   ├── plugin_manager.py      # Auto-discovery engine
│   └── rule_engine.py          # YAML rule processor
├── plugins/
│   ├── detectors/              # Detector plugins (Python files)
│   │   ├── prelogin.py
│   │   ├── failed_login.py
│   │   ├── port_scan.py
│   │   └── crowdsec.py
│   └── parsers/                # Parser plugins (Python files)
│       ├── syslog.py
│       ├── mssql.py
│       ├── apache.py
│       └── nftables.py
└── rules/
    ├── detectors/              # YAML detection rules
    │   ├── sql_injection.yaml
    │   ├── rdp_bruteforce.yaml
    │   ├── wordpress_attacks.yaml
    │   └── custom_environment_examples.yaml
    └── parsers/                # YAML parser patterns
        ├── apache.yaml
        ├── syslog.yaml
        ├── mssql.yaml
        ├── nftables.yaml
        └── PARSER_TEMPLATE.yaml.example
```

**See Also:**
- [PLUGIN_DEVELOPMENT.md](PLUGIN_DEVELOPMENT.md) - Creating custom plugins
- [RULE_SYNTAX.md](RULE_SYNTAX.md) - YAML rule syntax reference
- [PARSER_EVENTTYPES_MAPPING.md](PARSER_EVENTTYPES_MAPPING.md) - Parser pattern syntax and event types

---

### [storage] - Storage Backend

Choose between SQLite database or file-based storage:

```ini
[storage]
# Use SQLite database (RECOMMENDED for >1000 IPs)
use_database = true

# Sync database changes to text files (for compatibility with legacy tools)
sync_to_file = true
```

**Recommendations**:
- **Small deployments** (<1000 IPs): Either mode works
- **Large deployments** (>10,000 IPs): `use_database = true` (required for performance)
- **Database + file sync**: Best compatibility, slight performance cost
- **Database only**: `sync_to_file = false` for maximum performance

---

### [performance] - Performance Tuning

```ini
[performance]
# Batch size for bulk operations
batch_size = 2000

# Backup configuration
backup_enabled = true                   # Enable automatic backups
backup_interval_days = 7                # Only backup if last backup was >7 days ago
backup_retention_days = 30              # Days to keep backups
backup_min_keep = 4                     # Minimum backups to keep (even if older than retention)
backup_compress_age_days = 1            # Compress backups older than 1 day
```

**Backup Settings Explained**:
- **backup_enabled**: Master switch for automatic backups (set to false to disable all backups)
- **backup_interval_days**: Only create backup if last backup was more than X days ago (0 = every run, not recommended)
- **backup_retention_days**: Delete backups older than this
- **backup_min_keep**: Always keep at least this many (even if older than retention)
- **backup_compress_age_days**: Compress backups older than this (0 = compress immediately)

**New Optimization** (v1.3.0+): Smart backups skip redundant backups (identical content or <1 hour since last backup), reducing backup count by ~90%.

---

### [ipinfo] - IP Geolocation Service

Configure IPInfo.io integration for geolocation enrichment:

```ini
[ipinfo]
# API token file location (get token at https://ipinfo.io/signup)
token_file = ${paths:config_dir}/ipinfo_token.txt

# Cache directory for geolocation results
cache_dir = ${paths:state_dir}/ipinfo_cache

# Results files
results_file = ${paths:state_dir}/ipinfo_results.json
csv_cache_file = ${paths:state_dir}/ipinfo_results_legacy.csv

# Batch service settings (if running as systemd service)
batch_interval = 3600                   # Seconds between batch runs
batch_size = 2000                       # IPs per batch
```

**Setup**:
```bash
# Get free token at https://ipinfo.io/signup
echo "YOUR_TOKEN_HERE" > ~/.local/share/tribanft/ipinfo_token.txt
chmod 600 ~/.local/share/tribanft/ipinfo_token.txt
```

---

### [nftables] - NFTables Integration

Configure firewall synchronization and discovery:

```ini
[nftables]
# NFTables binary path
nft_bin = /usr/sbin/nft

# NFTables sets to sync (format: table_family table_name set_name)
blacklist_set = inet filter blacklist_ipv4
port_scanners_set = inet filter port_scanners

# CrowdSec sets to import (space-separated)
crowdsec_sets = inet filter crowdsec

# Fail2Ban sets pattern (supports wildcards)
fail2ban_pattern = inet f2b-table addr-set-*

# NFTables Discovery & Event Logging (NEW in v2.4)
nftables_event_log_enabled = false       # Enable shadow event log (JSONL format)
nftables_auto_discovery = false          # Auto-discover all NFTables sets
nftables_import_sets =                   # Comma-separated sets to import
                                         # Format: family:table:set_name
                                         # Example: inet:filter:attackers_ipv4
```

**Bidirectional Sync**:
- **Import**: IPs from `port_scanners_set`, `crowdsec_sets`, `fail2ban_pattern` → TribanFT blacklist
- **Export**: TribanFT blacklist → `blacklist_set` in NFTables

**Discovery Features (v2.4+)**:
- **Event Log**: Optional JSONL audit trail at `${state_dir}/nftables_events.jsonl`
- **Auto-Discovery**: Automatically detect all NFTables sets in the system
- **Flexible Import**: Import IPs from any NFTables set, not just predefined ones
- **Whitelist Filtering**: Automatically skips whitelisted IPs during import

**Usage Examples**:

```bash
# Example 1: Enable auto-discovery (logs all available sets)
[nftables]
nftables_auto_discovery = true

# Example 2: Import from custom CrowdSec and attacker sets
[nftables]
nftables_import_sets = inet:filter:crowdsec,inet:filter:attackers_ipv4

# Example 3: Enable event logging for debugging
[nftables]
nftables_event_log_enabled = true

# View event log:
tail -f ~/.local/share/tribanft/nftables_events.jsonl
jq . ~/.local/share/tribanft/nftables_events.jsonl  # Pretty-print with jq
```

**Expected Log Output** (with `tribanft --detect --verbose`):
```
INFO - Discovered 5 NFTables sets
DEBUG -    - inet:filter:blacklist_ipv4: type=ipv4_addr, flags=['timeout']
DEBUG -    - inet:filter:port_scanners: type=ipv4_addr, flags=['timeout', 'dynamic']
INFO - Imported 42 IPs from inet:filter:crowdsec
INFO - Found 15 IPs in port_scanners
```

---

### [realtime] - Real-Time Log Monitoring (NEW in v2.3)

Real-time monitoring uses filesystem events (inotify/kqueue) to detect new log entries immediately, reducing detection lag from 5 minutes to <2 seconds.

If watchdog library is unavailable or fails, automatically falls back to periodic mode with 60-second intervals (no manual configuration needed).

```ini
[realtime]
# Enable real-time monitoring for specific log sources
# Set to false to disable monitoring for that source
monitor_syslog = true
monitor_mssql = true
monitor_apache = true
monitor_nginx = true

# Alternative: Explicitly list custom files to monitor
# Uncomment to override auto-detection from log paths
# monitor_files = /var/log/auth.log, /custom/app.log

# Debounce interval (seconds)
# Batch rapid log writes within this window to reduce processing load
# Default: 1.0 second (handles log bursts efficiently)
debounce_interval = 1.0

# Rate limiting for DoS protection
# Maximum log events to process per second before triggering backoff
# Prevents attackers from overwhelming the system by flooding logs
max_events_per_second = 1000

# Rate limit backoff duration (seconds)
# If rate limit exceeded, pause real-time monitoring for this duration
# System falls back to periodic mode during backoff
rate_limit_backoff = 30

# Fallback interval (seconds)
# If real-time monitoring fails to start (missing inotify, permissions, etc),
# automatically fall back to periodic polling at this interval
# Default: 60 seconds (1 minute)
fallback_interval = 60
```

**Key Features:**

- **Sub-second Detection**: Near-instant detection of new attacks (<2 seconds vs 5 minutes in periodic mode)
- **Automatic Fallback**: Gracefully degrades to periodic mode if real-time monitoring is unavailable
- **DoS Protection**: Rate limiting prevents log flooding attacks from overwhelming the system
- **Debouncing**: Efficiently batches rapid log writes to reduce CPU usage
- **Per-Source Control**: Enable/disable monitoring for individual log sources

**Requirements:**

- Python `watchdog` library (install with `pip install watchdog`)
- Read access to monitored log files
- Filesystem support for inotify (Linux) or kqueue (BSD/macOS)

**Troubleshooting:**

If real-time monitoring fails to start:
1. Check log file permissions: `ls -l /var/log/syslog`
2. Verify watchdog is installed: `pip list | grep watchdog`
3. Check system logs for inotify errors: `dmesg | grep inotify`
4. System will automatically fall back to periodic mode (60-second interval)

---

### [advanced] - Advanced Settings

```ini
[advanced]
# Enable verbose logging (debug mode)
verbose = false

# Disable startup integrity verification (faster but risky)
skip_verify = false

# Minimum expected IPs in blacklist (anti-corruption protection)
# If blacklist drops below this threshold and loses >50% of IPs, write is blocked
# Set to 0 to disable protection (not recommended)
min_expected_ips = 1000

# User and group for service execution (systemd only)
service_user = root
service_group = root
```

**Advanced Settings Explained**:

- **verbose**: Enable debug-level logging for troubleshooting
- **skip_verify**: Disable integrity checks on startup (only use for emergency performance - disables corruption detection)
- **min_expected_ips**: Anti-corruption threshold - prevents accidental mass deletion of blacklist entries
- **service_user/service_group**: User and group for systemd service execution (requires root for NFTables access)

**Warning**: `skip_verify = true` disables corruption detection. Only use for emergency performance.

---

## Systemd Service Configuration

TribanFT runs as a systemd service for continuous operation with automatic restart on failure, boot persistence, and centralized logging via journald.

### Installation

**Automatic** (recommended):
```bash
# On your server (as root)
cd /path/to/tribanft
sudo ./install-service.sh
```

This automatically removes existing cron jobs, installs the systemd service, and starts it.

**Manual**:
```bash
sudo cp tribanft.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable tribanft.service
sudo systemctl start tribanft.service
```

### Service Management

**Basic commands**:
```bash
# Status and control
sudo systemctl status tribanft
sudo systemctl start tribanft
sudo systemctl stop tribanft
sudo systemctl restart tribanft

# Boot behavior
sudo systemctl enable tribanft   # Start on boot
sudo systemctl disable tribanft  # Don't start on boot
```

**View logs**:
```bash
# Live logs (follow mode)
sudo journalctl -u tribanft -f

# Last 100 lines
sudo journalctl -u tribanft -n 100

# Errors only
sudo journalctl -u tribanft -p err

# Since specific time
sudo journalctl -u tribanft --since "2025-12-18 10:00"
sudo journalctl -u tribanft --since today
```

### Detection Interval

**Service file location**: `/etc/systemd/system/tribanft.service`

Change detection interval by editing the `ExecStart` line:

```ini
[Service]
# Run detection every 5 minutes (300 seconds)
ExecStart=/usr/bin/python3 /usr/local/bin/tribanft --daemon --interval 300

# Run detection every 10 minutes (600 seconds)
ExecStart=/usr/bin/python3 /usr/local/bin/tribanft --daemon --interval 600

# Run detection every hour (3600 seconds)
ExecStart=/usr/bin/python3 /usr/local/bin/tribanft --daemon --interval 3600
```

After changes:
```bash
sudo systemctl daemon-reload
sudo systemctl restart tribanft
```

### Resource Limits

Add to `[Service]` section to prevent excessive CPU/memory usage:

```ini
[Service]
# Memory limits
MemoryMax=512M              # Hard limit
MemoryHigh=400M             # Soft limit (triggers pressure)

# CPU limits
CPUQuota=50%                # Maximum 50% of one CPU core

# I/O priority
IOSchedulingClass=2         # Best-effort
IOSchedulingPriority=4      # Lower priority
```

### Restart Policy

Configure automatic restart behavior:

```ini
[Service]
# Restart on any failure
Restart=on-failure

# Wait 10 seconds before restarting
RestartSec=10

# Give up after 5 restarts in 300 seconds
StartLimitInterval=300
StartLimitBurst=5
```

### Security Hardening

Additional security restrictions:

```ini
[Service]
# Prevent privilege escalation
NoNewPrivileges=false       # false = allow root operations (required for NFTables)

# Isolate /tmp
PrivateTmp=true

# Read-only system directories
ProtectSystem=strict
ProtectHome=true

# Allow writes only to TribanFT directories
ReadWritePaths=/var/lib/tribanft
ReadWritePaths=/var/log/tribanft
```

### Troubleshooting

**Service won't start**:
```bash
# Check detailed status
sudo systemctl status tribanft

# View recent errors
sudo journalctl -u tribanft -n 50 --no-pager

# Test manually
sudo /usr/bin/python3 /usr/local/bin/tribanft --daemon --interval 300

# Check permissions
ls -la /var/lib/tribanft/
ls -la /usr/local/bin/tribanft
```

**Service crashes repeatedly**:
```bash
# Check for Python errors
sudo journalctl -u tribanft -p err

# Increase restart delay in service file
RestartSec=30

# Then reload
sudo systemctl daemon-reload
sudo systemctl restart tribanft
```

### Production Service Example

Complete production-ready service configuration:

```ini
[Unit]
Description=TribanFT - IP Visibility & Intelligent Blacklist Management
Documentation=https://github.com/n0tjohnny/tribanft
After=network.target nftables.service

[Service]
Type=simple
User=root
Group=root

# Main service command - 5 minute detection interval
ExecStart=/usr/bin/python3 /usr/local/bin/tribanft --daemon --interval 300

# Restart policy
Restart=on-failure
RestartSec=10
StartLimitInterval=300
StartLimitBurst=5

# Resource limits
MemoryMax=512M
CPUQuota=50%
LimitNOFILE=65536
Nice=10

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=tribanft

# Security
NoNewPrivileges=false
PrivateTmp=true

# Working directory
WorkingDirectory=/var/lib/tribanft

# Environment
Environment="PYTHONUNBUFFERED=1"

[Install]
WantedBy=multi-user.target
```

---

## Environment Variable Overrides

Temporarily override settings without editing `config.conf`:

```bash
# Path overrides
export TRIBANFT_DATA_DIR=/tmp/tribanft/data
export TRIBANFT_STATE_DIR=/tmp/tribanft/state
export TRIBANFT_CONFIG_DIR=/tmp/tribanft/config

# Detection thresholds
export BFD_FAILED_LOGIN_THRESHOLD=10
export BFD_TIME_WINDOW_MINUTES=1440  # 24 hours
export BFD_PORT_SCAN_THRESHOLD=15
export BFD_PRELOGIN_PATTERN_THRESHOLD=25

# Storage backend
export BFD_USE_DATABASE=true
export BFD_SYNC_TO_FILE=false

# Backup settings
export BFD_BACKUP_ENABLED=true
export BFD_BACKUP_INTERVAL_DAYS=7
export BFD_BACKUP_RETENTION_DAYS=30
export BFD_BACKUP_MIN_KEEP=4
export BFD_BACKUP_COMPRESS_AGE_DAYS=1

# Advanced settings
export BFD_VERBOSE=true
export BFD_MIN_EXPECTED_IPS=500

# Real-time monitoring
export BFD_MONITOR_SYSLOG=true
export BFD_DEBOUNCE_INTERVAL=1.0
export BFD_MAX_EVENTS_PER_SECOND=1000

# NFTables discovery
export BFD_NFTABLES_AUTO_DISCOVERY=true
export BFD_NFTABLES_EVENT_LOG_ENABLED=true

# Run with overrides
tribanft --detect
```

---

## Performance Tuning Guide

### Scenario: Slow Detection Cycles (>30s)

**Diagnosis**:
```bash
tribanft --detect --verbose | grep -E "Enriching|Skipping"
```

**Solutions**:

1. **Check enrichment frequency**:
   - Look for "Running periodic metadata enrichment" every run
   - Should only see this once per 24 hours
   - If running every time, check `state.json` exists

2. **Disable file sync** (if using database):
   ```ini
   [storage]
   use_database = true
   sync_to_file = false  # Faster
   ```

3. **Reduce backup overhead**:
   ```bash
   # Check backup count
   ls ~/.local/share/tribanft/backups/ | wc -l

   # Should be <100. If >500, cleanup:
   find ~/.local/share/tribanft/backups/ -mtime +3 -delete
   ```

### Scenario: Too Many Backups

**Current optimization** (v1.3.0+): Smart backups reduce count by ~90%.

**Manual cleanup**:
```bash
# Compress old backups
tribanft --compress-backups

# Delete old backups (keep 3 days)
find ~/.local/share/tribanft/backups/ -mtime +3 -delete
```

**Aggressive settings**:
```ini
[performance]
backup_retention_days = 1  # Keep only 1 day
backup_min_keep = 2        # Keep minimum 2
```

### Scenario: High Memory Usage

**Check database size**:
```bash
du -h ~/.local/share/tribanft/blacklist.db
# Should be <100MB for 40,000 IPs
```

**Optimize database**:
```bash
sqlite3 ~/.local/share/tribanft/blacklist.db "VACUUM;"
```

---

## Migration Scenarios

### From File-Based to Database

```bash
# 1. Enable database in config
nano ~/.local/share/tribanft/config.conf
# Set: use_database = true

# 2. Run detection (auto-migrates data)
tribanft --detect

# 3. Verify migration
tribanft --stats-only
```

### From Database to File-Only

```bash
# 1. Sync database to files
tribanft --sync-files

# 2. Disable database
nano ~/.local/share/tribanft/config.conf
# Set: use_database = false

# 3. Verify files exist
ls -lh ~/.local/share/tribanft/*.txt
```

---

## Troubleshooting

### Config File Not Found

**Symptom**: "No config.conf file found!"

**Solution**:
```bash
cp config.conf.template ~/.local/share/tribanft/config.conf
nano ~/.local/share/tribanft/config.conf
```

### Path Configuration Issues

**Check current paths**:
```bash
python3 -c "from bruteforce_detector.config import get_config; c = get_config(); print(f'Data: {c.data_dir}\nState: {c.state_dir}\nDatabase: {c.database_path}')"
```

### Database Locked

**Symptom**: "Database is locked"

**Solution**:
```bash
# Check for concurrent processes
ps aux | grep tribanft

# Kill duplicates
pkill -f tribanft

# Check database
sqlite3 ~/.local/share/tribanft/blacklist.db "PRAGMA integrity_check;"
```

---

## Best Practices

1. **Start with defaults**: Only customize what you need
2. **Use config.conf**: Better than environment variables for permanent settings
3. **Enable database**: For >1000 IPs, essential for >10,000 IPs
4. **Keep file sync**: Compatibility with legacy tools
5. **Smart backups**: 30 days retention with interval-based backups (default in v1.3.0+) - reduces backup count by ~90%
6. **Monitor logs**: Check `~/.local/share/tribanft/tribanft.log` for issues
7. **Verify integrity**: Run `tribanft --verify` monthly
8. **Enable real-time monitoring**: Reduce detection lag from 5 minutes to <2 seconds (v2.3+)

---

## Complete Example Configuration

See `config.conf.template` for a fully documented example with all options.