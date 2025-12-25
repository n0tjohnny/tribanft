# TribanFT Command Reference

Complete command reference for tribanft CLI, helper tools, and system integration.

---

## Quick Navigation

- [Quick Start](#quick-start)
- [Detection & Operational](#detection--operational-commands)
- [Blacklist Management](#blacklist-management)
- [Whitelist Management](#whitelist-management)
- [Query & Analysis](#query--analysis-database-mode-only)
- [Export](#export-commands)
- [Live Monitoring](#live-monitoring)
- [Database Sync](#database-sync-commands)
- [Integrity & Backup](#integrity--backup-commands)
- [Integration](#integration-commands)
- [Helper Scripts](#helper-scripts)
- [System Commands](#system-commands)
- [Workflows](#command-workflows)
- [Database Mode](#database-mode-requirements)
- [Troubleshooting](#troubleshooting)

---

## Quick Start

```bash
# Run single detection cycle
tribanft --detect

# Show all blocked IPs with metadata
tribanft --show-blacklist

# Investigate specific IP
tribanft --query-ip 1.2.3.4

# Check service status
sudo systemctl status tribanft

# View live logs
sudo journalctl -u tribanft -f
```

---

## Detection & Operational Commands

| Command | Description |
|---------|-------------|
| `tribanft --detect` | Run single detection cycle (parse logs, run detectors, update blacklist) |
| `tribanft --daemon` | Run as daemon service with real-time monitoring (inotify/kqueue) with auto-fallback to periodic mode |
| `tribanft -v` or `tribanft --verbose` | Enable verbose logging (debug level) |

**Examples:**

```bash
# Basic detection
tribanft --detect

# Detection with verbose logging
tribanft --detect --verbose

# Run as daemon (typically managed by systemd)
tribanft --daemon
```

---

## Blacklist Management

| Command | Arguments | Description |
|---------|-----------|-------------|
| `--blacklist-add` | `<IP>` | Manually block IP (auto-investigates logs by default) |
| `--blacklist-reason` | `<reason>` | Specify reason for manual blacklisting (used with --blacklist-add) |
| `--no-log-search` | - | Skip automatic log investigation when adding manual IP |
| `--blacklist-remove` | `<IP>` | Remove IP from blacklist |
| `--blacklist-search` | `<IP>` | Search logs for IP activity without adding to blacklist |
| `--show-blacklist` | - | Display current blacklist with full metadata |
| `--show-manual` | - | Show manual blacklist entries only |

**Examples:**

```bash
# Block IP (auto-investigates logs for context)
tribanft --blacklist-add 5.6.7.8

# Block IP with specific reason
tribanft --blacklist-add 5.6.7.8 --blacklist-reason "Repeated SQL injection attempts"

# Block IP without log search
tribanft --blacklist-add 5.6.7.8 --no-log-search

# Investigate IP without blocking
tribanft --blacklist-search 1.2.3.4

# Remove IP from blacklist
tribanft --blacklist-remove 5.6.7.8

# Show all blocked IPs
tribanft --show-blacklist

# Show only manually added IPs
tribanft --show-manual
```

---

## Whitelist Management

| Command | Arguments | Description |
|---------|-----------|-------------|
| `--whitelist-add` | `<IP>` | Add IP to whitelist (never blocked) |
| `--whitelist-remove` | `<IP>` | Remove IP from whitelist |
| `--show-whitelist` | - | Display current whitelist entries |

**Examples:**

```bash
# Add IP to whitelist
tribanft --whitelist-add 192.168.1.100

# Remove from whitelist
tribanft --whitelist-remove 192.168.1.100

# Show all whitelisted IPs
tribanft --show-whitelist
```

---

## Query & Analysis (Database Mode Only)

**Requires:** `use_database = true` in config.conf

| Command | Arguments | Description |
|---------|-----------|-------------|
| `--query-ip` | `<IP>` | Query detailed information about specific IP (geolocation, attack timeline, event types) |
| `--query-country` | `<COUNTRY>` | List all IPs from specific country (e.g., CN, RU) |
| `--query-reason` | `<REASON>` | Search IPs by block reason (partial match) |
| `--query-attack-type` | `<TYPE>` | Filter IPs by attack/event type (sql_injection, ssh_attack, dns_attack, etc.) |
| `--query-timerange` | `<RANGE>` | Filter by time range (formats: "2025-12-01 to 2025-12-24" or "last 7 days") |
| `--list-countries` | - | List all countries with IP counts |
| `--list-sources` | - | List all detection sources with counts |
| `--top-threats` | `<N>` | Show top N IPs by event count |

**Examples:**

```bash
# Detailed IP information
tribanft --query-ip 1.2.3.4

# All IPs from China
tribanft --query-country CN

# Search by reason
tribanft --query-reason "SQL injection"

# Filter by attack type
tribanft --query-attack-type sql_injection
tribanft --query-attack-type dns_attack
tribanft --query-attack-type ssh_attack

# Time-based queries
tribanft --query-timerange "last 7 days"
tribanft --query-timerange "last 30 days"
tribanft --query-timerange "2025-12-01 to 2025-12-24"

# List all countries
tribanft --list-countries

# List all detection sources
tribanft --list-sources

# Top 20 most aggressive IPs
tribanft --top-threats 20
```

---

## Export Commands

**Requires:** `use_database = true` in config.conf

| Command | Arguments | Description |
|---------|-----------|-------------|
| `--export-csv` | `<FILE>` | Export blacklist to CSV file (spreadsheet-compatible) |
| `--export-json` | `<FILE>` | Export blacklist to JSON file (full metadata) |

**Examples:**

```bash
# Export to CSV
tribanft --export-csv blacklist.csv

# Export to JSON
tribanft --export-json blacklist.json

# Export with custom path
tribanft --export-csv /path/to/export/blacklist_$(date +%Y%m%d).csv
```

---

## Live Monitoring

**Requires:** `use_database = true` in config.conf

| Command | Description |
|---------|-------------|
| `--live-monitor` | Monitor threats in real-time (2-second updates, shows IP/location/attack type/event count) |

**Examples:**

```bash
# Start live monitoring
tribanft --live-monitor

# Features:
# - Real-time threat detection (2-second updates)
# - Displays: IP, location, attack type, event count, reason
# - Periodic statistics (threats/minute, uptime)
# - Graceful shutdown with final summary (Ctrl+C)
```

---

## Database Sync Commands

**Requires:** `use_database = true` in config.conf

| Command | Arguments | Description |
|---------|-----------|-------------|
| `--sync-files` | - | Force sync database to blacklist files (creates backups) |
| `--sync-output` | `<FILE>` | Custom output file for sync (default: config file) |
| `--sync-stats` | - | Show database statistics with sync |
| `--stats-only` | - | Show database statistics without syncing |

**Examples:**

```bash
# Force sync database to files
tribanft --sync-files

# Sync with statistics
tribanft --sync-files --sync-stats

# Custom output file
tribanft --sync-files --sync-output /custom/path/blacklist.txt

# Show statistics only
tribanft --stats-only
```

---

## Integrity & Backup Commands

| Command | Arguments | Description |
|---------|-----------|-------------|
| `--verify` | - | Run integrity checks on blacklist files and database |
| `--skip-verify` | - | Skip automatic integrity verification on startup (used with --detect) |
| `--list-backups` | `<FILE>` | List available backups for file (e.g., blacklist_ipv4.txt) |
| `--restore-backup` | `<BACKUP_PATH>` | Restore from specific backup file (requires --restore-target) |
| `--restore-target` | `<TARGET_PATH>` | Target path for backup restoration (required with --restore-backup) |
| `--compress-backups` | - | Compress old uncompressed backups (saves storage space) |

**Examples:**

```bash
# Run integrity checks
tribanft --verify

# Skip integrity check on startup
tribanft --detect --skip-verify

# List available backups
tribanft --list-backups blacklist_ipv4.txt

# Restore from backup
tribanft --restore-backup /path/to/backup.txt --restore-target /path/to/blacklist_ipv4.txt

# Compress old backups
tribanft --compress-backups
```

---

## Integration Commands

| Command | Arguments | Description |
|---------|-----------|-------------|
| `--import-crowdsec-csv` | `<CSV_FILE>` | Import and replace blacklist with trusted CrowdSec CSV data |
| `--migrate` | - | Migrate from cron-based setup to systemd service |

**Examples:**

```bash
# Import CrowdSec blocklist
tribanft --import-crowdsec-csv crowdsec_export.csv

# Migrate to systemd
tribanft --migrate
```

---

## Helper Scripts

### tribanft-ipinfo-batch.py

Batch geolocation enrichment service for blacklisted IPs.

| Command | Arguments | Description |
|---------|-----------|-------------|
| `tribanft-ipinfo-batch.py` | - | Run batch geolocation once |
| `--daemon` or `-d` | - | Run as daemon (continuous mode) |
| `--interval` or `-i` | `<seconds>` | Interval between iterations (default: 3600 = 1 hour, min: 60) |
| `--batch-size` or `-b` | `<N>` | Max IPs to process per iteration (default: 100, range: 1-1000) |
| `--token` or `-t` | `<TOKEN>` | ipinfo.io API token (or save to config) |
| `--show-stats` or `-s` | - | Display statistics before starting |
| `--verbose` or `-v` | - | Verbose mode (debug) |

**Examples:**

```bash
# Run once
tribanft-ipinfo-batch.py

# Run as daemon (default interval: 1 hour)
tribanft-ipinfo-batch.py --daemon

# Custom interval and batch size
tribanft-ipinfo-batch.py --daemon --interval 3600 --batch-size 200

# With statistics and verbose output
tribanft-ipinfo-batch.py --show-stats --verbose

# Specify API token
tribanft-ipinfo-batch.py --token YOUR_TOKEN_HERE
```

### Administrative Scripts

| Script | Arguments | Description |
|--------|-----------|-------------|
| `scripts/setup-config.sh` | `[--learning-mode\|--production]` | Interactive configuration setup |
| `scripts/analyze_and_tune.sh` | `[days]` | Analysis and tuning recommendations (default: 7 days) |

**Examples:**

```bash
# Setup for learning mode (no blocking)
scripts/setup-config.sh --learning-mode

# Setup for production (with blocking)
scripts/setup-config.sh --production

# Analyze last 7 days
scripts/analyze_and_tune.sh

# Analyze last 30 days
scripts/analyze_and_tune.sh 30
```

---

## System Commands

### Systemd Service Management

```bash
# Start service
sudo systemctl start tribanft

# Stop service
sudo systemctl stop tribanft

# Restart service
sudo systemctl restart tribanft

# Check status
sudo systemctl status tribanft

# Enable on boot
sudo systemctl enable tribanft

# Enable and start immediately
sudo systemctl enable --now tribanft

# Disable service
sudo systemctl disable tribanft

# View live logs
sudo journalctl -u tribanft -f

# View last 100 lines
sudo journalctl -u tribanft -n 100

# View logs since date
sudo journalctl -u tribanft --since "2025-12-01"
```

### NFTables Verification

```bash
# View IPv4 blacklist set
sudo nft list set inet filter blacklist_ipv4

# View IPv6 blacklist set
sudo nft list set inet filter blacklist_ipv6

# View filter table
sudo nft list table inet filter

# View all rules
sudo nft list ruleset

# Count IPs in blacklist
sudo nft list set inet filter blacklist_ipv4 | grep -c "elements"
```

---

## Command Workflows

### Basic Detection Workflow

```bash
# 1. Run detection
tribanft --detect

# 2. Review blacklist
tribanft --show-blacklist

# 3. Check NFTables sync
sudo nft list set inet filter blacklist_ipv4

# 4. View logs
sudo journalctl -u tribanft -n 50
```

### Investigation Workflow

```bash
# 1. Search logs for IP
tribanft --blacklist-search 1.2.3.4

# 2. Query detailed info (requires database mode)
tribanft --query-ip 1.2.3.4

# 3. Check country origin
tribanft --query-country CN

# 4. Review attack patterns
tribanft --query-attack-type sql_injection
```

### Manual IP Management

```bash
# 1. Investigate before blocking
tribanft --blacklist-search 5.6.7.8

# 2. Add with reason
tribanft --blacklist-add 5.6.7.8 --blacklist-reason "Manual block: Persistent scanning"

# 3. Verify blacklist
tribanft --show-manual

# 4. Verify NFTables sync
sudo nft list set inet filter blacklist_ipv4 | grep 5.6.7.8
```

### Database Query Workflow

```bash
# 1. View statistics
tribanft --stats-only

# 2. Top threats
tribanft --top-threats 20

# 3. Filter by time
tribanft --query-timerange "last 7 days"

# 4. Export results
tribanft --export-csv analysis_$(date +%Y%m%d).csv
```

### Backup & Restore Workflow

```bash
# 1. List available backups
tribanft --list-backups blacklist_ipv4.txt

# 2. Run integrity check
tribanft --verify

# 3. Restore if needed
tribanft --restore-backup /path/to/backup.txt --restore-target /path/to/blacklist_ipv4.txt

# 4. Compress old backups
tribanft --compress-backups
```

### Live Monitoring Setup

```bash
# Terminal 1: Live monitoring
tribanft --live-monitor

# Terminal 2: View logs
sudo journalctl -u tribanft -f

# Terminal 3: NFTables monitoring
watch -n 2 'sudo nft list set inet filter blacklist_ipv4 | tail -20'
```

---

## Database Mode Requirements

Commands that require `use_database = true` in config.conf:

| Category | Commands |
|----------|----------|
| **Query** | `--query-ip`, `--query-country`, `--query-reason`, `--query-attack-type`, `--query-timerange` |
| **Lists** | `--list-countries`, `--list-sources`, `--top-threats` |
| **Export** | `--export-csv`, `--export-json` |
| **Monitoring** | `--live-monitor` |
| **Sync** | `--sync-files`, `--sync-output`, `--sync-stats`, `--stats-only` |

**Enable database mode:**

```ini
# Edit config.conf
[storage]
use_database = true
```

**Verify database mode:**

```bash
# Check if database file exists
ls -lh ~/.local/share/tribanft/blacklist.db

# View statistics
tribanft --stats-only
```

---

## Troubleshooting

### Database Mode Required

**Error:**
```
Error: This command requires database mode
```

**Solution:**
```bash
# Enable in config
vim ~/.local/share/tribanft/config.conf

# Set: use_database = true under [storage] section
```

### Permission Denied

**Error:**
```
Permission denied: /var/log/...
```

**Solution:**
```bash
# Add user to adm group (for log access)
sudo usermod -a -G adm $USER

# Or run with sudo (not recommended for regular use)
sudo tribanft --detect
```

### NFTables Not Syncing

**Check:**
```bash
# 1. Verify feature enabled
grep enable_nftables_update ~/.local/share/tribanft/config.conf

# 2. Check NFTables set exists
sudo nft list set inet filter blacklist_ipv4

# 3. Review logs for errors
sudo journalctl -u tribanft -n 100 | grep -i nftables
```

### Invalid IP Format

**Error:**
```
Error: Invalid IP address format
```

**Valid formats:**
```bash
# IPv4
tribanft --blacklist-add 192.168.1.100
tribanft --blacklist-add 10.0.0.1

# IPv6
tribanft --blacklist-add 2001:db8::1
tribanft --blacklist-add fe80::1

# Invalid (will fail)
tribanft --blacklist-add 192.168.1  # Incomplete
tribanft --blacklist-add 192.168.1.256  # Out of range
```

### Service Not Starting

**Check:**
```bash
# 1. View service status
sudo systemctl status tribanft

# 2. Check for errors
sudo journalctl -u tribanft -n 50

# 3. Verify configuration
tribanft --verify

# 4. Test detection manually
tribanft --detect --verbose
```

### No IPs Being Blocked

**Diagnose:**
```bash
# 1. Check thresholds
grep threshold ~/.local/share/tribanft/config.conf

# 2. Run in verbose mode
tribanft --detect --verbose

# 3. Verify log paths
grep log_path ~/.local/share/tribanft/config.conf

# 4. Check log files exist and are readable
ls -l /var/log/apache2/access.log
ls -l /var/log/nginx/access.log
```

### Geolocation Not Working

**Check:**
```bash
# 1. Verify ipinfo batch service
sudo systemctl status tribanft-ipinfo-batch

# 2. Check API token
grep token ~/.local/share/tribanft/config.conf

# 3. View batch service logs
sudo journalctl -u tribanft-ipinfo-batch -f

# 4. Test manually
tribanft-ipinfo-batch.py --show-stats --verbose
```

---

## Command Cheatsheet

```bash
# COMMON OPERATIONS
tribanft --detect                              # Run detection
tribanft --show-blacklist                      # Show blocked IPs
tribanft --query-ip 1.2.3.4                   # Investigate IP
tribanft --blacklist-add 5.6.7.8              # Block IP
tribanft --whitelist-add 192.168.1.100        # Whitelist IP

# ANALYSIS
tribanft --top-threats 20                      # Top 20 threats
tribanft --query-country CN                    # IPs from China
tribanft --query-attack-type sql_injection    # SQL injection attacks
tribanft --query-timerange "last 7 days"      # Recent activity
tribanft --export-csv report.csv              # Export to CSV

# MONITORING
tribanft --live-monitor                        # Live monitoring
sudo journalctl -u tribanft -f                # Live logs
sudo nft list set inet filter blacklist_ipv4  # NFTables sync

# SERVICE
sudo systemctl status tribanft                 # Check status
sudo systemctl restart tribanft                # Restart
scripts/analyze_and_tune.sh                    # Analysis report

# MAINTENANCE
tribanft --verify                              # Integrity check
tribanft --stats-only                          # Database stats
tribanft --compress-backups                    # Compress backups
```

---

## See Also

- [CONFIGURATION.md](CONFIGURATION.md) - Complete configuration reference
- [MONITORING_AND_TUNING.md](MONITORING_AND_TUNING.md) - Performance optimization
- [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) - Production deployment
- [PLUGIN_DEVELOPMENT.md](PLUGIN_DEVELOPMENT.md) - Custom detectors and parsers
- [API_REFERENCE.md](API_REFERENCE.md) - Plugin API documentation
