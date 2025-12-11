# tribanFT  
**Threat Intelligence & Brute Force Advanced Network Firewall**

Cybersecurity system that unifies CrowdSec, NFTables, and Fail2Ban into a coordinated threat detection and blocking platform.

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

---

## Overview

**Purpose**  
Automated brute force detection and IP blocking for Linux servers, protecting against:
- Failed login attempts (SSH, MSSQL, FTP)
- MSSQL prelogin reconnaissance
- Port scanning
- Other malicious activities detected by CrowdSec

**How it works**
1. **Parse** - Extract security events from system logs (syslog, MSSQL errorlog)
2. **Detect** - Identify attack patterns using configurable thresholds
3. **Block** - Add malicious IPs to blacklist with geolocation metadata
4. **Sync** - Bidirectional synchronization with NFTables firewall

**Performance**  
- 10-minute sync cycles complete in ~40 seconds (without geolocation)
- Handles 36,000+ blacklisted IPs efficiently
- Optional SQLite backend for large-scale deployments

---

## Requirements

- NFTables
- Python 3.8+
- Optional: CrowdSec, Fail2Ban (It's possible to manage a Blacklist without it)
---

## Installation

### Quick Start (Non-Root User)

The system now uses XDG Base Directory specification, allowing non-root installation:

```bash
# Clone repository
git clone https://github.com/n0tjohnny/tribanft.git
cd tribanft

# Install package (creates ~/.local/share/tribanft, ~/.local/state/tribanft automatically)
pip install -e .

# Verify directories created
python3 -c "from bruteforce_detector.config import get_config; c = get_config(); print(f'Data: {c.data_dir}\nState: {c.state_dir}')"

# Set up hourly detection (crontab)
(crontab -l 2>/dev/null; echo "10 * * * * $HOME/.local/bin/tribanft --detect") | crontab -
```

### Traditional System-Wide Installation (Root)

For system-wide deployment with legacy paths:

```bash
# Install as root
sudo pip install -e .

# Use environment variables to specify system paths
export TRIBANFT_DATA_DIR=/var/lib/tribanft/data
export TRIBANFT_STATE_DIR=/var/lib/tribanft/state

# Or keep legacy paths (with deprecation warnings)
export TRIBANFT_DATA_DIR=/root
export TRIBANFT_STATE_DIR=/var/lib/tribanft

# Create directories
mkdir -p $TRIBANFT_DATA_DIR $TRIBANFT_STATE_DIR

# Set up cron
(crontab -l 2>/dev/null; echo "10 * * * * /usr/local/bin/tribanft --detect") | crontab -
```

### Custom Installation Path

```bash
# Set custom directories
export TRIBANFT_DATA_DIR=/opt/tribanft/data
export TRIBANFT_CONFIG_DIR=/opt/tribanft/config
export TRIBANFT_STATE_DIR=/opt/tribanft/state

# Install and run
pip install -e .
tribanft --detect
```

### Optional - Geolocation Service

```bash
# Store IPInfo.io token in config directory
CONFIG_DIR=$(python3 -c "from bruteforce_detector.config import get_config; print(get_config().config_dir)")
echo "YOUR_IPINFO_TOKEN" > "$CONFIG_DIR/ipinfo_token.txt"
chmod 600 "$CONFIG_DIR/ipinfo_token.txt"

# Install systemd service
sudo ./install-ipinfo-batch-service.sh
```

### Migrating from Legacy Paths

See [UPGRADE.md](UPGRADE.md) for detailed migration instructions from `/root/` paths to XDG-compliant paths.

---

## Configuration

### Directory Structure

**Default (XDG):**
```
~/.config/tribanft/          # Configuration files
~/.local/share/tribanft/     # Blacklist/whitelist data files
~/.local/state/tribanft/     # Runtime state, database, backups
  ├── backups/               # Rotating backup files
  ├── blacklist.db           # SQLite database (if enabled)
  ├── state.json             # Detection state
  └── tribanft.log           # Application logs
```

### Environment Variables

**Path Configuration:**
```bash
TRIBANFT_DATA_DIR         # Override data directory
TRIBANFT_CONFIG_DIR       # Override config directory  
TRIBANFT_STATE_DIR        # Override state directory

# Or use XDG variables
XDG_DATA_HOME             # Base for data directory
XDG_CONFIG_HOME           # Base for config directory
XDG_STATE_HOME            # Base for state directory
```

**Backup Configuration:**
```bash
BFD_BACKUP_RETENTION_DAYS=7   # Days to keep backups
BFD_BACKUP_MIN_KEEP=5         # Minimum backups to keep
```

### Configuration File

Create `$XDG_CONFIG_HOME/tribanft/.env` or `/etc/tribanft/.env`:

```bash
# Detection thresholds (events within time window)
BFD_TIME_WINDOW_MINUTES=10080          # 7 days
BFD_FAILED_LOGIN_THRESHOLD=20          # 20 failed logins
BFD_PRELOGIN_PATTERN_THRESHOLD=20      # 20 prelogin attempts
BFD_PORT_SCAN_THRESHOLD=20             # 20 port scans

# Feature flags
BFD_ENABLE_PRELOGIN_DETECTION=true
BFD_ENABLE_FAILED_LOGIN_DETECTION=true
BFD_ENABLE_PORT_SCAN_DETECTION=true
BFD_ENABLE_CROWDSEC_INTEGRATION=true

# Storage backend
BFD_USE_DATABASE=true                  # Recommended for >10k IPs
```

**Threshold Logic**  
An IP is blacklisted when it triggers N events within the configured time window (default: 20 events in 7 days).

---

## Usage

### Core Commands

| Command | Purpose |
|---------|---------|
| `tribanft --detect` | Run detection cycle and update blacklist |
| `tribanft --show-blacklist` | Display blacklist with geolocation |
| `tribanft --whitelist-add <ip>` | Add IP to whitelist |
| `tribanft --blacklist-add <ip>` | Manually block IP (with log investigation) |
| `tribanft --blacklist-search <ip>` | Search logs for IP activity |
| `tribanft --verbose` | Enable debug output |

### Integrity & Backup Commands (New)

| Command | Purpose |
|---------|---------|
| `tribanft --verify` | Run integrity checks on blacklist files and database |
| `tribanft --list-backups <file>` | List available backups for a file |
| `tribanft --restore-backup <path> --restore-target <path>` | Restore from specific backup |
| `tribanft --detect --skip-verify` | Skip automatic verification on startup |

### Examples

```bash
# Run detection
tribanft --detect

# Run detection with integrity check
tribanft --detect  # Automatic check on startup

# Skip startup verification (faster, for emergencies)
tribanft --detect --skip-verify

# Run full integrity verification
tribanft --verify

# Manually block an IP
tribanft --blacklist-add 1.2.3.4 --blacklist-reason "Confirmed attacker"

# Search logs for suspicious IP
tribanft --blacklist-search 5.6.7.8

# Whitelist your admin IP
tribanft --whitelist-add 192.168.1.100

# View current blacklist
tribanft --show-blacklist

# List available backups for blacklist file
tribanft --list-backups blacklist_ipv4.txt

# Restore from a specific backup
tribanft --restore-backup ~/.local/state/tribanft/backups/blacklist_ipv4.txt_20231211_143052.backup \
         --restore-target ~/.local/share/tribanft/blacklist_ipv4.txt
```

### Backup & Recovery

**Automatic Backups:**
- Created before every file modification
- Stored in `$STATE_DIR/backups/`
- Format: `{filename}_YYYYMMDD_HHMMSS.backup`
- Retention: 7 days (configurable)
- Minimum kept: 5 backups (configurable)

**Manual Recovery:**
```bash
# Check integrity
tribanft --verify

# List available backups
tribanft --list-backups blacklist_ipv4.txt

# Restore from backup
tribanft --restore-backup <backup-path> --restore-target <target-path>
```


---

## Architecture

### Components

| Module | Responsibility |
|--------|---------------|
| **Parsers** | Extract security events from logs (syslog, MSSQL) |
| **Detectors** | Identify attack patterns (prelogin, failed login, port scan, CrowdSec) |
| **BlacklistManager** | Orchestrates IP blocking and metadata storage |
| **NFTablesSync** | Bidirectional sync with firewall sets |
| **IPInvestigator** | Combines geolocation + log analysis |
| **Database** | Optional SQLite backend for large deployments |

### Detection Flow

```
Logs → Parsers → SecurityEvents → Detectors → DetectionResults → BlacklistManager → NFTables
```

### Monitored NFTables Sets

- `inet filter port_scanners` - Port scanning activity
- `inet filter blacklist_ipv4` - General malicious IPs
- `inet f2b-table addr-set-*` - Fail2Ban blocked IPs

---

## Detection System

| Detector | Threshold | Confidence |
|----------|-----------|------------|
| **Prelogin Pattern** | 20 events / 7 days | High |
| **Failed Login** | 20 events / 7 days | High |
| **Port Scan** | 20 scans / 7 days | Medium |
| **CrowdSec** | 1 block | Medium |

Each detector analyzes events within the configured time window and triggers blocking when thresholds are exceeded.

---

## Storage Options

### File-Based (Default)

- Plain text files with comprehensive metadata
- Includes geolocation, event counts, timestamps, sources
- Automatic backup with corruption prevention
- Best for <10k IPs

### SQLite Database (Recommended for Scale)

```bash
# Enable in config
BFD_USE_DATABASE=true

# Migrate existing data
python3 migrate_to_sqlite.py --migrate

# View statistics
python3 migrate_to_sqlite.py --stats
```

**Benefits:**
- Efficient queries for large datasets (>10k IPs)
- Atomic operations prevent corruption
- Historical event tracking
- Better performance for complex filters

---

## Troubleshooting

### No Detections

1. **Verify log paths exist**
   ```bash
   ls -la /var/log/syslog
   ls -la /var/opt/mssql/log/errorlog  # if using MSSQL
   ```

2. **Check thresholds**
   ```bash
   tribanft --verbose --detect
   ```

3. **Review recent events**
   ```bash
   # Log location depends on configuration
   STATE_DIR=$(python3 -c "from bruteforce_detector.config import get_config; print(get_config().state_dir)")
   tail -f "$STATE_DIR/tribanft.log"
   ```

### NFTables Sync Fails

1. **Verify NFTables sets exist**
   ```bash
   nft list sets
   ```

2. **Check permissions**
   ```bash
   which nft
   nft list tables  # Must run as root
   ```

### Geolocation Issues

1. **Verify token file**
   ```bash
   CONFIG_DIR=$(python3 -c "from bruteforce_detector.config import get_config; print(get_config().config_dir)")
   cat "$CONFIG_DIR/ipinfo_token.txt"
   ```

2. **Check service status**
   ```bash
   systemctl status tribanft-ipinfo-batch
   journalctl -u tribanft-ipinfo-batch -f
   ```

### File Corruption / Data Loss

1. **Run integrity check**
   ```bash
   tribanft --verify
   ```

2. **Check available backups**
   ```bash
   tribanft --list-backups blacklist_ipv4.txt
   ```

3. **Restore from backup**
   ```bash
   # List backups with full paths
   ls -lah ~/.local/state/tribanft/backups/
   
   # Restore specific backup
   tribanft --restore-backup <backup-path> --restore-target <target-path>
   ```

4. **Check disk space**
   ```bash
   df -h ~/.local/state/tribanft
   ```

### Permission Errors

1. **Check directory ownership**
   ```bash
   ls -la ~/.local/share/tribanft
   ls -la ~/.local/state/tribanft
   ```

2. **Fix permissions (if needed)**
   ```bash
   chmod -R 755 ~/.local/share/tribanft
   chmod -R 755 ~/.local/state/tribanft
   ```

3. **For system-wide installation**
   ```bash
   sudo chown -R tribanft:tribanft /var/lib/tribanft
   sudo chmod -R 755 /var/lib/tribanft
   ```

### Path Configuration Issues

1. **Verify current paths**
   ```bash
   python3 -c "
from bruteforce_detector.config import get_config
c = get_config()
print(f'Data dir: {c.data_dir}')
print(f'Config dir: {c.config_dir}')
print(f'State dir: {c.state_dir}')
print(f'Blacklist IPv4: {c.blacklist_ipv4_file}')
print(f'Database: {c.database_path}')
   "
   ```

2. **Override paths via environment**
   ```bash
   export TRIBANFT_DATA_DIR=/custom/path/data
   export TRIBANFT_STATE_DIR=/custom/path/state
   tribanft --detect
   ```

3. **Migration issues**
   See [UPGRADE.md](UPGRADE.md) for detailed migration guide

---

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup

```bash
# Clone repository
git clone https://github.com/n0tjohnny/tribanft.git
cd tribanft

# Install in development mode
pip install -e . --break-system-packages

# Run tests (if available)
python -m pytest tests/

# Enable verbose logging
export BFD_VERBOSE=true
```

---

## License

GNU General Public License v3.0 - see [LICENSE](LICENSE) file for details.

---

## Author

GitHub: [@n0tjohnny](https://github.com/n0tjohnny)

---

## Acknowledgments

- [CrowdSec](https://www.crowdsec.net/) - Collaborative threat intelligence
- [NFTables](https://netfilter.org/projects/nftables/) - Linux packet filtering framework
- [Fail2Ban](https://www.fail2ban.org/) - Intrusion prevention system
- [IPInfo.io](https://ipinfo.io/) - IP geolocation API
