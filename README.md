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

### Quick Start

```bash
# Clone repository
git clone https://github.com/n0tjohnny/tribanft.git
cd tribanft

# Install package
pip install -e .

# Create directories
mkdir -p /var/lib/tribanft /etc/tribanft
touch /root/blacklist_ipv4.txt /root/whitelist_ips.txt

# Set up hourly detection (crontab)
(crontab -l 2>/dev/null; echo "10 * * * * /usr/local/bin/tribanft --detect >> /var/log/tribanft.log 2>&1") | crontab -
```

### Optional - Geolocation Service

```bash
# Store IPInfo.io token
echo "YOUR_IPINFO_TOKEN" > /etc/tribanft/ipinfo_token.txt
chmod 600 /etc/tribanft/ipinfo_token.txt

# Install systemd service
sudo ./install-ipinfo-batch-service.sh
```

---

## Configuration

Create `/etc/tribanft/.env`:

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

### Examples

```bash
# Run detection
tribanft --detect

# Manually block an IP
tribanft --blacklist-add 1.2.3.4 --blacklist-reason "Confirmed attacker"

# Search logs for suspicious IP
tribanft --blacklist-search 5.6.7.8

# Whitelist your admin IP
tribanft --whitelist-add 192.168.1.100

# View current blacklist
tribanft --show-blacklist
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
   tail -f /var/log/tribanft.log
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
   cat /etc/tribanft/ipinfo_token.txt
   ```

2. **Check service status**
   ```bash
   systemctl status tribanft-ipinfo-batch
   journalctl -u tribanft-ipinfo-batch -f
   ```

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
