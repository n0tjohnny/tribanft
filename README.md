# tribanFT

<p align="center">
  <img
    width="480"
    height="360"
    alt="image"
    src="https://github.com/user-attachments/assets/3c0b0b19-80bc-4ae1-8485-052e73a8774d"
  />
</p>

<p align="center">Traditional firewalls block IPs. <strong>TribanFT understands attacks.</strong></p>

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

---

## Why TribanFT?
Blocking an IP is just a single data point. Threat intelligence is about **understanding behavior**, not just reacting to events.

Security decisions require **context**, **correlation**, and **patterns over time**.

Most tools stop at detection. **TribanFT explains the “why” behind the attack.**

### Key Capabilities

- **Intelligence-First**  
  Enriches every event with geolocation, ISP, timelines, and correlated activity.

- **Multi-Layer Detection**  
  Covers network attacks (L3/L4) and application attacks (L7), including scans and common web exploitation patterns.

- **Zero Configuration**  
  Automatic validation prevents misconfiguration and silent failures.

- **Unified Platform**  
  Integrates CrowdSec, nftables, and Fail2Ban into a single intelligence-driven system.

---

## Attack Detection

### Network Layer (L3/L4)
- **Port Scanning** - Behavioral analysis
- **Network Reconnaissance** - High-frequency connection attempts

### Application Layer (L7)
- **HTTP Errors** - Client errors (4xx) and server errors (5xx) for anomaly detection
- **SQL Injection** - 8 refined patterns with context validation (60-70% fewer false positives)
- **XSS Attacks** - 6 patterns (script injection, event handlers, embedded content)
- **Path Traversal** - 5 patterns (directory traversal, LFI/RFI, protocol wrappers)
- **Command Injection** - 4 patterns (shell metacharacters, URL-encoded, command substitution)
- **Malicious File Uploads** - 4 patterns (executable uploads, double extensions, SVG scripts)
- **WordPress Attacks** - 4 specialized detectors (login bruteforce, XML-RPC, plugin scanning)
- **FTP Attacks** - Bruteforce detection (vsftpd, ProFTPD, Pure-FTPd)
- **SMTP Attacks** - Authentication failures and relay attempts (Postfix, Sendmail, Exim)
- **DNS Attacks** - 16 patterns (amplification, zone transfers, tunneling, subdomain brute force) [NEW]
- **Failed Login Attempts** - Multi-source aggregation (MSSQL, Apache, Nginx, SSH, RDP, FTP)

### Threat Intelligence (NEW v2.5)
- **External Threat Feeds** - AbuseIPDB, Spamhaus DROP/EDROP, AlienVault OTX integration
- **CrowdSec Integration** - Community blocklist import and export
- **Known Malicious IPs** - Automatic enrichment from threat intelligence sources

---

## Quick Start

```bash
# Download latest release
wget https://github.com/n0tjohnny/tribanft/archive/v2.5.8.tar.gz
tar -xzf v2.5.8.tar.gz
cd tribanft-2.5.8

# Automated installation (one command)
./install.sh

# Verify running
sudo systemctl status tribanft
sudo journalctl -u tribanft -f
```

**That's it.** TribanFT starts detecting attacks immediately using sensible defaults.

---

## Key Features

### 1. **YAML Rule Engine**
Define detection rules without writing code:

```yaml
metadata:
  name: xss_attack_detector
  version: 1.0.0
  enabled: true

log_sources:
  parsers: [apache, nginx]

detection:
  event_types: [XSS_ATTACK]
  threshold: 3
  time_window_minutes: 30

  patterns:
    - regex: '(?i)<script[^>]*>'
      description: 'Script tag injection'
```

### 2. **Rich Threat Intelligence**
Every blacklisted IP includes:
- **Geolocation**: Country, city, ISP
- **Attack Timeline**: First seen, last seen, event count
- **Attack Patterns**: Which detectors triggered, confidence level, event types
- **External Feeds**: Integration with AbuseIPDB, Spamhaus, AlienVault OTX (NEW)
- **Queryable Data**: Search by country, attack type, time range, event count

```bash
# Find all attackers from China
tribanft --query-country CN

# Filter by attack type (NEW)
tribanft --query-attack-type sql_injection

# Time-based queries (NEW)
tribanft --query-timerange "last 7 days"

# Show top 20 most aggressive IPs
tribanft --top-threats 20

# Investigate specific IP
tribanft --query-ip 1.2.3.4
```

### 3. **Plugin System**
Drop-in architecture for custom detectors and parsers:

```python
class MyDetector(BaseDetector):
    METADATA = {
        'name': 'my_detector',
        'version': '1.0.0',
        'enabled_by_default': True
    }

    def detect(self, events):
        # Your detection logic
        return detections
```

**No core code changes needed.** Just drop files into `plugins/` directory.

### 4. **Bidirectional Sync**
- **NFTables**: Auto-sync blacklist to firewall rules
- **CrowdSec**: Import community blocklists, export local detections
- **Fail2Ban**: Import bans, maintain unified blacklist

### 5. **Database-Backed Storage**
SQLite backend for efficient queries:
- Query by country, attack type, source
- Event count tracking
- Atomic operations prevent corruption
- Handles millions of IPs efficiently

---

## Usage Examples

```bash
# Detection & Management
tribanft --detect                           # Run single detection cycle
tribanft --show-blacklist                   # Show all blocked IPs with metadata
tribanft --blacklist-add 5.6.7.8           # Manually block IP (auto-investigates logs)

# Query & Analysis
tribanft --query-ip 1.2.3.4                # Detailed IP information
tribanft --query-country CN                # All IPs from China
tribanft --query-attack-type sql_injection # Filter by attack type [NEW]
tribanft --query-timerange "last 7 days"   # Filter by time range [NEW]
tribanft --top-threats 20                  # Top 20 by event count
tribanft --export-csv output.csv           # Export to CSV
tribanft --export-json output.json         # Export to JSON [NEW]

# Real-Time Monitoring [NEW]
tribanft --live-monitor                    # Live threat stream monitoring

# Service Management
sudo systemctl status tribanft             # Check service status
sudo journalctl -u tribanft -f             # Live logs
sudo systemctl restart tribanft            # Restart service
scripts/setup-config.sh --production       # Configure for production
```

---

## Architecture

```
Firewall/Web/Auth Logs
    ↓
Parsers
    ↓
EventTypes (L3/L4 + L7)
    ↓
Validation
    ↓
Detectors (YAML rules + plugins)
    ↓
SQLite Database + Geolocation
    ↓
NFTables/CrowdSec/Fail2Ban Sync
```

**Multi-Source Detection:**

| Parser | Layer | EventTypes | Log Source |
|--------|-------|------------|------------|
| Apache/Nginx | L7 | 10 types (HTTP errors, SQL injection, XSS, path traversal, etc.) | access.log |
| FTP | L7 | 1 type (FTP attacks) | vsftpd.log, proftpd.log |
| SMTP | L7 | 1 type (SMTP attacks) | mail.log, maillog |
| DNS | L7 | 1 type (DNS attacks: amplification, tunneling, zone transfers) [NEW] | query.log, dnsmasq.log |
| NFTables/IPTables | L3/L4 | 2 types (port scan, network scan) | kern.log |
| MSSQL | L7 | 2 types (prelogin, failed login) | MSSQL logs |
| Syslog | L7 | 3 types (failed login, SSH/RDP attacks) | auth.log |

See [docs/PARSER_EVENTTYPES_MAPPING.md](docs/PARSER_EVENTTYPES_MAPPING.md) for complete parser capabilities.

---

## Performance & Query Features (v2.5)

### Database Optimization
- **Indexed Queries** - 50-100x speedup for common queries (event_count, date_added, last_seen)
- **Query Performance Logging** - Debug mode tracks query execution time ([PERF] logs)
- **Efficient Filtering** - Filter by attack type, time range, or top threats with optimized SQL

### Advanced Query Interface
```bash
# Filter by attack type
tribanft --query-attack-type sql_injection
tribanft --query-attack-type dns_attack

# Time-based queries
tribanft --query-timerange "last 7 days"
tribanft --query-timerange "2025-12-01 to 2025-12-24"

# Export formats
tribanft --export-json blacklist.json      # Full metadata export
tribanft --export-csv blacklist.csv        # Spreadsheet-compatible

# Real-time monitoring
tribanft --live-monitor                    # Live threat stream with stats
```

**Live Monitor Features:**
- Real-time threat detection (2-second updates)
- Displays: IP, location, attack type, event count, reason
- Periodic statistics (threats/minute, uptime)
- Graceful shutdown with final summary

---

## Configuration

**Default location:** `~/.local/share/tribanft/config.conf`

Key settings:

```ini
[storage]
use_database = true              # SQLite (recommended for >1000 IPs)

[detection]
failed_login_threshold = 20      # Events needed to blacklist
time_window_minutes = 10080      # 7 days

[plugins]
enable_plugin_system = true      # Auto-discover custom plugins
enable_yaml_rules = true         # YAML-based detection rules

[features]
enable_nftables_update = true    # Sync to NFTables firewall
enable_crowdsec_integration = true

[threat_intelligence]            # NEW in v2.5
threat_feeds_enabled = false     # Enable threat feed integration
threat_feed_sources = spamhaus   # Comma-separated: spamhaus,abuseipdb,alienvault
threat_feed_cache_hours = 24     # Cache duration for feeds

[logs]
dns_log_path = /var/log/named/query.log  # DNS server logs (NEW)
```

See [docs/CONFIGURATION.md](docs/CONFIGURATION.md) for all options.

---

## Documentation

| Document | Description |
|----------|-------------|
| [COMMANDS.md](docs/COMMANDS.md) | Complete command reference for all CLI commands |
| [QUICK_DEPLOY.md](docs/QUICK_DEPLOY.md) | Installation and deployment guide |
| [PARSER_EVENTTYPES_MAPPING.md](docs/PARSER_EVENTTYPES_MAPPING.md) | Parser capabilities matrix and validation guide |
| [RULE_SYNTAX.md](docs/RULE_SYNTAX.md) | YAML rule syntax reference |
| [PLUGIN_DEVELOPMENT.md](docs/PLUGIN_DEVELOPMENT.md) | Creating custom detectors and parsers |
| [CONFIGURATION.md](docs/CONFIGURATION.md) | Complete configuration reference |
| [MONITORING_AND_TUNING.md](docs/MONITORING_AND_TUNING.md) | Performance optimization guide |
| [DEPLOYMENT_GUIDE.md](docs/DEPLOYMENT_GUIDE.md) | Production deployment best practices |

---

## Requirements

- **Python 3.8+**
- **NFTables** (for firewall integration)
- **Optional**: CrowdSec, Fail2Ban, firewall logs for L3/L4 detection

---

## Troubleshooting

**Configuration errors?**
```bash
sudo journalctl -u tribanft -n 100 | grep -i "validation"
```

**Detection not working?**
```bash
tribanft --detect --verbose
# Check parser/EventType coherence in logs
```

**Quick setup?**
```bash
scripts/setup-config.sh --learning-mode  # Week 1: Learning mode
scripts/setup-config.sh --production     # Week 3+: Enable blocking
```

**Performance issues?**
See [docs/MONITORING_AND_TUNING.md](docs/MONITORING_AND_TUNING.md)

---

## License

GNU General Public License v3.0

---

## Author

GitHub: [@n0tjohnny](https://github.com/n0tjohnny)

---

## Acknowledgments

- [CrowdSec](https://www.crowdsec.net/) - Collaborative threat intelligence
- [NFTables](https://netfilter.org/projects/nftables/) - Linux firewall framework
- [Fail2Ban](https://www.fail2ban.org/) - Intrusion prevention
- [IPInfo.io](https://ipinfo.io/) - IP geolocation API
