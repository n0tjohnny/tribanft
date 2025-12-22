# tribanFT

<p align="center">
  <img
    width="480"
    height="360"
    alt="image"
    src="https://github.com/user-attachments/assets/3c0b0b19-80bc-4ae1-8485-052e73a8774d"
  />
</p>

<p align="center">
  <strong>Threat Intelligence &amp; Brute Force Advanced Network Firewall Technology (T.I.B.F.A.N.F.T) </strong>
</p>
<p align="center">
  ...but i thought <strong>TRIBANFT</strong> suits much better!
</p>

**TribanFT is a Multi-layer security platform** that detects sophisticated attacks across network (L3/L4) and application (L7) layers, enriches threat data with actionable intelligence, and unifies CrowdSec, NFTables, and Fail2Ban into a single detection engine.

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

---

## Why TribanFT?

**Traditional firewalls block IPs. TribanFT understands attacks.**

- **Intelligence-First**: Every blocked IP includes geolocation, ISP, attack timeline, and event correlation
- **Multi-Layer Detection**: Catches port scans (L3/L4) AND web attacks (L7) - SQL injection, XSS, command injection, path traversal
- **Zero Configuration**: Automatic validation prevents misconfigured rules - no silent failures
- **Unified Platform**: Bidirectional sync with CrowdSec, NFTables, Fail2Ban - one source of data

---

## Attack Detection

### Network Layer (L3/L4)
- **Port Scanning** - Behavioral analysis
- **Network Reconnaissance** - High-frequency connection attempts

### Application Layer (L7)
- **SQL Injection** - 8 refined patterns with context validation (60-70% fewer false positives)
- **XSS Attacks** - 6 patterns (script injection, event handlers, embedded content)
- **Path Traversal** - 5 patterns (directory traversal, LFI/RFI, protocol wrappers)
- **Command Injection** - 4 patterns (shell metacharacters, URL-encoded, command substitution)
- **Malicious File Uploads** - 4 patterns (executable uploads, double extensions, SVG scripts)
- **WordPress Attacks** - 4 specialized detectors (login bruteforce, XML-RPC, plugin scanning)
- **Failed Login Attempts** - Multi-source aggregation (MSSQL, Apache, Nginx, SSH, RDP)

---

## Quick Start

```bash
# Clone and install
git clone https://github.com/n0tjohnny/tribanft.git
cd tribanft
sudo python3 setup.py install

# Install systemd service
cd scripts
sudo ./install-service.sh

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
- **Attack Patterns**: Which detectors triggered, confidence level
- **Queryable Data**: Search by country, attack type, event count

```bash
# Find all attackers from China
tribanft --query-country CN

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
tribanft --top-threats 20                  # Top 20 by event count
tribanft --export-csv output.csv           # Export for analysis

# Service Management
sudo systemctl status tribanft             # Check service status
sudo journalctl -u tribanft -f             # Live logs
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
| Apache/Nginx | L7 | 8 types (SQL injection, XSS, path traversal, etc.) | access.log |
| NFTables/IPTables | L3/L4 | 2 types (port scan, network scan) | kern.log |
| MSSQL | L7 | 2 types (prelogin, failed login) | MSSQL logs |
| Syslog | L7 | 3 types (failed login, SSH/RDP attacks) | auth.log |

See [docs/PARSER_EVENTTYPES_MAPPING.md](docs/PARSER_EVENTTYPES_MAPPING.md) for complete parser capabilities.

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
```

See [docs/CONFIGURATION.md](docs/CONFIGURATION.md) for all options.

---

## Documentation

| Document | Description |
|----------|-------------|
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
