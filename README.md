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

## Overview

TribanFT combines behavioral attack detection with threat intelligence. Every blocked IP includes geolocation, attack timeline, and correlation across multiple log sources.

---

## Attack Detection

| Layer | Coverage |
|-------|----------|
| L3/L4 | Port scanning, network reconnaissance |
| L7 | HTTP errors, SQL injection, XSS, path traversal, command injection, file uploads, WordPress, FTP, SMTP, DNS, failed logins |
| Threat Intel | AbuseIPDB, Spamhaus, AlienVault OTX, CrowdSec community blocklists |

See [PARSER_EVENTTYPES_MAPPING.md](docs/PARSER_EVENTTYPES_MAPPING.md) for complete detection matrix.

---

## Quick Start

```bash
# Download latest release
wget https://github.com/n0tjohnny/tribanft/archive/refs/tags/tribanft-v2.9.1.tar.gz
tar -xzf v2.9.1.tar.gz
cd tribanft-2.9.1

# Automated installation (one command)
./install.sh

# Verify running
sudo systemctl status tribanft
sudo journalctl -u tribanft -f
```

**That's it.** TribanFT starts detecting attacks immediately using sensible defaults.

---

## Key Features

- **YAML Rule Engine** - Define detection logic without coding ([RULE_SYNTAX.md](docs/RULE_SYNTAX.md))
- **Rich Threat Intelligence** - Geolocation, attack timelines, queryable metadata ([COMMANDS.md](docs/COMMANDS.md))
- **Plugin System** - Drop-in detectors and parsers ([PLUGIN_DEVELOPMENT.md](docs/PLUGIN_DEVELOPMENT.md))
- **Bidirectional Sync** - NFTables, CrowdSec, Fail2Ban integration
- **Database Backend** - SQLite for efficient queries ([CONFIGURATION.md](docs/CONFIGURATION.md))

---

## Usage

```bash
tribanft --detect              # Single detection cycle
tribanft --daemon              # Run as service
tribanft --show-blacklist      # View blocked IPs
tribanft --query-ip 1.2.3.4    # Investigate IP
```

See [COMMANDS.md](docs/COMMANDS.md) for complete command reference.

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
| DNS | L7 | 1 type (DNS attacks: amplification, tunneling, zone transfers) | query.log, dnsmasq.log |
| NFTables/IPTables | L3/L4 | 2 types (port scan, network scan) | kern.log |
| MSSQL | L7 | 2 types (prelogin, failed login) | MSSQL logs |
| Syslog | L7 | 3 types (failed login, SSH/RDP attacks) | auth.log |

See [docs/PARSER_EVENTTYPES_MAPPING.md](docs/PARSER_EVENTTYPES_MAPPING.md) for complete parser capabilities.

---

## Configuration

Default: `~/.local/share/tribanft/config.conf`

Key settings: storage backend, detection thresholds, plugin system, NFTables/CrowdSec integration, threat feeds.

See [CONFIGURATION.md](docs/CONFIGURATION.md) for complete reference.

---

## Documentation

| Document | Description |
|----------|-------------|
| [COMMANDS.md](docs/COMMANDS.md) | Complete command reference for all CLI commands |
| [DEPLOYMENT_GUIDE.md](docs/DEPLOYMENT_GUIDE.md) | Installation and deployment guide |
| [PARSER_EVENTTYPES_MAPPING.md](docs/PARSER_EVENTTYPES_MAPPING.md) | Parser capabilities matrix and validation guide |
| [RULE_SYNTAX.md](docs/RULE_SYNTAX.md) | YAML rule syntax reference |
| [PLUGIN_DEVELOPMENT.md](docs/PLUGIN_DEVELOPMENT.md) | Creating custom detectors and parsers |
| [CONFIGURATION.md](docs/CONFIGURATION.md) | Complete configuration reference |
| [MONITORING_AND_TUNING.md](docs/MONITORING_AND_TUNING.md) | Performance optimization guide |

---

## Requirements

| Requirement | Version | Purpose |
|-------------|---------|---------|
| Python | 3.8+ | Core runtime |
| NFTables | Latest | Firewall integration |
| CrowdSec | Optional | Community blocklists |
| Fail2Ban | Optional | Ban import |

---

## Troubleshooting

| Issue | Command |
|-------|---------|
| Configuration errors | `journalctl -u tribanft -n 100 \| grep -i validation` |
| Detection not working | `tribanft --detect --verbose` |
| Learning mode setup | `scripts/setup-config.sh --learning-mode` |
| Production setup | `scripts/setup-config.sh --production` |

See [MONITORING_AND_TUNING.md](docs/MONITORING_AND_TUNING.md) for comprehensive troubleshooting.

---

## Security

For security vulnerabilities, please open a GitHub issue or contact [@n0tjohnny](https://github.com/n0tjohnny).

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
