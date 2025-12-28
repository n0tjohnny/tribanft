# TribanFT Command Reference

```
╔═══════════════════════════════════════════════════════════════════════════╗
║ TribanFT Command Reference                                                ║
║ Author: TribanFT Project | License: GNU GPL v3 | Updated: 2025-12-25      ║
╚═══════════════════════════════════════════════════════════════════════════╝
```

## Command Table

| Command | Arguments | Description |
|---------|-----------|-------------|
| **Core Operations** |||
| `--detect` | - | Run detection cycle |
| `--daemon` | - | Run as daemon (real-time with periodic fallback) |
| `--verbose` / `-v` | - | Debug logging |
| **Blacklist** |||
| `--blacklist-add` | `<IP>` | Block IP with automatic log investigation and geolocation enrichment |
| `--blacklist-reason` | `<reason>` | Specify custom block reason (use with --blacklist-add) |
| `--no-log-search` | - | Skip automatic log investigation when manually adding IP |
| `--blacklist-remove` | `<IP>` | Remove IP from all blacklist files and database |
| `--blacklist-search` | `<IP>` | Search logs for IP activity without adding to blacklist |
| `--show-blacklist` | - | Display all blocked IPs with metadata (reason, country, timestamps, event counts, attack types) |
| `--show-manual` | - | Display only manually added blacklist entries with reasons |
| **Whitelist** |||
| `--whitelist-add` | `<IP>` | Add to whitelist (never blocked) |
| `--whitelist-remove` | `<IP>` | Remove from whitelist |
| `--show-whitelist` | - | Display whitelist |
| **Query** (requires `use_database = true`) |||
| `--query-ip` | `<IP>` | Detailed IP information (geolocation, attack timeline, event types, sources) |
| `--query-country` | `<CODE>` | List all IPs from country code (e.g., CN, RU, US, BR) |
| `--query-reason` | `<TEXT>` | Search IPs by block reason (partial text match) |
| `--query-attack-type` | `<TYPE>` | Filter by attack type (sql_injection, ssh_attack, dns_attack, port_scan, etc.) - NEW v2.8.3: EventTypes now visible in blacklist files |
| `--query-timerange` | `<RANGE>` | Filter by time range (format: "2025-12-01 to 2025-12-24" or "last 7 days") |
| `--list-countries` | - | List all countries with IP counts and percentages |
| `--list-sources` | - | List detection sources with counts (detectors, CrowdSec, manual, NFTables) |
| `--top-threats` | `<N>` | Show top N most aggressive IPs by event count |
| **Export** (requires `use_database = true`) |||
| `--export-csv` | `<FILE>` | Export blacklist to CSV format (spreadsheet-compatible with full metadata) |
| `--export-json` | `<FILE>` | Export blacklist to JSON format (complete structured data with all fields) |
| **Monitoring** (requires `use_database = true`) |||
| `--live-monitor` | - | Real-time threat monitoring (2-second updates, shows IP/location/attack type/event count) |
| **Database Sync** (requires `use_database = true`) |||
| `--sync-files` | - | Force sync database to blacklist text files (creates automatic backups before writing) |
| `--sync-output` | `<FILE>` | Custom output file for sync operation (default uses configured blacklist paths) |
| `--sync-stats` | - | Display database statistics (IP counts, sources, countries) during sync |
| `--stats-only` | - | Display database statistics without performing sync operation |
| **Integrity & Backup** |||
| `--verify` | - | Run comprehensive integrity checks (file corruption, metadata consistency, database health) |
| `--skip-verify` | - | Skip automatic integrity verification on startup (use with --detect for faster runs) |
| `--list-backups` | `<FILE>` | List available backups for file with timestamps and sizes (e.g., blacklist_ipv4.txt) |
| `--restore-backup` | `<BACKUP>` | Restore from specific backup file (requires --restore-target for safety) |
| `--restore-target` | `<TARGET>` | Specify target path for backup restoration (prevents accidental overwrites) |
| `--compress-backups` | - | Compress old uncompressed backups to save storage space (preserves all data) |
| **Integration** |||
| `--import-crowdsec-csv` | `<CSV>` | Import CrowdSec CSV data (replaces blacklist with trusted threat intelligence) |

---

## Helper Scripts

### tribanft-ipinfo-batch.py
Batch geolocation enrichment using ipinfo.io API.

**Note:** Verify available flags with `tribanft-ipinfo-batch.py --help`

| Usage | Description |
|-------|-------------|
| `tribanft-ipinfo-batch.py` | Run once |
| `--daemon` | Continuous mode |
| `--interval <sec>` | Iteration interval (default: 3600) |
| `--batch-size <N>` | IPs per iteration (default: 100) |
| `--token <TOKEN>` | ipinfo.io API token |
| `--show-stats` | Display statistics |
| `--verbose` | Debug logging |

### Administration

| Script | Usage |
|--------|-------|
| `scripts/setup-config.sh` | Interactive config setup |
| `scripts/analyze_and_tune.sh [days]` | Analysis report (default: 7 days) |

---

## System Commands

```bash
# Systemd
sudo systemctl {start|stop|restart|status|enable|disable} tribanft
sudo journalctl -u tribanft -f          # Live logs

# NFTables
sudo nft list set inet filter blacklist_ipv4
sudo nft list set inet filter blacklist_ipv6
```

---

## Critical Notes

**Database mode required for:** `--query-*`, `--list-*`, `--top-threats`, `--export-*`, `--live-monitor`, `--sync-*`, `--stats-only`

**Whitelist priority:** Whitelisted IPs never blocked regardless of detections

**Default paths (XDG):**
- Data: `~/.local/share/tribanft/` (organized in subdirs: data/, state/, cache/, logs/, backups/ v2.9.0+)
- Config: `~/.local/share/tribanft/config.conf`
- State: `~/.local/state/tribanft/` (legacy, deprecated in v2.9.0+)

**Common fixes:**
- Permission denied: `sudo usermod -a -G adm $USER`
- Enable database: `use_database = true` in `[storage]` section
- Enable NFTables: `enable_nftables_update = true` in config

---

## See Also

[CONFIGURATION.md](CONFIGURATION.md) | [MONITORING_AND_TUNING.md](MONITORING_AND_TUNING.md) | [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) | [PLUGIN_DEVELOPMENT.md](PLUGIN_DEVELOPMENT.md) | [API_REFERENCE.md](API_REFERENCE.md)