# TribanFT Command Reference

```
╔═══════════════════════════════════════════════════════════════════════════╗
║ TribanFT Command Reference                                                ║
║ Author: TribanFT Project | License: GNU GPL v3 | Updated: 2025-12-25     ║
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
| `--blacklist-add` | `<IP>` | Block IP (auto-investigates logs) |
| `--blacklist-reason` | `<reason>` | Block reason (with --blacklist-add) |
| `--no-log-search` | - | Skip log search when adding IP |
| `--blacklist-remove` | `<IP>` | Remove IP from blacklist |
| `--blacklist-search` | `<IP>` | Search logs without blocking |
| `--show-blacklist` | - | Display all blocked IPs |
| `--show-manual` | - | Display manual entries only |
| **Whitelist** |||
| `--whitelist-add` | `<IP>` | Add to whitelist (never blocked) |
| `--whitelist-remove` | `<IP>` | Remove from whitelist |
| `--show-whitelist` | - | Display whitelist |
| **Query** (requires `use_database = true`) |||
| `--query-ip` | `<IP>` | IP details (geo, timeline, events) |
| `--query-country` | `<CODE>` | List IPs by country (CN, RU, US) |
| `--query-reason` | `<TEXT>` | Search by block reason |
| `--query-attack-type` | `<TYPE>` | Filter by attack type |
| `--query-timerange` | `<RANGE>` | Filter by time range |
| `--list-countries` | - | List countries with counts |
| `--list-sources` | - | List detection sources |
| `--top-threats` | `<N>` | Top N IPs by event count |
| **Export** (requires `use_database = true`) |||
| `--export-csv` | `<FILE>` | Export to CSV |
| `--export-json` | `<FILE>` | Export to JSON |
| **Monitoring** (requires `use_database = true`) |||
| `--live-monitor` | - | Real-time threat monitor |
| **Database Sync** (requires `use_database = true`) |||
| `--sync-files` | - | Sync database to files (creates backups) |
| `--sync-output` | `<FILE>` | Custom sync output file |
| `--sync-stats` | - | Show stats during sync |
| `--stats-only` | - | Show stats without syncing |
| **Integrity & Backup** |||
| `--verify` | - | Run integrity checks |
| `--skip-verify` | - | Skip startup integrity check |
| `--list-backups` | `<FILE>` | List available backups |
| `--restore-backup` | `<BACKUP>` | Restore from backup (needs --restore-target) |
| `--restore-target` | `<TARGET>` | Restoration target path |
| `--compress-backups` | - | Compress old backups |
| **Integration** |||
| `--import-crowdsec-csv` | `<CSV>` | Import CrowdSec CSV data |
| `--migrate` | - | Migrate cron to systemd |

---

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
```

---

## See Also

[CONFIGURATION.md](CONFIGURATION.md) | [MONITORING_AND_TUNING.md](MONITORING_AND_TUNING.md) | [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) | [PLUGIN_DEVELOPMENT.md](PLUGIN_DEVELOPMENT.md) | [API_REFERENCE.md](API_REFERENCE.md)