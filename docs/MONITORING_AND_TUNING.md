# TribanFT Monitoring & Tuning

Quick reference for monitoring detections and tuning thresholds.

---

## Quick Commands

### Monitor Service

```bash
# Live logs
sudo journalctl -u tribanft -f

# Detections only
sudo journalctl -u tribanft -f | grep "Blacklisted"

# Errors only
sudo journalctl -u tribanft --since "1 hour ago" | grep -i error
```

### Analyze Detections

```bash
# Last 7 days analysis
scripts/analyze_and_tune.sh 7

# Last 24 hours
scripts/analyze_and_tune.sh 1

# Current week
scripts/analyze_and_tune.sh 7 > report_$(date +%Y%m%d).txt
```

### View Blacklist

```bash
# Show all blocked IPs
tribanft --show-blacklist

# Recent blocks (last 20)
tribanft --show-blacklist | tail -20

# Count total
tribanft --show-blacklist | wc -l
```

---

## Threshold Tuning

### Tuning Guidelines

| Metric | Target | Action if Too High | Action if Too Low |
|--------|--------|-------------------|-------------------|
| Detections/day | 10-50 | Increase thresholds | Decrease thresholds |
| False positives | <1% | Whitelist + increase thresholds | Good |
| Blocked IPs | 50-200/week | Review patterns | Lower thresholds |

### Adjust YAML Rule Thresholds

```bash
# Edit rule file
vim ~/.local/share/tribanft/bruteforce_detector/rules/detectors/sql_injection.yaml
```

Common adjustments:

| Scenario | Before | After | Reason |
|----------|--------|-------|--------|
| Too many FPs | threshold: 5 | threshold: 10 | More permissive |
| Missing attacks | threshold: 10 | threshold: 5 | More sensitive |
| High traffic site | time_window: 300 | time_window: 600 | Longer window |
| Low traffic site | time_window: 600 | time_window: 300 | Shorter window |

```bash
# Restart after changes
sudo systemctl restart tribanft
```

### Adjust Plugin Thresholds

Built-in detectors (edit source code):

| Detector | File | Threshold Variable |
|----------|------|-------------------|
| Prelogin | plugins/detectors/prelogin.py | `self.threshold` |
| Failed Login | plugins/detectors/failed_login.py | `self.threshold` |
| Port Scan | plugins/detectors/port_scan.py | `self.threshold` |

---

## False Positive Analysis

### Identify False Positives

```bash
# List all blocked IPs from today
sudo journalctl -u tribanft --since today | \
  grep "Blacklisted" | \
  awk '{print $NF}' | \
  sort -u > today_blocks.txt

# Check each IP
while read ip; do
  tribanft --query-ip "$ip"
done < today_blocks.txt
```

### Common False Positive Sources

| Source | Signature | Solution |
|--------|-----------|----------|
| Monitoring tools | Regular interval access | Whitelist IP |
| Load balancers | Many IPs, same pattern | Whitelist subnet |
| API clients | High request rate | Increase threshold |
| Backup systems | Scheduled access | Whitelist + document |
| Internal services | RFC1918 addresses | Whitelist internal ranges |

### Whitelist Management

```bash
# Add to whitelist
tribanft --whitelist-add 10.0.0.5 --reason "Zabbix monitoring"
tribanft --whitelist-add 192.168.1.0/24 --reason "Internal network"

# View whitelist
tribanft --show-whitelist

# Remove from whitelist
tribanft --whitelist-remove 10.0.0.5
```

---

## Baseline Learning (Week 1)

### Checklist

- [ ] Deploy with `enable_nftables_update = false` (learning mode)
- [ ] Run for 7 days minimum
- [ ] Collect baseline data with `analyze_and_tune.sh`
- [ ] Identify normal traffic patterns
- [ ] Whitelist legitimate IPs
- [ ] Adjust thresholds based on data
- [ ] Test with blocking disabled
- [ ] Enable blocking in Week 3

### Commands

```bash
# Day 1: Deploy in learning mode
scripts/setup-config.sh --learning-mode
sudo systemctl start tribanft

# Days 2-7: Monitor
scripts/analyze_and_tune.sh 1  # Daily check

# Day 7: Full analysis
scripts/analyze_and_tune.sh 7 > baseline_report.txt

# Review top IPs
grep "Top" baseline_report.txt

# Whitelist as needed
tribanft --whitelist-add IP --reason "Description"
```

---

## Performance Monitoring

### Resource Usage

```bash
# Check CPU/Memory
top -p $(pgrep -f tribanft)

# Disk usage (organized structure v2.9.0+)
du -h ~/.local/share/tribanft/

# Database size (if using SQLite) - v2.9.0+
ls -lh ~/.local/share/tribanft/state/blacklist.db

# Log files size - v2.9.0+
ls -lh ~/.local/share/tribanft/logs/

# Backup files - v2.9.0+
du -h ~/.local/share/tribanft/backups/
```

### Performance Issues

| Symptom | Check | Solution |
|---------|-------|----------|
| High CPU | Rule complexity | Simplify regex patterns |
| High memory | Large blacklist | Use database mode |
| Slow startup | Plugin count | Disable unused plugins |
| Disk full | Backup retention | Adjust retention settings, check `backups/` dir (v2.9.0+) |
| Large logs | Log rotation | Check `log_max_bytes` and `log_backup_count` (v2.9.0+) |

### Optimization

```bash
# Enable database mode for large blacklists (>1000 IPs)
vim ~/.local/share/tribanft/config.conf
```

```ini
[storage]
use_database = true
sync_to_file = false  # Maximum performance

[performance]
batch_size = 2000
backup_interval_days = 7
```

### NEW in v2.8.0

**SQLite Backup Improvements**
- Backups now use SQLite backup() API instead of file copy
- Backups are consistent even during active database writes
- Backup filename includes timestamp: blacklist.db.backup.YYYYMMDD_HHMMSS
- Integrity verification automatically performed after backup
- See database.py:create_backup() for implementation details

**Rate Limit State Persistence**
- Rate limit tracking now persists across process restarts
- State file: {data_dir}/rate_limit_state.json
- Automatically saved when rate limit exceeded
- Automatically loaded on startup
- DoS protection settings survive service restarts

---

## Weekly Monitoring Routine

### Checklist

**Monday Morning** (10 minutes):
- [ ] Run `scripts/analyze_and_tune.sh 7`
- [ ] Review detection trends
- [ ] Check for new attack patterns
- [ ] Verify service health

**As Needed**:
- [ ] Whitelist false positives
- [ ] Adjust thresholds
- [ ] Update rules for new threats
- [ ] Review blocked IPs

### Automated Reports

```bash
# Add to crontab
crontab -e

# Daily summary (8 AM)
0 8 * * * ~/.local/share/tribanft/scripts/analyze_and_tune.sh 1 | mail -s "TribanFT Daily" admin@example.com

# Weekly detailed report (Monday 9 AM)
0 9 * * 1 ~/.local/share/tribanft/scripts/analyze_and_tune.sh 7 | mail -s "TribanFT Weekly" admin@example.com
```

---

## Key Metrics Reference

### Detection Metrics

| Metric | Command | Good Range |
|--------|---------|-----------|
| Total detections | `analyze_and_tune.sh 7 \| grep "Total"` | 50-500/week |
| Unique IPs blocked | `tribanft --show-blacklist \| wc -l` | 10-100 |
| Detection rate | Manual calculation | 1-5% of events |
| Average events/IP | `analyze_and_tune.sh 7` | 5-20 |

### Service Health Metrics

| Metric | Command | Good Value |
|--------|---------|-----------|
| Service uptime | `systemctl status tribanft` | Active (running) |
| Recent errors | `journalctl -u tribanft --since "1 hour ago" \| grep ERROR` | 0 |
| Plugin load status | `journalctl -u tribanft \| grep "Loaded plugin"` | All loaded |
| Rule load status | `journalctl -u tribanft \| grep "Loaded rule"` | Expected count |

---

## Environment-Specific Tuning

### E-commerce Site

```yaml
# Higher thresholds for shopping cart activity
threshold: 20
time_window: 600
```

### Corporate Network

```yaml
# Lower thresholds for strict security
threshold: 3
time_window: 300
```

### API Gateway

```yaml
# Moderate thresholds with rate limiting focus
threshold: 50
time_window: 60  # 1 minute window
```

### Public Web Server

```yaml
# Balanced approach
threshold: 10
time_window: 300  # 5 minutes
```

---

## Troubleshooting

### No Detections

```bash
# Check parsers finding events
sudo journalctl -u tribanft | grep "Parser.*found.*events"

# Verify log paths
grep -E "_path" ~/.local/share/tribanft/config.conf

# Test log file accessibility
ls -la /var/log/syslog
ls -la /var/opt/mssql/log/errorlog
```

### Too Many False Positives

```bash
# Increase thresholds by 50%
# Example: threshold: 5 → threshold: 8

# Add broader time window
# Example: time_window: 300 → time_window: 600

# Whitelist internal networks
tribanft --whitelist-add 10.0.0.0/8 --reason "Internal"
tribanft --whitelist-add 172.16.0.0/12 --reason "Internal"
tribanft --whitelist-add 192.168.0.0/16 --reason "Internal"
```

### Detection Lag

```bash
# Enable real-time monitoring
vim ~/.local/share/tribanft/config.conf
```

```ini
[realtime]
monitor_syslog = true
monitor_mssql = true
```

```bash
pip3 install --user watchdog
sudo systemctl restart tribanft
```

---

## Related Documentation

- **Configuration**: docs/CONFIGURATION.md
- **Rule Syntax**: docs/RULE_SYNTAX.md
- **Deployment**: docs/DEPLOYMENT_GUIDE.md
