# TribanFT Deployment & Testing Guide

Complete guide for deploying TribanFT with plugin system, YAML rules, real-time monitoring, and NFTables integration.

**Author**: TribanFT Project
**License**: GNU GPL v3
**Last Updated**: 2025-12-23
**Version**: 2.4.0

**Features Covered**:
- Plugin auto-discovery system (Phase 1 & 2)
- YAML-based detection rules and parser patterns
- Real-time log monitoring (v2.3)
- NFTables discovery and integration (v2.4)
- SQLite database backend with smart backups
- CrowdSec and Fail2Ban integration

---

## Table of Contents

1. [Pre-Deployment Checklist](#pre-deployment-checklist)
2. [Deployment Steps](#deployment-steps)
3. [Initial Configuration](#initial-configuration)
4. [Testing Phase](#testing-phase)
5. [Production Deployment](#production-deployment)
6. [Post-Deployment Monitoring](#post-deployment-monitoring)
7. [Rollback Procedures](#rollback-procedures)

---

## Pre-Deployment Checklist

### System Requirements

- [ ] Python 3.8 or higher
- [ ] sudo/root access
- [ ] systemd (for service management)
- [ ] NFTables installed and configured
- [ ] Minimum 512MB RAM
- [ ] Minimum 1GB disk space

### Backup Current Installation

```bash
# On remote server
cd ~/.local/share/tribanft

# Backup configuration
cp config.conf config.conf.backup.$(date +%Y%m%d)

# Backup blacklists
cp blacklist_ipv4.txt blacklist_ipv4.backup.$(date +%Y%m%d)
cp blacklist_ipv6.txt blacklist_ipv6.backup.$(date +%Y%m%d)

# Backup whitelist
cp whitelist_ips.txt whitelist_ips.backup.$(date +%Y%m%d)

# Stop service
sudo systemctl stop tribanft
```

### Prerequisites Check

```bash
# Check Python version
python3 --version  # Should be >= 3.8

# Check required Python packages
python3 -c "import yaml; print('PyYAML:', yaml.__version__)"
python3 -c "import pydantic; print('Pydantic:', pydantic.__version__)"
python3 -c "import pydantic_settings; print('Pydantic Settings: OK')"
# If not installed: pip3 install pyyaml pydantic pydantic-settings

# Check optional packages
python3 -c "import watchdog; print('watchdog:', watchdog.__version__)" || \
    echo "⚠ watchdog not installed (real-time monitoring will be disabled)"
# If not installed: pip3 install watchdog

# Check systemd
systemctl --version

# Check NFTables
sudo nft list ruleset | head
```

---

## Deployment Steps

### Step 1: Deploy New Code

**From your local machine** (where you've been developing):

```bash
# Create deployment package
cd /home/jc/Documents/projetos/tribanft

# Exclude unnecessary files
tar -czf tribanft-phase2.tar.gz \
    --exclude='*.pyc' \
    --exclude='__pycache__' \
    --exclude='.git' \
    --exclude='*.backup' \
    bruteforce_detector/ \
    scripts/ \
    *.md

# Copy to server
scp tribanft-phase2.tar.gz user@your-server:~/ scp MONITORING_AND_TUNING.md user@your-server:~/
scp DEPLOYMENT_GUIDE.md user@your-server:~/
```

**On remote server**:

```bash
# Extract new code
cd ~
tar -xzf tribanft-phase2.tar.gz

# Backup old installation
sudo mv ~/.local/share/tribanft/bruteforce_detector \
    ~/.local/share/tribanft/bruteforce_detector.old.$(date +%Y%m%d)

# Deploy new code
cp -r bruteforce_detector ~/.local/share/tribanft/

# Make scripts executable
chmod +x ~/.local/share/tribanft/scripts/*.sh

# Verify structure
ls -la ~/.local/share/tribanft/bruteforce_detector/
# Should see: core/, plugins/, rules/
```

### Step 2: Update Configuration

```bash
cd ~/.local/share/tribanft

# If you don't have config.conf yet, create from template
if [ ! -f config.conf ]; then
    cp config.conf.template config.conf
    echo "✓ Created config.conf from template"
else
    echo "✓ config.conf already exists"
fi

# Verify plugin system settings are present
grep -q "\[plugins\]" config.conf || cat >> config.conf << 'EOF'

# ═══════════════════════════════════════════════════════════════════════════
# [plugins] - Plugin System Configuration
# ═══════════════════════════════════════════════════════════════════════════
[plugins]

# Enable plugin auto-discovery system
# When enabled, detectors and parsers are automatically loaded from plugins/ directory
# When disabled, uses legacy hardcoded detector/parser initialization
enable_plugin_system = true

# Plugin directories (relative to project_dir)
# These directories are scanned for detector and parser plugins
detector_plugin_dir = ${paths:project_dir}/bruteforce_detector/plugins/detectors
parser_plugin_dir = ${paths:project_dir}/bruteforce_detector/plugins/parsers

# Enable YAML-based detection rules
# When enabled, scans rules_dir for YAML rule files
enable_yaml_rules = true

# Rules directory for YAML-based detection patterns
# Place your custom .yaml rule files here
rules_dir = ${paths:project_dir}/bruteforce_detector/rules
EOF

echo "✓ Configuration updated"
```

### Step 3: Install Python Dependencies

```bash
# Install required dependencies
pip3 install --user pyyaml pydantic pydantic-settings

# Install optional dependencies (highly recommended)
pip3 install --user watchdog  # For real-time log monitoring (v2.3+)

# Verify installation
python3 -c "import yaml; print('✓ PyYAML installed')"
python3 -c "import pydantic; print('✓ Pydantic installed')"
python3 -c "import watchdog; print('✓ watchdog installed')" || echo "⚠ watchdog not installed (real-time monitoring unavailable)"
```

### Step 4: Validate Installation

```bash
# Test Python imports
python3 -c "
from bruteforce_detector.core.plugin_manager import PluginManager
from bruteforce_detector.core.rule_engine import RuleEngine
from bruteforce_detector.config import get_config
print('✓ All imports successful')
"

# Validate detector YAML rules
echo "Validating detector rules..."
for f in ~/.local/share/tribanft/bruteforce_detector/rules/detectors/*.yaml; do
    python3 -c "import yaml; yaml.safe_load(open('$f'))" && \
        echo "✓ $(basename $f) valid" || \
        echo "✗ $(basename $f) INVALID"
done

# Validate parser YAML patterns
echo "Validating parser patterns..."
for f in ~/.local/share/tribanft/bruteforce_detector/rules/parsers/*.yaml; do
    python3 -c "import yaml; yaml.safe_load(open('$f'))" && \
        echo "✓ $(basename $f) valid" || \
        echo "✗ $(basename $f) INVALID"
done
```

---

## Initial Configuration

### Configure for Learning Mode

**First week: Monitor without blocking**

```bash
# Edit config.conf
vim ~/.local/share/tribanft/config.conf

# Find and set:
[features]
enable_nftables_update = false  # Disable blocking temporarily

# Keep detection enabled
enable_prelogin_detection = true
enable_failed_login_detection = true
enable_port_scan_detection = true
enable_crowdsec_integration = true

# Optionally enable real-time monitoring (v2.3+)
[realtime]
monitor_syslog = true
monitor_mssql = true
monitor_apache = false  # Enable if you have Apache
monitor_nginx = false   # Enable if you have Nginx
```

### Enable Example YAML Rules

**Start with conservative rules**:

```bash
cd ~/.local/share/tribanft/bruteforce_detector/rules/detectors/

# SQL Injection - ENABLE with high threshold
vim sql_injection.yaml
# Change: enabled: false → enabled: true
# Change: threshold: 5 → threshold: 10

# RDP Bruteforce - ENABLE
vim rdp_bruteforce.yaml
# Change: enabled: false → enabled: true
# Keep: threshold: 10 (already conservative)

# WordPress - KEEP DISABLED initially
# (only enable if you have WordPress)

# Verify changes
grep "enabled:" *.yaml
```

### Set Appropriate Thresholds

**Review and adjust based on your environment**:

```bash
# Check your typical auth failure rate
sudo journalctl --since "7 days ago" | \
    grep -i "failed\|authentication\|login" | \
    wc -l

# If >1000 failures/week, you have high legitimate traffic
# → Use higher thresholds (20-30)

# If <100 failures/week, you have low traffic
# → Use lower thresholds (5-10)
```

### Configure Real-Time Monitoring (v2.3+)

**Enable for near-instant detection (<2 seconds vs 5 minutes)**:

```bash
# Edit config.conf
vim ~/.local/share/tribanft/config.conf

# Add or verify [realtime] section
[realtime]
# Enable monitoring for active log sources
monitor_syslog = true
monitor_mssql = true
monitor_apache = true   # If you have Apache
monitor_nginx = true    # If you have Nginx

# Debounce interval (batch rapid log writes)
debounce_interval = 1.0

# Rate limiting for DoS protection
max_events_per_second = 1000
rate_limit_backoff = 30

# Fallback to periodic mode if inotify unavailable
fallback_interval = 60
```

**Install watchdog library** (required for real-time monitoring):

```bash
pip3 install --user watchdog

# Verify installation
python3 -c "import watchdog; print('✓ watchdog installed')"
```

**Note**: If watchdog is unavailable, tribanFT automatically falls back to periodic monitoring (60-second intervals).

### Configure Storage Backend

**Choose between SQLite database or file-based storage**:

```bash
# Edit config.conf
vim ~/.local/share/tribanft/config.conf

# Recommended: Use SQLite database (better performance for >1000 IPs)
[storage]
use_database = true
sync_to_file = true  # Keep text files synced for compatibility

# Configure backup settings
[performance]
backup_enabled = true
backup_interval_days = 7     # Only backup if last backup was >7 days ago
backup_retention_days = 30   # Keep backups for 30 days
backup_min_keep = 4          # Always keep at least 4 backups
backup_compress_age_days = 1 # Compress backups older than 1 day
```

**For large deployments (>10,000 IPs)**:

```bash
# Optimize for performance
[storage]
use_database = true
sync_to_file = false  # Disable file sync for maximum performance

[performance]
batch_size = 2000
backup_interval_days = 7
backup_retention_days = 30
```

---

## Testing Phase

### Phase 1: Dry Run (Week 1)

**Goal**: Validate installation and collect baseline data

```bash
# Start service in learning mode
sudo systemctl start tribanft

# Watch logs in real-time
sudo journalctl -u tribanft -f

# Look for:
# ✓ Loaded X plugin
# ✓ Loaded rule: rule_name v1.0.0
# ✓ YAML Rule Engine: Loaded X/X rules
```

**Monitor for errors**:
```bash
# Check for errors
sudo journalctl -u tribanft --since "1 hour ago" | grep -i error

# Check for warnings
sudo journalctl -u tribanft --since "1 hour ago" | grep -i warning
```

**Verify plugin loading**:
```bash
# Check all plugins loaded
sudo journalctl -u tribanft --since "1 hour ago" | grep "Loaded plugin"
# Should see: prelogin_detector, failed_login_detector, port_scan_detector, crowdsec_detector

# Check all rules loaded
sudo journalctl -u tribanft --since "1 hour ago" | grep "Loaded rule"
# Should see your enabled YAML rules
```

### Phase 2: Detection Analysis (Week 1)

**Collect detection data**:

```bash
# Run analysis script
cd ~/.local/share/tribanft
./scripts/analyze_and_tune.sh 7

# Review output for:
# - Total detections
# - Top rules/detectors
# - Top blocked IPs
# - Threshold recommendations
```

**Check for false positives**:

```bash
# List all detected IPs today
sudo journalctl -u tribanft --since today | \
    grep "Blacklisted" | \
    awk '{print $9}' | \
    sort -u > detected_ips.txt

# Check each IP
while read ip; do
    echo "Checking $ip..."
    tribanft --ip-info "$ip"
    echo "---"
done < detected_ips.txt
```

**Common false positive sources**:
- Monitoring tools (Nagios, Zabbix, etc.)
- Backup systems
- Load balancers
- Internal services
- Development/testing activity

**Action**: Whitelist legitimate IPs
```bash
tribanft --whitelist-add 10.0.0.5 --reason "Zabbix monitoring server"
```

### Phase 3: Threshold Tuning (Week 2)

**Based on Week 1 data**:

```bash
# If too many detections (>50/day)
# Increase thresholds by 50%

# Example: sql_injection.yaml
vim ~/.local/share/tribanft/bruteforce_detector/rules/detectors/sql_injection.yaml

# Change:
threshold: 10  →  threshold: 15

# If too few detections (known attacks missed)
# Decrease thresholds by 30%

# Restart after changes
sudo systemctl restart tribanft
```

**Monitor impact**:
```bash
# Compare before/after
./scripts/analyze_and_tune.sh 1  # Today only
```

---

## Production Deployment

### Enable NFTables Integration

**After 2 weeks of tuning**:

```bash
# Edit config
vim ~/.local/share/tribanft/config.conf

# Enable blocking
[features]
enable_nftables_update = true

# Configure NFTables sets
[nftables]
nft_bin = /usr/sbin/nft
blacklist_set = inet filter blacklist_ipv4
port_scanners_set = inet filter port_scanners
crowdsec_sets = inet filter crowdsec
fail2ban_pattern = inet f2b-table addr-set-*

# Optional: Enable NFTables discovery (v2.4+)
nftables_auto_discovery = false  # Enable to auto-discover all sets
nftables_event_log_enabled = false  # Enable for audit logging
# nftables_import_sets = inet:filter:custom_set  # Additional sets to import

# Restart
sudo systemctl restart tribanft

# Verify NFTables rules
sudo nft list ruleset | grep -A 10 "blacklist_ipv4"
sudo nft list set inet filter blacklist_ipv4
```

### Gradual Rollout

**Day 1-3: Monitor Closely**

```bash
# Check every hour
watch -n 3600 'sudo journalctl -u tribanft --since "1 hour ago" | tail -50'

# Check for new blocks
tribanft --show-blacklist | tail -20

# Verify legitimate traffic not blocked
# (test from external IP if possible)
```

**Day 4-7: Normal Monitoring**

```bash
# Daily check
./scripts/analyze_and_tune.sh 1

# Weekly full analysis
./scripts/analyze_and_tune.sh 7
```

### Enable Additional Rules

**After successful 1 week in production**:

```bash
# Enable more YAML rules gradually
cd ~/.local/share/tribanft/bruteforce_detector/rules/detectors/

# Week 2: Enable WordPress rules (if applicable)
vim wordpress_attacks.yaml
# enabled: false → enabled: true (for each detector)

# Week 3: Add custom rules for your environment
cp custom_environment_examples.yaml my_environment.yaml
# Edit and enable relevant detectors

# Restart after each addition
sudo systemctl restart tribanft
```

---

## Post-Deployment Monitoring

### Daily Monitoring

```bash
# Quick status check
tribanft --show-stats

# Recent detections
sudo journalctl -u tribanft --since today | grep "Blacklisted" | tail -20

# Service health
systemctl status tribanft
```

### Weekly Analysis

```bash
# Full analysis
cd ~/.local/share/tribanft
./scripts/analyze_and_tune.sh 7 > reports/week_$(date +%V).txt

# Review:
# - Detection trends
# - New attack patterns
# - False positive rate
# - Performance metrics
```

### Monthly Review

**Actions**:
1. Review and update whitelist
2. Analyze rule effectiveness
3. Update thresholds based on trends
4. Check for TribanFT updates
5. Review NFTables ban times
6. Backup configuration

```bash
# Monthly backup
DATE=$(date +%Y%m)
tar -czf ~/tribanft_backup_$DATE.tar.gz \
    ~/.local/share/tribanft/config.conf \
    ~/.local/share/tribanft/whitelist_ips.txt \
    ~/.local/share/tribanft/bruteforce_detector/rules/detectors/*.yaml
```

### Alerts and Notifications

**Set up alerts for**:
- High detection rate (>100/day)
- Service failures
- Disk space issues
- Whitelist modifications

**Example with cron**:
```bash
# Add to crontab
crontab -e

# Daily detection summary (8 AM)
0 8 * * * /home/user/.local/share/tribanft/scripts/analyze_and_tune.sh 1 | mail -s "TribanFT Daily Report" admin@example.com

# Weekly detailed report (Monday 9 AM)
0 9 * * 1 /home/user/.local/share/tribanft/scripts/analyze_and_tune.sh 7 | mail -s "TribanFT Weekly Report" admin@example.com
```

---

## Rollback Procedures

### Emergency Rollback (Critical Issue)

```bash
# Stop service immediately
sudo systemctl stop tribanft

# Restore old version
cd ~/.local/share/tribanft
rm -rf bruteforce_detector
mv bruteforce_detector.old.YYYYMMDD bruteforce_detector

# Restore old config
cp config.conf.backup.YYYYMMDD config.conf

# Restart
sudo systemctl start tribanft

# Verify
sudo journalctl -u tribanft -n 50
```

### Partial Rollback (Disable Specific Feature)

**Disable YAML rules only**:
```bash
vim ~/.local/share/tribanft/config.conf

[plugins]
enable_yaml_rules = false

sudo systemctl restart tribanft
```

**Disable specific rule**:
```bash
vim ~/.local/share/tribanft/bruteforce_detector/rules/detectors/problematic_rule.yaml

metadata:
  enabled: false

sudo systemctl restart tribanft
```

**Disable plugin system entirely**:
```bash
vim ~/.local/share/tribanft/config.conf

[plugins]
enable_plugin_system = false

sudo systemctl restart tribanft
```

### Clear All Blocks (Nuclear Option)

```bash
# Remove all blocked IPs from NFTables
sudo nft flush set inet filter blacklist_ipv4
sudo nft flush set inet filter port_scanners

# Clear blacklist files
> ~/.local/share/tribanft/blacklist_ipv4.txt
> ~/.local/share/tribanft/blacklist_ipv6.txt

# Clear database (if using)
rm ~/.local/share/tribanft/blacklist.db

# Restart fresh
sudo systemctl restart tribanft
```

---

## Troubleshooting

### Service Won't Start

```bash
# Check logs
sudo journalctl -u tribanft -n 100 --no-pager

# Common issues:
# 1. Config syntax error
python3 -c "from bruteforce_detector.config import get_config; get_config()"

# 2. Missing dependencies
pip3 list | grep -i yaml

# 3. Permission issues
ls -la ~/.local/share/tribanft/

# 4. Port already in use (if applicable)
sudo lsof -i :PORT
```

### Rules Not Loading

```bash
# Check YAML syntax
for f in ~/.local/share/tribanft/bruteforce_detector/rules/detectors/*.yaml; do
    python3 -c "import yaml; yaml.safe_load(open('$f'))" || echo "ERROR in $f"
done

# Check if rules directory exists
ls -la ~/.local/share/tribanft/bruteforce_detector/rules/detectors/

# Check config
grep "enable_yaml_rules" ~/.local/share/tribanft/config.conf
grep "rules_dir" ~/.local/share/tribanft/config.conf
```

### No Detections

```bash
# Check if parsers are finding events
sudo journalctl -u tribanft | grep "Parser.*found.*events"

# Check log file paths
grep -E "syslog_path|mssql.*path" ~/.local/share/tribanft/config.conf

# Verify log files exist and are readable
ls -la /var/log/syslog
ls -la /var/opt/mssql/log/errorlog

# Check detection enabled
grep "enable.*detection" ~/.local/share/tribanft/config.conf
```

### High CPU/Memory Usage

```bash
# Check resource usage
top -p $(pgrep -f tribanft)

# Check database size (if using SQLite)
du -h ~/.local/share/tribanft/blacklist.db
# Optimize if large: sqlite3 blacklist.db "VACUUM;"

# Reduce rule complexity
# - Disable unused rules
# - Simplify regex patterns
# - Increase thresholds

# Optimize storage backend
vim ~/.local/share/tribanft/config.conf
[storage]
use_database = true
sync_to_file = false  # Disable file sync for better performance

# Adjust backup settings
[performance]
backup_interval_days = 7  # Less frequent backups
batch_size = 2000  # Larger batches

# Disable real-time monitoring if causing issues
[realtime]
monitor_syslog = false
monitor_mssql = false
# Falls back to periodic mode
```

### Real-Time Monitoring Not Working

```bash
# Check if watchdog is installed
python3 -c "import watchdog; print('watchdog available')" || \
    echo "watchdog not installed - install with: pip3 install watchdog"

# Check log file permissions
ls -la /var/log/syslog
ls -la /var/opt/mssql/log/errorlog

# Check for inotify errors
dmesg | grep inotify

# Verify fallback to periodic mode
sudo journalctl -u tribanft | grep -i "fallback\|periodic"

# Test manually
python3 -c "
from watchdog.observers import Observer
print('✓ inotify available')
"
```

### NFTables Integration Not Working

```bash
# Check NFTables configuration
sudo nft list ruleset | grep -A 5 "blacklist_ipv4"

# Verify set exists
sudo nft list set inet filter blacklist_ipv4 || \
    echo "Set does not exist - create with scripts/setup_nftables.sh"

# Check config
grep -A 10 "\[nftables\]" ~/.local/share/tribanft/config.conf

# Verify feature enabled
grep "enable_nftables_update" ~/.local/share/tribanft/config.conf

# Check permissions
sudo nft list ruleset > /dev/null && echo "✓ NFTables accessible" || \
    echo "✗ No NFTables permissions - run as root or configure sudo"
```

---

## Success Criteria

### Week 1 (Learning Mode)
- [ ] Service running without errors
- [ ] All plugins loading successfully (detectors and parsers)
- [ ] YAML rules loading successfully (detectors and parsers)
- [ ] Events being parsed from logs
- [ ] Detections occurring (in logs only, NFTables disabled)
- [ ] No critical performance issues
- [ ] Database initialized (if using SQLite backend)
- [ ] Real-time monitoring active (or fallback to periodic mode)

### Week 2 (Tuning Phase)
- [ ] False positive rate < 5%
- [ ] All legitimate services whitelisted
- [ ] Thresholds tuned for environment
- [ ] Analysis script providing useful insights
- [ ] No service crashes or errors
- [ ] Backup system working correctly
- [ ] Log file paths configured correctly
- [ ] Parser patterns detecting relevant events

### Week 3+ (Production)
- [ ] NFTables integration active and blocking attacks
- [ ] Real attacks being blocked in real-time
- [ ] False positive rate < 1%
- [ ] Service stable and performant
- [ ] Monitoring and alerting in place
- [ ] Documentation updated for your environment
- [ ] CrowdSec/Fail2Ban integration working (if applicable)
- [ ] IP geolocation enrichment working (if configured)
- [ ] Backup retention policy optimized

---

## Quick Reference Commands

```bash
# Service management
sudo systemctl start tribanft
sudo systemctl stop tribanft
sudo systemctl restart tribanft
sudo systemctl status tribanft

# Logs
sudo journalctl -u tribanft -f                    # Follow
sudo journalctl -u tribanft --since today         # Today
sudo journalctl -u tribanft --since "1 hour ago"  # Last hour

# Analysis
./scripts/analyze_and_tune.sh 7   # Last 7 days

# Blacklist management
tribanft --show-blacklist
tribanft --show-whitelist
tribanft --whitelist-add IP --reason "Description"
tribanft --ip-info IP

# Configuration
vim ~/.local/share/tribanft/config.conf
vim ~/.local/share/tribanft/bruteforce_detector/rules/detectors/rule.yaml

# Testing
python3 -c "from bruteforce_detector.core.rule_engine import RuleEngine"
python3 -c "import yaml; yaml.safe_load(open('rule.yaml'))"
```

---

**For detailed monitoring and tuning, see: [MONITORING_AND_TUNING.md](MONITORING_AND_TUNING.md)**
**For rule syntax reference, see: [RULE_SYNTAX.md](RULE_SYNTAX.md)**
**For plugin development, see: [PLUGIN_DEVELOPMENT.md](PLUGIN_DEVELOPMENT.md)**
