# TribanFT Monitoring & Threshold Tuning Guide

Complete guide for monitoring detections and tuning thresholds for your environment.

**Author**: TribanFT Project
**License**: GNU GPL v3
**Last Updated**: 2025-01-20

---

## Table of Contents

1. [Overview](#overview)
2. [Monitoring Logs](#monitoring-logs)
3. [Analyzing Detection Patterns](#analyzing-detection-patterns)
4. [Threshold Tuning](#threshold-tuning)
5. [Environment-Specific Patterns](#environment-specific-patterns)
6. [False Positive Analysis](#false-positive-analysis)
7. [Performance Monitoring](#performance-monitoring)
8. [Best Practices](#best-practices)

---

## Overview

### Why Monitor and Tune?

**Before Production**:
- Establish baseline for normal traffic
- Identify false positives
- Optimize thresholds for your environment
- Validate detection accuracy

**In Production**:
- Monitor detection effectiveness
- Adjust for changing attack patterns
- Reduce false positives
- Track performance metrics

### Key Metrics to Track

| Metric | Purpose | Target |
|--------|---------|--------|
| **Detection Rate** | Events → Detections | 1-5% (depends on environment) |
| **False Positive Rate** | Legitimate IPs blocked | <1% |
| **True Positive Rate** | Actual attacks blocked | >95% |
| **Detection Latency** | Time to block | <5 minutes |
| **Resource Usage** | CPU/Memory impact | <5% CPU |

---

## Monitoring Logs

### Real-Time Log Monitoring

**Monitor TribanFT service logs**:
```bash
# Follow live logs
sudo journalctl -u tribanft -f

# With grep filter for detections
sudo journalctl -u tribanft -f | grep -E "found|detection|Loaded"

# Color-coded for readability
sudo journalctl -u tribanft -f | grep --color=auto -E "found|detection|ERROR|WARNING"
```

**Key log messages to watch**:
```
# Successful startup
✓ Loaded plugin: prelogin_detector
✓ Loaded rule: sql_injection_detector v1.0.0
YAML Rule Engine: Loaded 3/4 rules

# Detection events
Detector PreloginDetector found 5 detections
YAML Rule Engine found 2 detections
Rule 'sql_injection_detector' found 2 detections

# Blocked IPs
Blacklisted 1.2.3.4 (SQL injection: UNION-based injection - 15 attempts)
Added to NFTables blacklist: 1.2.3.4
```

### Log Analysis Commands

**1. Count detections per hour**:
```bash
# Last 24 hours
sudo journalctl -u tribanft --since "24 hours ago" | \
  grep "found.*detection" | \
  awk '{print $1" "$2" "$3}' | \
  cut -d: -f1 | \
  uniq -c | \
  sort -rn
```

**2. List all blocked IPs today**:
```bash
sudo journalctl -u tribanft --since today | \
  grep "Blacklisted" | \
  awk '{print $NF, $0}' | \
  sort -u
```

**3. Find most common detection reasons**:
```bash
sudo journalctl -u tribanft --since "7 days ago" | \
  grep "Blacklisted" | \
  sed 's/.*Blacklisted [^ ]* (\(.*\))/\1/' | \
  sort | \
  uniq -c | \
  sort -rn | \
  head -20
```

**4. Check YAML rule performance**:
```bash
sudo journalctl -u tribanft --since today | \
  grep "Rule.*found.*detection" | \
  sed "s/.*Rule '\([^']*\)' found \([0-9]*\).*/\1: \2/" | \
  awk '{a[$1]+=$2} END {for(i in a) print a[i], i}' | \
  sort -rn
```

**5. Identify potential false positives**:
```bash
# IPs with exactly threshold detections (may be borderline)
sudo journalctl -u tribanft --since "24 hours ago" | \
  grep "Blacklisted.*- 10 attempts" | \
  awk '{print $9}' | \
  sort | \
  uniq -c
```

---

## Analyzing Detection Patterns

### Step 1: Baseline Normal Traffic

**Run in learning mode** (first week):

```bash
# Enable detection but don't apply to NFTables yet
# Edit config.conf:
[features]
enable_nftables_integration = false  # Temporary
enable_auto_enrichment = true

# Monitor without blocking
sudo systemctl restart tribanft

# Collect logs for 7 days
sudo journalctl -u tribanft --since "7 days ago" > tribanft_baseline.log
```

**Analyze baseline**:
```bash
# Count unique IPs detected
grep "Blacklisted" tribanft_baseline.log | \
  awk '{print $9}' | \
  sort -u | \
  wc -l

# Top detected IPs (potential legitimate traffic)
grep "Blacklisted" tribanft_baseline.log | \
  awk '{print $9}' | \
  sort | \
  uniq -c | \
  sort -rn | \
  head -20

# Time distribution of detections
grep "Blacklisted" tribanft_baseline.log | \
  awk '{print $3}' | \
  cut -d: -f1 | \
  sort | \
  uniq -c
```

### Step 2: Identify Legitimate Traffic

**Check blocked IPs against**:

1. **Your infrastructure**:
   ```bash
   # Your server IPs, monitoring tools, backup systems
   # Add to whitelist if legitimate
   tribanft --whitelist-add 10.0.0.5 --reason "Monitoring server"
   ```

2. **Known services**:
   ```bash
   # Search engine crawlers, CDNs, payment processors
   # Example: Google bot
   whois 1.2.3.4 | grep -i google
   ```

3. **Geolocation**:
   ```bash
   # Check IP metadata
   tribanft --ip-info 1.2.3.4

   # Expected traffic sources?
   # If blocking legitimate users from specific countries, adjust
   ```

### Step 3: Pattern Analysis

**Create analysis script**:
```bash
#!/bin/bash
# analyze_detections.sh

LOG_FILE="${1:-/var/log/tribanft/tribanft.log}"
DAYS="${2:-7}"

echo "=== TribanFT Detection Analysis (Last $DAYS days) ==="
echo

echo "1. Total Detections:"
sudo journalctl -u tribanft --since "$DAYS days ago" | \
  grep -c "Blacklisted"

echo
echo "2. Detections by Rule:"
sudo journalctl -u tribanft --since "$DAYS days ago" | \
  grep "Blacklisted" | \
  sed 's/.*(\(.*\):.*)/\1/' | \
  sort | \
  uniq -c | \
  sort -rn

echo
echo "3. Top 10 Detected IPs:"
sudo journalctl -u tribanft --since "$DAYS days ago" | \
  grep "Blacklisted" | \
  awk '{print $9}' | \
  sort | \
  uniq -c | \
  sort -rn | \
  head -10

echo
echo "4. Detection Time Distribution:"
sudo journalctl -u tribanft --since "$DAYS days ago" | \
  grep "Blacklisted" | \
  awk '{print $3}' | \
  cut -d: -f1 | \
  sort | \
  uniq -c | \
  sort -k2 -n

echo
echo "5. Average Events Per Detection:"
sudo journalctl -u tribanft --since "$DAYS days ago" | \
  grep "Blacklisted.*attempts" | \
  sed 's/.*- \([0-9]*\) attempts.*/\1/' | \
  awk '{sum+=$1; n++} END {if(n>0) print int(sum/n); else print 0}'
```

**Run analysis**:
```bash
chmod +x analyze_detections.sh
./analyze_detections.sh
```

---

## Threshold Tuning

### Understanding Thresholds

**Threshold Formula**:
```
Detection Triggered = (Events >= Threshold) within Time Window
```

**Example**:
```yaml
threshold: 15
time_window_minutes: 30
# = 15 events in 30 minutes triggers detection
```

### Tuning Strategy

#### 1. Too Many False Positives

**Symptoms**:
- Legitimate users getting blocked
- Same IPs frequently in blocklist
- Users complaining about access issues

**Solutions**:

A. **Increase threshold**:
```yaml
# Before
threshold: 10

# After (more permissive)
threshold: 20
```

B. **Extend time window**:
```yaml
# Before
time_window_minutes: 30

# After (allows burst traffic)
time_window_minutes: 60
```

C. **Lower confidence**:
```yaml
# Before
confidence: high

# After (less aggressive)
confidence: medium
```

D. **Refine patterns**:
```yaml
# Before (too broad)
- regex: "(?i).*failed.*"

# After (more specific)
- regex: "(?i).*authentication failed.*password.*"
```

#### 2. Missing Real Attacks

**Symptoms**:
- Known attacks not blocked
- Analysis shows attacks below threshold
- Post-incident review shows missed detections

**Solutions**:

A. **Decrease threshold**:
```yaml
# Before
threshold: 20

# After (more sensitive)
threshold: 10
```

B. **Shorten time window**:
```yaml
# Before
time_window_minutes: 60

# After (detect fast attacks)
time_window_minutes: 15
```

C. **Add more patterns**:
```yaml
patterns:
  - regex: "(?i).*failed.*login.*"
  - regex: "(?i).*authentication.*error.*"  # NEW
  - regex: "(?i).*invalid.*credentials.*"   # NEW
```

D. **Increase confidence**:
```yaml
# Before
confidence: medium

# After (more aggressive)
confidence: high
```

### Threshold Guidelines by Attack Type

| Attack Type | Threshold | Time Window | Reasoning |
|-------------|-----------|-------------|-----------|
| **SQL Injection** | 3-5 | 60 min | Even 1 attempt is suspicious |
| **SSH Bruteforce** | 10-15 | 30 min | Typical bruteforce pattern |
| **RDP Bruteforce** | 8-12 | 30 min | Lower than SSH (fewer attempts) |
| **Port Scan** | 20-50 | 15 min | Many ports = fast scan |
| **Web Scan** | 15-25 | 30 min | Typical scanner behavior |
| **WordPress** | 10-20 | 30 min | Depends on site traffic |

### Environment-Specific Adjustments

#### High-Traffic Environment

```yaml
# Production web server with legitimate traffic
detection:
  threshold: 30  # Higher to avoid false positives
  time_window_minutes: 60
  confidence: high
```

#### Low-Traffic Environment

```yaml
# Internal database server (should have minimal auth failures)
detection:
  threshold: 5  # Lower - any failures suspicious
  time_window_minutes: 120
  confidence: high
```

#### Development Environment

```yaml
# Dev server with frequent deployments/testing
detection:
  threshold: 50  # Very high
  time_window_minutes: 30
  confidence: low
  enabled: false  # Or disable entirely
```

---

## Environment-Specific Patterns

### E-commerce Platform

**Characteristics**:
- Payment processing
- Customer accounts
- API integrations
- Shopping cart

**Custom Rules**:

```yaml
# rules/detectors/ecommerce_attacks.yaml
detectors:
  - metadata:
      name: payment_fraud_detection
      version: 1.0.0
      enabled: true

    detection:
      event_types:
        - FAILED_LOGIN
      threshold: 3  # Low - payment fraud is critical
      time_window_minutes: 60
      confidence: high

      patterns:
        - regex: "(?i).*payment.*declined.*"
        - regex: "(?i).*card.*invalid.*"
        - regex: "(?i).*cvv.*mismatch.*"

    aggregation:
      group_by: source_ip

    output:
      reason_template: "Payment fraud attempt - {event_count} failed transactions"

  - metadata:
      name: account_takeover
      version: 1.0.0
      enabled: true

    detection:
      event_types:
        - FAILED_LOGIN
      threshold: 5
      time_window_minutes: 15
      confidence: high

      patterns:
        - regex: "(?i).*password.*reset.*failed.*"
        - regex: "(?i).*email.*change.*denied.*"
        - regex: "(?i).*2fa.*bypass.*attempt.*"

    aggregation:
      group_by: source_ip

    output:
      reason_template: "Account takeover attempt - {event_count} security events"
```

### Database Server (MSSQL/MySQL)

**Characteristics**:
- Direct database access
- Should have minimal failed logins
- Highly sensitive to injection

**Custom Rules**:

```yaml
# rules/detectors/database_security.yaml
metadata:
  name: database_privilege_escalation
  version: 1.0.0
  enabled: true

detection:
  event_types:
    - FAILED_LOGIN
    - PRELOGIN_INVALID
  threshold: 2  # Very low - database auth failures are critical
  time_window_minutes: 120
  confidence: high

  patterns:
    - regex: "(?i).*sa.*login.*failed.*"
      description: "SA account bruteforce"
      severity: critical

    - regex: "(?i).*sysadmin.*denied.*"
      description: "Sysadmin privilege escalation"
      severity: critical

    - regex: "(?i).*exec.*master.*"
      description: "Master database access attempt"
      severity: high

aggregation:
  group_by: source_ip

output:
  reason_template: "DATABASE SECURITY: {pattern_description} from {ip}"
```

### Web Application (Apache/Nginx)

**Custom Rules**:

```yaml
# rules/detectors/web_application_attacks.yaml
detectors:
  - metadata:
      name: directory_traversal
      version: 1.0.0
      enabled: true

    detection:
      event_types:
        - PORT_SCAN
      threshold: 3
      time_window_minutes: 30
      confidence: high

      patterns:
        - regex: "(?i).*\\.\\./.*"
        - regex: "(?i).*/etc/passwd.*"
        - regex: "(?i).*/proc/self.*"
        - regex: "(?i).*\\\\windows\\\\system32.*"

    aggregation:
      group_by: source_ip

    output:
      reason_template: "Directory traversal attack - {event_count} attempts"

  - metadata:
      name: file_upload_exploit
      version: 1.0.0
      enabled: true

    detection:
      event_types:
        - PORT_SCAN
      threshold: 5
      time_window_minutes: 60
      confidence: medium

      patterns:
        - regex: "(?i).*\\.php.*uploads.*"
        - regex: "(?i).*\\.jsp.*upload.*"
        - regex: "(?i).*shell\\..*"
        - regex: "(?i).*webshell.*"

    aggregation:
      group_by: source_ip

    output:
      reason_template: "File upload exploit attempt - {event_count} suspicious uploads"
```

### SSH Server

**Custom Rules**:

```yaml
# rules/detectors/ssh_advanced_attacks.yaml
detectors:
  - metadata:
      name: ssh_user_enumeration
      version: 1.0.0
      enabled: true

    detection:
      event_types:
        - FAILED_LOGIN
      threshold: 8
      time_window_minutes: 15
      confidence: medium

      patterns:
        - regex: "(?i).*sshd.*invalid user.*"
        - regex: "(?i).*sshd.*user.*not exist.*"

    aggregation:
      group_by: source_ip

    output:
      reason_template: "SSH user enumeration - {event_count} invalid users"

  - metadata:
      name: ssh_password_spray
      version: 1.0.0
      enabled: true

    detection:
      event_types:
        - FAILED_LOGIN
      threshold: 20
      time_window_minutes: 120  # Longer window for slow attacks
      confidence: high

      patterns:
        - regex: "(?i).*sshd.*failed.*password.*"

    aggregation:
      group_by: source_ip

    output:
      reason_template: "SSH password spray attack - {event_count} attempts"
```

---

## False Positive Analysis

### Identifying False Positives

**1. Review recent blocks**:
```bash
# Last 24 hours
tribanft --show-blacklist | tail -50
```

**2. Check IP reputation**:
```bash
# For each suspicious IP
tribanft --ip-info 1.2.3.4

# Manual check
whois 1.2.3.4
curl -s "https://www.abuseipdb.com/check/1.2.3.4"
```

**3. Analyze detection reason**:
```bash
sudo journalctl -u tribanft | \
  grep "Blacklisted 1.2.3.4"
# Check if reason makes sense for your environment
```

### Common False Positives

| Scenario | Cause | Solution |
|----------|-------|----------|
| **Monitoring Tools** | Health checks trigger failed logins | Whitelist monitoring IPs |
| **Backup Systems** | Backup authentication attempts | Whitelist backup servers |
| **Load Balancers** | Connection probes | Whitelist LB IPs |
| **CDN/WAF** | Origin checks | Whitelist CDN ranges |
| **Internal Services** | Service restarts cause auth bursts | Increase threshold or whitelist |
| **API Clients** | Retry logic | Extend time window |

### Whitelist Management

**Add to whitelist**:
```bash
# Single IP
tribanft --whitelist-add 10.0.0.5 --reason "Monitoring server - Zabbix"

# CIDR range
tribanft --whitelist-add 10.0.0.0/24 --reason "Internal network"

# Verify
tribanft --show-whitelist
```

**Whitelist best practices**:
- Document reason for each entry
- Review whitelist monthly
- Use CIDR ranges for networks
- Don't whitelist public IPs unless necessary

---

## Performance Monitoring

### Resource Usage

**Check CPU/Memory**:
```bash
# Real-time monitoring
top -p $(pgrep -f tribanft)

# Historical data
pidstat -r -p $(pgrep -f tribanft) 1 10
```

**Log processing performance**:
```bash
# Time detection cycle
sudo journalctl -u tribanft | \
  grep "Starting advanced brute force detection" -A 30 | \
  grep "detection found" | \
  tail -20
```

### Optimization Tips

**If CPU usage high (>10%)**:

1. **Reduce pattern complexity**:
   - Simplify regex patterns
   - Avoid backtracking: `.*?` instead of `.*`
   - Test patterns at regex101.com

2. **Optimize log parsing**:
   - Reduce `max_lines` if set
   - Use more specific parsers

3. **Disable unused rules**:
   ```yaml
   metadata:
     enabled: false  # Disable rule
   ```

4. **Increase detection interval**:
   ```ini
   # config.conf
   [detection]
   detection_interval_seconds = 600  # Less frequent
   ```

**If memory usage high (>500MB)**:

1. **Reduce event retention**:
   ```python
   # Shorter time windows
   time_window_minutes: 30  # Instead of 1440
   ```

2. **Clear old state**:
   ```bash
   rm ~/.local/share/tribanft/state.json
   sudo systemctl restart tribanft
   ```

3. **Use database backend** (more efficient for large datasets):
   ```ini
   [storage]
   use_database = true
   ```

---

## Best Practices

### Tuning Workflow

**Week 1-2: Learning Mode**
```ini
# config.conf
[features]
enable_nftables_integration = false  # Monitor only
```
- Collect baseline
- Identify false positives
- Adjust thresholds

**Week 3-4: Testing Mode**
```ini
[features]
enable_nftables_integration = true   # Block enabled
```
- Monitor blocks closely
- Fine-tune based on feedback
- Whitelist legitimate IPs

**Week 5+: Production Mode**
- Regular monitoring (daily check)
- Monthly whitelist review
- Quarterly threshold review

### Documentation

**Keep records**:
```bash
# Log all changes
echo "$(date): Increased SQL injection threshold to 7" >> ~/tribanft_tuning.log
echo "$(date): Whitelisted 10.0.0.5 (monitoring)" >> ~/tribanft_tuning.log
```

**Track metrics**:
```bash
# Weekly report
cat > ~/tribanft_weekly_report.sh << 'EOF'
#!/bin/bash
WEEK=$(date +%Y-W%V)
REPORT=~/tribanft_reports/report_$WEEK.txt

mkdir -p ~/tribanft_reports

echo "TribanFT Weekly Report - Week $WEEK" > $REPORT
echo "Generated: $(date)" >> $REPORT
echo >> $REPORT

echo "=== Detections ===" >> $REPORT
sudo journalctl -u tribanft --since "7 days ago" | \
  grep -c "Blacklisted" >> $REPORT

echo "=== Top Rules ===" >> $REPORT
sudo journalctl -u tribanft --since "7 days ago" | \
  grep "Blacklisted" | \
  sed 's/.*(\(.*\):.*)/\1/' | \
  sort | uniq -c | sort -rn | head -5 >> $REPORT

echo >> $REPORT
echo "=== Top Blocked IPs ===" >> $REPORT
sudo journalctl -u tribanft --since "7 days ago" | \
  grep "Blacklisted" | \
  awk '{print $9}' | \
  sort | uniq -c | sort -rn | head -10 >> $REPORT

cat $REPORT
EOF

chmod +x ~/tribanft_weekly_report.sh
```

### Testing Changes

**Before applying threshold changes**:

1. **Test with historical data**:
   ```bash
   # Simulate with old logs
   grep "SecurityEvent" tribanft.log | \
     # Apply new threshold mentally
     # Count would-be detections
   ```

2. **A/B test**:
   - Keep backup of working config
   - Apply changes during low-traffic period
   - Monitor for 24 hours
   - Rollback if issues

3. **Document results**:
   ```bash
   echo "Tested threshold=15, resulted in 20% fewer FPs" >> tuning.log
   ```

---

## Quick Reference

### Monitoring Commands

```bash
# Live monitoring
sudo journalctl -u tribanft -f | grep --color=auto detection

# Today's detections
sudo journalctl -u tribanft --since today | grep "Blacklisted" | wc -l

# Top detected IPs this week
sudo journalctl -u tribanft --since "7 days ago" | \
  grep "Blacklisted" | awk '{print $9}' | sort | uniq -c | sort -rn | head -10

# Rule performance
sudo journalctl -u tribanft --since today | \
  grep "Rule.*found.*detection" | sed "s/.*Rule '\([^']*\)'.*/\1/" | \
  sort | uniq -c | sort -rn
```

### Quick Threshold Changes

```bash
# Edit rule
vim ~/.local/share/tribanft/bruteforce_detector/rules/detectors/my_rule.yaml

# Change threshold
threshold: 15  →  threshold: 20

# Restart
sudo systemctl restart tribanft

# Monitor
sudo journalctl -u tribanft -f
```

---

**Need help tuning?** Check RULE_SYNTAX.md for pattern examples or PLUGIN_DEVELOPMENT.md for custom detectors.
