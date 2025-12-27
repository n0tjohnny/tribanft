# TribanFT Real-Time Service Fix - Testing Guide

## What Was Fixed

1. **Config Sync Utility**: Automatically merges new options from `config.conf.template` to your active config
2. **Diagnostic Tool**: `tools/diagnose-realtime.py` to identify real-time service issues
3. **Watchdog Library**: Installed (required for real-time log monitoring)

## Commands to Run (as root)

### Step 1: Run Diagnostic

```bash
cd /root/tribanft
python3 tools/diagnose-realtime.py
```

**Expected Output:**
- ✓ Watchdog library installed
- ✓ At least 1 monitored log file exists (syslog or mssql)
- ✓ Detectors enabled
- ✓ Service running

### Step 2: Test Config Sync

Config sync now runs automatically on service startup. To test manually:

```bash
# Verify [threat_intelligence] section is missing
grep -A5 '^\[threat_intelligence\]' ~/.local/share/tribanft/config.conf

# If missing, restart service (triggers auto-sync)
systemctl restart tribanft.service

# Check logs for sync message
journalctl -u tribanft.service | grep -i "CONFIG AUTO-SYNC"

# Verify section was added
grep -A5 '^\[threat_intelligence\]' ~/.local/share/tribanft/config.conf
```

### Step 3: Verify Real-Time Monitoring Started

```bash
# Check service logs for real-time initialization
journalctl -u tribanft.service --since "5 minutes ago" | grep -i realtime

# Should see messages like:
#   "Real-time monitoring initialized successfully"
#   "Monitoring X log file(s)"
```

### Step 4: Test Real-Time Detection (Critical!)

Open two terminals as root:

**Terminal 1 - Monitor logs:**
```bash
journalctl -u tribanft.service -f
```

**Terminal 2 - Trigger test event:**
```bash
# Test SSH failed login detection
logger -p auth.info "Failed password for invalid user testuser from 192.0.2.99 port 22 ssh2"

# OR test MSSQL prelogin detection (if MSSQL log exists)
logger -p local0.info "Login failed for user 'sa'. Reason: Could not find a login matching the name provided. [CLIENT: 192.0.2.88]"
```

**What to Look For in Terminal 1:**
```
REALTIME: Processing syslog offset 12345→12456
REALTIME: Parsed 1 new events from syslog
REALTIME DETECTION: 1 malicious IPs detected!
  → 192.0.2.99 (FAILED_LOGIN)
SECURITY ALERT: Detected 1 new malicious IPs
```

### Step 5: Verify IP Was Blacklisted

```bash
# Check blacklist file
grep "192.0.2.99" ~/.local/share/tribanft/blacklist_ipv4.txt

# Should show entry with timestamp
```

### Step 6: Verify NFTables Sync (if enabled)

```bash
# Check if IP was added to NFTables
nft list set inet filter blacklist_ipv4 | grep "192.0.2.99"
```

## Troubleshooting

### If diagnostic shows "No log files available"

Check which log files exist:
```bash
ls -lh /var/log/syslog        # Ubuntu/Debian syslog
ls -lh /var/log/messages      # RedHat/CentOS syslog
ls -lh /var/opt/mssql/log/errorlog  # MSSQL log
```

Update config if needed:
```bash
nano ~/.local/share/tribanft/config.conf
# Edit [logs] section to point to correct paths
# Then restart: systemctl restart tribanft.service
```

### If real-time not working after fix

1. Check watchdog is available:
```bash
python3 -c "from watchdog.observers import Observer; print('OK')"
```

2. Check config has realtime section:
```bash
grep -A10 '^\[realtime\]' ~/.local/share/tribanft/config.conf
```

3. Check for errors in logs:
```bash
journalctl -u tribanft.service --since "10 minutes ago" | grep -i error
```

4. Re-run diagnostic:
```bash
cd /root/tribanft
python3 tools/diagnose-realtime.py
```

### If service fails to start

```bash
# Check service status
systemctl status tribanft.service

# View recent logs
journalctl -u tribanft.service --since "10 minutes ago" -n 50

# Check config syntax
python3 -c "from bruteforce_detector.config import get_config; get_config()"
```

## Rollback Instructions

If issues occur, restore from automatic backup:

```bash
# List backups
ls -lh ~/.local/share/tribanft/config.conf.backup-*

# Restore most recent backup
cp ~/.local/share/tribanft/config.conf.backup-YYYYMMDD-HHMMSS \
   ~/.local/share/tribanft/config.conf

# Restart service
systemctl restart tribanft.service
```

## Security Verification

All security invariants preserved:

1. **Whitelist precedence**: Whitelisted IPs never blocked
2. **Atomic operations**: Blacklist updates are atomic
3. **Thread safety**: Proper locking in place
4. **Input validation**: All IPs validated
5. **No assumptions**: Explicit checks everywhere

Test whitelist precedence:
```bash
# Add test IP to whitelist
echo "192.0.2.100" >> ~/.local/share/tribanft/whitelist.txt

# Try to blacklist it (should fail)
logger -p auth.info "Failed password for invalid user test from 192.0.2.100 port 22 ssh2"

# Verify NOT in blacklist
grep "192.0.2.100" ~/.local/share/tribanft/blacklist_ipv4.txt
# (should be empty)

# Cleanup
sed -i '/192.0.2.100/d' ~/.local/share/tribanft/whitelist.txt
```

## Expected Outcomes

✓ Config auto-sync adds `[threat_intelligence]` section (and any other new options)
✓ Real-time monitoring active (messages in logs)
✓ New IPs detected and blacklisted in <2 seconds
✓ All security invariants maintained
✓ Service stable and running

## Files Modified

- `tools/diagnose-realtime.py` - NEW diagnostic tool
- `bruteforce_detector/config_sync.py` - NEW config sync utility
- `bruteforce_detector/config.py` - Added auto-sync call to `get_config()`

## Next Steps

After verification:
1. Monitor service for 24 hours
2. Check blacklist growth: `wc -l ~/.local/share/tribanft/blacklist_ipv4.txt`
3. Review logs for any errors: `journalctl -u tribanft.service --since "1 day ago" | grep -i error`
4. Verify real-time detection latency is <2 seconds

---

**Generated by Claude Code**
**TribanFT v2.6.0 Security Investigation**
