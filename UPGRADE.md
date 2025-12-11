# TribanFT Upgrade Guide

## Upgrading to Path-Flexible Architecture

This guide covers upgrading from legacy hardcoded paths (`/root/`, `/var/lib/tribanft`) to the new XDG Base Directory compliant architecture.

---

## What Changed

### Path System

**Before:**
```
/root/blacklist_ipv4.txt
/root/blacklist_ipv6.txt
/root/whitelist_ips.txt
/root/manual_blacklist.txt
/var/lib/tribanft/state.json
/var/lib/tribanft/blacklist.db
```

**After (XDG Default):**
```
~/.local/share/tribanft/blacklist_ipv4.txt
~/.local/share/tribanft/blacklist_ipv6.txt
~/.local/share/tribanft/whitelist_ips.txt
~/.local/share/tribanft/manual_blacklist.txt
~/.local/state/tribanft/state.json
~/.local/state/tribanft/blacklist.db
~/.local/state/tribanft/backups/  (new)
~/.config/tribanft/  (new, for future config files)
```

### New Features

1. **XDG Base Directory Compliance**
   - Config: `$XDG_CONFIG_HOME/tribanft` (default: `~/.config/tribanft`)
   - Data: `$XDG_DATA_HOME/tribanft` (default: `~/.local/share/tribanft`)
   - State: `$XDG_STATE_HOME/tribanft` (default: `~/.local/state/tribanft`)

2. **Environment Variable Overrides**
   - `TRIBANFT_DATA_DIR` - Override data directory
   - `TRIBANFT_CONFIG_DIR` - Override config directory
   - `TRIBANFT_STATE_DIR` - Override state directory

3. **Rotating Backups**
   - Automatic backup before every file write
   - Timestamp-based backup files
   - Retention policy: 7 days (configurable)
   - Minimum 5 backups kept (configurable)

4. **Integrity Verification**
   - `--verify` command to check file integrity
   - Automatic startup checks
   - Corruption detection and recovery

5. **Atomic Writes**
   - Write-to-temp-then-rename pattern
   - Prevents partial file corruption
   - File locking for concurrent access

---

## Upgrade Procedures

### Option 1: Fresh Install (Recommended for New Systems)

If this is a new deployment or you're okay starting fresh:

```bash
# 1. Install updated version
cd /path/to/tribanft
git pull
pip install -e .

# 2. Run tribanft (will auto-create directories)
tribanft --detect

# 3. Verify paths
python3 -c "from bruteforce_detector.config import get_config; c = get_config(); print('Data:', c.data_dir); print('State:', c.state_dir)"
```

### Option 2: Migrate Existing Data

To migrate from legacy paths to XDG paths:

**Step 1: Backup Current Data**
```bash
# Create backup directory
mkdir -p ~/tribanft-backup-$(date +%Y%m%d)

# Backup existing files
cp /root/blacklist_ipv4.txt ~/tribanft-backup-$(date +%Y%m%d)/ 2>/dev/null || true
cp /root/blacklist_ipv6.txt ~/tribanft-backup-$(date +%Y%m%d)/ 2>/dev/null || true
cp /root/whitelist_ips.txt ~/tribanft-backup-$(date +%Y%m%d)/ 2>/dev/null || true
cp /root/manual_blacklist.txt ~/tribanft-backup-$(date +%Y%m%d)/ 2>/dev/null || true
cp /var/lib/tribanft/state.json ~/tribanft-backup-$(date +%Y%m%d)/ 2>/dev/null || true
cp /var/lib/tribanft/blacklist.db ~/tribanft-backup-$(date +%Y%m%d)/ 2>/dev/null || true
```

**Step 2: Install Updated Version**
```bash
cd /path/to/tribanft
git pull
pip install -e .
```

**Step 3: Run Setup (Creates New Directories)**
```bash
# This will create XDG directories automatically
python3 -c "from bruteforce_detector.config import get_config; get_config()"

# Verify directories created
ls -la ~/.local/share/tribanft
ls -la ~/.local/state/tribanft
```

**Step 4: Copy Data to New Locations**
```bash
# Get new paths
DATA_DIR=$(python3 -c "from bruteforce_detector.config import get_config; print(get_config().data_dir)")
STATE_DIR=$(python3 -c "from bruteforce_detector.config import get_config; print(get_config().state_dir)")

# Copy data files
cp /root/blacklist_ipv4.txt "$DATA_DIR/" 2>/dev/null || true
cp /root/blacklist_ipv6.txt "$DATA_DIR/" 2>/dev/null || true
cp /root/whitelist_ips.txt "$DATA_DIR/" 2>/dev/null || true
cp /root/manual_blacklist.txt "$DATA_DIR/" 2>/dev/null || true

# Copy state files
cp /var/lib/tribanft/state.json "$STATE_DIR/" 2>/dev/null || true
cp /var/lib/tribanft/blacklist.db "$STATE_DIR/" 2>/dev/null || true
```

**Step 5: Verify Migration**
```bash
# Run integrity check
tribanft --verify

# Check that data is accessible
tribanft --show-blacklist | head -20
```

**Step 6: Update Cron Jobs**

If you have cron jobs running tribanft:

```bash
# Edit crontab
crontab -e

# Update log paths (if using file logging)
# Old: >> /var/log/tribanft.log 2>&1
# New: Logs now go to $STATE_DIR/tribanft.log automatically
# Or redirect to custom location:
# >> /path/to/logs/tribanft.log 2>&1
```

### Option 3: Continue Using Legacy Paths

The new version supports legacy paths for backward compatibility:

```bash
# Set environment variable to use old locations
export TRIBANFT_DATA_DIR=/root
export TRIBANFT_STATE_DIR=/var/lib/tribanft

# Run as before
tribanft --detect
```

**Note:** You'll see deprecation warnings, but functionality remains the same.

---

## Environment Variable Configuration

### Basic Configuration

Set these in your shell profile (`~/.bashrc`, `~/.profile`) or systemd service:

```bash
# Use custom installation directory
export TRIBANFT_DATA_DIR=/opt/tribanft/data
export TRIBANFT_CONFIG_DIR=/etc/tribanft
export TRIBANFT_STATE_DIR=/var/lib/tribanft

# Or use XDG variables
export XDG_DATA_HOME=/opt/xdg/data
export XDG_CONFIG_HOME=/etc/xdg
export XDG_STATE_HOME=/var/lib/xdg
```

### Systemd Service Example

If running as a systemd service:

```ini
[Unit]
Description=TribanFT Threat Detection
After=network.target

[Service]
Type=oneshot
User=tribanft
Group=tribanft
Environment="TRIBANFT_DATA_DIR=/opt/tribanft/data"
Environment="TRIBANFT_STATE_DIR=/var/lib/tribanft"
ExecStart=/usr/local/bin/tribanft --detect
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

### Docker/Container Example

```dockerfile
FROM python:3.11-slim

# Install tribanft
RUN pip install tribanft

# Set paths to container-friendly locations
ENV TRIBANFT_DATA_DIR=/app/data
ENV TRIBANFT_CONFIG_DIR=/app/config
ENV TRIBANFT_STATE_DIR=/app/state

# Create directories
RUN mkdir -p /app/data /app/config /app/state /app/backups

# Run
CMD ["tribanft", "--detect"]
```

---

## New CLI Commands

### Integrity Verification

```bash
# Run full integrity check
tribanft --verify

# Skip automatic verification on startup
tribanft --detect --skip-verify
```

### Backup Management

```bash
# List available backups for a file
tribanft --list-backups blacklist_ipv4.txt

# Restore from specific backup
tribanft --restore-backup /path/to/backup/blacklist_ipv4_20231211_143052.backup \
         --restore-target ~/.local/share/tribanft/blacklist_ipv4.txt
```

---

## Configuration File Support

### Backup Retention Settings

Add to environment or `.env` file:

```bash
# Days to retain backups
BFD_BACKUP_RETENTION_DAYS=7

# Minimum backups to keep regardless of age
BFD_BACKUP_MIN_KEEP=5
```

---

## Troubleshooting

### Issue: "Permission denied" errors

**Solution:** Check directory permissions

```bash
# Fix ownership
chown -R $(whoami):$(whoami) ~/.local/share/tribanft
chown -R $(whoami):$(whoami) ~/.local/state/tribanft

# Fix permissions
chmod -R 755 ~/.local/share/tribanft
chmod -R 755 ~/.local/state/tribanft
```

### Issue: Can't find old data

**Solution:** Legacy paths are checked automatically

If `/root/blacklist_ipv4.txt` exists and is accessible, it will be used automatically with a deprecation warning. To migrate:

```bash
# Copy to new location
cp /root/blacklist_ipv4.txt ~/.local/share/tribanft/
```

### Issue: Backups filling up disk

**Solution:** Adjust retention policy

```bash
# Reduce retention period
export BFD_BACKUP_RETENTION_DAYS=3
export BFD_BACKUP_MIN_KEEP=3

# Or manually clean old backups
cd ~/.local/state/tribanft/backups
find . -name "*.backup" -mtime +7 -delete
```

### Issue: Want to use old paths permanently

**Solution:** Set environment variables

```bash
# Add to ~/.bashrc or systemd service
export TRIBANFT_DATA_DIR=/root
export TRIBANFT_STATE_DIR=/var/lib/tribanft
```

---

## Rollback Procedure

If you need to rollback to the previous version:

**Step 1: Restore Old Version**
```bash
cd /path/to/tribanft
git checkout <previous-commit>
pip install -e .
```

**Step 2: Restore Data (if migrated)**
```bash
# If you kept backups in ~/tribanft-backup-*
cp ~/tribanft-backup-*/blacklist_ipv4.txt /root/
cp ~/tribanft-backup-*/blacklist_ipv6.txt /root/
# ... etc
```

---

## Migration Checklist

- [ ] Backup current data files
- [ ] Install updated version
- [ ] Verify new directory structure created
- [ ] Copy data to new locations (if migrating)
- [ ] Run integrity check (`--verify`)
- [ ] Test blacklist display (`--show-blacklist`)
- [ ] Update cron jobs / systemd services
- [ ] Update any scripts that reference paths
- [ ] Monitor logs for deprecation warnings
- [ ] Document custom configuration (environment variables)

---

## Support

If you encounter issues during upgrade:

1. Check logs: `tail -f ~/.local/state/tribanft/tribanft.log`
2. Run integrity check: `tribanft --verify`
3. Review backup files: `tribanft --list-backups blacklist_ipv4.txt`
4. Open GitHub issue with details

---

## Benefits of Upgrading

1. **Flexible Deployment** - Run as non-root user
2. **Multi-User Support** - Each user has own blacklist
3. **Container Ready** - Easy Docker/Kubernetes deployment
4. **Data Safety** - Automatic rotating backups
5. **Corruption Protection** - Atomic writes + integrity checks
6. **Better Organization** - XDG-compliant directory structure
7. **Easier Testing** - Test in user directory without root access

---

Last Updated: 2025-12-11
