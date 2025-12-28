# TribanFT Deployment Guide

---

## Installation

```bash
# On server
cd ~
wget https://github.com/n0tjohnny/tribanft/archive/v2.9.0.tar.gz
tar -xzf v2.9.0.tar.gz
cd tribanft-2.9.0
./install.sh
```

Done. The script handles everything automatically.

**v2.9.0+ Directory Organization**: On first startup, the system automatically migrates to organized subdirectories (`data/`, `state/`, `cache/`, `logs/`, `backups/`). A full backup is created before migration.

---

## Start Service

```bash
sudo systemctl enable --now tribanft
sudo journalctl -u tribanft -f
```

Default config runs in **learning mode** (no blocking) for Week 1.

---

## Week 2: Tune & Enable Blocking

**Config location:** `~/.local/share/tribanft/config.conf`

```bash
# Review detections from Week 1
~/.local/share/tribanft/scripts/analyze_and_tune.sh 7

# Whitelist legitimate IPs
tribanft --whitelist-add 10.0.0.5 --reason "Monitoring server"

# Setup NFTables
sudo ~/.local/share/tribanft/scripts/setup_nftables.sh

# Enable blocking (edit config file)
sed -i 's/enable_nftables_update = false/enable_nftables_update = true/' \
    ~/.local/share/tribanft/config.conf

sudo systemctl restart tribanft
```

---

## Monitoring

```bash
# Daily
tribanft --show-blacklist | tail -20

# Weekly
~/.local/share/tribanft/scripts/analyze_and_tune.sh 7

# Logs
sudo journalctl -u tribanft -f
```

---

## Rollback

```bash
# Emergency rollback
sudo systemctl stop tribanft
cd ~/.local/share/tribanft
rm -rf bruteforce_detector
mv bruteforce_detector.old.* bruteforce_detector
sudo systemctl start tribanft

# Disable blocking only
sed -i 's/enable_nftables_update = true/enable_nftables_update = false/' \
    ~/.local/share/tribanft/config.conf
sudo systemctl restart tribanft
```

---

## Troubleshooting

```bash
# Check service status
sudo journalctl -u tribanft -n 50

# Reinstall dependencies
pip3 install --user pyyaml pydantic pydantic-settings watchdog

# Verify NFTables
sudo ~/.local/share/tribanft/scripts/setup_nftables.sh
```

### NFTables Failure Handling (v2.8.0)

TribanFT now handles NFTables failures gracefully:
- Blacklist storage always updated successfully
- NFTables sync failures logged with clear error messages
- Manual sync available: tribanft --sync-files
- Check logs: journalctl -u tribanft | grep -i nftables
- Graceful degradation prevents data loss

Recovery from NFTables failures:
```bash
# View current blacklist state
tribanft --show-blacklist

# Manual sync to firewall
tribanft --sync-files

# Verify NFTables state
sudo nft list set inet filter blacklist_ipv4
```

---

## Commands

```bash
# Service
sudo systemctl start|stop|restart|status tribanft
sudo journalctl -u tribanft -f

# Management
tribanft --show-blacklist
tribanft --whitelist-add 10.0.0.5 --reason "Description"

# Config
vim ~/.local/share/tribanft/config.conf
```
