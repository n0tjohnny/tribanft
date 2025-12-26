# TribanFT Deployment Guide

Automated deployment for TribanFT v2.5.9

---

## Installation

```bash
# On server
cd ~
wget https://github.com/n0tjohnny/tribanft/archive/v2.5.9.tar.gz
tar -xzf v2.5.9.tar.gz
cd tribanft-2.5.9
./install.sh
```

Done. The script handles everything automatically.

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
