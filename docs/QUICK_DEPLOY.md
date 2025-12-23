# TribanFT Phase 1 & 2 - Quick Deployment Guide

**Complete plugin system and YAML rule engine implementation**

---

## FROM YOUR LOCAL MACHINE

### 1. Create deployment package

```bash
cd /home/jc/Documents/projetos/tribanft

tar -czf tribanft-phase1-2.tar.gz \
    --exclude='*.pyc' \
    --exclude='__pycache__' \
    --exclude='.git' \
    --exclude='*.backup' \
    bruteforce_detector/ \
    scripts/ \
    *.md
```

### 2. Copy to your server

```bash
scp tribanft-phase1-2.tar.gz user@your-server:~/
scp DEPLOYMENT_GUIDE.md user@your-server:~/
scp PHASE_1_2_SUMMARY.md user@your-server:~/
```

---

## ON YOUR REMOTE SERVER

### 3. Stop TribanFT

```bash
sudo systemctl stop tribanft
```

### 4. Backup current installation

```bash
cd ~/.local/share/tribanft
tar -czf ~/tribanft_backup_$(date +%Y%m%d).tar.gz .
```

### 5. Extract new code

```bash
cd ~
tar -xzf tribanft-phase1-2.tar.gz

# Deploy to installation directory
cp -r bruteforce_detector ~/.local/share/tribanft/
cp -r scripts ~/.local/share/tribanft/
chmod +x ~/.local/share/tribanft/scripts/*.sh
```

### 6. Install PyYAML dependency

```bash
pip3 install --user pyyaml
```

### 7. Update configuration

```bash
vim ~/.local/share/tribanft/config.conf
```

Add this section:

```ini
[plugins]
enable_plugin_system = true
enable_yaml_rules = true
detector_plugin_dir = ~/.local/share/tribanft/bruteforce_detector/plugins/detectors
parser_plugin_dir = ~/.local/share/tribanft/bruteforce_detector/plugins/parsers
rules_dir = ~/.local/share/tribanft/bruteforce_detector/rules
```

### 8. IMPORTANT - Start in LEARNING MODE (no blocking)

In `config.conf`, set:

```ini
[features]
enable_nftables_integration = false  # Monitor only, don't block yet
```

### 9. Validate installation

```bash
python3 -c "
from bruteforce_detector.core.plugin_manager import PluginManager
from bruteforce_detector.core.rule_engine import RuleEngine
print('✓ Installation validated')
"

# Validate YAML rules
for f in ~/.local/share/tribanft/bruteforce_detector/rules/detectors/*.yaml; do
    python3 -c "import yaml; yaml.safe_load(open('$f'))" && \
        echo "✓ $(basename $f)" || echo "✗ $(basename $f) ERROR"
done
```

### 10. Start TribanFT

```bash
sudo systemctl start tribanft

# Watch logs
sudo journalctl -u tribanft -f
```

You should see:
```
✓ Loaded plugin: prelogin_detector v1.0.0
✓ Loaded plugin: failed_login_detector v1.0.0
✓ Loaded plugin: port_scan_detector v1.0.0
✓ Loaded plugin: crowdsec_detector v1.0.0
✓ Loaded rule: sql_injection_detector v1.0.0
✓ Loaded rule: rdp_bruteforce_detector v1.0.0
✓ YAML Rule Engine: Loaded X/X rules
```

---

## LEARNING MODE (Week 1)

### 11. Monitor for 7 days without blocking

```bash
# Daily check
~/.local/share/tribanft/scripts/analyze_and_tune.sh 1

# After 7 days, full analysis
~/.local/share/tribanft/scripts/analyze_and_tune.sh 7
```

### 12. Review detections and tune thresholds

```bash
# Edit YAML rules
vim ~/.local/share/tribanft/bruteforce_detector/rules/detectors/sql_injection.yaml

# Adjust threshold based on analysis
# Restart after changes
sudo systemctl restart tribanft
```

---

## PRODUCTION MODE (Week 2+)

### 13. After tuning is complete, enable blocking

```bash
vim ~/.local/share/tribanft/config.conf
```

```ini
[features]
enable_nftables_integration = true
```

```bash
sudo systemctl restart tribanft
```

### 14. Verify NFTables rules

```bash
sudo nft list ruleset | grep -A 10 "set tribanft"
```

---

## DOCUMENTATION

| Document | Purpose |
|----------|---------|
| **DEPLOYMENT_GUIDE.md** | Complete deployment procedures |
| **PHASE_1_2_SUMMARY.md** | What was implemented and how to use it |
| **PLUGIN_DEVELOPMENT.md** | Creating custom detector/parser plugins |
| **RULE_SYNTAX.md** | YAML rule syntax reference |
| **MONITORING_AND_TUNING.md** | Log monitoring and threshold optimization |

---

## QUICK COMMANDS

### Service management
```bash
sudo systemctl status tribanft
sudo systemctl restart tribanft
```

### View logs
```bash
sudo journalctl -u tribanft -f
sudo journalctl -u tribanft --since today
```

### Analysis
```bash
~/.local/share/tribanft/scripts/analyze_and_tune.sh 7
```

### Blacklist management
```bash
tribanft --show-blacklist
tribanft --ip-info 1.2.3.4
tribanft --whitelist-add 1.2.3.4 --reason "Monitoring server"
```

### Edit rules
```bash
vim ~/.local/share/tribanft/bruteforce_detector/rules/detectors/*.yaml
```

---

## ROLLBACK (if needed)

```bash
sudo systemctl stop tribanft
cd ~/.local/share/tribanft
rm -rf bruteforce_detector scripts
tar -xzf ~/tribanft_backup_YYYYMMDD.tar.gz
sudo systemctl start tribanft
```

---

## WHAT'S NEW

### Phase 1 - Plugin System
- Auto-discovery of detector and parser plugins
- No code changes needed to add new detectors
- Drop-in plugin architecture
- Metadata-driven plugin management

### Phase 2 - YAML Rule Engine
- Define detection rules without coding
- Regex pattern matching
- Configurable thresholds per rule
- Multi-rule YAML files
- 5 example rule files included

### Monitoring & Tuning
- Automated log analysis script
- Threshold tuning recommendations
- False positive detection
- Environment-specific examples (8 scenarios)
- 800+ pages of documentation

---

**License**: GNU GPL v3
**Author**: TribanFT Project
