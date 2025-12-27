# TriBANFT v2.5.0 - Phase 2: Shell Scripts & Installation Security Audit

**Audit Date:** 2025-12-25
**Auditor:** Security Analysis (Automated)
**Scope:** All installation scripts, setup utilities, and systemd service definitions
**Files Analyzed:** 7 (5 shell scripts + 2 systemd service files)

---

## EXECUTIVE SUMMARY

This Phase 2 audit examined all shell scripts and systemd service files for security vulnerabilities, error handling gaps, privilege management issues, and portability problems across Linux distributions.

### Critical Findings Summary

- **3 Critical Issues** requiring immediate fixes before stable release
- **6 High Severity Issues** causing installation failures or security risks
- **9 Medium Severity Issues** affecting reliability and portability
- **7 Low Severity Issues** related to code quality and version consistency

### Most Critical Issues

1. **install.sh**: Broken Python version check (undefined variables) - completely non-functional
2. **setup_nftables.sh**: Overwrites entire firewall ruleset - destroys unrelated firewall rules
3. **install-ipinfo-batch-service.sh**: Command injection via `eval` - security vulnerability
4. **tribanft.service**: Wrong ExecStart path - service won't start

---

## DETAILED FINDINGS BY FILE

---

## FILE: install.sh (Main Installation Script - 171 lines)

**Purpose:** Main entry point for TribanFT installation
**Version Shown:** 2.4.1 (should be 2.5.0)

### 1. Broken Python Version Check - CRITICAL
**Location:** Lines 29-32
**Severity:** CRITICAL

**Issue:**
```bash
python_version=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
if [ "$(printf '%s\n' "$REQUIRED" "$PY_VERSION" | sort -V | head -n1)" != "$REQUIRED" ]; then
    echo "[ERROR] Python 3.8+ required (found $PY_VERSION)"
    exit 1
fi
```

**Problem:** Variables `$REQUIRED` and `$PY_VERSION` are never defined. The check always fails or produces unpredictable results.

**Attack Scenario:**
- Users with Python 3.8+ fail installation due to broken version check
- Users with Python 2.x could potentially bypass the check if variables default to empty strings

**Impact:** Installation completely broken. Users cannot install TribanFT even with correct Python version.

**Fix:**
```bash
python_version=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
REQUIRED="3.8"
# Check if Python version is >= 3.8
if [ "$(printf '%s\n' "$REQUIRED" "$python_version" | sort -V | head -n1)" != "$REQUIRED" ]; then
    echo_error "Python 3.8+ required (found $python_version)"
    exit 1
fi
echo_info "Python $python_version OK"
```

---

### 2. Missing pip3 Availability Check - HIGH
**Location:** Line 40
**Severity:** HIGH

**Issue:**
```bash
install_dependencies() {
    echo_info "Installing Python dependencies..."
    pip3 install --user pyyaml pydantic pydantic-settings watchdog
    echo_info "Dependencies installed"
}
```

**Problem:** No check if `pip3` command exists before attempting installation.

**Failure Scenario:**
- On minimal Linux installations, pip3 may not be installed
- Script fails with cryptic "command not found" error
- User sees "Installing Python dependencies..." then immediate crash

**Impact:** Installation fails on systems without pip3, with confusing error message.

**Fix:**
```bash
install_dependencies() {
    echo_info "Installing Python dependencies..."

    if ! command -v pip3 &> /dev/null; then
        echo_error "pip3 not found"
        echo_error "Install with: apt-get install python3-pip (Debian/Ubuntu)"
        echo_error "              dnf install python3-pip (Fedora/RHEL)"
        exit 1
    fi

    if ! pip3 install --user pyyaml pydantic pydantic-settings watchdog; then
        echo_error "Failed to install Python dependencies"
        exit 1
    fi

    echo_info "Dependencies installed"
}
```

---

### 3. Unquoted Loop Variables in YAML Validation - MEDIUM
**Location:** Lines 112-123
**Severity:** MEDIUM

**Issue:**
```bash
for f in "$INSTALL_DIR/bruteforce_detector/rules/detectors"/*.yaml; do
    if ! python3 -c "import yaml; yaml.safe_load(open('$f'))" 2>/dev/null; then
        echo_error "Invalid YAML: $(basename "$f")"
        exit 1
    fi
done
```

**Problem:** Variable `$f` used inside single-quoted Python string without proper escaping. Will break if filenames contain special characters.

**Failure Scenario:**
- YAML file with space in name: `detection rules.yaml`
- Python sees: `yaml.safe_load(open('...bruteforce_detector/rules/detectors/detection rules.yaml'))`
- Python interprets as syntax error

**Impact:** Validation fails for valid YAML files with spaces in filenames.

**Fix:**
```bash
for f in "$INSTALL_DIR/bruteforce_detector/rules/detectors"/*.yaml; do
    if ! python3 -c "import yaml; yaml.safe_load(open('''$f'''))" 2>/dev/null; then
        echo_error "Invalid YAML: $(basename "$f")"
        exit 1
    fi
done
```

---

### 4. Missing Error Handling Directives - MEDIUM
**Location:** Line 5
**Severity:** MEDIUM

**Issue:**
```bash
set -e
```

**Problem:** Only `set -e` is used. Missing `set -u` (undefined variables) and `set -o pipefail` (pipe failures).

**Failure Scenario:**
- Piped commands like `cmd1 | cmd2` where cmd1 fails but cmd2 succeeds - script continues
- Typo in variable name uses empty string instead of failing

**Impact:** Silent failures in edge cases. Given the undefined variable bug (issue #1), adding `set -u` would have caught it immediately.

**Fix:**
```bash
set -euo pipefail
```

---

### 5. No sudo Availability Check - MEDIUM
**Location:** Line 138
**Severity:** MEDIUM

**Issue:**
```bash
sudo cp "$INSTALL_DIR/systemd/tribanft.service" /etc/systemd/system/
```

**Problem:** Assumes `sudo` is available and user has sudo privileges.

**Failure Scenario:**
- User runs script on system without sudo
- User doesn't have sudo privileges
- Script fails with unclear error

**Impact:** Confusing error message, unclear fix for users.

**Fix:**
```bash
setup_systemd() {
    if [ ! -d "$INSTALL_DIR/systemd" ]; then
        echo_warn "systemd directory not found, skipping service setup"
        return
    fi

    echo_info "Setting up systemd service..."

    if [ "$EUID" -ne 0 ]; then
        if ! command -v sudo &> /dev/null; then
            echo_error "sudo not available and not running as root"
            echo_info "Manually copy: $INSTALL_DIR/systemd/tribanft.service to /etc/systemd/system/"
            return
        fi
        SUDO_CMD="sudo"
    else
        SUDO_CMD=""
    fi

    $SUDO_CMD cp "$INSTALL_DIR/systemd/tribanft.service" /etc/systemd/system/
    $SUDO_CMD systemctl daemon-reload

    echo_info "Systemd service installed"
}
```

---

### 6. Version Mismatch - LOW
**Location:** Line 3, 148
**Severity:** LOW

**Issue:** Script shows version 2.4.1 but this is v2.5.0 release.

**Impact:** User confusion about installed version.

**Fix:** Update to `# Version: 2.5.0` and line 148 to `echo_info "TribanFT Installation v2.5.0"`

---

## FILE: scripts/setup-config.sh (Configuration Setup - 135 lines)

**Purpose:** Interactive configuration creation and mode toggling

### 1. sed Operations Without Error Checking - MEDIUM
**Location:** Lines 70-75, 100-104
**Severity:** MEDIUM

**Issue:**
```bash
if [ "$MODE" = "learning" ]; then
    sed -i 's/enable_nftables_update = true/enable_nftables_update = false/' "$CONFIG_FILE"
    echo_info "Learning mode enabled (blocking disabled)"
else
    sed -i 's/enable_nftables_update = false/enable_nftables_update = true/' "$CONFIG_FILE"
    echo_info "Production mode enabled (blocking enabled)"
fi
```

**Problem:**
- `sed -i` modifications have no error checking
- If pattern doesn't match, sed succeeds but makes no changes
- User sees success message but config unchanged

**Failure Scenario:**
- Config file uses different spacing: `enable_nftables_update=true` (no spaces)
- sed pattern doesn't match
- Script reports success but mode not changed
- User enables production thinking blocking is active, but attacks pass through

**Impact:** **Security risk** - users believe they're in production mode with blocking enabled, but blocking is actually disabled.

**Fix:**
```bash
if [ "$MODE" = "learning" ]; then
    if ! grep -q "enable_nftables_update = true" "$CONFIG_FILE"; then
        echo_warn "Config already in learning mode or pattern not found"
    elif ! sed -i 's/enable_nftables_update = true/enable_nftables_update = false/' "$CONFIG_FILE"; then
        echo_error "Failed to modify config file"
        exit 1
    fi
    echo_info "Learning mode enabled (blocking disabled)"
else
    if ! grep -q "enable_nftables_update = false" "$CONFIG_FILE"; then
        echo_warn "Config already in production mode or pattern not found"
    elif ! sed -i 's/enable_nftables_update = false/enable_nftables_update = true/' "$CONFIG_FILE"; then
        echo_error "Failed to modify config file"
        exit 1
    fi
    echo_info "Production mode enabled (blocking enabled)"
fi
```

---

### 2. Fragile Text-Based Mode Toggle - MEDIUM
**Location:** Lines 70-75
**Severity:** MEDIUM

**Issue:** Mode toggle relies on exact text match `enable_nftables_update = true` with specific spacing.

**Problem:**
- If config.conf.template format changes (spacing, comments, etc.), mode toggle silently fails
- No validation that toggle actually worked

**Failure Scenario:**
- Future version changes config to `enable_nftables_update=true` (no spaces)
- Old setup-config.sh can't toggle mode
- User stuck in wrong mode

**Impact:** Silent failures when switching between learning/production modes after config format changes.

**Fix:** Use more robust parsing (grep to verify before/after) or use Python config parser instead of sed.

---

### 3. Missing Error Handling Directives - LOW
**Location:** Line 5
**Severity:** LOW

**Issue:** Only `set -e`, missing `set -u` and `set -o pipefail`.

**Fix:**
```bash
set -euo pipefail
```

---

## FILE: scripts/install-service.sh (Service Installer - 104 lines)

**Purpose:** Convert cron-based execution to systemd service

### 1. Cron Removal Could Fail with Empty Result - HIGH
**Location:** Line 55
**Severity:** HIGH

**Issue:**
```bash
if crontab -l 2>/dev/null | grep -q "tribanft"; then
    echo "Found existing cron job, removing..."
    crontab -l | grep -v "tribanft" | crontab -
    echo_info "Cron job removed"
fi
```

**Problem:** If user has ONLY tribanft in crontab, `grep -v "tribanft"` produces empty output, and `crontab -` with empty stdin could fail or create unexpected behavior on some systems.

**Failure Scenario:**
- User has single cron line: `*/5 * * * * /path/to/tribanft`
- `crontab -l | grep -v "tribanft"` produces empty output
- Some cron implementations reject empty crontab, others clear all cron jobs
- Script may fail at this step

**Impact:** Installation fails or clears user's entire crontab unexpectedly.

**Fix:**
```bash
if crontab -l 2>/dev/null | grep -q "tribanft"; then
    echo "Found existing cron job, removing..."
    TEMP_CRON=$(mktemp)
    crontab -l | grep -v "tribanft" > "$TEMP_CRON" || true
    if [ -s "$TEMP_CRON" ]; then
        # File has content
        crontab "$TEMP_CRON"
    else
        # Empty crontab - explicitly clear it
        crontab -r 2>/dev/null || true
    fi
    rm -f "$TEMP_CRON"
    echo_info "Cron job removed"
fi
```

---

### 2. Hardcoded Root User Path - MEDIUM
**Location:** Lines 34, 40, 42
**Severity:** MEDIUM

**Issue:**
```bash
mkdir -p /root/.local/share/tribanft
```

**Problem:** Hardcodes `/root/.local/share/tribanft`, assuming script runs as root and TribanFT is for root user only.

**Failure Scenario:**
- Organization wants to run TribanFT as non-root user (principle of least privilege)
- Paths hardcoded to /root
- Cannot install for different user without editing script

**Impact:** Forces root execution, prevents running as dedicated service account for security isolation.

**Fix:**
```bash
# Detect installation directory based on user
if [ "$EUID" -eq 0 ]; then
    INSTALL_DIR="/root/.local/share/tribanft"
else
    INSTALL_DIR="${HOME}/.local/share/tribanft"
fi

mkdir -p "$INSTALL_DIR"
```

---

### 3. Missing Error Handling Directives - LOW
**Location:** Line 8
**Severity:** LOW

**Issue:** Only `set -e`, missing `set -u` and `set -o pipefail`.

**Fix:**
```bash
set -euo pipefail
```

---

## FILE: scripts/setup_nftables.sh (NFTables Setup - 138 lines)

**Purpose:** Create required NFTables sets and rules for TribanFT

### 1. Overwrites Entire Firewall Ruleset - CRITICAL
**Location:** Lines 100-113
**Severity:** CRITICAL

**Issue:**
```bash
echo -n "Saving NFTables configuration..."
if [ -d /etc/nftables.d ]; then
    # Debian/Ubuntu style
    nft list ruleset > /etc/nftables.d/tribanft.nft
    echo -e " ${GREEN}Saved to /etc/nftables.d/tribanft.nft${NC}"
elif [ -f /etc/sysconfig/nftables.conf ]; then
    # RHEL/Fedora style
    nft list ruleset > /etc/sysconfig/nftables.conf
    echo -e " ${GREEN}Saved to /etc/sysconfig/nftables.conf${NC}"
else
    # Generic fallback
    nft list ruleset > /etc/nftables.conf
    echo -e " ${GREEN}Saved to /etc/nftables.conf${NC}"
fi
```

**Problem:** `nft list ruleset` dumps **ENTIRE** firewall configuration (all tables, chains, rules) and overwrites system firewall files. This destroys any existing firewall rules unrelated to TribanFT.

**Attack Scenario:**
1. System administrator has existing NFTables rules:
   - SSH rate limiting: `limit rate 10/minute`
   - Port forwarding for internal services
   - Country-based geo-blocking
   - Custom security rules

2. Admin runs `setup_nftables.sh` to add TribanFT sets

3. Script overwrites `/etc/nftables.conf` or `/etc/sysconfig/nftables.conf`

4. On next boot or nftables restart:
   - ALL previous rules are replaced with just TribanFT rules
   - SSH rate limiting gone → brute force attacks succeed
   - Port forwarding gone → services unreachable
   - Geo-blocking gone → international attacks resume

**Impact:** **CATASTROPHIC** - Destroys existing firewall security rules, potentially exposing server to attacks TribanFT was meant to prevent.

**Fix:**
```bash
# Save configuration (TribanFT-specific rules only)
echo -n "Saving NFTables configuration..."
if [ -d /etc/nftables.d ]; then
    # Debian/Ubuntu style - save only TribanFT table
    cat > /etc/nftables.d/tribanft.nft << 'EOF'
#!/usr/sbin/nft -f
# TribanFT Blacklist Sets and Rules
# This file is managed by TribanFT - do not edit manually

table inet filter {
    set blacklist_ipv4 {
        type ipv4_addr
        flags interval
    }

    set blacklist_ipv6 {
        type ipv6_addr
        flags interval
    }

    set port_scanners {
        type ipv4_addr
        flags dynamic, timeout
        timeout 14400m
    }
}
EOF
    echo -e " ${GREEN}Saved to /etc/nftables.d/tribanft.nft${NC}"
    echo -e " ${YELLOW}NOTE: Add 'include \"/etc/nftables.d/tribanft.nft\"' to main nftables config${NC}"
else
    # For systems without nftables.d, provide manual instructions
    echo -e " ${YELLOW}WARNING: Automatic save not possible${NC}"
    echo -e " ${YELLOW}Current NFTables rules are active but not persisted${NC}"
    echo -e " ${YELLOW}To persist, manually add the following to your nftables config:${NC}"
    echo ""
    echo "  table inet filter {"
    echo "      set blacklist_ipv4 { type ipv4_addr; flags interval; }"
    echo "      set blacklist_ipv6 { type ipv6_addr; flags interval; }"
    echo "      set port_scanners { type ipv4_addr; flags dynamic, timeout; timeout 14400m; }"
    echo "  }"
    echo ""
fi
```

---

### 2. Creates Unused port_scanners Set - MEDIUM
**Location:** Lines 47-53
**Severity:** MEDIUM

**Issue:**
```bash
nft add set inet filter port_scanners '{ type ipv4_addr; flags dynamic, timeout; timeout 14400m; }'
```

**Problem:** Script creates `port_scanners` set, but Python code never references it. This is orphaned infrastructure.

**Evidence:** Grepped all Python files - no references to "port_scanners" set. Only blacklist_ipv4 and blacklist_ipv6 are used.

**Impact:**
- Clutters firewall configuration
- Suggests feature planned but not implemented
- Could confuse users/admins

**Fix:** Either remove the set creation, or document that it's reserved for future use.

---

### 3. Missing Error Handling Directives - LOW
**Location:** Line 11
**Severity:** LOW

**Issue:** Only `set -e`, missing `set -u` and `set -o pipefail`.

**Fix:**
```bash
set -euo pipefail
```

---

## FILE: scripts/install-ipinfo-batch-service.sh (Batch Service Installer - 216 lines)

**Purpose:** Install systemd service for IP geolocation batch processing

### 1. Command Injection via eval - CRITICAL
**Location:** Lines 36-63
**Severity:** CRITICAL

**Issue:**
```bash
# Execute Python script and source the output
CONFIG_OUTPUT=$(python3 -c "$PYTHON_SCRIPT" 2>&1)
CONFIG_EXIT_CODE=$?

if [ $CONFIG_EXIT_CODE -ne 0 ]; then
    echo -e "${RED}ERROR: Failed to load config.conf${NC}"
    echo -e "${YELLOW}Error: $CONFIG_OUTPUT${NC}"
    echo -e "${YELLOW}TIP: Run ./setup.sh to create configuration${NC}"
    exit 1
fi

# Parse configuration
eval "$CONFIG_OUTPUT"
```

**Problem:** Uses `eval` to execute Python script output directly. If Python code is compromised or config.py has malicious content, arbitrary commands execute as root.

**Attack Scenario:**
1. Attacker compromises `bruteforce_detector/config.py` (e.g., via supply chain attack, malicious plugin, or local file write vulnerability)

2. Attacker adds malicious code to config.py:
```python
def get_config():
    print('PROJECT_DIR=/tmp/fake; rm -rf /var/lib/tribanft/*; echo "pwned" > /etc/motd')
    # ... rest of config
```

3. Admin runs `sudo ./install-ipinfo-batch-service.sh`

4. Line 63 executes: `eval 'PROJECT_DIR=/tmp/fake; rm -rf /var/lib/tribanft/*; echo "pwned" > /etc/motd'`

5. Arbitrary commands run as root:
   - Deletes all TribanFT data
   - Modifies system files
   - Could install backdoors, exfiltrate data, etc.

**Impact:** Root privilege escalation if any Python file is compromised. Violates principle of least privilege.

**Fix:**
```bash
# Execute Python script and parse output safely
CONFIG_OUTPUT=$(python3 -c "$PYTHON_SCRIPT" 2>&1)
CONFIG_EXIT_CODE=$?

if [ $CONFIG_EXIT_CODE -ne 0 ]; then
    echo -e "${RED}ERROR: Failed to load config.conf${NC}"
    echo -e "${YELLOW}Error: $CONFIG_OUTPUT${NC}"
    echo -e "${YELLOW}TIP: Run ./setup.sh to create configuration${NC}"
    exit 1
fi

# Parse configuration SAFELY (no eval)
PROJECT_DIR=$(echo "$CONFIG_OUTPUT" | grep "^PROJECT_DIR=" | cut -d= -f2)
CONFIG_DIR=$(echo "$CONFIG_OUTPUT" | grep "^CONFIG_DIR=" | cut -d= -f2)
STATE_DIR=$(echo "$CONFIG_OUTPUT" | grep "^STATE_DIR=" | cut -d= -f2)
PYTHON_BIN=$(echo "$CONFIG_OUTPUT" | grep "^PYTHON_BIN=" | cut -d= -f2)

# Validate parsed values
if [ -z "$PROJECT_DIR" ] || [ -z "$CONFIG_DIR" ] || [ -z "$STATE_DIR" ] || [ -z "$PYTHON_BIN" ]; then
    echo -e "${RED}ERROR: Failed to parse configuration${NC}"
    exit 1
fi
```

---

### 2. Non-Atomic Token File Writes - HIGH
**Location:** Lines 139, 147
**Severity:** HIGH

**Issue:**
```bash
echo "$TOKEN" > "$TOKEN_FILE"
chmod 600 "$TOKEN_FILE"
```

**Problem:** Token write is not atomic. If script crashes between write and chmod, token file is world-readable.

**Attack Scenario:**
1. User runs install script, enters IPInfo API token
2. Script executes `echo "$TOKEN" > "$TOKEN_FILE"` (file created with default perms 0644 - world readable)
3. Script crashes or is interrupted (Ctrl+C, OOM, etc.) before `chmod 600`
4. Token file remains world-readable
5. Any local user can read API token: `cat ~/.local/share/tribanft/config/ipinfo_token.txt`
6. Attacker uses token for API calls, exhausting quota or using for reconnaissance

**Impact:** API token exposure, quota exhaustion, unauthorized data access.

**Fix:**
```bash
# Create token file atomically with correct permissions
TOKEN_FILE="${CONFIG_DIR}/ipinfo_token.txt"
TEMP_TOKEN=$(mktemp --tmpdir="${CONFIG_DIR}")
chmod 600 "$TEMP_TOKEN"  # Set permissions BEFORE writing
echo "$TOKEN" > "$TEMP_TOKEN"
mv "$TEMP_TOKEN" "$TOKEN_FILE"  # Atomic rename
echo -e "${GREEN}Token configured${NC}"
```

---

### 3. Interactive Prompts Break Automation - MEDIUM
**Location:** Lines 135-136, 171-178
**Severity:** MEDIUM

**Issue:**
```bash
read -p "Update token? (s/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Ss]$ ]]; then
```

**Problem:** Script requires interactive input, making it impossible to automate via configuration management tools (Ansible, Puppet, etc.).

**Failure Scenario:**
- DevOps team wants to deploy TribanFT across 100 servers using Ansible
- Ansible runs script non-interactively
- Script hangs waiting for input, deployment fails

**Impact:** Cannot use in automated deployment pipelines.

**Fix:** Add non-interactive mode:
```bash
# Support non-interactive mode via environment variables
if [ -n "$TRIBANFT_IPINFO_TOKEN" ]; then
    echo "$TRIBANFT_IPINFO_TOKEN" > "$TOKEN_FILE"
    chmod 600 "$TOKEN_FILE"
    echo -e "${GREEN}Token configured from environment${NC}"
elif [ -f "$TOKEN_FILE" ]; then
    # Interactive update prompt
    echo -e "${YELLOW}WARNING: Token already configured: ${TOKEN_FILE}${NC}"
    read -p "Update token? (s/N): " -n 1 -r
    # ... rest of interactive logic
else
    # Interactive prompt for new token
    # ... existing logic
fi
```

---

### 4. Missing Error Handling Directives - LOW
**Location:** Line 9
**Severity:** LOW

**Issue:** Only `set -e`, missing `set -u` and `set -o pipefail`.

**Fix:**
```bash
set -euo pipefail
```

---

## FILE: systemd/tribanft.service (Primary Service Definition)

**Purpose:** Systemd service definition for main TribanFT daemon

### 1. Wrong ExecStart Path - CRITICAL
**Location:** Line 13
**Severity:** CRITICAL

**Issue:**
```
ExecStart=/usr/bin/python3 /usr/local/bin/tribanft --daemon
```

**Problem:** Service points to `/usr/local/bin/tribanft`, but `install.sh` installs to `~/.local/share/tribanft/`. This path mismatch means service won't start.

**Evidence from install.sh:**
```bash
INSTALL_DIR="${HOME}/.local/share/tribanft"
```

**Failure Scenario:**
1. User runs `install.sh` → files copied to `~/.local/share/tribanft/`
2. User runs `sudo systemctl start tribanft`
3. Systemd tries to execute `/usr/local/bin/tribanft`
4. File doesn't exist → service fails
5. User sees cryptic error: "No such file or directory"

**Impact:** Service completely broken, TribanFT never runs, system unprotected.

**Fix:**
```
# Adjust ExecStart to match actual installation location
ExecStart=/usr/bin/python3 /root/.local/share/tribanft/bruteforce_detector/main.py --daemon

# OR install a wrapper script to /usr/local/bin/tribanft:
# #!/bin/bash
# exec /usr/bin/python3 /root/.local/share/tribanft/bruteforce_detector/main.py "$@"
```

---

### 2. Hardcoded Root User Path - HIGH
**Location:** Line 35
**Severity:** HIGH

**Issue:**
```
WorkingDirectory=/root/.local/share/tribanft
```

**Problem:** Hardcodes `/root/.local/share/tribanft`, preventing installation for non-root users.

**Impact:**
- Forces root execution (security risk)
- Violates principle of least privilege
- Cannot run as dedicated service account

**Fix:** Use systemd specifiers or make path configurable:
```
# Option 1: Use systemd specifier for user home
WorkingDirectory=%h/.local/share/tribanft

# Option 2: Use /etc/tribanft.conf to specify path
EnvironmentFile=-/etc/tribanft.conf
WorkingDirectory=${TRIBANFT_DIR}
```

---

### 3. NoNewPrivileges Disabled - MEDIUM
**Location:** Line 31
**Severity:** MEDIUM

**Issue:**
```
NoNewPrivileges=false
```

**Problem:** `NoNewPrivileges=false` allows processes to gain additional privileges via setuid binaries. Should be `true` for security hardening.

**Security Impact:** If TribanFT process is compromised, attacker could potentially execute setuid binaries to escalate privileges.

**Fix:**
```
NoNewPrivileges=true
```

**Note:** Test thoroughly - if TribanFT legitimately needs to execute setuid binaries, document why in comments.

---

## FILE: systemd/tribanft-ipinfo-batch.service (Batch Service Definition)

**Purpose:** Systemd service for IP geolocation batch processing

### 1. Inefficient Multi-Python Invocation - HIGH
**Location:** Lines 17-19
**Severity:** HIGH

**Issue:**
```bash
ExecStart=/bin/bash -c 'PYTHON_BIN=$(/usr/bin/python3 -c "from bruteforce_detector.config import get_config; print(get_config().python_bin)" 2>/dev/null || echo /usr/bin/python3); \
PROJECT_DIR=$(/usr/bin/python3 -c "from bruteforce_detector.config import get_config; print(get_config().project_dir)" 2>/dev/null || echo /root/tribanft); \
$PYTHON_BIN $PROJECT_DIR/tools/tribanft-ipinfo-batch.py --daemon'
```

**Problem:**
- Runs Python interpreter **4 separate times** on every service start
- Loads config module 2 times (once for python_bin, once for project_dir)
- Extremely inefficient and slow
- Fragile fallback values may not match actual installation

**Failure Scenario:**
- Config loading takes 2 seconds per invocation
- Service startup delayed by 8+ seconds
- If config.py has import errors, fallback values used silently
- Service runs from wrong directory with wrong Python

**Impact:** Slow service startup, silent failures with incorrect fallback values.

**Fix:**
```bash
# Create a startup wrapper script at installation time
# /usr/local/bin/tribanft-ipinfo-batch-wrapper.sh:
#!/bin/bash
PYTHON_BIN=$(/usr/bin/python3 -c "from bruteforce_detector.config import get_config; c = get_config(); print(c.python_bin + ' ' + str(c.project_dir))")
exec $PYTHON_BIN/tools/tribanft-ipinfo-batch.py --daemon

# Then in service file:
ExecStart=/usr/local/bin/tribanft-ipinfo-batch-wrapper.sh
```

---

### 2. Wrong Working Directory - MEDIUM
**Location:** Line 39
**Severity:** MEDIUM

**Issue:**
```
WorkingDirectory=/tmp
```

**Problem:** Uses `/tmp` as working directory instead of actual project directory. Files created with relative paths go to wrong location.

**Impact:**
- Log files may be created in /tmp instead of proper location
- Relative path imports could fail
- Temporary files in /tmp may be cleaned up by system, causing data loss

**Fix:**
```
# Set working directory to match project location
WorkingDirectory=/root/.local/share/tribanft

# Or make it dynamic:
ExecStart=/bin/bash -c 'cd $(python3 -c "from bruteforce_detector.config import get_config; print(get_config().project_dir)") && ...'
```

---

### 3. Fallback Values May Not Match Installation - MEDIUM
**Location:** Lines 17-18
**Severity:** MEDIUM

**Issue:**
```bash
... || echo /usr/bin/python3
... || echo /root/tribanft
```

**Problem:** Fallback values (`/usr/bin/python3`, `/root/tribanft`) may not match actual installation location.

**Failure Scenario:**
- User installed to custom location: `/opt/tribanft`
- Config loading fails (missing dependency, corrupted file)
- Service falls back to `/root/tribanft` - doesn't exist
- Service tries to run non-existent script, fails silently

**Impact:** Service fails to start with confusing errors if config loading fails.

**Fix:** Don't use fallback values - fail explicitly if config can't be loaded:
```bash
ExecStart=/bin/bash -c 'PYTHON_BIN=$(/usr/bin/python3 -c "from bruteforce_detector.config import get_config; print(get_config().python_bin)") && \
PROJECT_DIR=$(/usr/bin/python3 -c "from bruteforce_detector.config import get_config; print(get_config().project_dir)") && \
$PYTHON_BIN $PROJECT_DIR/tools/tribanft-ipinfo-batch.py --daemon'
```

---

## CROSS-FILE INTEGRATION ISSUES

### 1. install.sh vs tribanft.service Path Mismatch - CRITICAL
**Severity:** CRITICAL

**Issue:**
- `install.sh` installs to `${HOME}/.local/share/tribanft` (line 7)
- `tribanft.service` expects `/usr/local/bin/tribanft` (line 13)
- Paths completely incompatible

**Impact:** Service cannot start after installation. Complete installation failure.

**Fix:** Either:
1. Update service file to match install.sh paths, OR
2. Update install.sh to create `/usr/local/bin/tribanft` wrapper script

---

### 2. setup_nftables.sh Creates Sets That Don't Persist Correctly - HIGH
**Severity:** HIGH

**Issue:** Script creates NFTables sets in running configuration, but save strategy overwrites entire ruleset instead of just adding TribanFT rules.

**Impact:** On systems with existing firewall rules, setup_nftables.sh destroys unrelated security rules.

**Fix:** Change save strategy to append TribanFT rules instead of replacing entire ruleset.

---

### 3. install-service.sh Hardcodes Root Paths, But install.sh Uses $HOME - MEDIUM
**Severity:** MEDIUM

**Issue:**
- `install.sh` uses `${HOME}/.local/share/tribanft` - works for any user
- `install-service.sh` hardcodes `/root/.local/share/tribanft` - only works for root

**Impact:** Cannot install as non-root user. Inconsistent behavior.

**Fix:** Use consistent path resolution across all scripts.

---

## SUMMARY OF ISSUES BY SEVERITY

### CRITICAL (3 issues)
1. **install.sh:29-32** - Broken Python version check (undefined variables)
2. **setup_nftables.sh:103-112** - Overwrites entire firewall ruleset
3. **install-ipinfo-batch-service.sh:63** - Command injection via eval
4. **tribanft.service:13** - Wrong ExecStart path

### HIGH (6 issues)
1. **install.sh:40** - Missing pip3 availability check
2. **install-service.sh:55** - Cron removal could fail with empty result
3. **install-ipinfo-batch-service.sh:139,147** - Non-atomic token file writes
4. **tribanft.service:35** - Hardcoded root user path
5. **tribanft-ipinfo-batch.service:17-19** - Inefficient multi-Python invocation
6. **Integration** - setup_nftables.sh creates sets that don't persist correctly

### MEDIUM (9 issues)
1. **install.sh:112-123** - Unquoted loop variables in YAML validation
2. **install.sh:5** - Missing error handling directives (set -u, set -o pipefail)
3. **install.sh:138** - No sudo availability check
4. **setup-config.sh:70-104** - sed operations without error checking
5. **setup-config.sh:70-75** - Fragile text-based mode toggle
6. **install-service.sh:34** - Hardcoded root user path
7. **setup_nftables.sh:47-53** - Creates unused port_scanners set
8. **install-ipinfo-batch-service.sh:135-178** - Interactive prompts break automation
9. **tribanft.service:31** - NoNewPrivileges disabled
10. **tribanft-ipinfo-batch.service:39** - Wrong working directory
11. **tribanft-ipinfo-batch.service:17-18** - Fallback values may not match installation
12. **Integration** - install-service.sh vs install.sh path inconsistency

### LOW (7 issues)
1. **install.sh:3,148** - Version mismatch (shows 2.4.1 instead of 2.5.0)
2. **setup-config.sh:5** - Missing error handling directives
3. **install-service.sh:8** - Missing error handling directives
4. **setup_nftables.sh:11** - Missing error handling directives
5. **install-ipinfo-batch-service.sh:9** - Missing error handling directives

---

## RECOMMENDATIONS FOR STABLE RELEASE

### Immediate Fixes Required (Before v2.5.0 Stable)

1. **Fix install.sh Python version check** - Installation completely broken
2. **Fix tribanft.service ExecStart path** - Service won't start
3. **Fix setup_nftables.sh save strategy** - Destroys existing firewall rules
4. **Remove eval in install-ipinfo-batch-service.sh** - Security vulnerability

### High Priority Fixes

1. Add pip3 availability check in install.sh
2. Fix cron removal logic in install-service.sh
3. Make token file writes atomic in install-ipinfo-batch-service.sh
4. Optimize tribanft-ipinfo-batch.service startup (eliminate redundant Python calls)

### Medium Priority Improvements

1. Add `set -euo pipefail` to all shell scripts
2. Add automation support (non-interactive mode) to install-ipinfo-batch-service.sh
3. Unify path handling across all scripts (use variables, not hardcoded paths)
4. Improve sed error checking in setup-config.sh

### Testing Recommendations

1. **Test installation on clean systems:**
   - Debian 11, 12 (stable, testing)
   - Ubuntu 20.04, 22.04, 24.04 LTS
   - RHEL 8, 9
   - Fedora 38, 39
   - With and without existing NFTables rules

2. **Test edge cases:**
   - System without pip3
   - User without sudo access
   - Empty crontab removal
   - Config files with different spacing/formatting
   - Installation to non-root user

3. **Test automation:**
   - Ansible playbook with non-interactive installation
   - Terraform deployment
   - Docker container builds

---

## PORTABILITY ANALYSIS

### Distribution Support Matrix

| Script | Debian/Ubuntu | RHEL/Fedora | Arch | Alpine | Issues |
|--------|---------------|-------------|------|--------|--------|
| install.sh | ✓ (broken) | ✓ (broken) | ✓ (broken) | ✗ | Python check broken on all |
| setup-config.sh | ✓ | ✓ | ✓ | ? | sed -i behavior differs on BSD |
| install-service.sh | ✓ | ✓ | ✓ | ✓ | Good portability |
| setup_nftables.sh | ✓ | ✓ | ✓ | ✓ | Excellent multi-distro support |
| install-ipinfo-batch-service.sh | ✓ | ✓ | ✓ | ✓ | Good portability |

### Package Manager Dependencies

Scripts assume:
- `python3` package name (universal)
- `pip3` command (may be `python3-pip` or included in python3)
- `nftables` package name (universal)
- `systemctl` available (systemd-based distros only)

**Recommendation:** Add checks for package managers and provide installation commands for each distro.

---

## SECURITY BEST PRACTICES VIOLATIONS

1. **Command Injection:** eval of external data (install-ipinfo-batch-service.sh)
2. **Privilege Escalation Risk:** NoNewPrivileges=false (tribanft.service)
3. **Race Conditions:** Non-atomic file writes with permission changes
4. **Information Disclosure:** Token file world-readable if script interrupted
5. **Firewall Destruction:** Overwrites entire ruleset instead of appending

---

## CONCLUSION

Phase 2 identified **25 issues** across 7 files, with **4 critical issues** that completely break installation or create severe security risks:

1. Python version check broken (install.sh)
2. Service path mismatch (tribanft.service)
3. Firewall ruleset destruction (setup_nftables.sh)
4. Command injection vulnerability (install-ipinfo-batch-service.sh)

**All 4 critical issues must be fixed before v2.5.0 stable release.** Without these fixes:
- Users cannot install TribanFT (broken version check)
- Installed service won't start (path mismatch)
- Existing firewall rules destroyed (security degradation)
- Root command injection vulnerability (privilege escalation)

The installation system is currently **not production-ready** and requires significant fixes before stable release.

---

**End of Phase 2 Security Audit**
