#!/bin/bash
set -e

# TribanFT Setup Script
# Creates configuration file with human-readable paths that override config. py defaults

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/.env"
BACKUP_SUFFIX=".backup. $(date +%s)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
info() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

prompt_with_default() {
    local prompt="$1"
    local default="$2"
    local result
    read -p "$(echo -e "${BLUE}${prompt}${NC} [${default}]:  ")" result
    echo "${result:-$default}"
}

yes_no_prompt() {
    local prompt="$1"
    local default="$2"
    local result
    while true; do
        read -p "$(echo -e "${BLUE}${prompt}${NC} (y/n) [${default}]: ")" result
        result="${result:-$default}"
        case "${result,,}" in
            y|yes) return 0 ;;
            n|no) return 1 ;;
            *) warn "Please answer y or n" ;;
        esac
    done
}

detect_existing_path() {
    local legacy_path="$1"
    local xdg_path="$2"
    
    if [[ -f "$legacy_path" ]] || [[ -d "$legacy_path" ]]; then
        echo "$legacy_path"
    elif [[ -f "$xdg_path" ]] || [[ -d "$xdg_path" ]]; then
        echo "$xdg_path"
    else
        echo "$xdg_path"
    fi
}

# Banner
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║           TribanFT Configuration Setup                    ║"
echo "║   Security Intelligence Platform Configuration Tool       ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# Check if . env already exists
if [[ -f "$ENV_FILE" ]]; then
    warn "Configuration file already exists: $ENV_FILE"
    if yes_no_prompt "Backup existing config and create new one?" "n"; then
        mv "$ENV_FILE" "${ENV_FILE}${BACKUP_SUFFIX}"
        success "Backed up to:  ${ENV_FILE}${BACKUP_SUFFIX}"
    else
        info "Exiting without changes"
        exit 0
    fi
fi

# Detect current environment
info "Detecting existing environment..."

# Default paths
XDG_DATA_DEFAULT="${XDG_DATA_HOME:-$HOME/.local/share}/tribanft"
XDG_CONFIG_DEFAULT="${XDG_CONFIG_HOME:-$HOME/. config}/tribanft"
XDG_STATE_DEFAULT="${XDG_STATE_HOME:-$HOME/.local/state}/tribanft"

# Detect if running as root or with sudo
if [[ $EUID -eq 0 ]]; then
    warn "Running as root - will use system paths by default"
    DATA_DIR_DEFAULT="/var/lib/tribanft"
    CONFIG_DIR_DEFAULT="/etc/tribanft"
    STATE_DIR_DEFAULT="/var/lib/tribanft"
else
    DATA_DIR_DEFAULT="$XDG_DATA_DEFAULT"
    CONFIG_DIR_DEFAULT="$XDG_CONFIG_DEFAULT"
    STATE_DIR_DEFAULT="$XDG_STATE_DEFAULT"
fi

# Check for existing legacy installations
LEGACY_DETECTED=false
if [[ -f "/root/blacklist_ipv4.txt" ]] || [[ -f "/root/whitelist_ips.txt" ]]; then
    warn "Detected legacy installation in /root/"
    LEGACY_DETECTED=true
    if yes_no_prompt "Migrate from legacy paths?" "y"; then
        DATA_DIR_DEFAULT="/root"
    fi
fi

echo ""
info "═══ Directory Configuration ═══"
echo ""

# Directory paths
DATA_DIR=$(prompt_with_default "Data directory (blacklists, whitelists)" "$DATA_DIR_DEFAULT")
CONFIG_DIR=$(prompt_with_default "Config directory" "$CONFIG_DIR_DEFAULT")
STATE_DIR=$(prompt_with_default "State directory (database, runtime state)" "$STATE_DIR_DEFAULT")

echo ""
info "═══ Log File Paths ═══"
echo ""

SYSLOG_PATH=$(prompt_with_default "Syslog path" "/var/log/syslog")
MSSQL_LOG_PATH=$(prompt_with_default "MS SQL error log path" "/var/opt/mssql/log/errorlog")

echo ""
info "═══ Detection Thresholds ═══"
echo ""

BRUTE_FORCE_THRESHOLD=$(prompt_with_default "Brute force threshold (attempts)" "20")
TIME_WINDOW_MINUTES=$(prompt_with_default "Time window (minutes)" "10080")
FAILED_LOGIN_THRESHOLD=$(prompt_with_default "Failed login threshold" "20")
PRELOGIN_PATTERN_THRESHOLD=$(prompt_with_default "Prelogin pattern threshold" "20")
PORT_SCAN_THRESHOLD=$(prompt_with_default "Port scan threshold" "20")

echo ""
info "═══ Feature Flags ═══"
echo ""

ENABLE_PRELOGIN=$(yes_no_prompt "Enable prelogin detection?" "y" && echo "true" || echo "false")
ENABLE_FAILED_LOGIN=$(yes_no_prompt "Enable failed login detection?" "y" && echo "true" || echo "false")
ENABLE_PORT_SCAN=$(yes_no_prompt "Enable port scan detection?" "y" && echo "true" || echo "false")
ENABLE_CROWDSEC=$(yes_no_prompt "Enable CrowdSec integration?" "y" && echo "true" || echo "false")
ENABLE_NFTABLES=$(yes_no_prompt "Enable NFTables auto-update?" "y" && echo "true" || echo "false")
ENABLE_AUTO_ENRICHMENT=$(yes_no_prompt "Enable automatic IP enrichment?" "y" && echo "true" || echo "false")

echo ""
info "═══ Storage Backend ═══"
echo ""

USE_DATABASE=$(yes_no_prompt "Use SQLite database backend?" "n" && echo "true" || echo "false")
SYNC_TO_FILE=$(yes_no_prompt "Sync database changes to files?" "y" && echo "true" || echo "false")

echo ""
info "═══ Performance Settings ═══"
echo ""

BATCH_SIZE=$(prompt_with_default "Batch processing size" "1000")
BACKUP_RETENTION_DAYS=$(prompt_with_default "Backup retention (days)" "7")
BACKUP_MIN_KEEP=$(prompt_with_default "Minimum backups to keep" "5")

# Generate .env file
info "Generating configuration file..."

cat > "$ENV_FILE" << EOF
# TribanFT Configuration File
# Generated:  $(date)
# This file overrides defaults in bruteforce_detector/config.py
#
# To reload configuration, restart the TribanFT service or application

# ═══════════════════════════════════════════════════════════
# DIRECTORY PATHS
# ═══════════════════════════════════════════════════════════
# These directories will be created automatically if they don't exist

# Main data directory (blacklists, whitelists, IP intelligence data)
TRIBANFT_DATA_DIR=${DATA_DIR}

# Configuration directory (reserved for future config files)
TRIBANFT_CONFIG_DIR=${CONFIG_DIR}

# State directory (database, runtime state, backups)
TRIBANFT_STATE_DIR=${STATE_DIR}

# ═══════════════════════════════════════════════════════════
# LOG FILE PATHS
# ═══════════════════════════════════════════════════════════

# System log file (for Linux auth events)
BFD_SYSLOG_PATH=${SYSLOG_PATH}

# MS SQL Server error log
BFD_MSSQL_ERROR_LOG_PATH=${MSSQL_LOG_PATH}

# ═══════════════════════════════════════════════════════════
# DETECTION THRESHOLDS
# ═══════════════════════════════════════════════════════════

# Number of failed attempts before triggering brute force detection
BFD_BRUTE_FORCE_THRESHOLD=${BRUTE_FORCE_THRESHOLD}

# Time window for event correlation (in minutes)
# Default: 10080 minutes = 7 days
BFD_TIME_WINDOW_MINUTES=${TIME_WINDOW_MINUTES}

# Failed login attempt threshold
BFD_FAILED_LOGIN_THRESHOLD=${FAILED_LOGIN_THRESHOLD}

# Prelogin pattern detection threshold
BFD_PRELOGIN_PATTERN_THRESHOLD=${PRELOGIN_PATTERN_THRESHOLD}

# Port scan detection threshold
BFD_PORT_SCAN_THRESHOLD=${PORT_SCAN_THRESHOLD}

# ═══════════════════════════════════════════════════════════
# FEATURE FLAGS
# ═══════════════════════════════════════════════════════════

# Enable/disable specific detection modules
BFD_ENABLE_PRELOGIN_DETECTION=${ENABLE_PRELOGIN}
BFD_ENABLE_FAILED_LOGIN_DETECTION=${ENABLE_FAILED_LOGIN}
BFD_ENABLE_PORT_SCAN_DETECTION=${ENABLE_PORT_SCAN}

# Enable/disable external integrations
BFD_ENABLE_CROWDSEC_INTEGRATION=${ENABLE_CROWDSEC}
BFD_ENABLE_NFTABLES_UPDATE=${ENABLE_NFTABLES}
BFD_ENABLE_AUTO_ENRICHMENT=${ENABLE_AUTO_ENRICHMENT}

# ═══════════════════════════════════════════════════════════
# STORAGE BACKEND
# ═══════════════════════════════════════════════════════════

# Use SQLite database for IP storage (recommended for >10k IPs)
BFD_USE_DATABASE=${USE_DATABASE}

# Sync database changes back to text files (for compatibility)
BFD_SYNC_TO_FILE=${SYNC_TO_FILE}

# ═══════════════════════════════════════════════════════════
# PERFORMANCE SETTINGS
# ═══════════════════════════════════════════════════════════

# Batch size for processing large IP lists
BFD_BATCH_SIZE=${BATCH_SIZE}

# Backup retention settings
BFD_BACKUP_RETENTION_DAYS=${BACKUP_RETENTION_DAYS}
BFD_BACKUP_MIN_KEEP=${BACKUP_MIN_KEEP}

# ═══════════════════════════════════════════════════════════
# ADVANCED SETTINGS (OPTIONAL)
# ═══════════════════════════════════════════════════════════
# Uncomment and modify these to override individual file paths
# By default, files are stored in TRIBANFT_DATA_DIR

# BFD_BLACKLIST_IPV4_FILE=${DATA_DIR}/blacklist_ipv4.txt
# BFD_BLACKLIST_IPV6_FILE=${DATA_DIR}/blacklist_ipv6.txt
# BFD_PRELOGIN_BRUTEFORCE_FILE=${DATA_DIR}/prelogin-bruteforce-ips.txt
# BFD_WHITELIST_FILE=${DATA_DIR}/whitelist_ips.txt
# BFD_MANUAL_BLACKLIST_FILE=${DATA_DIR}/manual_blacklist.txt
# BFD_STATE_FILE=${STATE_DIR}/state.json
# BFD_DATABASE_PATH=${STATE_DIR}/blacklist.db
EOF

success "Configuration file created: $ENV_FILE"

# Create directories
echo ""
info "Creating directories..."

for dir in "$DATA_DIR" "$CONFIG_DIR" "$STATE_DIR" "${STATE_DIR}/backups"; do
    if [[ ! -d "$dir" ]]; then
        if mkdir -p "$dir" 2>/dev/null; then
            success "Created:  $dir"
        else
            warn "Could not create:  $dir (may need sudo)"
        fi
    else
        info "Already exists: $dir"
    fi
done

# Migrate legacy files if detected
if [[ "$LEGACY_DETECTED" == "true" ]] && [[ "$DATA_DIR" != "/root" ]]; then
    echo ""
    if yes_no_prompt "Copy legacy files to new data directory?" "y"; then
        info "Migrating legacy files..."
        for file in blacklist_ipv4.txt blacklist_ipv6.txt prelogin-bruteforce-ips.txt whitelist_ips.txt manual_blacklist.txt; do
            if [[ -f "/root/$file" ]]; then
                if cp "/root/$file" "$DATA_DIR/" 2>/dev/null; then
                    success "Migrated: $file"
                else
                    warn "Could not migrate: $file (may need sudo)"
                fi
            fi
        done
    fi
fi

# Summary
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║                  Setup Complete                           ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
info "Configuration saved to: $ENV_FILE"
info "To use this configuration, ensure it's loaded before running TribanFT:"
echo ""
echo -e "  ${GREEN}# Option 1: Export in current shell${NC}"
echo -e "  ${YELLOW}export \$(grep -v '^#' $ENV_FILE | xargs)${NC}"
echo ""
echo -e "  ${GREEN}# Option 2: Source in your shell profile${NC}"
echo -e "  ${YELLOW}echo 'set -a; source $ENV_FILE; set +a' >> ~/. bashrc${NC}"
echo ""
echo -e "  ${GREEN}# Option 3: Use with systemd service${NC}"
echo -e "  ${YELLOW}EnvironmentFile=$ENV_FILE${NC}"
echo ""
info "Review and edit $ENV_FILE to customize further"
echo ""