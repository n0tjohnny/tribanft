#!/bin/bash
#
# install-ipinfo-batch-service.sh
# Installation script for TribanFT IP Geolocation Batch Service
#
# This script reads configuration from config.conf and sets up the systemd service
#

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}TribanFT - IP Geolocation Service Installation${NC}"
echo -e "${BLUE}========================================${NC}\n"

# Verify running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}ERROR: This script must be run as root${NC}"
    echo -e "${YELLOW}TIP: Use: sudo $0${NC}"
    exit 1
fi

# ═══════════════════════════════════════════════════════════════════════════
# Load Configuration from config.conf
# ═══════════════════════════════════════════════════════════════════════════

echo -e "${BLUE}Loading configuration from config.conf...${NC}"

# Use Python to read config.conf
read -r -d '' PYTHON_SCRIPT << 'EOF' || true
from bruteforce_detector.config import get_config
import sys

try:
    config = get_config()
    print(f"PROJECT_DIR={config.project_dir}")
    print(f"CONFIG_DIR={config.config_dir}")
    print(f"STATE_DIR={config.state_dir}")
    print(f"PYTHON_BIN={config.python_bin}")
except Exception as e:
    print(f"ERROR: {e}", file=sys.stderr)
    sys.exit(1)
EOF

# Execute Python script and source the output
CONFIG_OUTPUT=$(python3 -c "$PYTHON_SCRIPT" 2>&1)
CONFIG_EXIT_CODE=$?

if [ $CONFIG_EXIT_CODE -ne 0 ]; then
    echo -e "${RED}ERROR: Failed to load config.conf${NC}"
    echo -e "${YELLOW}Error: $CONFIG_OUTPUT${NC}"
    echo -e "${YELLOW}TIP: Run ./setup.sh to create configuration${NC}"
    exit 1
fi

# Parse configuration safely (without eval to prevent command injection)
while IFS='=' read -r key value; do
    case "$key" in
        PROJECT_DIR) PROJECT_DIR="$value" ;;
        CONFIG_DIR) CONFIG_DIR="$value" ;;
        STATE_DIR) STATE_DIR="$value" ;;
        PYTHON_BIN) PYTHON_BIN="$value" ;;
    esac
done <<< "$CONFIG_OUTPUT"

echo -e "${GREEN}Configuration loaded${NC}"
echo -e "   Project directory: ${PROJECT_DIR}"
echo -e "   Config directory:  ${CONFIG_DIR}"
echo -e "   State directory:   ${STATE_DIR}"
echo -e "   Python binary:     ${PYTHON_BIN}"

# ═══════════════════════════════════════════════════════════════════════════
# Verify Project Files
# ═══════════════════════════════════════════════════════════════════════════

echo -e "\n${BLUE}Verifying project files...${NC}"

SERVICE_TEMPLATE="${PROJECT_DIR}/systemd/tribanft-ipinfo-batch.service"
SCRIPT_FILE="${PROJECT_DIR}/tools/tribanft-ipinfo-batch.py"

if [ ! -f "$SCRIPT_FILE" ]; then
    echo -e "${RED}ERROR: Script not found: ${SCRIPT_FILE}${NC}"
    exit 1
fi

if [ ! -f "$SERVICE_TEMPLATE" ]; then
    echo -e "${RED}ERROR: Service template not found: ${SERVICE_TEMPLATE}${NC}"
    exit 1
fi

echo -e "${GREEN}Project files verified${NC}"

# ═══════════════════════════════════════════════════════════════════════════
# Create Directories
# ═══════════════════════════════════════════════════════════════════════════

echo -e "\n${BLUE}Creating directories...${NC}"

mkdir -p "$CONFIG_DIR"
mkdir -p "$STATE_DIR"
mkdir -p "${STATE_DIR}/ipinfo_cache"

echo -e "${GREEN}Directories created${NC}"

# ═══════════════════════════════════════════════════════════════════════════
# Make Script Executable
# ═══════════════════════════════════════════════════════════════════════════

echo -e "\n${BLUE}Configuring script permissions...${NC}"

chmod +x "$SCRIPT_FILE"

echo -e "${GREEN}Script permissions configured${NC}"

# ═══════════════════════════════════════════════════════════════════════════
# Install Service File
# ═══════════════════════════════════════════════════════════════════════════

echo -e "\n${BLUE}Installing systemd service...${NC}"

# Copy service file to systemd directory
cp "$SERVICE_TEMPLATE" /etc/systemd/system/tribanft-ipinfo-batch.service

echo -e "${GREEN}Service file installed${NC}"

# ═══════════════════════════════════════════════════════════════════════════
# Configure IPInfo Token
# ═══════════════════════════════════════════════════════════════════════════

TOKEN_FILE="${CONFIG_DIR}/ipinfo_token.txt"

echo -e "\n${BLUE}IPInfo.io Token Configuration${NC}"

if [ -f "$TOKEN_FILE" ]; then
    echo -e "${YELLOW}WARNING: Token already configured: ${TOKEN_FILE}${NC}"
    read -p "Update token? (s/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Ss]$ ]]; then
        read -p "Enter your ipinfo.io token: " TOKEN
        echo "$TOKEN" > "$TOKEN_FILE"
        chmod 600 "$TOKEN_FILE"
        echo -e "${GREEN}Token updated${NC}"
    fi
else
    echo -e "${YELLOW}TIP: Get a free token at: https://ipinfo.io/signup${NC}"
    read -p "Enter your ipinfo.io token (or press Enter to skip): " TOKEN
    if [ -n "$TOKEN" ]; then
        echo "$TOKEN" > "$TOKEN_FILE"
        chmod 600 "$TOKEN_FILE"
        echo -e "${GREEN}Token configured${NC}"
    else
        echo -e "${YELLOW}WARNING: No token configured (limit: 50k requests/month)${NC}"
    fi
fi

# ═══════════════════════════════════════════════════════════════════════════
# Reload Systemd
# ═══════════════════════════════════════════════════════════════════════════

echo -e "\n${BLUE}Reloading systemd...${NC}"

systemctl daemon-reload

echo -e "${GREEN}Systemd reloaded${NC}"

# ═══════════════════════════════════════════════════════════════════════════
# Enable and Start Service
# ═══════════════════════════════════════════════════════════════════════════

echo -e "\n${BLUE}Service Configuration${NC}"

read -p "Enable service to start automatically? (S/n): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    systemctl enable tribanft-ipinfo-batch.service
    echo -e "${GREEN}Service enabled for automatic start${NC}"
fi

read -p "Start service now? (S/n): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    systemctl start tribanft-ipinfo-batch.service
    echo -e "${GREEN}Service started${NC}"

    # Wait and check status
    sleep 2
    echo -e "\n${BLUE}Service Status:${NC}"
    systemctl status tribanft-ipinfo-batch.service --no-pager -l
fi

# ═══════════════════════════════════════════════════════════════════════════
# Final Information
# ═══════════════════════════════════════════════════════════════════════════

echo -e "\n${BLUE}========================================${NC}"
echo -e "${BLUE}INSTALLATION COMPLETE!${NC}"
echo -e "${BLUE}========================================${NC}\n"

echo -e "${YELLOW}Useful Commands:${NC}"
echo -e "   ${GREEN}systemctl status tribanft-ipinfo-batch${NC}     - Check status"
echo -e "   ${GREEN}systemctl start tribanft-ipinfo-batch${NC}      - Start service"
echo -e "   ${GREEN}systemctl stop tribanft-ipinfo-batch${NC}       - Stop service"
echo -e "   ${GREEN}systemctl restart tribanft-ipinfo-batch${NC}    - Restart service"
echo -e "   ${GREEN}journalctl -u tribanft-ipinfo-batch -f${NC}     - View logs (realtime)"
echo -e "   ${GREEN}journalctl -u tribanft-ipinfo-batch -n 100${NC} - View last 100 log lines"

echo -e "\n${YELLOW}Configuration:${NC}"
echo -e "   Config file: ${CONFIG_DIR}/config.conf"
echo -e "   Token file:  ${TOKEN_FILE}"
echo -e "   Cache dir:   ${STATE_DIR}/ipinfo_cache"
echo -e "   Logs:        journalctl -u tribanft-ipinfo-batch"

echo -e "\n${YELLOW}Documentation:${NC}"
echo -e "   https://github.com/n0tjohnny/tribanft\n"

exit 0
