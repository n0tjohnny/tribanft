#!/bin/bash
#
# TribanFT Service Installation Script
#
# Converts TribanFT from cron-based execution to systemd service
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}TribanFT Service Installer${NC}"
echo "================================"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root${NC}"
    exit 1
fi

# Check if systemd is available
if ! command -v systemctl &> /dev/null; then
    echo -e "${RED}Error: systemd not found${NC}"
    exit 1
fi

# Step 1: Create tribanft directory (matches config.conf.template)
echo -e "${YELLOW}[1/5]${NC} Creating tribanft directory..."
mkdir -p /root/.local/share/tribanft
echo -e "${GREEN}OK${NC} Directory created"

# Step 2: Copy config template if it doesn't exist
echo -e "${YELLOW}[2/5]${NC} Checking configuration..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ ! -f /root/.local/share/tribanft/config.conf ]; then
    if [ -f "$SCRIPT_DIR/../config.conf.template" ]; then
        cp "$SCRIPT_DIR/../config.conf.template" /root/.local/share/tribanft/config.conf
        echo -e "${GREEN}OK${NC} Created config from template"
    else
        echo -e "${YELLOW}WARNING${NC}  config.conf.template not found, please copy manually"
    fi
else
    echo "Config already exists"
fi

# Step 3: Remove cron job if exists
echo -e "${YELLOW}[3/5]${NC} Checking for existing cron job..."
if crontab -l 2>/dev/null | grep -q "tribanft"; then
    echo "Found existing cron job, removing..."
    crontab -l | grep -v "tribanft" | crontab -
    echo -e "${GREEN}OK${NC} Cron job removed"
else
    echo "No cron job found"
fi

# Step 4: Copy service file
echo -e "${YELLOW}[4/5]${NC} Installing systemd service file..."
cp "$SCRIPT_DIR/../systemd/tribanft.service" /etc/systemd/system/
chmod 644 /etc/systemd/system/tribanft.service
systemctl daemon-reload
systemctl enable tribanft.service
echo -e "${GREEN}OK${NC} Service installed and enabled"

# Step 5: Start service
echo -e "${YELLOW}[5/5]${NC} Starting tribanft service..."
systemctl start tribanft.service
sleep 2

# Check status
if systemctl is-active --quiet tribanft.service; then
    echo -e "${GREEN}OK${NC} Service started successfully"
else
    echo -e "${RED}ERROR${NC} Service failed to start"
    echo "Check logs with: journalctl -u tribanft -n 50"
    exit 1
fi

echo ""
echo -e "${GREEN}Installation complete!${NC}"
echo ""
echo "Installation paths:"
echo "  Config:  /root/.local/share/tribanft/config.conf"
echo "  Data:    /root/.local/share/tribanft/"
echo "  Logs:    journalctl -u tribanft"
echo "  Backups: /root/.local/share/tribanft/backups/"
echo ""
echo "Useful commands:"
echo "  systemctl status tribanft    # Check service status"
echo "  systemctl stop tribanft      # Stop service"
echo "  systemctl restart tribanft   # Restart service"
echo "  journalctl -u tribanft -f    # View live logs"
echo "  journalctl -u tribanft -n 100 # View last 100 log lines"
echo ""
echo "The service is now running and will:"
echo "  - Run detection every 5 minutes (300 seconds)"
echo "  - Restart automatically on failure"
echo "  - Start automatically on boot"
echo ""
