#!/bin/bash
# TribanFT Configuration Setup Script
# Interactive configuration creation and management

set -e

INSTALL_DIR="${HOME}/.local/share/tribanft"
CONFIG_FILE="${INSTALL_DIR}/config.conf"
TEMPLATE="config.conf.template"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
echo_prompt() { echo -e "${BLUE}[?]${NC} $1"; }
echo_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

# Parse arguments
MODE="learning"
while [[ $# -gt 0 ]]; do
    case $1 in
        --learning-mode)
            MODE="learning"
            shift
            ;;
        --production)
            MODE="production"
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [--learning-mode|--production]"
            echo ""
            echo "Options:"
            echo "  --learning-mode  Setup for learning mode (no blocking, default)"
            echo "  --production     Setup for production mode (with blocking)"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Check if config exists
if [ -f "$CONFIG_FILE" ]; then
    echo_warn "config.conf already exists at $CONFIG_FILE"
    echo_prompt "What would you like to do?"
    echo "  1) Keep existing config (default)"
    echo "  2) Recreate from template"
    echo "  3) Toggle learning/production mode only"
    read -p "Choice [1-3]: " choice
    choice=${choice:-1}

    case $choice in
        1)
            echo_info "Keeping existing config"
            exit 0
            ;;
        2)
            echo_info "Backing up existing config..."
            cp "$CONFIG_FILE" "${CONFIG_FILE}.backup.$(date +%Y%m%d_%H%M%S)"
            ;;
        3)
            echo_info "Toggling mode in existing config..."
            if [ "$MODE" = "learning" ]; then
                sed -i 's/enable_nftables_update = true/enable_nftables_update = false/' "$CONFIG_FILE"
                echo_info "Learning mode enabled (blocking disabled)"
            else
                sed -i 's/enable_nftables_update = false/enable_nftables_update = true/' "$CONFIG_FILE"
                echo_info "Production mode enabled (blocking enabled)"
            fi
            exit 0
            ;;
    esac
fi

# Create install directory if needed
mkdir -p "$INSTALL_DIR"

# Find template
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "${SCRIPT_DIR}/../${TEMPLATE}" ]; then
    TEMPLATE_PATH="${SCRIPT_DIR}/../${TEMPLATE}"
elif [ -f "${TEMPLATE}" ]; then
    TEMPLATE_PATH="${TEMPLATE}"
else
    echo "Error: config.conf.template not found"
    exit 1
fi

echo_info "Creating config from template..."
cp "$TEMPLATE_PATH" "$CONFIG_FILE"

# Set mode
if [ "$MODE" = "learning" ]; then
    sed -i 's/enable_nftables_update = true/enable_nftables_update = false/' "$CONFIG_FILE" 2>/dev/null || true
    echo_info "Learning mode enabled (blocking disabled for Week 1)"
else
    sed -i 's/enable_nftables_update = false/enable_nftables_update = true/' "$CONFIG_FILE" 2>/dev/null || true
    echo_info "Production mode enabled (blocking enabled)"
fi

# Verify [plugins] section exists
if ! grep -q "\[plugins\]" "$CONFIG_FILE"; then
    echo_info "Adding [plugins] section..."
    cat >> "$CONFIG_FILE" << 'EOF'

# ═══════════════════════════════════════════════════════════════════════════
# [plugins] - Plugin System Configuration
# ═══════════════════════════════════════════════════════════════════════════
[plugins]

enable_plugin_system = true
detector_plugin_dir = ${paths:project_dir}/bruteforce_detector/plugins/detectors
parser_plugin_dir = ${paths:project_dir}/bruteforce_detector/plugins/parsers
enable_yaml_rules = true
rules_dir = ${paths:project_dir}/bruteforce_detector/rules
EOF
fi

echo_info ""
echo_info "Configuration created successfully!"
echo_info "Location: $CONFIG_FILE"
echo_info ""
echo_info "Current mode: $MODE"
echo_info ""
echo_info "Next steps:"
echo_info "  1. Review config: vim $CONFIG_FILE"
echo_info "  2. Start service: sudo systemctl start tribanft"
echo_info "  3. View logs: sudo journalctl -u tribanft -f"
