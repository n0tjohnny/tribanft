#!/bin/bash
# =============================================================================
# TribanFT Automated Installation Script
# Version: 2.9.2
#
# This script installs TribanFT to ~/.local/share/tribanft with automatic
# backup of existing installation and comprehensive validation.
#
# Author: TribanFT Project
# License: GNU GPL v3
# =============================================================================

set -e  # Exit on error
set -u  # Exit on undefined variable
set -o pipefail  # Exit on pipe failure

# =============================================================================
# Configuration
# =============================================================================

INSTALL_DIR="${HOME}/.local/share/tribanft"
BACKUP_SUFFIX=$(date +%Y%m%d_%H%M%S)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'  # No Color

# =============================================================================
# Helper Functions
# =============================================================================

echo_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

echo_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

echo_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

echo_progress() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# Error handler for cleanup on failure
error_handler() {
    local line_no=$1
    echo_error "Installation failed at line ${line_no}"
    echo_error "Please check the error message above and try again"
    exit 1
}

trap 'error_handler ${LINENO}' ERR

# =============================================================================
# Prerequisite Checks
# =============================================================================

check_python() {
    echo_progress "Checking Python installation..."

    # Check if python3 command exists
    if ! command -v python3 &> /dev/null; then
        echo_error "Python 3 is not installed"
        echo_error "Please install Python 3.8 or later and try again"
        echo_error "  Debian/Ubuntu: sudo apt install python3 python3-pip"
        echo_error "  RHEL/Fedora: sudo dnf install python3 python3-pip"
        exit 1
    fi

    # Verify minimum version (3.8)
    REQUIRED="3.8"
    python_version=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')

    if [ "$(printf '%s\n' "$REQUIRED" "$python_version" | sort -V | head -n1)" != "$REQUIRED" ]; then
        echo_error "Python 3.8 or later required (found ${python_version})"
        echo_error "Please upgrade Python and try again"
        exit 1
    fi

    echo_info "Python ${python_version} detected"

    # Check if pip3 is available
    if ! command -v pip3 &> /dev/null; then
        echo_error "pip3 is not installed"
        echo_error "Please install pip3 and try again"
        echo_error "  Debian/Ubuntu: sudo apt install python3-pip"
        echo_error "  RHEL/Fedora: sudo dnf install python3-pip"
        exit 1
    fi

    echo_info "pip3 detected"
}

check_path() {
    echo_progress "Checking PATH configuration..."

    local bin_dir="${HOME}/.local/bin"

    # Check if ~/.local/bin is in PATH
    if [[ ":${PATH}:" != *":${bin_dir}:"* ]]; then
        echo_warn "~/.local/bin is NOT in your PATH"
        echo_warn "The 'tribanft' command will not be available in your shell"
        echo ""
        echo_warn "To fix this, add the following to your ~/.bashrc or ~/.zshrc:"
        echo_warn "  export PATH=\"\${HOME}/.local/bin:\${PATH}\""
        echo ""
        echo_warn "Then reload your shell configuration:"
        echo_warn "  source ~/.bashrc  (or source ~/.zshrc)"
        echo ""
        read -p "Continue installation anyway? [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo_error "Installation aborted"
            exit 1
        fi
    else
        echo_info "~/.local/bin is in PATH"
    fi
}

check_systemd() {
    echo_progress "Checking systemd availability..."

    if ! command -v systemctl &> /dev/null; then
        echo_warn "systemd not detected - service installation will be skipped"
        echo_warn "You will need to run tribanft manually or use another init system"
        return 1
    fi

    echo_info "systemd detected"
    return 0
}

# =============================================================================
# Installation Functions
# =============================================================================

install_dependencies() {
    echo_progress "Installing Python dependencies..."

    if ! pip3 install --user pyyaml pydantic pydantic-settings watchdog 2>&1 | grep -i "successfully\|already satisfied" > /dev/null; then
        echo_error "Failed to install Python dependencies"
        echo_error "Please check your internet connection and pip configuration"
        exit 1
    fi

    echo_info "Dependencies installed successfully"
}

backup_existing() {
    if [ ! -d "$INSTALL_DIR" ]; then
        echo_info "No existing installation found (first install)"
        return
    fi

    echo_progress "Backing up existing installation..."

    local backed_up=0

    # Backup configuration file
    if [ -f "$INSTALL_DIR/config.conf" ]; then
        cp "$INSTALL_DIR/config.conf" "$INSTALL_DIR/config.conf.backup.$BACKUP_SUFFIX"
        echo_info "  Backed up: config.conf"
        ((backed_up++))
    fi

    # Backup blacklist files
    if [ -f "$INSTALL_DIR/blacklist_ipv4.txt" ]; then
        cp "$INSTALL_DIR/blacklist_ipv4.txt" "$INSTALL_DIR/blacklist_ipv4.backup.$BACKUP_SUFFIX"
        echo_info "  Backed up: blacklist_ipv4.txt"
        ((backed_up++))
    fi

    if [ -f "$INSTALL_DIR/blacklist_ipv6.txt" ]; then
        cp "$INSTALL_DIR/blacklist_ipv6.txt" "$INSTALL_DIR/blacklist_ipv6.backup.$BACKUP_SUFFIX"
        echo_info "  Backed up: blacklist_ipv6.txt"
        ((backed_up++))
    fi

    # Backup whitelist
    if [ -f "$INSTALL_DIR/whitelist_ips.txt" ]; then
        cp "$INSTALL_DIR/whitelist_ips.txt" "$INSTALL_DIR/whitelist_ips.backup.$BACKUP_SUFFIX"
        echo_info "  Backed up: whitelist_ips.txt"
        ((backed_up++))
    fi

    # Backup old code
    if [ -d "$INSTALL_DIR/bruteforce_detector" ]; then
        mv "$INSTALL_DIR/bruteforce_detector" "$INSTALL_DIR/bruteforce_detector.old.$BACKUP_SUFFIX"
        echo_info "  Backed up: bruteforce_detector/ (code)"
        ((backed_up++))
    fi

    if [ $backed_up -gt 0 ]; then
        echo_info "Backup completed: ${backed_up} item(s) backed up with suffix .$BACKUP_SUFFIX"
    else
        echo_info "No files to backup"
    fi
}

install_files() {
    echo_progress "Installing TribanFT files to ${INSTALL_DIR}..."

    # Create installation directory
    mkdir -p "$INSTALL_DIR"

    # Copy core Python package
    if [ ! -d "$SCRIPT_DIR/bruteforce_detector" ]; then
        echo_error "bruteforce_detector/ directory not found in ${SCRIPT_DIR}"
        echo_error "Please run this script from the TribanFT source directory"
        exit 1
    fi
    cp -r "$SCRIPT_DIR/bruteforce_detector" "$INSTALL_DIR/"
    echo_info "  Copied: bruteforce_detector/"

    # Copy scripts
    if [ -d "$SCRIPT_DIR/scripts" ]; then
        cp -r "$SCRIPT_DIR/scripts" "$INSTALL_DIR/"
        chmod +x "$INSTALL_DIR/scripts"/*.sh
        echo_info "  Copied: scripts/ (made executable)"
    fi

    # Copy systemd service files
    if [ -d "$SCRIPT_DIR/systemd" ]; then
        cp -r "$SCRIPT_DIR/systemd" "$INSTALL_DIR/"
        echo_info "  Copied: systemd/"
    fi

    # Copy setup.py and configuration
    cp "$SCRIPT_DIR/setup.py" "$INSTALL_DIR/"
    cp "$SCRIPT_DIR/config.conf.template" "$INSTALL_DIR/"
    echo_info "  Copied: setup.py, config.conf.template"

    # Copy documentation (optional)
    [ -f "$SCRIPT_DIR/README.md" ] && cp "$SCRIPT_DIR/README.md" "$INSTALL_DIR/" && echo_info "  Copied: README.md"
    [ -f "$SCRIPT_DIR/LICENSE" ] && cp "$SCRIPT_DIR/LICENSE" "$INSTALL_DIR/" && echo_info "  Copied: LICENSE"

    echo_info "Files installed successfully"
}

install_package() {
    echo_progress "Installing TribanFT Python package..."

    # Change to install directory
    cd "$INSTALL_DIR" || exit 1

    # Install package in editable mode
    # This creates ~/.local/bin/tribanft entry point
    if ! pip3 install --user -e . > /dev/null 2>&1; then
        echo_error "Failed to install package"
        echo_error "Run 'pip3 install --user -e $INSTALL_DIR' manually to see full error"
        exit 1
    fi

    # Verify entry point was created
    if [ ! -f "$HOME/.local/bin/tribanft" ]; then
        echo_error "Entry point not found at ~/.local/bin/tribanft"
        echo_error "Package installation may have failed"
        exit 1
    fi

    echo_info "Entry point created: ~/.local/bin/tribanft"
    echo_info "Package installed successfully"
}

setup_config() {
    echo_progress "Configuring TribanFT..."

    if [ -f "$INSTALL_DIR/config.conf" ]; then
        echo_info "config.conf already exists (preserved from backup)"
        echo_info "Review your configuration for any new settings"
        return
    fi

    echo_info "Creating config.conf from template..."
    cp "$SCRIPT_DIR/config.conf.template" "$INSTALL_DIR/config.conf"

    # Set learning mode by default (safe for first install)
    if command -v sed &> /dev/null; then
        sed -i 's/enable_nftables_update = true/enable_nftables_update = false/' \
            "$INSTALL_DIR/config.conf" 2>/dev/null || true
        echo_info "Learning mode enabled (NFTables blocking DISABLED for safety)"
        echo_warn "Week 1 Recommendation: Monitor detections before enabling blocking"
    fi

    echo_info "Configuration created successfully"
}

validate_install() {
    echo_progress "Validating installation..."

    cd "$INSTALL_DIR" || exit 1

    # Test Python imports
    if ! python3 -c "from bruteforce_detector.core.plugin_manager import PluginManager; from bruteforce_detector.core.rule_engine import RuleEngine" 2>/dev/null; then
        echo_error "Import validation failed"
        echo_error "Python package may not be installed correctly"
        exit 1
    fi
    echo_info "  Python imports: OK"

    # Validate detector YAML files
    local yaml_count=0
    for f in "$INSTALL_DIR/bruteforce_detector/rules/detectors"/*.yaml; do
        if [ -f "$f" ]; then
            if ! python3 -c "import yaml; yaml.safe_load(open('$f'))" 2>/dev/null; then
                echo_error "Invalid YAML: $(basename "$f")"
                exit 1
            fi
            ((yaml_count++))
        fi
    done
    echo_info "  Detector YAMLs: ${yaml_count} files validated"

    # Validate parser YAML files
    yaml_count=0
    for f in "$INSTALL_DIR/bruteforce_detector/rules/parsers"/*.yaml; do
        if [ -f "$f" ]; then
            if ! python3 -c "import yaml; yaml.safe_load(open('$f'))" 2>/dev/null; then
                echo_error "Invalid YAML: $(basename "$f")"
                exit 1
            fi
            ((yaml_count++))
        fi
    done
    echo_info "  Parser YAMLs: ${yaml_count} files validated"

    # Test tribanft command
    if [ -f "$HOME/.local/bin/tribanft" ]; then
        if ! "$HOME/.local/bin/tribanft" --help > /dev/null 2>&1; then
            echo_warn "tribanft command exists but --help failed"
            echo_warn "You may need to check your installation"
        else
            echo_info "  Command check: tribanft --help works"
        fi
    fi

    echo_info "Installation validated successfully"
}

setup_systemd() {
    if ! check_systemd; then
        echo_info "Skipping systemd service setup (systemd not available)"
        return
    fi

    if [ ! -d "$INSTALL_DIR/systemd" ]; then
        echo_warn "systemd/ directory not found, skipping service setup"
        return
    fi

    echo_progress "Setting up systemd service..."

    if [ ! -f "$INSTALL_DIR/systemd/tribanft.service" ]; then
        echo_warn "tribanft.service file not found, skipping"
        return
    fi

    # Check if sudo is available
    if ! command -v sudo &> /dev/null; then
        echo_warn "sudo not available, cannot install systemd service"
        echo_info "Manually copy: $INSTALL_DIR/systemd/tribanft.service to /etc/systemd/system/"
        return
    fi

    # Install service file
    if ! sudo cp "$INSTALL_DIR/systemd/tribanft.service" /etc/systemd/system/ 2>&1; then
        echo_warn "Failed to copy service file (requires sudo)"
        echo_info "Manually copy: sudo cp $INSTALL_DIR/systemd/tribanft.service /etc/systemd/system/"
        return
    fi

    # Reload systemd
    if ! sudo systemctl daemon-reload 2>&1; then
        echo_warn "Failed to reload systemd daemon"
    fi

    echo_info "Systemd service installed successfully"
}

# =============================================================================
# Main Installation
# =============================================================================

main() {
    echo ""
    echo_info "======================================="
    echo_info "  TribanFT Installation v2.9.2"
    echo_info "======================================="
    echo ""

    # Prerequisite checks
    check_python
    check_path

    # Installation steps
    install_dependencies
    backup_existing
    install_files
    setup_config
    install_package
    validate_install
    setup_systemd

    echo ""
    echo_info "======================================="
    echo_info "  Installation Completed Successfully!"
    echo_info "======================================="
    echo ""
    echo_info "Installation directory: ${INSTALL_DIR}"
    echo_info ""
    echo_info "Next Steps:"
    echo_info ""
    echo_info "1. Review Configuration:"
    echo_info "   vim ${INSTALL_DIR}/config.conf"
    echo_info ""
    echo_info "2. Test TribanFT:"
    echo_info "   tribanft --help"
    echo_info "   tribanft --detect"
    echo_info ""
    echo_info "3. Enable Systemd Service (optional):"
    echo_info "   sudo systemctl enable tribanft"
    echo_info "   sudo systemctl start tribanft"
    echo_info ""
    echo_info "4. Monitor Service:"
    echo_info "   sudo systemctl status tribanft"
    echo_info "   sudo journalctl -u tribanft -f"
    echo_info ""
    echo_warn "IMPORTANT: NFTables blocking is DISABLED by default (learning mode)"
    echo_warn "Monitor detections for 1 week before enabling blocking in config.conf"
    echo ""
}

main "$@"
