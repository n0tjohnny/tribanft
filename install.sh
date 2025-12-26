#!/bin/bash
# TribanFT Automated Installation Script
# Version: 2.5.9

set -e

INSTALL_DIR="${HOME}/.local/share/tribanft"
BACKUP_SUFFIX=$(date +%Y%m%d_%H%M%S)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
echo_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
echo_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check Python version
check_python() {
    echo_info "Checking Python version..."
    if ! command -v python3 &> /dev/null; then
        echo_error "Python 3 not found"
        exit 1
    fi

    REQUIRED="3.8"
    python_version=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    if [ "$(printf '%s\n' "$REQUIRED" "$python_version" | sort -V | head -n1)" != "$REQUIRED" ]; then
        echo_error "Python 3.8+ required (found $python_version)"
        exit 1
    fi
    echo_info "Python $python_version OK"
}

# Install dependencies
install_dependencies() {
    echo_info "Installing Python dependencies..."
    pip3 install --user pyyaml pydantic pydantic-settings watchdog
    echo_info "Dependencies installed"
}

# Backup existing installation
backup_existing() {
    if [ -d "$INSTALL_DIR" ]; then
        echo_info "Backing up existing installation..."

        [ -f "$INSTALL_DIR/config.conf" ] && \
            cp "$INSTALL_DIR/config.conf" "$INSTALL_DIR/config.conf.backup.$BACKUP_SUFFIX"

        [ -f "$INSTALL_DIR/blacklist_ipv4.txt" ] && \
            cp "$INSTALL_DIR/blacklist_ipv4.txt" "$INSTALL_DIR/blacklist_ipv4.backup.$BACKUP_SUFFIX"

        [ -f "$INSTALL_DIR/blacklist_ipv6.txt" ] && \
            cp "$INSTALL_DIR/blacklist_ipv6.txt" "$INSTALL_DIR/blacklist_ipv6.backup.$BACKUP_SUFFIX"

        [ -f "$INSTALL_DIR/whitelist_ips.txt" ] && \
            cp "$INSTALL_DIR/whitelist_ips.txt" "$INSTALL_DIR/whitelist_ips.backup.$BACKUP_SUFFIX"

        [ -d "$INSTALL_DIR/bruteforce_detector" ] && \
            mv "$INSTALL_DIR/bruteforce_detector" "$INSTALL_DIR/bruteforce_detector.old.$BACKUP_SUFFIX"

        echo_info "Backup completed: *.$BACKUP_SUFFIX"
    fi
}

# Install files
install_files() {
    echo_info "Installing TribanFT to $INSTALL_DIR..."

    mkdir -p "$INSTALL_DIR"

    # Copy Python package and supporting files
    cp -r "$SCRIPT_DIR/bruteforce_detector" "$INSTALL_DIR/"
    cp -r "$SCRIPT_DIR/scripts" "$INSTALL_DIR/"
    [ -d "$SCRIPT_DIR/systemd" ] && cp -r "$SCRIPT_DIR/systemd" "$INSTALL_DIR/"

    # Copy setup.py and dependencies needed for package installation
    cp "$SCRIPT_DIR/setup.py" "$INSTALL_DIR/"
    cp "$SCRIPT_DIR/config.conf.template" "$INSTALL_DIR/"
    [ -f "$SCRIPT_DIR/README.md" ] && cp "$SCRIPT_DIR/README.md" "$INSTALL_DIR/"
    [ -f "$SCRIPT_DIR/LICENSE" ] && cp "$SCRIPT_DIR/LICENSE" "$INSTALL_DIR/"

    chmod +x "$INSTALL_DIR/scripts"/*.sh

    echo_info "Files installed"
}

# Install package
install_package() {
    echo_info "Installing TribanFT package..."

    # Change to install directory where we copied setup.py
    cd "$INSTALL_DIR"

    # Install package in editable mode from install directory
    # This creates ~/.local/bin/tribanft entry point
    # Editable mode keeps code in ~/.local/share/tribanft (current architecture)
    if ! pip3 install --user -e . ; then
        echo_error "Failed to install package"
        exit 1
    fi

    # Verify entry point was created
    if [ -f "$HOME/.local/bin/tribanft" ]; then
        echo_info "✓ Entry point created: $HOME/.local/bin/tribanft"
    else
        echo_error "Entry point not found at $HOME/.local/bin/tribanft"
        exit 1
    fi

    echo_info "Package installation completed"
}

# Setup configuration
setup_config() {
    if [ ! -f "$INSTALL_DIR/config.conf" ]; then
        echo_info "Creating config.conf from template..."
        cp "$SCRIPT_DIR/config.conf.template" "$INSTALL_DIR/config.conf"

        # Set learning mode by default (no blocking)
        sed -i 's/enable_nftables_update = true/enable_nftables_update = false/' \
            "$INSTALL_DIR/config.conf" 2>/dev/null || true

        echo_info "Learning mode enabled (blocking disabled for Week 1)"
    else
        echo_info "config.conf already exists, keeping existing"
    fi
}

# Validate installation
validate_install() {
    echo_info "Validating installation..."

    cd "$INSTALL_DIR"

    # Test imports
    if ! python3 -c "from bruteforce_detector.core.plugin_manager import PluginManager; from bruteforce_detector.core.rule_engine import RuleEngine" 2>/dev/null; then
        echo_error "Import validation failed"
        exit 1
    fi

    # Validate YAML files
    for f in "$INSTALL_DIR/bruteforce_detector/rules/detectors"/*.yaml; do
        if ! python3 -c "import yaml; yaml.safe_load(open('$f'))" 2>/dev/null; then
            echo_error "Invalid YAML: $(basename "$f")"
            exit 1
        fi
    done

    for f in "$INSTALL_DIR/bruteforce_detector/rules/parsers"/*.yaml; do
        if ! python3 -c "import yaml; yaml.safe_load(open('$f'))" 2>/dev/null; then
            echo_error "Invalid YAML: $(basename "$f")"
            exit 1
        fi
    done

    echo_info "Validation passed"
}

# Setup systemd service
setup_systemd() {
    if [ ! -d "$INSTALL_DIR/systemd" ]; then
        echo_warn "systemd directory not found, skipping service setup"
        return
    fi

    echo_info "Setting up systemd service..."

    sudo cp "$INSTALL_DIR/systemd/tribanft.service" /etc/systemd/system/
    sudo systemctl daemon-reload

    echo_info "Systemd service installed"
    echo_info "Enable with: sudo systemctl enable tribanft"
    echo_info "Start with: sudo systemctl start tribanft"
}

# Main installation
main() {
    echo_info "TribanFT Installation v2.5.9"
    echo_info "=============================="

    check_python
    install_dependencies
    backup_existing
    install_files
    setup_config
    install_package
    validate_install
    setup_systemd

    echo_info ""
    echo_info "=============================="
    echo_info "Installation completed successfully!"
    echo_info ""
    echo_info "Next steps:"
    echo_info "1. Review config: $INSTALL_DIR/config.conf"
    echo_info "2. Enable service: sudo systemctl enable tribanft"
    echo_info "3. Start service: sudo systemctl start tribanft"
    echo_info "4. Check logs: sudo journalctl -u tribanft -f"
}

main "$@"
