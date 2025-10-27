#!/bin/bash

# AKS Flex Node Uninstallation Script
set -e

BINARY_NAME="aks-flex-node"
SERVICE_NAME="aks-flex-node"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root. Please use sudo."
        exit 1
    fi
}

# Stop and disable service
stop_service() {
    log_info "Stopping and disabling AKS Flex Node service..."

    if systemctl is-active --quiet "$SERVICE_NAME"; then
        systemctl stop "$SERVICE_NAME"
        log_success "Stopped $SERVICE_NAME service"
    else
        log_info "Service $SERVICE_NAME is not running"
    fi

    if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
        systemctl disable "$SERVICE_NAME"
        log_success "Disabled $SERVICE_NAME service"
    else
        log_info "Service $SERVICE_NAME is not enabled"
    fi
}

# Reset node configuration
reset_node() {
    log_info "Resetting node configuration..."

    if [[ -f "/usr/bin/$BINARY_NAME" ]]; then
        # Try to reset gracefully first
        if /usr/bin/$BINARY_NAME reset --force --config "/etc/$BINARY_NAME/config.yaml" 2>/dev/null; then
            log_success "Node reset completed"
        else
            log_warning "Graceful reset failed, proceeding with manual cleanup"
        fi
    else
        log_info "Binary not found, skipping reset"
    fi
}

# Remove files and directories
remove_files() {
    log_info "Removing AKS Flex Node files..."

    # Remove systemd service
    if [[ -f "/lib/systemd/system/$SERVICE_NAME.service" ]]; then
        rm -f "/lib/systemd/system/$SERVICE_NAME.service"
        log_success "Removed systemd service file"
    fi

    # Remove binary
    if [[ -f "/usr/bin/$BINARY_NAME" ]]; then
        rm -f "/usr/bin/$BINARY_NAME"
        log_success "Removed binary"
    fi

    # Remove configuration (ask user first)
    if [[ -d "/etc/$BINARY_NAME" ]]; then
        read -p "Remove configuration directory /etc/$BINARY_NAME? [y/N]: " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            rm -rf "/etc/$BINARY_NAME"
            log_success "Removed configuration directory"
        else
            log_info "Kept configuration directory"
        fi
    fi

    # Remove state directory (ask user first)
    if [[ -d "/var/lib/$BINARY_NAME" ]]; then
        read -p "Remove state directory /var/lib/$BINARY_NAME? [y/N]: " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            rm -rf "/var/lib/$BINARY_NAME"
            log_success "Removed state directory"
        else
            log_info "Kept state directory"
        fi
    fi

    # Remove log directory (ask user first)
    if [[ -d "/var/log/$BINARY_NAME" ]]; then
        read -p "Remove log directory /var/log/$BINARY_NAME? [y/N]: " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            rm -rf "/var/log/$BINARY_NAME"
            log_success "Removed log directory"
        else
            log_info "Kept log directory"
        fi
    fi

    # Reload systemd
    systemctl daemon-reload
    log_success "Reloaded systemd configuration"
}

# Show uninstallation summary
show_summary() {
    echo
    log_success "AKS Flex Node uninstalled successfully!"
    echo
    log_info "What was removed:"
    echo "  • Binary: /usr/bin/$BINARY_NAME"
    echo "  • Service: /lib/systemd/system/$SERVICE_NAME.service"
    echo "  • Systemd daemon reloaded"
    echo
    log_info "What might remain (if you chose to keep them):"
    echo "  • Configuration: /etc/$BINARY_NAME/"
    echo "  • State: /var/lib/$BINARY_NAME/"
    echo "  • Logs: /var/log/$BINARY_NAME/"
    echo
    log_warning "Note: Azure Arc registration and VPN connections were reset"
    log_warning "You may need to clean up Azure resources if they were created"
}

# Main uninstallation function
main() {
    log_info "Starting AKS Flex Node uninstallation..."

    check_root
    stop_service
    reset_node
    remove_files
    show_summary
}

# Run main function
main "$@"