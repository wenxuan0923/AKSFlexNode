#!/bin/bash

# AKS Flex Node Installation Script
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
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

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."

    # Check if Go is installed (for building)
    if ! command -v go &> /dev/null; then
        log_warning "Go is not installed. Will attempt to build binary if it exists."
    fi

    # Check if Azure CLI is installed
    if ! command -v az &> /dev/null; then
        log_error "Azure CLI is not installed. Please install it first:"
        log_error "  curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash"
        exit 1
    fi

    # Check if systemctl is available
    if ! command -v systemctl &> /dev/null; then
        log_error "systemd is not available on this system."
        exit 1
    fi

    log_success "Prerequisites check passed"
}

# Build the binary
build_binary() {
    log_info "Building AKS Flex Node binary..."

    cd "$PROJECT_ROOT"

    if [[ -f "build/bin/$BINARY_NAME" ]]; then
        log_info "Binary already exists in build directory"
        return 0
    fi

    if command -v make &> /dev/null; then
        make build
    else
        # Fallback to direct go build
        mkdir -p build/bin
        CGO_ENABLED=0 go build -o "build/bin/$BINARY_NAME" "./cmd/$BINARY_NAME"
    fi

    if [[ ! -f "build/bin/$BINARY_NAME" ]]; then
        log_error "Failed to build binary"
        exit 1
    fi

    log_success "Binary built successfully"
}

# Install the binary and configuration
install_files() {
    log_info "Installing AKS Flex Node files..."

    # Install binary
    install -D -m 0755 "$PROJECT_ROOT/build/bin/$BINARY_NAME" "/usr/bin/$BINARY_NAME"
    log_success "Installed binary to /usr/bin/$BINARY_NAME"

    # Install configuration
    mkdir -p "/etc/$BINARY_NAME"
    if [[ -f "$PROJECT_ROOT/configs/config.yaml" ]]; then
        install -D -m 0644 "$PROJECT_ROOT/configs/config.yaml" "/etc/$BINARY_NAME/config.yaml"
        log_success "Installed configuration to /etc/$BINARY_NAME/config.yaml"
    else
        log_warning "Configuration file not found, skipping"
    fi

    # Install systemd service
    install -D -m 0644 "$PROJECT_ROOT/configs/systemd/$SERVICE_NAME.service" "/lib/systemd/system/$SERVICE_NAME.service"
    log_success "Installed systemd service to /lib/systemd/system/$SERVICE_NAME.service"

    # Create directories with proper permissions
    mkdir -p "/var/lib/$BINARY_NAME" "/var/log/$BINARY_NAME"
    chown root:root "/var/lib/$BINARY_NAME" "/var/log/$BINARY_NAME"
    chmod 755 "/var/lib/$BINARY_NAME" "/var/log/$BINARY_NAME"
    log_success "Created state and log directories with proper permissions"

    # Reload systemd
    systemctl daemon-reload
    log_success "Reloaded systemd configuration"
}

# Show installation summary
show_summary() {
    echo
    log_success "AKS Flex Node installed successfully!"
    echo
    log_info "Installation Summary:"
    echo "  • Binary: /usr/bin/$BINARY_NAME"
    echo "  • Config: /etc/$BINARY_NAME/config.yaml"
    echo "  • Service: /lib/systemd/system/$SERVICE_NAME.service"
    echo "  • State Dir: /var/lib/$BINARY_NAME"
    echo "  • Log Dir: /var/log/$BINARY_NAME"
    echo
    log_info "Next Steps:"
    echo "  1. Configure Azure credentials: az login"
    echo "  2. Edit configuration: /etc/$BINARY_NAME/config.yaml"
    echo "  3. Enable service: systemctl enable $SERVICE_NAME"
    echo "  4. Start service: systemctl start $SERVICE_NAME"
    echo "  5. Check status: systemctl status $SERVICE_NAME"
    echo
    log_info "Testing:"
    echo "  • Test cert generation: sudo ./scripts/test-cert-permissions.sh"
    echo
    log_info "Manual Usage:"
    echo "  • Register Arc: $BINARY_NAME arc register"
    echo "  • Setup VPN: $BINARY_NAME bootstrap-vpn --auto-provision"
    echo "  • Setup Node: $BINARY_NAME bootstrap-node"
    echo "  • Check Status: $BINARY_NAME status"
    echo "  • Reset: $BINARY_NAME reset"
    echo
    log_info "Logs can be viewed with: journalctl -u $SERVICE_NAME -f"
}

# Main installation function
main() {
    log_info "Starting AKS Flex Node installation..."

    check_root
    check_prerequisites
    build_binary
    install_files
    show_summary
}

# Run main function
main "$@"