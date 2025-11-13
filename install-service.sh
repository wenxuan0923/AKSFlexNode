#!/bin/bash

# AKS Flex Node Service Installation Script
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
SERVICE_NAME="aks-flex-node"
SERVICE_USER="aks-flex-node"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/aks-flex-node"
DATA_DIR="/var/lib/aks-flex-node"
LOG_DIR="/var/log/aks-flex-node"

echo -e "${GREEN}Installing AKS Flex Node Service...${NC}"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root (use sudo)${NC}"
   exit 1
fi

# Check if Go is installed, install if needed
if ! command -v go &> /dev/null && [[ ! -x "/usr/local/go/bin/go" ]]; then
    echo -e "${YELLOW}Go not found, installing Go...${NC}"

    # Detect architecture
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) GO_ARCH="amd64" ;;
        aarch64) GO_ARCH="arm64" ;;
        armv7l) GO_ARCH="armv6l" ;;
        *) echo -e "${RED}Unsupported architecture: $ARCH${NC}"; exit 1 ;;
    esac

    # Download and install Go
    GO_VERSION="1.23.3"
    GO_TARBALL="go${GO_VERSION}.linux-${GO_ARCH}.tar.gz"

    echo -e "${YELLOW}Downloading Go ${GO_VERSION} for ${GO_ARCH}...${NC}"
    wget -q "https://golang.org/dl/${GO_TARBALL}" -O "/tmp/${GO_TARBALL}"

    echo -e "${YELLOW}Installing Go to /usr/local...${NC}"
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "/tmp/${GO_TARBALL}"

    # Add Go to PATH for current session
    export PATH=/usr/local/go/bin:$PATH

    # Add Go to system PATH permanently
    if ! grep -q "/usr/local/go/bin" /etc/environment; then
        sed -i 's|PATH="\(.*\)"|PATH="/usr/local/go/bin:\1"|' /etc/environment
    fi

    # Clean up
    rm -f "/tmp/${GO_TARBALL}"

    echo -e "${GREEN}Go ${GO_VERSION} installed successfully${NC}"
else
    # Check Go version using either the PATH version or the direct path
    if command -v go &> /dev/null; then
        echo -e "${GREEN}Go is already installed: $(go version)${NC}"
    elif [[ -x "/usr/local/go/bin/go" ]]; then
        echo -e "${GREEN}Go is already installed: $(/usr/local/go/bin/go version)${NC}"
    fi
fi

# Build the binary if it doesn't exist
if [[ ! -f "./aks-flex-node" ]]; then
    echo -e "${YELLOW}Building aks-flex-node binary...${NC}"

    # Get the directory where this script is located
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    # Change to the script directory to ensure we're in the right place for Go build
    cd "$SCRIPT_DIR"

    # Verify go.mod exists
    if [[ ! -f "go.mod" ]]; then
        echo -e "${RED}Error: go.mod not found in $SCRIPT_DIR${NC}"
        echo -e "${RED}Please run this script from the AKSFlexNode project root directory${NC}"
        exit 1
    fi

    # Use Go from PATH if available, otherwise use direct path
    if command -v go &> /dev/null; then
        go build -o aks-flex-node .
    elif [[ -x "/usr/local/go/bin/go" ]]; then
        /usr/local/go/bin/go build -o aks-flex-node .
    else
        echo -e "${RED}Error: Go not found in PATH or /usr/local/go/bin/go${NC}"
        exit 1
    fi
fi

# Create service user
echo -e "${YELLOW}Creating service user...${NC}"
if ! id "$SERVICE_USER" &>/dev/null; then
    useradd --system --shell /bin/false --home-dir "$DATA_DIR" --create-home "$SERVICE_USER"
    echo -e "${GREEN}Created user: $SERVICE_USER${NC}"
else
    echo -e "${YELLOW}User $SERVICE_USER already exists${NC}"
fi

# Install Azure Arc agent (required for himds group)
echo -e "${YELLOW}Installing Azure Arc agent...${NC}"
if ! command -v azcmagent &> /dev/null; then
    echo "Downloading Azure Arc agent installation script..."
    wget https://gbl.his.arc.azure.com/azcmagent-linux -O /tmp/install_linux_azcmagent.sh
    chmod +x /tmp/install_linux_azcmagent.sh
    echo "Installing Azure Arc agent..."
    bash /tmp/install_linux_azcmagent.sh
    rm -f /tmp/install_linux_azcmagent.sh
    echo -e "${GREEN}Azure Arc agent installed successfully${NC}"
else
    echo -e "${GREEN}Azure Arc agent already installed${NC}"
fi

# Add service user to himds group (created by Arc agent installation)
echo -e "${YELLOW}Adding $SERVICE_USER to himds group...${NC}"
usermod -a -G himds "$SERVICE_USER"

# Give service user access to current user's Azure CLI config (for development)
echo -e "${YELLOW}Configuring Azure CLI access for service user...${NC}"
CURRENT_USER=$(logname 2>/dev/null || whoami)
CURRENT_USER_HOME=$(eval echo "~$CURRENT_USER")

if [[ -d "$CURRENT_USER_HOME/.azure" ]]; then
    # Add service user to current user's group for Azure CLI access
    usermod -a -G "$CURRENT_USER" "$SERVICE_USER"
    # Set group read/write permissions on Azure CLI directory and files
    chmod g+rwX "$CURRENT_USER_HOME/.azure"
    chmod g+rw "$CURRENT_USER_HOME/.azure"/*
    echo -e "${GREEN}Azure CLI access configured for service user (user: $CURRENT_USER)${NC}"
else
    echo -e "${YELLOW}Azure CLI not found at $CURRENT_USER_HOME/.azure - skipping CLI access setup${NC}"
fi

# Configure sudo permissions
echo -e "${YELLOW}Configuring sudo permissions for $SERVICE_USER...${NC}"
cp ./aks-flex-node-sudoers /etc/sudoers.d/aks-flex-node
chmod 440 /etc/sudoers.d/aks-flex-node
chown root:root /etc/sudoers.d/aks-flex-node

# Validate sudoers syntax
if ! visudo -c -f /etc/sudoers.d/aks-flex-node; then
    echo -e "${RED}Error: Invalid sudoers configuration. Removing...${NC}"
    rm -f /etc/sudoers.d/aks-flex-node
    exit 1
fi
echo -e "${GREEN}Sudo permissions configured successfully${NC}"

# Create directories
echo -e "${YELLOW}Creating directories...${NC}"
mkdir -p "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR"
chown root:root "$CONFIG_DIR"
chown "$SERVICE_USER:$SERVICE_USER" "$DATA_DIR" "$LOG_DIR"
chmod 755 "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR"

# Ensure log file can be created with correct permissions
echo -e "${YELLOW}Setting up log file permissions...${NC}"
touch "$LOG_DIR/aks-flex-node.log"
chown "$SERVICE_USER:$SERVICE_USER" "$LOG_DIR/aks-flex-node.log"
chmod 644 "$LOG_DIR/aks-flex-node.log"

# Install binary
echo -e "${YELLOW}Installing binary...${NC}"
cp ./aks-flex-node "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/aks-flex-node"
chown root:root "$INSTALL_DIR/aks-flex-node"

# Check if config file exists - prompt user to create it if missing
CONFIG_FILE_MISSING=false
if [[ ! -f "$CONFIG_DIR/config.json" ]]; then
    CONFIG_FILE_MISSING=true
    echo -e "${RED}Configuration file not found: $CONFIG_DIR/config.json${NC}"
    echo -e "${YELLOW}Please create the configuration file before starting the service.${NC}"
    echo -e "${YELLOW}Example configuration:${NC}"
    cat << EOF
{
  "azure": {
    "subscriptionId": "YOUR_SUBSCRIPTION_ID",
    "tenantId": "YOUR_TENANT_ID",
    "cloud": "AzurePublicCloud",
    "arc": {
      "machineName": "YOUR_MACHINE_NAME",
      "tags": {
        "node-type": "edge"
      },
      "resourceGroup": "YOUR_RESOURCE_GROUP",
      "location": "YOUR_LOCATION"
    },
    "targetCluster": {
      "resourceId": "/subscriptions/YOUR_SUBSCRIPTION_ID/resourceGroups/YOUR_RESOURCE_GROUP/providers/Microsoft.ContainerService/managedClusters/YOUR_CLUSTER_NAME",
      "location": "YOUR_LOCATION"
    }
  },
  "agent": {
    "logLevel": "info",
    "logDir": "/var/log/aks-flex-node"
  }
}
EOF
    echo ""
    echo -e "${YELLOW}Save this configuration to: $CONFIG_DIR/config.json${NC}"
else
    echo -e "${GREEN}Configuration file found: $CONFIG_DIR/config.json${NC}"
fi

# Install systemd service file
echo -e "${YELLOW}Installing systemd service file...${NC}"
cp ./aks-flex-node@.service /etc/systemd/system/
chmod 644 /etc/systemd/system/aks-flex-node@.service

# Update the service file with the correct user path for Azure CLI access
echo -e "${YELLOW}Configuring service file for current user ($CURRENT_USER)...${NC}"
sed -i "s|Environment=AZURE_CONFIG_DIR=/home/ubuntu/.azure|Environment=AZURE_CONFIG_DIR=$CURRENT_USER_HOME/.azure|g" /etc/systemd/system/aks-flex-node@.service
sed -i "s|SupplementaryGroups=himds|SupplementaryGroups=himds $CURRENT_USER|g" /etc/systemd/system/aks-flex-node@.service

# Reload systemd
echo -e "${YELLOW}Reloading systemd...${NC}"
systemctl daemon-reload

# Enable the bootstrap service only if config file exists
if [[ "$CONFIG_FILE_MISSING" == "false" ]]; then
    echo -e "${YELLOW}Enabling bootstrap service...${NC}"
    systemctl enable aks-flex-node@bootstrap.service
    echo -e "${GREEN}Service enabled and ready to start${NC}"
else
    echo -e "${YELLOW}Service installation complete but NOT enabled${NC}"
    echo -e "${RED}Please create the configuration file before enabling/starting the service${NC}"
fi

# Check status
echo -e "${GREEN}Installation complete!${NC}"
echo ""
echo -e "${YELLOW}Service Status:${NC}"
echo "Parametric service installed: aks-flex-node@.service"

if [[ "$CONFIG_FILE_MISSING" == "false" ]]; then
    echo "Service is enabled and ready to start"
    echo "Use 'systemctl status aks-flex-node@bootstrap' or 'systemctl status aks-flex-node@unbootstrap' to check specific operations"
    echo ""
    echo -e "${YELLOW}Useful Commands:${NC}"
    echo "  Bootstrap node:       systemctl start aks-flex-node@bootstrap"
    echo "  Unbootstrap node:     systemctl start aks-flex-node@unbootstrap"
    echo "  Check bootstrap logs: journalctl -u aks-flex-node@bootstrap -f"
    echo "  Check unbootstrap logs: journalctl -u aks-flex-node@unbootstrap -f"
    echo "  Service status:       systemctl status aks-flex-node@bootstrap"
else
    echo -e "${RED}Service is NOT enabled (missing configuration file)${NC}"
    echo ""
    echo -e "${YELLOW}After creating the config file, enable the service with:${NC}"
    echo "  sudo systemctl enable aks-flex-node@bootstrap.service"
    echo "  sudo systemctl start aks-flex-node@bootstrap"
fi

echo "  CLI bootstrap:        /usr/local/bin/aks-flex-node bootstrap --config $CONFIG_DIR/config.json"
echo "  CLI unbootstrap:      /usr/local/bin/aks-flex-node unbootstrap --config $CONFIG_DIR/config.json"
echo ""
echo -e "${YELLOW}Configuration file:${NC} $CONFIG_DIR/config.json"
echo -e "${YELLOW}Log directory:${NC} $LOG_DIR"
echo -e "${YELLOW}Data directory:${NC} $DATA_DIR"