#!/bin/bash

# AKS Flex Node Service Uninstallation Script
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

echo -e "${RED}Uninstalling AKS Flex Node Service...${NC}"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root (use sudo)${NC}"
   exit 1
fi

# Stop and disable any running service instances
echo -e "${YELLOW}Stopping and disabling service instances...${NC}"
systemctl stop aks-flex-node@bootstrap.service 2>/dev/null || true
systemctl disable aks-flex-node@bootstrap.service 2>/dev/null || true
systemctl stop aks-flex-node@unbootstrap.service 2>/dev/null || true
systemctl disable aks-flex-node@unbootstrap.service 2>/dev/null || true

# Run unbootstrap directly using the CLI before removing the service
echo -e "${YELLOW}Running unbootstrap to clean up the node...${NC}"
if [[ -f "/usr/local/bin/aks-flex-node" && -f "/etc/aks-flex-node/config.json" ]]; then
    /usr/local/bin/aks-flex-node unbootstrap --config /etc/aks-flex-node/config.json
    if [[ $? -eq 0 ]]; then
        echo -e "${GREEN}Unbootstrap completed successfully${NC}"
    else
        echo -e "${RED}Unbootstrap failed, continuing with service cleanup...${NC}"
    fi
else
    echo -e "${YELLOW}aks-flex-node binary or config not found, skipping unbootstrap${NC}"
fi

# Remove systemd service file
echo -e "${YELLOW}Removing systemd service file...${NC}"
rm -f /etc/systemd/system/aks-flex-node@.service

# Remove sudo configuration
echo -e "${YELLOW}Removing sudo configuration...${NC}"
rm -f /etc/sudoers.d/aks-flex-node

# Reload systemd
echo -e "${YELLOW}Reloading systemd...${NC}"
systemctl daemon-reload

# Remove binary
echo -e "${YELLOW}Removing binary...${NC}"
rm -f "$INSTALL_DIR/aks-flex-node"

# Ask before removing user and data
echo ""
read -p "Remove service user '$SERVICE_USER'? [y/N]: " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}Removing service user...${NC}"
    userdel "$SERVICE_USER" 2>/dev/null || true
else
    echo -e "${YELLOW}Keeping service user '$SERVICE_USER'${NC}"
fi

echo ""
read -p "Remove configuration directory '$CONFIG_DIR'? [y/N]: " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}Removing configuration directory...${NC}"
    rm -rf "$CONFIG_DIR"
else
    echo -e "${YELLOW}Keeping configuration directory '$CONFIG_DIR'${NC}"
fi

echo ""
read -p "Remove data directory '$DATA_DIR'? [y/N]: " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}Removing data directory...${NC}"
    rm -rf "$DATA_DIR"
else
    echo -e "${YELLOW}Keeping data directory '$DATA_DIR'${NC}"
fi

echo ""
read -p "Remove log directory '$LOG_DIR'? [y/N]: " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}Removing log directory...${NC}"
    rm -rf "$LOG_DIR"
else
    echo -e "${YELLOW}Keeping log directory '$LOG_DIR'${NC}"
fi

echo ""
echo -e "${GREEN}AKS Flex Node Service uninstalled successfully!${NC}"