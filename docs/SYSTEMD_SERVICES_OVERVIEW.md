# AKS Flex Node Systemd Service Overview

This document provides a quick reference for the systemd service included in the AKS Flex Node package.

## Service File Created

### Main Setup Service
**File**: `configs/systemd/aks-flex-node.service`
**Type**: oneshot (RemainAfterExit=yes)

```bash
# Commands
systemctl enable aks-flex-node
systemctl start aks-flex-node
systemctl status aks-flex-node
```

**Purpose**: Executes the complete AKS node setup workflow:
- Azure Arc registration
- VPN Gateway provisioning and connection
- Kubernetes node bootstrapping
- Cluster joining

**Configuration**: Uses `/etc/aks-flex-node/config.yaml` for all settings

## Installation Scripts

### Install Script
**File**: `scripts/install.sh`
- Builds binary
- Installs all files and services
- Creates directories
- Provides usage instructions

### Uninstall Script
**File**: `scripts/uninstall.sh`
- Stops and disables all services
- Resets node configuration
- Removes files (with user confirmation)

## Makefile Integration

The Makefile has been updated with:
- `make install` - Installs all systemd services
- `make uninstall` - Removes all systemd services
- Improved output showing available services

## Usage Patterns

### Typical Setup Workflow

1. **Install Package**:
   ```bash
   sudo ./scripts/install.sh
   # or
   sudo make install
   ```

2. **Configure Azure Authentication**:
   ```bash
   az login
   ```

3. **Edit Configuration**:
   ```bash
   sudo nano /etc/aks-flex-node/config.yaml
   ```

4. **Enable and Start Service**:
   ```bash
   # Main setup (one-time)
   sudo systemctl enable aks-flex-node
   sudo systemctl start aks-flex-node
   ```

5. **Monitor Progress**:
   ```bash
   # Watch setup progress
   sudo journalctl -u aks-flex-node -f

   # Check final status
   sudo systemctl status aks-flex-node
   aks-flex-node status
   ```

### Service Management Commands

```bash
# View service status
systemctl status aks-flex-node

# Stop service
sudo systemctl stop aks-flex-node

# Restart service (re-run setup)
sudo systemctl restart aks-flex-node

# View logs
sudo journalctl -u aks-flex-node -f

# Check if service is enabled
systemctl is-enabled aks-flex-node
```

## Security and Permissions

The service runs as root and has elevated privileges for:
- Network configuration (VPN setup)
- System package installation
- Kubernetes component management
- Azure Arc operations

## File Locations Summary

| Component | Location |
|-----------|----------|
| Binary | `/usr/bin/aks-flex-node` |
| Config | `/etc/aks-flex-node/config.yaml` |
| Service | `/lib/systemd/system/aks-flex-node.service` |
| State | `/var/lib/aks-flex-node/` |
| Logs | `/var/log/aks-flex-node/` |
| Scripts | `scripts/install.sh`, `scripts/uninstall.sh` |

## Quick Reference Commands

```bash
# Installation
sudo ./scripts/install.sh

# Basic setup
sudo systemctl enable aks-flex-node
sudo systemctl start aks-flex-node

# Check status
systemctl status aks-flex-node
aks-flex-node status

# View logs
sudo journalctl -u aks-flex-node -f

# Reset/cleanup
aks-flex-node reset --force

# Uninstall
sudo ./scripts/uninstall.sh
```