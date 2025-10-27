# AKS Flex Node Systemd Service

This document describes how to install, configure, and manage the AKS Flex Node as a systemd service.

## Overview

The AKS Flex Node can be packaged and run as a systemd service to automatically connect non-Azure VMs to AKS clusters through VPN Gateway connectivity. The service setup includes:

- **Main Service**: `aks-flex-node.service` - Executes the complete setup workflow
- **Health Monitoring**: `aks-flex-node-health.timer` - Periodic health checks
- **Continuous Monitoring**: `aks-flex-node-monitor.service` - Real-time monitoring (optional)

## Installation

### Automatic Installation

Use the provided installation script:

```bash
# Make sure you're in the project root
cd aks-flex-node

# Run the installation script
sudo ./scripts/install.sh
```

### Manual Installation

```bash
# Build the project
make build

# Install using Makefile
make install
```

### Package Installation (if available)

```bash
# Install via APT (if package is available)
sudo apt update
sudo apt install aks-flex-node

# Or install .deb package directly
sudo dpkg -i aks-flex-node_*.deb
```

## Configuration

### Prerequisites

1. **Azure CLI**: Must be installed and authenticated
   ```bash
   # Install Azure CLI
   curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

   # Login to Azure
   az login
   ```

2. **Configuration File**: Edit `/etc/aks-flex-node/aks-flex-node.yaml`
   ```yaml
   # Azure Configuration
   azure:
     subscriptionId: "your-subscription-id"
     resourceGroup: "your-resource-group"
     tenantId: "your-tenant-id"
     location: "your-location"

   # Agent Configuration
   agent:
     logLevel: "info"
     logFile: "/var/log/aks-flex-node/agent.log"
   ```

## Service Management

### Main Setup Service

The main service performs the complete AKS node setup workflow:

```bash
# Enable the service to run on boot
sudo systemctl enable aks-flex-node

# Start the setup process
sudo systemctl start aks-flex-node

# Check status
sudo systemctl status aks-flex-node

# View logs
sudo journalctl -u aks-flex-node -f
```

**What it does:**
1. Registers the node with Azure Arc
2. Sets up VPN connection with auto-provisioning
3. Bootstraps Kubernetes node components
4. Joins the node to the AKS cluster

### Health Monitoring

Enable periodic health checks:

```bash
# Enable health monitoring (runs every 5 minutes)
sudo systemctl enable aks-flex-node-health.timer
sudo systemctl start aks-flex-node-health.timer

# Check timer status
sudo systemctl status aks-flex-node-health.timer

# View health check logs
sudo journalctl -u aks-flex-node-health -f
```

### Continuous Monitoring (Optional)

For real-time monitoring:

```bash
# Enable continuous monitoring
sudo systemctl enable aks-flex-node-monitor
sudo systemctl start aks-flex-node-monitor

# Check status
sudo systemctl status aks-flex-node-monitor

# View monitoring logs
sudo journalctl -u aks-flex-node-monitor -f
```

## Service Types and Behavior

### Main Service (`aks-flex-node.service`)

- **Type**: `oneshot` with `RemainAfterExit=yes`
- **Behavior**: Runs the complete setup once and remains "active" after completion
- **Restart**: Does not automatically restart on failure
- **Timeout**: 30 minutes for setup, 5 minutes for cleanup

### Health Timer (`aks-flex-node-health.timer`)

- **Type**: Timer that triggers health service every 5 minutes
- **Behavior**: Runs `aks-flex-node status` periodically
- **Logs**: Health status and any issues detected

### Monitor Service (`aks-flex-node-monitor.service`)

- **Type**: `simple` - continuous running service
- **Behavior**: Checks status every 5 minutes in a loop
- **Restart**: Automatically restarts on failure

## Troubleshooting

### Check Service Status

```bash
# Main service status
sudo systemctl status aks-flex-node

# All related services
sudo systemctl status aks-flex-node*
```

### View Logs

```bash
# Main service logs
sudo journalctl -u aks-flex-node -f

# Health check logs
sudo journalctl -u aks-flex-node-health -f

# All AKS Flex Node logs
sudo journalctl -t aks-flex-node* -f

# Application-specific logs
sudo tail -f /var/log/aks-flex-node/agent.log
```

### Manual Operations

If the service fails, you can run commands manually:

```bash
# Check current status
aks-flex-node status

# Register with Arc manually
aks-flex-node arc register

# Setup VPN manually
aks-flex-node bootstrap-vpn --auto-provision

# Bootstrap node manually
aks-flex-node bootstrap-node

# Reset everything
aks-flex-node reset --force
```

### Common Issues

1. **Service fails to start**
   - Check Azure CLI authentication: `az account show`
   - Verify configuration file: `/etc/aks-flex-node/aks-flex-node.yaml`
   - Check permissions on directories: `/var/lib/aks-flex-node`, `/var/log/aks-flex-node`

2. **VPN connection fails**
   - Verify Azure subscriptions and permissions
   - Check network connectivity to Azure
   - Review VPN Gateway provisioning logs

3. **Node fails to join cluster**
   - Ensure VPN connection is established
   - Verify cluster credentials and configuration
   - Check kubelet service status: `sudo systemctl status kubelet`

## Uninstallation

### Automatic Uninstallation

```bash
# Use the uninstall script
sudo ./scripts/uninstall.sh
```

### Manual Uninstallation

```bash
# Using Makefile
make uninstall

# Or manually
sudo systemctl stop aks-flex-node*
sudo systemctl disable aks-flex-node*
sudo rm -f /usr/bin/aks-flex-node
sudo rm -f /lib/systemd/system/aks-flex-node*
sudo rm -rf /etc/aks-flex-node
sudo rm -rf /var/lib/aks-flex-node
sudo rm -rf /var/log/aks-flex-node
sudo systemctl daemon-reload
```

## File Locations

| Component | Location | Purpose |
|-----------|----------|---------|
| Binary | `/usr/bin/aks-flex-node` | Main executable |
| Configuration | `/etc/aks-flex-node/aks-flex-node.yaml` | Service configuration |
| Service Files | `/lib/systemd/system/aks-flex-node*` | Systemd service definitions |
| State Data | `/var/lib/aks-flex-node/` | Runtime state and bootstrap tracking |
| Logs | `/var/log/aks-flex-node/` | Application logs |
| Journal Logs | `journalctl -u aks-flex-node*` | Systemd service logs |

## Security Considerations

The AKS Flex Node service requires elevated privileges to:
- Install and configure system components
- Manage network interfaces and VPN connections
- Configure Kubernetes components
- Manage systemd services

**Security measures implemented:**
- Runs as root but with capability restrictions where possible
- Read-write access limited to necessary directories
- Uses Azure managed identity for authentication when possible
- Logs all operations for audit purposes

## Best Practices

1. **Monitoring**: Enable health monitoring to detect issues early
2. **Logging**: Regularly review logs for warnings or errors
3. **Updates**: Keep the service updated with latest versions
4. **Backup**: Backup configuration before making changes
5. **Testing**: Test in non-production environments first
6. **Documentation**: Document any custom configurations or modifications