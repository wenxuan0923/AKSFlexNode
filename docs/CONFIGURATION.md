# Configuration Guide

This guide covers all configuration options for the AKS Flex Node Agent.

## Table of Contents

- [Configuration File Location](#configuration-file-location)
- [Configuration Structure](#configuration-structure)
- [Cluster Configuration](#cluster-configuration)
- [Azure Configuration](#azure-configuration)
- [Node Configuration](#node-configuration)
- [Container Runtime Configuration](#container-runtime-configuration)
- [Agent Configuration](#agent-configuration)
- [Feature Flags](#feature-flags)
- [Path Configuration](#path-configuration)
- [Environment Variables](#environment-variables)
- [Configuration Examples](#configuration-examples)

## Configuration File Location

The agent looks for configuration files in the following order:

1. File specified by `--config` flag
2. `/etc/aks-flex-node/aks-flex-node.yaml`
3. `$HOME/.aks-flex-node/aks-flex-node.yaml`
4. `./aks-flex-node.yaml` (current directory)

## Configuration Structure

The configuration file is written in YAML format with the following top-level sections:

```yaml
cluster:      # AKS cluster connection settings
azure:        # Azure-specific configuration
node:         # Node-specific settings
containerd:   # Container runtime configuration
kubernetes:   # Kubernetes component configuration
runc:         # Runtime configuration
agent:        # Agent behavior settings
features:     # Feature flags
paths:        # Directory and file paths
```

## Cluster Configuration

Controls how the agent connects to the AKS cluster:

```yaml
cluster:
  # Required: AKS cluster ARM resource ID
  resourceId: "/subscriptions/xxx/resourceGroups/xxx/providers/Microsoft.ContainerService/managedClusters/xxx"

  # Kubernetes API server endpoint (auto-discovered if empty)
  server: "https://xxx.hcp.region.azmk8s.io"

  # Path to cluster CA certificate
  caCert: "/etc/kubernetes/certs/ca.crt"

  # Cluster DNS service IP
  clusterDNS: "10.245.2.10"

  # Cluster domain name
  clusterDomain: "cluster.local"
```

### Required Fields

- `resourceId`: The full ARM resource ID of your AKS cluster

### Optional Fields

- `server`: Auto-discovered from cluster metadata if not specified
- `caCert`: Default path works for most configurations
- `clusterDNS`: Should match your cluster's DNS service IP
- `clusterDomain`: Should match your cluster's domain

## Azure Configuration

Configures Azure integration and authentication:

```yaml
azure:
  # Azure subscription ID (auto-discovered from Arc if empty)
  subscriptionId: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

  # Resource group name (auto-discovered from Arc if empty)
  resourceGroup: "my-resource-group"

  # Azure tenant ID (auto-discovered from Arc if empty)
  tenantId: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

  # Azure region (auto-discovered from Arc if empty)
  location: "eastus"

  # Azure cloud environment
  cloud: "AzureCloud"
```

### Auto-Discovery

If Azure Arc is properly configured on the node, these values will be auto-discovered:
- `subscriptionId`
- `resourceGroup`
- `tenantId`
- `location`

### Cloud Environments

Supported values for `cloud`:
- `AzureCloud` (default)
- `AzureGovernmentCloud`
- `AzureChinaCloud`

## Node Configuration

Defines node-specific settings and Kubernetes configuration:

```yaml
node:
  # Node name (uses hostname if empty)
  name: ""

  # Maximum pods per node
  maxPods: 110

  # Node labels to apply
  labels:
    kubernetes.azure.com/mode: "user"
    kubernetes.azure.com/role: "agent"
    kubernetes.azure.com/managed: "false"
    kubernetes.azure.com/stretch: "true"
    node.kubernetes.io/exclude-from-external-load-balancers: "true"
    custom.label/example: "value"

  # Node taints (optional)
  taints:
    - "key=value:NoSchedule"
    - "special-node=true:NoExecute"

  # Kubelet configuration
  kubelet:
    # Memory reserved for system processes
    kubeReserved:
      cpu: "100m"
      memory: "200Mi"

    # Eviction thresholds
    evictionHard:
      memory.available: "100Mi"
      nodefs.available: "10%"
      nodefs.inodesFree: "5%"

    # Image garbage collection thresholds
    imageGCHighThreshold: 85
    imageGCLowThreshold: 80
```

### Node Labels

Common AKS node labels:
- `kubernetes.azure.com/cluster`: Cluster identifier
- `kubernetes.azure.com/agentpool`: Agent pool name
- `kubernetes.azure.com/mode`: Node mode (system/user)
- `kubernetes.azure.com/role`: Node role (agent)
- `kubernetes.azure.com/managed`: Whether node is managed by AKS
- `kubernetes.azure.com/stretch`: Whether node supports stretched clusters

### Node Taints

Use taints to control pod scheduling:
- Format: `key=value:effect` or `key:effect`
- Effects: `NoSchedule`, `PreferNoSchedule`, `NoExecute`

### Kubelet Resource Reservations

Configure resources reserved for system processes:
- `kubeReserved`: Resources reserved for Kubernetes components
- `systemReserved`: Resources reserved for system processes
- `evictionHard`: Hard eviction thresholds

## Container Runtime Configuration

Configures containerd and related components:

```yaml
containerd:
  # Containerd version to install
  version: "1.7.20"

  # Pause container image
  pauseImage: "mcr.microsoft.com/oss/kubernetes/pause:3.6"

  # Metrics endpoint address
  metricsAddress: "0.0.0.0:10257"

kubernetes:
  # Kubernetes version to install
  version: "1.32.7"

  # Download URL template for Kubernetes binaries
  urlTemplate: "https://acs-mirror.azureedge.net/kubernetes/v%s/binaries/kubernetes-node-linux-%s.tar.gz"

runc:
  # Runc version to install
  version: "1.1.12"

  # Download URL for runc binary
  url: "https://github.com/opencontainers/runc/releases/download/v1.1.12/runc.amd64"
```

### Version Compatibility

Ensure version compatibility:
- Kubernetes version should match your cluster version
- Containerd version should be compatible with Kubernetes
- Runc version should be compatible with containerd

## Agent Configuration

Controls agent behavior and operational settings:

```yaml
agent:
  # Log level (debug, info, warn, error)
  logLevel: "info"

  # Log file path
  logFile: "/var/log/aks-flex-node/agent.log"

  # Health check interval
  healthCheckInterval: "30s"

  # Configuration refresh interval
  configRefreshInterval: "5m"

  # Bootstrap operation timeout
  bootstrapTimeout: "10m"

  # Enable HTTP metrics endpoint
  metricsEnabled: true

  # HTTP server port for metrics and health endpoints
  metricsPort: 8080

  # PID file location
  pidFile: "/var/run/aks-flex-node.pid"
```

### Log Levels

- `debug`: Verbose debugging information
- `info`: General operational messages
- `warn`: Warning messages
- `error`: Error messages only

### Time Intervals

Use Go duration format:
- `30s`: 30 seconds
- `5m`: 5 minutes
- `1h`: 1 hour
- `24h`: 24 hours

## Feature Flags

Enable or disable specific features:

```yaml
features:
  # Enable automatic bootstrap on startup
  autoBootstrap: true

  # Enable health monitoring
  healthMonitoring: true

  # Enable automatic service recovery
  autoRecovery: true

  # Enable Azure Arc integration
  azureArcIntegration: true

  # Enable certificate rotation
  certRotation: true
```

### Feature Descriptions

- `autoBootstrap`: Automatically bootstrap the node if not already done
- `healthMonitoring`: Continuously monitor component health
- `autoRecovery`: Automatically restart failed services
- `azureArcIntegration`: Use Azure Arc for authentication
- `certRotation`: Automatically rotate certificates (future feature)

## Path Configuration

Customize file and directory locations:

```yaml
paths:
  # Configuration directory
  configDir: "/etc/aks-flex-node"

  # Data directory
  dataDir: "/var/lib/aks-flex-node"

  # Log directory
  logDir: "/var/log/aks-flex-node"

  # Kubernetes paths
  kubernetes:
    configDir: "/etc/kubernetes"
    certsDir: "/etc/kubernetes/certs"
    manifestsDir: "/etc/kubernetes/manifests"
    volumePluginDir: "/etc/kubernetes/volumeplugins"
    kubeletDir: "/var/lib/kubelet"

  # CNI paths
  cni:
    binDir: "/opt/cni/bin"
    confDir: "/etc/cni/net.d"
    libDir: "/var/lib/cni"
```

### Standard Paths

These paths follow Kubernetes and Linux conventions:
- `/etc/kubernetes`: Kubernetes configuration
- `/var/lib/kubelet`: Kubelet data directory
- `/opt/cni/bin`: CNI plugin binaries
- `/etc/cni/net.d`: CNI configuration

## Environment Variables

Override configuration values using environment variables:

```bash
# Prefix all environment variables with AKS_NODE_CONTROLLER_
export AKS_NODE_CONTROLLER_CLUSTER_RESOURCEID="/subscriptions/xxx/resourceGroups/xxx/providers/Microsoft.ContainerService/managedClusters/xxx"
export AKS_NODE_CONTROLLER_AGENT_LOGLEVEL="debug"
export AKS_NODE_CONTROLLER_FEATURES_AUTOBOOTSTRAP="false"
```

### Variable Format

- Prefix: `AKS_NODE_CONTROLLER_`
- Nested values: Use underscores to separate levels
- Example: `cluster.resourceId` becomes `AKS_NODE_CONTROLLER_CLUSTER_RESOURCEID`

## Configuration Examples

### Minimal Configuration

```yaml
cluster:
  resourceId: "/subscriptions/xxx/resourceGroups/xxx/providers/Microsoft.ContainerService/managedClusters/xxx"

azure:
  subscriptionId: "xxx"
  resourceGroup: "my-rg"
  tenantId: "xxx"
  location: "eastus"
```

### Development Configuration

```yaml
cluster:
  resourceId: "/subscriptions/xxx/resourceGroups/xxx/providers/Microsoft.ContainerService/managedClusters/xxx"
  server: "https://my-cluster.hcp.eastus.azmk8s.io"

azure:
  subscriptionId: "xxx"
  resourceGroup: "dev-rg"
  tenantId: "xxx"
  location: "eastus"

agent:
  logLevel: "debug"
  healthCheckInterval: "10s"
  metricsEnabled: true

features:
  autoBootstrap: true
  healthMonitoring: true
  autoRecovery: false  # Disable for debugging
```

### Production Configuration

```yaml
cluster:
  resourceId: "/subscriptions/xxx/resourceGroups/xxx/providers/Microsoft.ContainerService/managedClusters/xxx"

azure:
  subscriptionId: "xxx"
  resourceGroup: "prod-rg"
  tenantId: "xxx"
  location: "eastus"

node:
  maxPods: 250
  labels:
    kubernetes.azure.com/mode: "user"
    kubernetes.azure.com/role: "agent"
    environment: "production"
    workload-type: "compute-intensive"
  kubelet:
    kubeReserved:
      cpu: "200m"
      memory: "500Mi"
    evictionHard:
      memory.available: "500Mi"
      nodefs.available: "5%"

agent:
  logLevel: "info"
  healthCheckInterval: "60s"
  configRefreshInterval: "10m"
  metricsEnabled: true

features:
  autoBootstrap: true
  healthMonitoring: true
  autoRecovery: true
  azureArcIntegration: true
```

### High Availability Configuration

```yaml
cluster:
  resourceId: "/subscriptions/xxx/resourceGroups/xxx/providers/Microsoft.ContainerService/managedClusters/xxx"

node:
  labels:
    kubernetes.azure.com/mode: "system"
    node-role.kubernetes.io/control-plane: ""
  taints:
    - "CriticalAddonsOnly=true:NoSchedule"
  kubelet:
    kubeReserved:
      cpu: "500m"
      memory: "1Gi"

agent:
  healthCheckInterval: "15s"
  bootstrapTimeout: "15m"

features:
  autoBootstrap: true
  healthMonitoring: true
  autoRecovery: true
```

## Configuration Validation

Validate your configuration:

```bash
# Check configuration syntax
sudo aks-flex-node daemon --config /etc/aks-flex-node/aks-flex-node.yaml --validate-only

# Test configuration with dry-run
sudo aks-flex-node daemon --config /etc/aks-flex-node/aks-flex-node.yaml --dry-run
```

## Configuration Hot Reload

The agent automatically reloads configuration changes based on the `configRefreshInterval` setting. Some changes require a service restart:

**Hot reloadable:**
- Log level changes
- Health check intervals
- Feature flags (some)

**Requires restart:**
- Cluster configuration
- Azure configuration
- Path changes
- HTTP server settings