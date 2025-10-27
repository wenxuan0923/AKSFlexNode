# Complete Guide: AKS Cluster with ExpressRoute and Regular VM Setup

This guide provides step-by-step instructions for creating an AKS cluster with ExpressRoute connectivity and joining a regular Ubuntu VM (on-premises or in another cloud) to the cluster using the aks-flex-node.

## Prerequisites

- Azure CLI installed and logged in
- Azure subscription with appropriate permissions
- ExpressRoute circuit provisioned by your network provider
- On-premises network or VM with Ubuntu (18.04+ or 20.04+)
- Network administrator access for BGP routing configuration
- Basic knowledge of Azure networking, ExpressRoute, and Kubernetes

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        Azure Cloud                              │
│  ┌─────────────────┐    ┌─────────────────────────────────────┐ │
│  │   AKS Cluster   │    │         Virtual Network            │ │
│  │                 │    │  ┌─────────────────────────────────┐ │ │
│  │  ┌───────────┐  │    │  │      ExpressRoute Gateway      │ │ │
│  │  │ Master    │  │    │  │                                 │ │ │
│  │  │ Nodes     │  │◄───┼──┤  - ExpressRoute Connection     │ │ │
│  │  └───────────┘  │    │  │  - Private Peering             │ │ │
│  └─────────────────┘    │  │  - BGP Routing                 │ │ │
│                         │  └─────────────────────────────────┘ │ │
└─────────────────────────┼────────────────────────────────────────┘
                          │
                          │ ExpressRoute Circuit
                          │ (MPLS/Ethernet)
                          │
                 ┌────────▼──────────┐
                 │  On-Premises      │
                 │  Data Center      │
                 │                   │
                 │  ┌─────────────┐  │
                 │  │ Ubuntu VM   │  │
                 │  │             │  │
                 │  │ aks-node-   │  │
                 │  │ controller  │  │
                 │  └─────────────┘  │
                 └───────────────────┘
```

## Part 1: Azure Infrastructure Setup with ExpressRoute

### Step 1: Create Resource Group and Base Network

```bash
# Set variables
RESOURCE_GROUP="aks-expressroute-demo"
LOCATION="eastus"
CLUSTER_NAME="aks-enterprise-cluster"
VNET_NAME="aks-enterprise-vnet"
SUBNET_NAME="aks-subnet"
GATEWAY_SUBNET="GatewaySubnet"
ER_GATEWAY_NAME="aks-er-gateway"
ER_CONNECTION_NAME="aks-er-connection"

# Your ExpressRoute circuit details (replace with actual values)
ER_CIRCUIT_ID="/subscriptions/YOUR_SUB/resourceGroups/YOUR_ER_RG/providers/Microsoft.Network/expressRouteCircuits/YOUR_CIRCUIT_NAME"
ER_PEERING_NAME="AzurePrivatePeering"

# Create resource group
az group create \
    --name $RESOURCE_GROUP \
    --location $LOCATION
```

### Step 2: Create Virtual Network with ExpressRoute Integration

```bash
# Create VNet with subnets
az network vnet create \
    --resource-group $RESOURCE_GROUP \
    --name $VNET_NAME \
    --address-prefixes 10.10.0.0/16 \
    --subnet-name $SUBNET_NAME \
    --subnet-prefixes 10.10.1.0/24

# Create Gateway subnet for ExpressRoute Gateway
az network vnet subnet create \
    --resource-group $RESOURCE_GROUP \
    --vnet-name $VNET_NAME \
    --name $GATEWAY_SUBNET \
    --address-prefixes 10.10.255.0/27

# Create additional subnets if needed
az network vnet subnet create \
    --resource-group $RESOURCE_GROUP \
    --vnet-name $VNET_NAME \
    --name "management-subnet" \
    --address-prefixes 10.10.2.0/24
```

### Step 3: Create ExpressRoute Gateway

```bash
# Create public IP for ExpressRoute gateway
az network public-ip create \
    --resource-group $RESOURCE_GROUP \
    --name "${ER_GATEWAY_NAME}-pip" \
    --allocation-method Static \
    --sku Standard

# Create ExpressRoute Gateway (this takes 20-45 minutes)
az network vnet-gateway create \
    --resource-group $RESOURCE_GROUP \
    --name $ER_GATEWAY_NAME \
    --public-ip-addresses "${ER_GATEWAY_NAME}-pip" \
    --vnet $VNET_NAME \
    --gateway-type ExpressRoute \
    --sku Standard \
    --no-wait

# Monitor gateway creation
echo "Monitoring ExpressRoute Gateway creation..."
while true; do
    STATUS=$(az network vnet-gateway show \
        --resource-group $RESOURCE_GROUP \
        --name $ER_GATEWAY_NAME \
        --query "provisioningState" -o tsv 2>/dev/null)

    if [ "$STATUS" = "Succeeded" ]; then
        echo "ExpressRoute Gateway created successfully!"
        break
    elif [ "$STATUS" = "Failed" ]; then
        echo "ExpressRoute Gateway creation failed!"
        exit 1
    else
        echo "Current status: $STATUS - waiting..."
        sleep 60
    fi
done
```

### Step 4: Connect ExpressRoute Circuit

```bash
# Create connection between ExpressRoute Gateway and Circuit
az network vpn-connection create \
    --resource-group $RESOURCE_GROUP \
    --name $ER_CONNECTION_NAME \
    --vnet-gateway1 $ER_GATEWAY_NAME \
    --express-route-circuit2 $ER_CIRCUIT_ID \
    --routing-weight 0

# Verify connection status
az network vpn-connection show \
    --resource-group $RESOURCE_GROUP \
    --name $ER_CONNECTION_NAME \
    --query "connectionStatus" -o tsv
```

### Step 5: Create AKS Cluster with Private Networking

```bash
# Create AKS cluster with VNet integration and private cluster option
az aks create \
    --resource-group $RESOURCE_GROUP \
    --name $CLUSTER_NAME \
    --node-count 3 \
    --node-vm-size Standard_DS3_v2 \
    --network-plugin azure \
    --vnet-subnet-id $(az network vnet subnet show \
        --resource-group $RESOURCE_GROUP \
        --vnet-name $VNET_NAME \
        --name $SUBNET_NAME \
        --query id -o tsv) \
    --service-cidr 10.11.0.0/24 \
    --dns-service-ip 10.11.0.10 \
    --docker-bridge-address 172.17.0.1/16 \
    --enable-private-cluster \
    --private-dns-zone system \
    --enable-managed-identity \
    --load-balancer-sku standard \
    --outbound-type userDefinedRouting \
    --generate-ssh-keys

# Get AKS credentials (may need to be done from a VM with ExpressRoute connectivity)
az aks get-credentials \
    --resource-group $RESOURCE_GROUP \
    --name $CLUSTER_NAME
```

## Part 2: Network Routing Configuration

### Step 6: Configure Route Tables

```bash
# Create route table for directing traffic through ExpressRoute
az network route-table create \
    --resource-group $RESOURCE_GROUP \
    --name "aks-route-table"

# Add route for on-premises networks (adjust CIDR as needed)
az network route-table route create \
    --resource-group $RESOURCE_GROUP \
    --route-table-name "aks-route-table" \
    --name "to-onpremises" \
    --address-prefix "192.168.0.0/16" \
    --next-hop-type VirtualNetworkGateway

# Associate route table with AKS subnet
az network vnet subnet update \
    --resource-group $RESOURCE_GROUP \
    --vnet-name $VNET_NAME \
    --name $SUBNET_NAME \
    --route-table "aks-route-table"
```

### Step 7: Configure Network Security Groups

```bash
# Create NSG for AKS subnet
az network nsg create \
    --resource-group $RESOURCE_GROUP \
    --name "aks-nsg"

# Allow ExpressRoute traffic
az network nsg rule create \
    --resource-group $RESOURCE_GROUP \
    --nsg-name "aks-nsg" \
    --name "allow-expressroute" \
    --priority 100 \
    --access Allow \
    --protocol "*" \
    --direction Inbound \
    --source-address-prefixes "192.168.0.0/16" \
    --source-port-ranges "*" \
    --destination-address-prefixes "*" \
    --destination-port-ranges "*"

# Allow Kubernetes API server access
az network nsg rule create \
    --resource-group $RESOURCE_GROUP \
    --nsg-name "aks-nsg" \
    --name "allow-k8s-api" \
    --priority 110 \
    --access Allow \
    --protocol "TCP" \
    --direction Inbound \
    --source-address-prefixes "192.168.0.0/16" \
    --source-port-ranges "*" \
    --destination-address-prefixes "*" \
    --destination-port-ranges "443"

# Associate NSG with subnet
az network vnet subnet update \
    --resource-group $RESOURCE_GROUP \
    --vnet-name $VNET_NAME \
    --name $SUBNET_NAME \
    --network-security-group "aks-nsg"
```

## Part 3: On-Premises Network Configuration

### Step 8: Configure BGP Routing (Network Administrator Task)

**Note**: This step requires coordination with your network administrator and ExpressRoute provider.

```bash
# On your on-premises router/firewall, configure BGP peering
# Example configuration (varies by vendor):

# Cisco Example:
# router bgp YOUR_ASN
#  neighbor AZURE_BGP_IP remote-as 12076
#  neighbor AZURE_BGP_IP activate
#  network 192.168.0.0 mask 255.255.0.0
#  network 192.168.1.0 mask 255.255.255.0

# Ensure routes to Azure VNet (10.10.0.0/16) are advertised
# Ensure on-premises networks are advertised to Azure
```

### Step 9: Verify ExpressRoute Connectivity

```bash
# From Azure CLI, check ExpressRoute circuit status
az network express-route show \
    --resource-group YOUR_ER_RG \
    --name YOUR_CIRCUIT_NAME \
    --query "circuitProvisioningState,serviceProviderProvisioningState"

# Check BGP peer status
az network express-route peering show \
    --resource-group YOUR_ER_RG \
    --circuit-name YOUR_CIRCUIT_NAME \
    --name AzurePrivatePeering \
    --query "azureAsn,peerAsn,primaryPeerAddressPrefix,secondaryPeerAddressPrefix,state"

# Check learned routes from on-premises
az network vnet-gateway list-learned-routes \
    --resource-group $RESOURCE_GROUP \
    --name $ER_GATEWAY_NAME \
    --query "value[?network=='192.168.0.0/16']"
```

## Part 4: On-Premises Ubuntu VM Setup

### Step 10: Prepare Ubuntu VM

Connect to your on-premises Ubuntu VM:

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install required dependencies
sudo apt install -y \
    curl \
    wget \
    gnupg \
    lsb-release \
    ca-certificates \
    apt-transport-https \
    software-properties-common \
    jq \
    git \
    net-tools \
    traceroute \
    dnsutils

# Install Go (required for building aks-flex-node)
wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc

# Verify Go installation
go version
```

### Step 11: Test Network Connectivity

```bash
# Test connectivity to Azure VNet
ping 10.10.1.1

# Test connectivity to AKS API server (get IP from Azure)
AKS_API_SERVER=$(az aks show \
    --resource-group $RESOURCE_GROUP \
    --name $CLUSTER_NAME \
    --query "privateFqdn" -o tsv)

echo "AKS API Server: $AKS_API_SERVER"

# Test API server connectivity
nslookup $AKS_API_SERVER
telnet $AKS_API_SERVER 443

# Test ExpressRoute path
traceroute 10.10.1.1
```

### Step 12: Install aks-flex-node

```bash
# Clone and build aks-flex-node
git clone <repository-url>
cd aks-flex-node
make build

# Install the binary
sudo cp build/bin/aks-flex-node /usr/local/bin/
sudo chmod +x /usr/local/bin/aks-flex-node

# Create configuration directory
sudo mkdir -p /etc/aks-flex-node

# Verify installation
aks-flex-node version
```

### Step 13: Create Configuration File

Create the configuration file `/etc/aks-flex-node/config.yaml`:

```bash
# Get cluster information
CLUSTER_API_SERVER=$(az aks show \
    --resource-group $RESOURCE_GROUP \
    --name $CLUSTER_NAME \
    --query "privateFqdn" -o tsv)

SUBSCRIPTION_ID=$(az account show --query "id" -o tsv)
TENANT_ID=$(az account show --query "tenantId" -o tsv)

# Create configuration file
sudo tee /etc/aks-flex-node/config.yaml > /dev/null <<EOF
cluster:
  resourceId: "/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.ContainerService/managedClusters/$CLUSTER_NAME"
  server: "https://$CLUSTER_API_SERVER:443"
  caCert: "/etc/kubernetes/certs/ca.crt"
  clusterDNS: "10.11.0.10"
  clusterDomain: "cluster.local"

azure:
  subscriptionId: "$SUBSCRIPTION_ID"
  resourceGroup: "$RESOURCE_GROUP"
  tenantId: "$TENANT_ID"
  location: "$LOCATION"

node:
  name: ""  # Auto-detected from hostname
  labels:
    kubernetes.azure.com/mode: "user"
    kubernetes.azure.com/role: "agent"
    node-type: "on-premises"
    location: "datacenter-1"
    connectivity: "expressroute"
  maxPods: 110
  kubelet:
    evictionHard:
      memory.available: "200Mi"
      nodefs.available: "10%"
    kubeReserved:
      cpu: "200m"
      memory: "2Gi"
    imageGCHighThreshold: 85
    imageGCLowThreshold: 80

# CNI Configuration
cni:
  type: "cilium"
  version: "1.14.5"

# Container Runtime
containerd:
  version: "1.7.13"
  pauseImage: "mcr.microsoft.com/oss/kubernetes/pause:3.9"
  metricsAddress: "127.0.0.1:1338"

# Runtime Configuration
runc:
  version: "1.1.12"

kubernetes:
  version: "1.31.1"
  urlTemplate: "https://dl.k8s.io/v%s/kubernetes-node-linux-%s.tar.gz"

agent:
  logLevel: "info"
  logFile: "/var/log/aks-flex-node/agent.log"
  pidFile: "/var/run/aks-flex-node.pid"
  healthCheckInterval: "30s"
  configRefreshInterval: "5m"

# Directory Paths
paths:
  dataDir: "/var/lib/aks-flex-node"
  logDir: "/var/log/aks-flex-node"
  cni:
    binDir: "/opt/cni/bin"
    confDir: "/etc/cni/net.d"
    libDir: "/var/lib/cni"
  kubernetes:
    kubeletDir: "/var/lib/kubelet"
    certsDir: "/etc/kubernetes/certs"
    manifestsDir: "/etc/kubernetes/manifests"
    volumePluginDir: "/etc/kubernetes/volumeplugins"
EOF
```

## Part 5: Bootstrap On-Premises Node to Cluster

### Step 14: Install Azure Arc Agent

```bash
# Download and install Azure Arc agent
wget https://aka.ms/azcmagent -O ~/install_linux_azcmagent.sh
chmod +x ~/install_linux_azcmagent.sh
sudo ~/install_linux_azcmagent.sh

# The Arc agent will be configured during the bootstrap process
```

### Step 15: Configure DNS Resolution

```bash
# Add Azure DNS entries if needed
# This may be required for private cluster access

# Option 1: Use Azure Private DNS zones (recommended)
# Configure your on-premises DNS to forward Azure zones to Azure DNS

# Option 2: Add static entries to /etc/hosts (temporary solution)
sudo bash -c "echo '10.10.1.4 $CLUSTER_API_SERVER' >> /etc/hosts"

# Verify DNS resolution
nslookup $CLUSTER_API_SERVER
```

### Step 16: Bootstrap Node to Cluster

```bash
# Bootstrap the node (standard bootstrap for ExpressRoute)
sudo aks-flex-node bootstrap

# This process will:
# 1. Install and configure Kubernetes components
# 2. Configure CNI networking with Cilium
# 3. Set up Azure Arc authentication via ExpressRoute
# 4. Join the node to the AKS cluster
# 5. Configure kubelet with appropriate settings

# Monitor the bootstrap process
sudo tail -f /var/log/aks-flex-node/agent.log
```

### Step 17: Verify Connection and Node Status

```bash
# Check aks-flex-node status
sudo aks-flex-node status

# Check health
sudo aks-flex-node health

# Check Kubernetes services
sudo systemctl status kubelet
sudo systemctl status containerd

# View kubelet logs
sudo journalctl -u kubelet -f

# Check network configuration
ip route show
ip addr show
```

## Part 6: Cluster Verification and Testing

### Step 18: Verify Node Registration

From a machine with kubectl access to the private cluster:

```bash
# List all nodes
kubectl get nodes -o wide

# Check the on-premises node specifically
kubectl get nodes -l node-type=on-premises

# Describe the node
kubectl describe node YOUR_ONPREM_NODE_NAME

# Check node labels and taints
kubectl get nodes --show-labels | grep YOUR_ONPREM_NODE_NAME
```

### Step 19: Test Network Connectivity

```bash
# Create a test pod that will run on the on-premises node
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: onprem-test-pod
  labels:
    app: onprem-test
spec:
  nodeSelector:
    node-type: "on-premises"
  containers:
  - name: network-test
    image: nicolaka/netshoot
    command: ["sleep", "3600"]
    resources:
      requests:
        memory: "128Mi"
        cpu: "100m"
      limits:
        memory: "256Mi"
        cpu: "200m"
EOF

# Wait for pod to be running
kubectl wait --for=condition=Ready pod/onprem-test-pod --timeout=300s

# Test network connectivity from the pod
kubectl exec -it onprem-test-pod -- ping 8.8.8.8
kubectl exec -it onprem-test-pod -- nslookup kubernetes.default.svc.cluster.local
kubectl exec -it onprem-test-pod -- wget -qO- http://httpbin.org/ip
```

### Step 20: Deploy Application Workload

Create a more comprehensive test application:

```yaml
# Save as onprem-app-test.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: onprem-nginx-app
  labels:
    app: onprem-nginx
spec:
  replicas: 2
  selector:
    matchLabels:
      app: onprem-nginx
  template:
    metadata:
      labels:
        app: onprem-nginx
    spec:
      nodeSelector:
        node-type: "on-premises"
      containers:
      - name: nginx
        image: nginx:latest
        ports:
        - containerPort: 80
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "256Mi"
            cpu: "200m"
        volumeMounts:
        - name: nginx-config
          mountPath: /usr/share/nginx/html/index.html
          subPath: index.html
      volumes:
      - name: nginx-config
        configMap:
          name: nginx-config
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: nginx-config
data:
  index.html: |
    <!DOCTYPE html>
    <html>
    <head>
        <title>On-Premises Node Test</title>
    </head>
    <body>
        <h1>Hello from On-Premises Node!</h1>
        <p>This application is running on an on-premises node connected via ExpressRoute.</p>
        <p>Node: $(hostname)</p>
        <p>Time: $(date)</p>
    </body>
    </html>
---
apiVersion: v1
kind: Service
metadata:
  name: onprem-nginx-service
spec:
  selector:
    app: onprem-nginx
  ports:
  - port: 80
    targetPort: 80
  type: ClusterIP
```

```bash
# Deploy the application
kubectl apply -f onprem-app-test.yaml

# Check deployment status
kubectl get deployment onprem-nginx-app
kubectl get pods -l app=onprem-nginx -o wide

# Test the service
kubectl run test-client --image=busybox --rm -it --restart=Never -- wget -qO- onprem-nginx-service
```

## Part 7: Production Configuration and Management

### Step 21: Set Up Systemd Service

```bash
# Create systemd service for automatic startup
sudo tee /etc/systemd/system/aks-flex-node.service > /dev/null <<EOF
[Unit]
Description=AKS Flex Node Agent
Documentation=https://github.com/your-org/aks-flex-node
After=network.target local-fs.target
Wants=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/aks-flex-node daemon --config /etc/aks-flex-node/config.yaml
Restart=always
RestartSec=10
KillMode=process
TimeoutSec=300

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=aks-flex-node

# Security
NoNewPrivileges=true
ProtectSystem=full

[Install]
WantedBy=multi-user.target
EOF

# Enable and start the service
sudo systemctl daemon-reload
sudo systemctl enable aks-flex-node
sudo systemctl start aks-flex-node

# Check service status
sudo systemctl status aks-flex-node
```

### Step 22: Configure Monitoring and Alerting

```bash
# Install monitoring tools
sudo apt install -y prometheus-node-exporter

# Configure node exporter
sudo systemctl enable prometheus-node-exporter
sudo systemctl start prometheus-node-exporter

# Create custom monitoring script
sudo tee /usr/local/bin/aks-node-monitor.sh > /dev/null <<'EOF'
#!/bin/bash
# Simple monitoring script for AKS node health

LOG_FILE="/var/log/aks-flex-node/monitor.log"

check_connectivity() {
    if ping -c 3 10.11.0.10 > /dev/null 2>&1; then
        echo "$(date): Cluster DNS connectivity OK" >> $LOG_FILE
        return 0
    else
        echo "$(date): ERROR - Cluster DNS connectivity failed" >> $LOG_FILE
        return 1
    fi
}

check_kubelet() {
    if systemctl is-active --quiet kubelet; then
        echo "$(date): Kubelet service OK" >> $LOG_FILE
        return 0
    else
        echo "$(date): ERROR - Kubelet service failed" >> $LOG_FILE
        systemctl restart kubelet
        return 1
    fi
}

check_expressroute() {
    if ip route | grep -q "10.10.0.0/16"; then
        echo "$(date): ExpressRoute routing OK" >> $LOG_FILE
        return 0
    else
        echo "$(date): WARNING - ExpressRoute routing issue" >> $LOG_FILE
        return 1
    fi
}

# Run checks
check_connectivity
check_kubelet
check_expressroute

# Send alerts if needed (customize as required)
if ! check_connectivity || ! check_kubelet; then
    # Add your alerting mechanism here (email, Slack, etc.)
    echo "$(date): ALERT - Critical issues detected" >> $LOG_FILE
fi
EOF

sudo chmod +x /usr/local/bin/aks-node-monitor.sh

# Create cron job for monitoring
echo "*/5 * * * * root /usr/local/bin/aks-node-monitor.sh" | sudo tee -a /etc/crontab
```

### Step 23: Configure Log Management

```bash
# Configure log rotation
sudo tee /etc/logrotate.d/aks-flex-node > /dev/null <<EOF
/var/log/aks-flex-node/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 0644 root root
    postrotate
        systemctl reload aks-flex-node 2>/dev/null || true
    endscript
}
EOF

# Configure rsyslog for centralized logging (optional)
sudo tee /etc/rsyslog.d/50-aks-flex-node.conf > /dev/null <<EOF
# AKS Flex Node logging
:programname,isequal,"aks-flex-node" /var/log/aks-flex-node/syslog.log
& stop
EOF

sudo systemctl restart rsyslog
```

## Part 8: Advanced Configuration

### Step 24: Configure High Availability

For production environments, consider setting up multiple on-premises nodes:

```bash
# On additional on-premises VMs, repeat the setup process
# Ensure proper load balancing and failover

# Configure node affinity for critical workloads
cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: critical-onprem-app
spec:
  replicas: 3
  selector:
    matchLabels:
      app: critical-app
  template:
    metadata:
      labels:
        app: critical-app
    spec:
      affinity:
        nodeAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            nodeSelectorTerms:
            - matchExpressions:
              - key: node-type
                operator: In
                values: ["on-premises"]
          preferredDuringSchedulingIgnoredDuringExecution:
          - weight: 100
            preference:
              matchExpressions:
              - key: connectivity
                operator: In
                values: ["expressroute"]
      containers:
      - name: app
        image: your-critical-app:latest
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "1Gi"
            cpu: "1000m"
EOF
```

### Step 25: Configure Security Policies

```bash
# Create network policies for on-premises workloads
cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: onprem-network-policy
spec:
  podSelector:
    matchLabels:
      location: "on-premises"
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          network-policy-allowed: "true"
    - podSelector:
        matchLabels:
          access-level: "trusted"
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          network-policy-allowed: "true"
  - to: []
    ports:
    - protocol: TCP
      port: 53
    - protocol: UDP
      port: 53
    - protocol: TCP
      port: 443
EOF

# Apply security context constraints
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: secure-onprem-pod
spec:
  nodeSelector:
    node-type: "on-premises"
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 2000
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: secure-app
    image: your-secure-app:latest
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
        - ALL
    resources:
      requests:
        memory: "256Mi"
        cpu: "200m"
      limits:
        memory: "512Mi"
        cpu: "400m"
EOF
```

## Troubleshooting

### Common Issues and Solutions

#### ExpressRoute Connectivity Issues

```bash
# Check ExpressRoute circuit status
az network express-route show \
    --resource-group YOUR_ER_RG \
    --name YOUR_CIRCUIT_NAME \
    --query "circuitProvisioningState,serviceProviderProvisioningState"

# Check BGP peering status
az network express-route peering show \
    --resource-group YOUR_ER_RG \
    --circuit-name YOUR_CIRCUIT_NAME \
    --name AzurePrivatePeering

# Test connectivity from on-premises
ping 10.10.1.1
traceroute 10.10.1.1

# Check routing table
ip route show
netstat -rn
```

#### DNS Resolution Issues

```bash
# Check DNS configuration
cat /etc/resolv.conf

# Test cluster DNS
nslookup kubernetes.default.svc.cluster.local 10.11.0.10

# Check private DNS zone configuration
az network private-dns zone list --resource-group $RESOURCE_GROUP

# Test API server resolution
nslookup $CLUSTER_API_SERVER
```

#### Node Registration Issues

```bash
# Check kubelet logs
sudo journalctl -u kubelet -f

# Check Arc agent status
sudo systemctl status azure-arc-agent

# Verify certificates
sudo ls -la /var/lib/kubelet/pki/

# Check API server connectivity
telnet $CLUSTER_API_SERVER 443
```

#### Network Policy Issues

```bash
# Check CNI logs
sudo journalctl -u cilium-agent -f

# Verify network policies
kubectl get networkpolicies -A

# Test pod-to-pod connectivity
kubectl exec -it test-pod -- ping other-pod-ip
kubectl exec -it test-pod -- nc -zv service-name port
```

## Maintenance and Operations

### Regular Maintenance Tasks

```bash
# Check system health
sudo aks-flex-node health --json

# Update node status
sudo aks-flex-node status

# Check ExpressRoute connectivity
ping 10.10.1.1
traceroute 10.10.1.1

# Monitor resource usage
kubectl top node YOUR_NODE_NAME
kubectl describe node YOUR_NODE_NAME

# Check for updates
sudo apt update && sudo apt list --upgradable
```

### Backup and Recovery

```bash
# Backup configuration
sudo tar -czf aks-node-backup-$(date +%Y%m%d).tar.gz \
    /etc/aks-flex-node/ \
    /var/lib/kubelet/config.yaml \
    /etc/systemd/system/aks-flex-node.service

# Create recovery script
sudo tee /usr/local/bin/aks-node-recovery.sh > /dev/null <<'EOF'
#!/bin/bash
# AKS Node Recovery Script

echo "Starting AKS node recovery..."

# Restart services
systemctl restart aks-flex-node
systemctl restart kubelet
systemctl restart containerd

# Wait for services to stabilize
sleep 30

# Check health
if aks-flex-node health; then
    echo "Recovery successful"
    exit 0
else
    echo "Recovery failed - manual intervention required"
    exit 1
fi
EOF

sudo chmod +x /usr/local/bin/aks-node-recovery.sh
```

### Performance Tuning

```bash
# Optimize for ExpressRoute latency
echo 'net.core.rmem_default = 262144' | sudo tee -a /etc/sysctl.conf
echo 'net.core.rmem_max = 16777216' | sudo tee -a /etc/sysctl.conf
echo 'net.core.wmem_default = 262144' | sudo tee -a /etc/sysctl.conf
echo 'net.core.wmem_max = 16777216' | sudo tee -a /etc/sysctl.conf
echo 'net.ipv4.tcp_rmem = 4096 65536 16777216' | sudo tee -a /etc/sysctl.conf
echo 'net.ipv4.tcp_wmem = 4096 65536 16777216' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Optimize kubelet configuration for on-premises
sudo tee -a /var/lib/kubelet/config.yaml <<EOF
nodeStatusUpdateFrequency: "4s"
imageGCHighThresholdPercent: 85
imageGCLowThresholdPercent: 80
maxPods: 110
evictionPressureTransitionPeriod: "5m"
EOF

sudo systemctl restart kubelet
```

## Security Considerations

1. **ExpressRoute Security**: Ensure proper BGP filtering and route advertisements
2. **Network Segmentation**: Use NSGs and network policies to control traffic
3. **Certificate Management**: Regularly rotate and monitor certificates
4. **Access Control**: Implement proper RBAC for cluster access
5. **Monitoring**: Set up comprehensive monitoring and alerting
6. **Updates**: Keep systems updated with security patches
7. **Backup**: Regular backup of configurations and certificates

## Cleanup

To remove the on-premises node and Azure resources:

```bash
# Remove node from cluster
kubectl delete node YOUR_ONPREM_NODE_NAME

# Stop services on on-premises VM
sudo systemctl stop aks-flex-node
sudo systemctl stop kubelet
sudo systemctl stop containerd

# Delete Azure resources
az group delete --name $RESOURCE_GROUP --yes --no-wait
```

## Summary

This guide covered:

1. **Azure Infrastructure**: Created AKS cluster with ExpressRoute connectivity
2. **ExpressRoute Setup**: Configured ExpressRoute Gateway and circuit connection
3. **Network Configuration**: Set up routing, NSGs, and DNS resolution
4. **On-Premises Setup**: Installed aks-flex-node on Ubuntu VM
5. **Cluster Integration**: Bootstrapped on-premises node to join AKS cluster
6. **Testing**: Verified connectivity and deployed test workloads
7. **Production Config**: Set up monitoring, logging, and maintenance procedures
8. **Security**: Implemented network policies and security best practices

The on-premises Ubuntu VM is now successfully connected to your AKS cluster via ExpressRoute and can run Kubernetes workloads with enterprise-grade networking and security.