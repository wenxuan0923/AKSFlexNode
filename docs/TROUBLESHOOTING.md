# Troubleshooting Guide

This guide helps you diagnose and resolve common issues with the AKS Flex Node Agent.

## Table of Contents

- [Service Issues](#service-issues)
- [Bootstrap Issues](#bootstrap-issues)
- [Health Check Issues](#health-check-issues)
- [Configuration Issues](#configuration-issues)
- [Network Issues](#network-issues)
- [Log Analysis](#log-analysis)
- [Advanced Debugging](#advanced-debugging)

## Service Issues

### Service Won't Start

**Symptoms:**
- `systemctl start aks-flex-node` fails
- Service shows as "failed" in `systemctl status`

**Diagnosis:**
```bash
# Check service status
sudo systemctl status aks-flex-node

# Check logs
sudo journalctl -u aks-flex-node -n 50

# Check configuration
sudo aks-flex-node status
```

**Common Solutions:**
1. **Configuration errors:**
   ```bash
   # Validate configuration
   sudo aks-flex-node daemon --config /etc/aks-flex-node/aks-flex-node.yaml --dry-run
   ```

2. **Permission issues:**
   ```bash
   # Fix ownership
   sudo chown -R root:root /etc/aks-flex-node
   sudo chown -R aks-flex-node:aks-flex-node /var/lib/aks-flex-node
   sudo chown -R aks-flex-node:aks-flex-node /var/log/aks-flex-node
   ```

3. **Missing dependencies:**
   ```bash
   # Install missing dependencies
   sudo apt update
   sudo apt install -y curl jq systemd
   ```

### Service Keeps Restarting

**Symptoms:**
- Service restarts frequently
- High restart count in `systemctl status`

**Diagnosis:**
```bash
# Check restart count and recent logs
sudo systemctl status aks-flex-node
sudo journalctl -u aks-flex-node --since "1 hour ago"
```

**Common Solutions:**
1. **Health check failures:**
   ```bash
   # Run manual health check
   sudo aks-flex-node health
   ```

2. **Resource exhaustion:**
   ```bash
   # Check system resources
   free -h
   df -h
   ```

3. **Configuration reload issues:**
   ```bash
   # Disable config auto-reload temporarily
   # Edit /etc/aks-flex-node/aks-flex-node.yaml
   # Set configRefreshInterval to a larger value
   ```

## Bootstrap Issues

### Bootstrap Fails

**Symptoms:**
- `aks-flex-node bootstrap` command fails
- Node remains in unbootstrapped state

**Diagnosis:**
```bash
# Check if already bootstrapped
sudo aks-flex-node status

# Run bootstrap with verbose logging
sudo aks-flex-node bootstrap --config /etc/aks-flex-node/aks-flex-node.yaml -v
```

**Common Solutions:**
1. **Network connectivity:**
   ```bash
   # Test connectivity to required endpoints
   curl -I https://acs-mirror.azureedge.net
   curl -I https://github.com/opencontainers/runc/releases
   ```

2. **Insufficient disk space:**
   ```bash
   # Check disk space
   df -h
   # Clean up if needed
   sudo apt clean
   sudo docker system prune -f  # if docker is installed
   ```

3. **Permission issues:**
   ```bash
   # Ensure running as root
   sudo aks-flex-node bootstrap
   ```

4. **Previous installation remnants:**
   ```bash
   # Reset before bootstrap
   sudo aks-flex-node reset --force
   sudo aks-flex-node bootstrap
   ```

### Kubernetes Components Won't Start

**Symptoms:**
- kubelet service fails to start
- containerd service fails to start

**Diagnosis:**
```bash
# Check individual services
sudo systemctl status kubelet
sudo systemctl status containerd

# Check service logs
sudo journalctl -u kubelet -n 50
sudo journalctl -u containerd -n 50
```

**Common Solutions:**
1. **Configuration errors:**
   ```bash
   # Check kubelet configuration
   sudo kubelet --config=/var/lib/kubelet/config.yaml --dry-run

   # Check containerd configuration
   sudo containerd config dump
   ```

2. **Missing certificates:**
   ```bash
   # Check certificate files
   ls -la /etc/kubernetes/certs/

   # Verify certificate validity
   sudo openssl x509 -in /etc/kubernetes/certs/ca.crt -text -noout
   ```

3. **SELinux issues (if applicable):**
   ```bash
   # Check SELinux status
   sestatus

   # Temporarily disable SELinux
   sudo setenforce 0
   ```

## Health Check Issues

### Health Checks Always Fail

**Symptoms:**
- `aks-flex-node health` shows unhealthy status
- Health monitoring triggers constant recovery attempts

**Diagnosis:**
```bash
# Run detailed health check
sudo aks-flex-node health --json

# Check individual components
sudo systemctl status kubelet
sudo systemctl status containerd
```

**Common Solutions:**
1. **Service startup delays:**
   ```bash
   # Increase health check interval in config
   # Edit /etc/aks-flex-node/aks-flex-node.yaml
   # Set healthCheckInterval: "60s"
   ```

2. **Kubelet health endpoint issues:**
   ```bash
   # Test kubelet health endpoint directly
   curl -k http://localhost:10248/healthz
   ```

3. **Containerd socket issues:**
   ```bash
   # Check containerd socket
   ls -la /run/containerd/containerd.sock
   sudo crictl ps  # if crictl is available
   ```

## Configuration Issues

### Invalid Configuration

**Symptoms:**
- Service fails to start with configuration errors
- Commands fail with "config validation failed"

**Diagnosis:**
```bash
# Validate configuration syntax
sudo aks-flex-node daemon --config /etc/aks-flex-node/aks-flex-node.yaml --validate-only
```

**Common Solutions:**
1. **YAML syntax errors:**
   ```bash
   # Check YAML syntax
   python3 -c "import yaml; yaml.safe_load(open('/etc/aks-flex-node/aks-flex-node.yaml'))"
   ```

2. **Missing required fields:**
   ```bash
   # Copy from template and fill in required values
   sudo cp /usr/share/doc/aks-flex-node/examples/config.yaml /etc/aks-flex-node/aks-flex-node.yaml
   ```

3. **Incorrect paths:**
   ```bash
   # Verify paths exist
   ls -la /etc/kubernetes/certs/ca.crt
   ls -la /var/lib/kubelet/
   ```

### Azure Arc Authentication Issues

**Symptoms:**
- Kubelet fails to authenticate with API server
- Token retrieval fails

**Diagnosis:**
```bash
# Check Arc agent status
sudo azcmagent show

# Test token retrieval manually
sudo /var/lib/kubelet/token.sh
```

**Common Solutions:**
1. **Arc agent not installed:**
   ```bash
   # Install Arc agent
   wget https://aka.ms/azcmagent -O /tmp/install_linux_azcmagent.sh
   sudo bash /tmp/install_linux_azcmagent.sh
   ```

2. **Arc agent not connected:**
   ```bash
   # Connect Arc agent
   sudo azcmagent connect --resource-group "<resource-group>" \
     --tenant-id "<tenant-id>" \
     --location "<location>" \
     --subscription-id "<subscription-id>"
   ```

3. **Token script permissions:**
   ```bash
   # Fix token script permissions
   sudo chmod 755 /var/lib/kubelet/token.sh
   sudo chown root:root /var/lib/kubelet/token.sh
   ```

## Network Issues

### Cannot Reach API Server

**Symptoms:**
- Health checks fail with network errors
- Kubelet cannot connect to API server

**Diagnosis:**
```bash
# Test API server connectivity
curl -k https://<api-server-endpoint>/healthz

# Check network configuration
ip route show
ip addr show
```

**Common Solutions:**
1. **Firewall blocking connections:**
   ```bash
   # Check firewall rules
   sudo iptables -L
   sudo ufw status  # if ufw is used

   # Allow required ports
   sudo ufw allow 443/tcp  # API server
   sudo ufw allow 10250/tcp  # kubelet
   ```

2. **DNS resolution issues:**
   ```bash
   # Test DNS resolution
   nslookup <api-server-hostname>

   # Check DNS configuration
   cat /etc/resolv.conf
   ```

3. **Proxy configuration:**
   ```bash
   # Check proxy settings
   echo $HTTP_PROXY
   echo $HTTPS_PROXY
   echo $NO_PROXY
   ```

## Log Analysis

### Finding Relevant Logs

**System logs:**
```bash
# AKS Flex Node logs
sudo journalctl -u aks-flex-node -f

# Kubelet logs
sudo journalctl -u kubelet -f

# Containerd logs
sudo journalctl -u containerd -f

# System logs
sudo journalctl -f
```

**Application logs:**
```bash
# AKS Flex Node application logs
sudo tail -f /var/log/aks-flex-node/agent.log

# Kubernetes logs
sudo tail -f /var/log/pods/*/*/*.log
```

### Common Log Patterns

**Bootstrap issues:**
- Look for "bootstrap step" messages
- Check for download failures
- Look for permission denied errors

**Health check issues:**
- Look for "health check" messages
- Check for timeout errors
- Look for connection refused errors

**Configuration issues:**
- Look for "config" or "configuration" messages
- Check for validation errors
- Look for file not found errors

## Advanced Debugging

### Debug Mode

Enable debug logging:
```bash
# Edit configuration
sudo nano /etc/aks-flex-node/aks-flex-node.yaml

# Set logLevel: "debug"

# Restart service
sudo systemctl restart aks-flex-node
```

### Manual Component Testing

**Test kubelet manually:**
```bash
sudo /usr/local/bin/kubelet \
  --config=/var/lib/kubelet/config.yaml \
  --bootstrap-kubeconfig=/var/lib/kubelet/bootstrap-kubeconfig \
  --kubeconfig=/var/lib/kubelet/kubeconfig \
  --v=2
```

**Test containerd manually:**
```bash
sudo /usr/bin/containerd --config /etc/containerd/config.toml
```

### Trace Network Issues

```bash
# Trace route to API server
traceroute <api-server-hostname>

# Test with different tools
wget --spider https://<api-server-endpoint>/healthz
nc -zv <api-server-hostname> 443
```

### System Resource Monitoring

```bash
# Monitor system resources
top
htop
iotop
nethogs

# Check for resource exhaustion
dmesg | grep -i "out of memory"
dmesg | grep -i "no space left"
```

## Getting Help

If you're still experiencing issues:

1. **Collect diagnostic information:**
   ```bash
   # Run the diagnostic script
   sudo aks-flex-node status --json > /tmp/aks-status.json
   sudo aks-flex-node health --json > /tmp/aks-health.json
   sudo journalctl -u aks-flex-node --since "1 hour ago" > /tmp/aks-logs.txt
   ```

2. **Check the GitHub issues:**
   - Search existing issues: https://github.com/Azure/aks-one/issues
   - Create a new issue with diagnostic information

3. **Contact support:**
   - Include system information (OS, version, architecture)
   - Include configuration (with sensitive data redacted)
   - Include relevant logs and error messages