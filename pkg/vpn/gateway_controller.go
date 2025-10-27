package vpn

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"go.goms.io/aks/AKSFlexNode/pkg/aks"
	"go.goms.io/aks/AKSFlexNode/pkg/arc"
	"go.goms.io/aks/AKSFlexNode/pkg/config"
	"go.goms.io/aks/AKSFlexNode/pkg/state"
	"go.goms.io/aks/AKSFlexNode/pkg/utils"
)

// VPNGatewayController handles VPN Gateway provisioning, certificate management, and VPN setup
type VPNGatewayController struct {
	config       *config.Config
	logger       *logrus.Logger
	arcManager   *arc.ArcManager
	vpnManager   *VPNManager
	stateManager *state.StateManager
}

// VPNSetupResult represents the result of VPN setup operations
type VPNSetupResult struct {
	Connected  bool
	ConfigPath string
}

// GatewayInfo represents VPN Gateway information
type GatewayInfo struct {
	Name          string
	State         string
	ResourceGroup string
}

// NewVPNGatewayController creates a new VPN Gateway Controller
func NewVPNGatewayController(cfg *config.Config, logger *logrus.Logger) *VPNGatewayController {
	return &VPNGatewayController{
		config:       cfg,
		logger:       logger,
		arcManager:   arc.NewArcManager(cfg, logger),
		vpnManager:   NewVPNManager(cfg),
		stateManager: state.NewStateManager(logger),
	}
}

// ProvisionAndSetupVPN handles complete VPN gateway lifecycle
func (vgc *VPNGatewayController) ProvisionAndSetupVPN(ctx context.Context) (*VPNSetupResult, error) {
	vgc.logger.Info("Starting VPN Gateway provisioning and setup...")

	// Load VPN-specific state
	vpnState, err := vgc.stateManager.LoadState()
	if err != nil {
		vgc.logger.Warnf("Could not load VPN state: %v, starting fresh", err)
		vpnState = &state.BootstrapState{
			CompletedSteps: make(map[string]bool),
			FailedSteps:    make(map[string]string),
		}
	}

	// Check if VPN is already established - if so, skip all VPN setup
	if vgc.vpnManager.IsVPNConnected() {
		vgc.logger.Info("VPN connection already established, skipping all VPN setup")
		return &VPNSetupResult{
			Connected:  true,
			ConfigPath: "", // No config needed, already connected
		}, nil
	}

	vgc.logger.Info("VPN not connected, proceeding with gateway provisioning...")

	// Step 1: Provision Gateway
	gatewayInfo, err := vgc.provisionGateway(ctx, vpnState)
	if err != nil {
		return nil, fmt.Errorf("gateway provisioning failed: %w", err)
	}

	// Step 2: Generate and Upload Certificates
	if err := vgc.setupCertificates(ctx, vpnState, gatewayInfo); err != nil {
		return nil, fmt.Errorf("certificate setup failed: %w", err)
	}

	// Step 3: Download VPN Configuration
	configPath, err := vgc.downloadVPNConfig(ctx, vpnState, gatewayInfo)
	if err != nil {
		return nil, fmt.Errorf("VPN config download failed: %w", err)
	}

	// Step 4: Establish VPN Connection
	connected, err := vgc.establishVPNConnection(ctx, vpnState, configPath)
	if err != nil {
		return nil, fmt.Errorf("VPN connection failed: %w", err)
	}

	vgc.logger.Info("VPN Gateway setup completed successfully")
	return &VPNSetupResult{
		Connected:  connected,
		ConfigPath: configPath,
	}, nil
}

// provisionGateway handles VPN Gateway provisioning with idempotency
func (vgc *VPNGatewayController) provisionGateway(ctx context.Context, state *state.BootstrapState) (*GatewayInfo, error) {

	// Now get full target cluster info with VNet details (this requires the permissions we just assigned)
	clusterInfo, err := vgc.arcManager.GetConnectedClusterInfoFromAzure(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get target cluster info: %w", err)
	}

	vgc.logger.Infof("Provisioning VPN Gateway for cluster: %s", clusterInfo.Name)

	// Provision VPN Gateway
	gatewayInfo, err := vgc.ProvisionVPNGateway(ctx, clusterInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to provision VPN Gateway: %w", err)
	}

	vgc.logger.Infof("VPN Gateway provisioned: %s (State: %s)", gatewayInfo.Name, gatewayInfo.State)

	// Get resource group for the gateway
	resourceGroup := clusterInfo.NodeResourceGroup
	vgc.logger.Infof("Using MC resource group: %s", resourceGroup)

	// Wait for gateway to be ready (this may take 20-30 minutes)
	vgc.logger.Info("VPN Gateway provisioning initiated. This may take 20-30 minutes to complete.")
	vgc.logger.Info("Waiting for VPN Gateway to be ready before proceeding with certificate operations...")

	if err := vgc.WaitForVPNGatewayReady(ctx, gatewayInfo.Name, resourceGroup); err != nil {
		return nil, fmt.Errorf("failed to wait for VPN Gateway to be ready: %w", err)
	}

	vgc.logger.Info("VPN Gateway is now ready for certificate operations")

	// Mark step as completed
	if err := vgc.stateManager.MarkStepCompleted(state, "vpn_gateway_provisioned"); err != nil {
		return nil, fmt.Errorf("failed to mark gateway provisioning as completed: %w", err)
	}

	return &GatewayInfo{
		Name:          gatewayInfo.Name,
		State:         gatewayInfo.State,
		ResourceGroup: resourceGroup,
	}, nil
}

// setupCertificates handles certificate generation and upload with idempotency
func (vgc *VPNGatewayController) setupCertificates(ctx context.Context, state *state.BootstrapState, gatewayInfo *GatewayInfo) error {
	if vgc.stateManager.IsStepCompleted(state, "vpn_certificates_generated") {
		vgc.logger.Info("VPN certificates already generated and uploaded")
		return nil
	}

	vgc.logger.Info("Generating VPN certificates...")
	certData, err := vgc.vpnManager.GenerateCertificates()
	if err != nil {
		vgc.stateManager.MarkStepFailed(state, "vpn_certificates_generated", err.Error())
		return fmt.Errorf("failed to generate VPN certificates: %w", err)
	}

	vgc.logger.Info("Uploading VPN certificate to Azure VPN Gateway...")
	if err := vgc.vpnManager.UploadCertificateToAzure(certData, gatewayInfo.Name, gatewayInfo.ResourceGroup); err != nil {
		vgc.logger.Warnf("Certificate upload failed (may already exist): %v", err)
		// Don't fail the entire operation if certificate already exists
	} else {
		vgc.logger.Info("Certificate uploaded successfully")
	}

	// Mark certificate step as completed
	if err := vgc.stateManager.MarkStepCompleted(state, "vpn_certificates_generated"); err != nil {
		return fmt.Errorf("failed to mark certificate generation as completed: %w", err)
	}

	return nil
}

// downloadVPNConfig handles VPN configuration download with idempotency
func (vgc *VPNGatewayController) downloadVPNConfig(ctx context.Context, state *state.BootstrapState, gatewayInfo *GatewayInfo) (string, error) {
	if vgc.stateManager.IsStepCompleted(state, "vpn_config_downloaded") {
		// Check if the config file actually exists in the expected location
		if configPath, err := vgc.getExistingConfigPath(); err == nil {
			vgc.logger.Info("VPN configuration already downloaded")
			return configPath, nil
		} else {
			// Config marked as downloaded but file doesn't exist - re-download
			vgc.logger.Warn("VPN config marked as downloaded but file not found, re-downloading...")
		}
	}

	vgc.logger.Info("Downloading VPN client configuration...")
	configData, err := vgc.vpnManager.DownloadVPNClientConfig(gatewayInfo.Name, gatewayInfo.ResourceGroup)
	if err != nil {
		vgc.stateManager.MarkStepFailed(state, "vpn_config_downloaded", err.Error())
		return "", fmt.Errorf("failed to download VPN client configuration: %w", err)
	}

	// Save configuration to temporary file
	configPath, err := vgc.saveVPNConfig(configData)
	if err != nil {
		vgc.stateManager.MarkStepFailed(state, "vpn_config_downloaded", err.Error())
		return "", fmt.Errorf("failed to save VPN config: %w", err)
	}

	// Mark step as completed
	if err := vgc.stateManager.MarkStepCompleted(state, "vpn_config_downloaded"); err != nil {
		return "", fmt.Errorf("failed to mark config download as completed: %w", err)
	}

	return configPath, nil
}

// establishVPNConnection handles VPN connection establishment with idempotency
func (vgc *VPNGatewayController) establishVPNConnection(ctx context.Context, state *state.BootstrapState, configPath string) (bool, error) {
	if vgc.stateManager.IsStepCompleted(state, "vpn_connection_established") {
		vgc.logger.Info("VPN connection already established")
		return true, nil
	}

	vgc.logger.Info("Setting up OpenVPN with downloaded configuration...")
	if err := vgc.vpnManager.SetupOpenVPN(configPath); err != nil {
		vgc.stateManager.MarkStepFailed(state, "vpn_connection_established", err.Error())
		return false, fmt.Errorf("failed to setup OpenVPN: %w", err)
	}

	vgc.logger.Info("Waiting for VPN connection to establish...")
	if err := vgc.waitForVPNConnection(30 * time.Second); err != nil {
		vgc.stateManager.MarkStepFailed(state, "vpn_connection_established", err.Error())
		return false, fmt.Errorf("VPN connection failed to establish: %w", err)
	}

	// Mark step as completed
	if err := vgc.stateManager.MarkStepCompleted(state, "vpn_connection_established"); err != nil {
		return false, fmt.Errorf("failed to mark VPN connection as completed: %w", err)
	}

	vgc.logger.Info("VPN connection established successfully")
	return true, nil
}

// waitForVPNConnection waits for VPN connection to be established
func (vgc *VPNGatewayController) waitForVPNConnection(timeout time.Duration) error {
	vgc.logger.Infof("Waiting up to %v for VPN connection...", timeout)

	start := time.Now()
	for time.Since(start) < timeout {
		if vgc.vpnManager.IsVPNConnected() {
			vgc.logger.Info("VPN connection established successfully")
			return nil
		}

		vgc.logger.Debug("VPN not connected yet, waiting...")
		time.Sleep(2 * time.Second)
	}

	return fmt.Errorf("VPN connection timeout after %v", timeout)
}

// saveVPNConfig saves VPN configuration to the user-appropriate directory
func (vgc *VPNGatewayController) saveVPNConfig(configData string) (string, error) {
	configDir, err := vgc.getVPNConfigDirectory()
	if err != nil {
		return "", err
	}

	configPath := filepath.Join(configDir, "vpn-config.ovpn")

	// Save VPN config to the persistent location atomically
	if err := utils.WriteFileAtomicSystem(configPath, []byte(configData), 0644); err != nil {
		return "", fmt.Errorf("failed to save VPN config file: %w", err)
	}

	vgc.logger.Infof("VPN configuration saved to: %s", configPath)
	return configPath, nil
}

// getVPNConfigDirectory returns the appropriate VPN config directory based on user privileges
func (vgc *VPNGatewayController) getVPNConfigDirectory() (string, error) {
	var configDir string

	if os.Geteuid() == 0 {
		// Running as root - use system directory
		configDir = vgc.config.Paths.DataDir
	} else {
		// Running as regular user - use user home directory
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("failed to get user home directory: %w", err)
		}
		configDir = filepath.Join(homeDir, ".aks-flex-node")
	}

	// Ensure directory exists
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create VPN config directory: %w", err)
	}

	return configDir, nil
}

// getExistingConfigPath returns the path to existing VPN configuration
func (vgc *VPNGatewayController) getExistingConfigPath() (string, error) {
	configDir, err := vgc.getVPNConfigDirectory()
	if err != nil {
		return "", err
	}

	configPath := filepath.Join(configDir, "vpn-config.ovpn")

	// Check if file exists
	if _, err := os.Stat(configPath); err != nil {
		return "", fmt.Errorf("existing VPN config not found at %s", configPath)
	}

	return configPath, nil
}

// IsVPNConnected checks if VPN connection is active (delegates to VPNManager)
func (vgc *VPNGatewayController) IsVPNConnected() bool {
	return vgc.vpnManager.IsVPNConnected()
}

// GetVPNStatus returns detailed VPN status information
func (vgc *VPNGatewayController) GetVPNStatus() (*VPNStatus, error) {
	status := &VPNStatus{
		Connected: vgc.vpnManager.IsVPNConnected(),
	}

	if status.Connected {
		iface, err := vgc.vpnManager.GetVPNInterface()
		if err == nil {
			status.Interface = iface
			ip, err := vgc.vpnManager.GetVPNIP(iface)
			if err == nil {
				status.IPAddress = ip
			}
		}
	}

	return status, nil
}

// VPNGatewayInfo represents VPN Gateway information
type VPNGatewayInfo struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Location      string `json:"location"`
	ResourceGroup string `json:"resourceGroup"`
	PublicIPID    string `json:"publicIpId"`
	State         string `json:"state"`
	GatewayType   string `json:"gatewayType"`
}

// VPNStatus represents VPN connection status
type VPNStatus struct {
	Connected bool
	Interface string
	IPAddress string
}

// ProvisionVPNGateway provisions a VPN Gateway in the AKS cluster's VNet
func (vgc *VPNGatewayController) ProvisionVPNGateway(ctx context.Context, clusterInfo *aks.ClusterInfo) (*VPNGatewayInfo, error) {
	if clusterInfo.VNetInfo == nil {
		return nil, fmt.Errorf("no VNet information available for cluster %s", clusterInfo.Name)
	}

	vgc.logger.Infof("Provisioning VPN Gateway in VNet: %s", clusterInfo.VNetInfo.Name)

	// Check if VPN Gateway already exists
	if existing, err := vgc.GetVPNGateway(ctx, clusterInfo.VNetInfo); err == nil && existing != nil {
		vgc.logger.Infof("VPN Gateway already exists: %s", existing.Name)
		return existing, nil
	}

	// Step 1: Ensure GatewaySubnet exists
	gatewaySubnetCIDR, err := vgc.calculateGatewaySubnetCIDR(ctx, clusterInfo.VNetInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate gateway subnet CIDR: %w", err)
	}
	if err := vgc.ensureGatewaySubnet(ctx, clusterInfo.VNetInfo, gatewaySubnetCIDR); err != nil {
		return nil, fmt.Errorf("failed to ensure gateway subnet: %w", err)
	}

	// Step 2: Create Public IP for VPN Gateway
	publicIPInfo, err := vgc.createPublicIPForVPNGateway(ctx, clusterInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to create public IP: %w", err)
	}

	// Step 3: Create VPN Gateway
	gatewayInfo, err := vgc.createVPNGateway(ctx, clusterInfo, publicIPInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to create VPN gateway: %w", err)
	}

	vgc.logger.Infof("Successfully provisioned VPN Gateway: %s", gatewayInfo.Name)
	return gatewayInfo, nil
}

// GetVPNGateway checks if a VPN Gateway exists in the VNet
func (vgc *VPNGatewayController) GetVPNGateway(ctx context.Context, vnetInfo *aks.VNetInfo) (*VPNGatewayInfo, error) {
	// Get management token
	token, err := vgc.arcManager.GetArcManagedIdentityToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get management token: %w", err)
	}

	// List VPN Gateways in the resource group
	url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/virtualNetworkGateways?api-version=2024-05-01",
		vgc.config.Azure.SubscriptionID, vnetInfo.ResourceGroup)

	client := &http.Client{Timeout: 60 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get VPN gateways: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get VPN gateways, status: %d, body: %s", resp.StatusCode, string(body))
	}

	var gatewayList struct {
		Value []struct {
			ID         string `json:"id"`
			Name       string `json:"name"`
			Location   string `json:"location"`
			Properties struct {
				GatewayType       string `json:"gatewayType"`
				ProvisioningState string `json:"provisioningState"`
				IPConfigurations  []struct {
					Properties struct {
						Subnet struct {
							ID string `json:"id"`
						} `json:"subnet"`
						PublicIPAddress struct {
							ID string `json:"id"`
						} `json:"publicIPAddress"`
					} `json:"properties"`
				} `json:"ipConfigurations"`
			} `json:"properties"`
		} `json:"value"`
	}

	if err := json.Unmarshal(body, &gatewayList); err != nil {
		return nil, fmt.Errorf("failed to parse gateway list: %w", err)
	}

	// Look for VPN Gateway in the same VNet
	for _, gw := range gatewayList.Value {
		if gw.Properties.GatewayType == "Vpn" {
			for _, ipConfig := range gw.Properties.IPConfigurations {
				// Check if the gateway is in the same VNet by comparing subnet ID
				if strings.Contains(ipConfig.Properties.Subnet.ID, vnetInfo.Name) {
					// Parse resource group from gateway ID
					gwParts := strings.Split(gw.ID, "/")
					gwResourceGroup := ""
					if len(gwParts) >= 5 {
						gwResourceGroup = gwParts[4]
					}

					return &VPNGatewayInfo{
						ID:            gw.ID,
						Name:          gw.Name,
						Location:      gw.Location,
						ResourceGroup: gwResourceGroup,
						PublicIPID:    ipConfig.Properties.PublicIPAddress.ID,
						State:         gw.Properties.ProvisioningState,
						GatewayType:   gw.Properties.GatewayType,
					}, nil
				}
			}
		}
	}

	return nil, nil // No VPN Gateway found
}

// ensureGatewaySubnet creates GatewaySubnet if it doesn't exist
func (vgc *VPNGatewayController) ensureGatewaySubnet(ctx context.Context, vnetInfo *aks.VNetInfo, gatewaySubnetCIDR string) error {
	vgc.logger.Infof("Ensuring GatewaySubnet exists in VNet: %s", vnetInfo.Name)

	// Get management token
	token, err := vgc.arcManager.GetArcManagedIdentityToken(ctx)
	if err != nil {
		return fmt.Errorf("failed to get management token: %w", err)
	}

	// Check if GatewaySubnet already exists
	subnetURL := fmt.Sprintf("https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/virtualNetworks/%s/subnets/GatewaySubnet?api-version=2024-05-01",
		vgc.config.Azure.SubscriptionID, vnetInfo.ResourceGroup, vnetInfo.Name)

	client := &http.Client{Timeout: 60 * time.Second}
	req, err := http.NewRequest("GET", subnetURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create get subnet request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to check gateway subnet: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		vgc.logger.Info("GatewaySubnet already exists")
		return nil
	}

	// Create GatewaySubnet
	vgc.logger.Infof("Creating GatewaySubnet with CIDR: %s", gatewaySubnetCIDR)

	subnetData := map[string]interface{}{
		"properties": map[string]interface{}{
			"addressPrefix": gatewaySubnetCIDR,
		},
	}

	subnetJSON, err := json.Marshal(subnetData)
	if err != nil {
		return fmt.Errorf("failed to marshal subnet data: %w", err)
	}

	req, err = http.NewRequest("PUT", subnetURL, bytes.NewBuffer(subnetJSON))
	if err != nil {
		return fmt.Errorf("failed to create subnet request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	resp, err = client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to create gateway subnet: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read subnet response: %w", err)
	}

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to create gateway subnet, status: %d, body: %s", resp.StatusCode, string(body))
	}

	vgc.logger.Info("Successfully created GatewaySubnet")
	return nil
}

// createPublicIPForVPNGateway ensures a public IP exists for the VPN Gateway (idempotent)
func (vgc *VPNGatewayController) createPublicIPForVPNGateway(ctx context.Context, clusterInfo *aks.ClusterInfo) (string, error) {
	publicIPName := fmt.Sprintf("%s-vpn-gateway-ip", clusterInfo.Name)
	vgc.logger.Infof("Ensuring public IP exists: %s", publicIPName)

	// Get management token
	token, err := vgc.arcManager.GetArcManagedIdentityToken(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get management token: %w", err)
	}

	publicIPURL := fmt.Sprintf("https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/publicIPAddresses/%s?api-version=2024-05-01",
		vgc.config.Azure.SubscriptionID, clusterInfo.VNetInfo.ResourceGroup, publicIPName)

	// First check if Public IP already exists
	client := &http.Client{Timeout: 60 * time.Second}
	req, err := http.NewRequest("GET", publicIPURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create get public IP request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to check public IP: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		// Public IP already exists, parse and return its ID
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", fmt.Errorf("failed to read existing public IP response: %w", err)
		}

		var existingIP struct {
			ID string `json:"id"`
		}

		if err := json.Unmarshal(body, &existingIP); err != nil {
			return "", fmt.Errorf("failed to parse existing public IP response: %w", err)
		}

		vgc.logger.Infof("Public IP already exists: %s", existingIP.ID)
		return existingIP.ID, nil
	}

	// Create Public IP if it doesn't exist
	vgc.logger.Infof("Creating new public IP: %s", publicIPName)

	publicIPData := map[string]interface{}{
		"location": clusterInfo.Location,
		"sku": map[string]interface{}{
			"name": "Standard",
		},
		"properties": map[string]interface{}{
			"publicIPAllocationMethod": "Static",
		},
		"zones": []string{"1"},
	}

	publicIPJSON, err := json.Marshal(publicIPData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public IP data: %w", err)
	}

	client = &http.Client{Timeout: 300 * time.Second} // Longer timeout for resource creation
	req, err = http.NewRequest("PUT", publicIPURL, bytes.NewBuffer(publicIPJSON))
	if err != nil {
		return "", fmt.Errorf("failed to create public IP request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	resp, err = client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to create public IP: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read public IP response: %w", err)
	}

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to create public IP, status: %d, body: %s", resp.StatusCode, string(body))
	}

	// Parse the response to get the public IP ID
	var publicIPResponse struct {
		ID string `json:"id"`
	}

	if err := json.Unmarshal(body, &publicIPResponse); err != nil {
		return "", fmt.Errorf("failed to parse public IP response: %w", err)
	}

	vgc.logger.Infof("Successfully created public IP: %s", publicIPResponse.ID)
	return publicIPResponse.ID, nil
}

// createVPNGateway creates the VPN Gateway
func (vgc *VPNGatewayController) createVPNGateway(ctx context.Context, clusterInfo *aks.ClusterInfo, publicIPID string) (*VPNGatewayInfo, error) {
	gatewayName := fmt.Sprintf("%s-vpn-gateway", clusterInfo.Name)
	vgc.logger.Infof("Creating VPN Gateway: %s", gatewayName)

	// Get management token
	token, err := vgc.arcManager.GetArcManagedIdentityToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get management token: %w", err)
	}

	// Construct gateway subnet ID
	gatewaySubnetID := fmt.Sprintf("%s/subnets/GatewaySubnet", clusterInfo.VNetInfo.ID)

	// Create VPN Gateway
	gatewayURL := fmt.Sprintf("https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/virtualNetworkGateways/%s?api-version=2024-05-01",
		vgc.config.Azure.SubscriptionID, clusterInfo.VNetInfo.ResourceGroup, gatewayName)

	gatewayData := map[string]interface{}{
		"location": clusterInfo.Location,
		"properties": map[string]interface{}{
			"sku": map[string]interface{}{
				"name": "VpnGw2AZ",
				"tier": "VpnGw2AZ",
			},
			"gatewayType":  "Vpn",
			"vpnType":      "RouteBased",
			"enableBgp":    false,
			"activeActive": false,
			"ipConfigurations": []map[string]interface{}{
				{
					"name": "P2SConfig",
					"properties": map[string]interface{}{
						"publicIPAddress": map[string]interface{}{
							"id": publicIPID,
						},
						"subnet": map[string]interface{}{
							"id": gatewaySubnetID,
						},
					},
				},
			},
			"vpnClientConfiguration": map[string]interface{}{
				"vpnClientAddressPool": map[string]interface{}{
					"addressPrefixes": []string{vgc.config.Azure.VPN.P2SGatewayCIDR},
				},
				"vpnClientProtocols": []string{"OpenVPN"},
			},
		},
	}

	gatewayJSON, err := json.Marshal(gatewayData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal gateway data: %w", err)
	}

	client := &http.Client{Timeout: 1800 * time.Second} // 30 minutes timeout for VPN Gateway creation
	req, err := http.NewRequest("PUT", gatewayURL, bytes.NewBuffer(gatewayJSON))
	if err != nil {
		return nil, fmt.Errorf("failed to create gateway request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	vgc.logger.Info("Starting VPN Gateway creation (this may take 20-30 minutes)...")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to create VPN gateway: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read gateway response: %w", err)
	}

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to create VPN gateway, status: %d, body: %s", resp.StatusCode, string(body))
	}

	// Parse the response to get the gateway info
	var gatewayResponse struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		Location string `json:"location"`
	}

	if err := json.Unmarshal(body, &gatewayResponse); err != nil {
		return nil, fmt.Errorf("failed to parse gateway response: %w", err)
	}

	gatewayInfo := &VPNGatewayInfo{
		ID:            gatewayResponse.ID,
		Name:          gatewayResponse.Name,
		Location:      gatewayResponse.Location,
		ResourceGroup: clusterInfo.VNetInfo.ResourceGroup,
		PublicIPID:    publicIPID,
		State:         "Creating",
		GatewayType:   "Vpn",
	}

	vgc.logger.Infof("VPN Gateway creation initiated: %s", gatewayInfo.Name)
	return gatewayInfo, nil
}

// calculateGatewaySubnetCIDR calculates an appropriate GatewaySubnet CIDR within the VNet's address space
func (vgc *VPNGatewayController) calculateGatewaySubnetCIDR(ctx context.Context, vnetInfo *aks.VNetInfo) (string, error) {
	vgc.logger.Infof("Calculating GatewaySubnet CIDR for VNet: %s", vnetInfo.Name)

	// Get management token
	token, err := vgc.arcManager.GetArcManagedIdentityToken(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get management token: %w", err)
	}

	// Get VNet details to find address space
	url := fmt.Sprintf("https://management.azure.com%s?api-version=2024-05-01", vnetInfo.ID)

	client := &http.Client{Timeout: 60 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to get VNet details: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get VNet details, status: %d, body: %s", resp.StatusCode, string(body))
	}

	var vnetDetails struct {
		Properties struct {
			AddressSpace struct {
				AddressPrefixes []string `json:"addressPrefixes"`
			} `json:"addressSpace"`
			Subnets []struct {
				Name       string `json:"name"`
				Properties struct {
					AddressPrefix string `json:"addressPrefix"`
				} `json:"properties"`
			} `json:"subnets"`
		} `json:"properties"`
	}

	if err := json.Unmarshal(body, &vnetDetails); err != nil {
		return "", fmt.Errorf("failed to parse VNet details: %w", err)
	}

	if len(vnetDetails.Properties.AddressSpace.AddressPrefixes) == 0 {
		return "", fmt.Errorf("VNet has no address prefixes")
	}

	// Use the first address prefix for calculation
	vnetCIDR := vnetDetails.Properties.AddressSpace.AddressPrefixes[0]
	vgc.logger.Infof("VNet address space: %s", vnetCIDR)

	// Check if GatewaySubnet already exists
	for _, subnet := range vnetDetails.Properties.Subnets {
		if subnet.Name == "GatewaySubnet" {
			vgc.logger.Infof("GatewaySubnet already exists with CIDR: %s", subnet.Properties.AddressPrefix)
			return subnet.Properties.AddressPrefix, nil
		}
	}

	// Calculate an available /27 subnet for GatewaySubnet
	gatewaySubnetCIDR, err := vgc.calculateAvailableSubnetInRange(vnetCIDR, vnetDetails.Properties.Subnets, 27)
	if err != nil {
		return "", fmt.Errorf("failed to calculate available subnet: %w", err)
	}

	vgc.logger.Infof("Calculated GatewaySubnet CIDR: %s", gatewaySubnetCIDR)
	return gatewaySubnetCIDR, nil
}

// calculateAvailableSubnetInRange finds an available subnet within the VNet address space
func (vgc *VPNGatewayController) calculateAvailableSubnetInRange(vnetCIDR string, existingSubnets []struct {
	Name       string `json:"name"`
	Properties struct {
		AddressPrefix string `json:"addressPrefix"`
	} `json:"properties"`
}, prefixLength int) (string, error) {

	// Parse VNet CIDR
	_, vnetNet, err := net.ParseCIDR(vnetCIDR)
	if err != nil {
		return "", fmt.Errorf("failed to parse VNet CIDR %s: %w", vnetCIDR, err)
	}

	// Convert existing subnets to IPNet for overlap checking
	var existingNets []*net.IPNet
	for _, subnet := range existingSubnets {
		if subnet.Properties.AddressPrefix != "" {
			_, subnetNet, err := net.ParseCIDR(subnet.Properties.AddressPrefix)
			if err != nil {
				vgc.logger.Warnf("Failed to parse existing subnet CIDR %s: %v", subnet.Properties.AddressPrefix, err)
				continue
			}
			existingNets = append(existingNets, subnetNet)
		}
	}

	// Calculate subnet size
	subnetSize := 1 << (32 - prefixLength)

	// Try to find an available subnet range
	vnetIP := vnetNet.IP.To4()
	if vnetIP == nil {
		return "", fmt.Errorf("only IPv4 networks are supported")
	}

	// Convert IP to uint32 for easier calculation
	vnetStart := uint32(vnetIP[0])<<24 | uint32(vnetIP[1])<<16 | uint32(vnetIP[2])<<8 | uint32(vnetIP[3])
	vnetMask := uint32(0xFFFFFFFF) << (32 - vgc.getNetworkPrefixLength(vnetNet))
	vnetEnd := vnetStart | (^vnetMask)

	// Start from a high address in the VNet range to avoid conflicts with existing subnets
	// Start from the last possible /27 subnet in the VNet
	startAddress := vnetEnd - uint32(subnetSize) + 1

	// Align to subnet boundary
	startAddress = startAddress &^ (uint32(subnetSize) - 1)

	for currentAddr := startAddress; currentAddr >= vnetStart; currentAddr -= uint32(subnetSize) {
		// Create candidate subnet
		candidateIP := net.IPv4(
			byte(currentAddr>>24),
			byte(currentAddr>>16),
			byte(currentAddr>>8),
			byte(currentAddr),
		)

		candidateNet := &net.IPNet{
			IP:   candidateIP,
			Mask: net.CIDRMask(prefixLength, 32),
		}

		// Check if this subnet overlaps with any existing subnet
		overlaps := false
		for _, existing := range existingNets {
			if vgc.subnetsOverlap(candidateNet, existing) {
				overlaps = true
				break
			}
		}

		if !overlaps {
			return candidateNet.String(), nil
		}
	}

	return "", fmt.Errorf("no available /%d subnet found in VNet %s", prefixLength, vnetCIDR)
}

// getNetworkPrefixLength returns the prefix length of a network
func (vgc *VPNGatewayController) getNetworkPrefixLength(network *net.IPNet) int {
	ones, _ := network.Mask.Size()
	return ones
}

// subnetsOverlap checks if two subnets overlap
func (vgc *VPNGatewayController) subnetsOverlap(subnet1, subnet2 *net.IPNet) bool {
	return subnet1.Contains(subnet2.IP) || subnet2.Contains(subnet1.IP) ||
		subnet1.Contains(vgc.getLastIP(subnet2)) || subnet2.Contains(vgc.getLastIP(subnet1))
}

// getLastIP returns the last IP address in a subnet
func (vgc *VPNGatewayController) getLastIP(network *net.IPNet) net.IP {
	ip := network.IP.To4()
	if ip == nil {
		return nil
	}

	// Convert to uint32
	ipInt := uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])

	// Get network mask
	ones, bits := network.Mask.Size()
	mask := uint32(0xFFFFFFFF) << (bits - ones)

	// Calculate last IP
	lastIPInt := ipInt | (^mask)

	return net.IPv4(
		byte(lastIPInt>>24),
		byte(lastIPInt>>16),
		byte(lastIPInt>>8),
		byte(lastIPInt),
	)
}

// WaitForVPNGatewayReady waits for the VPN Gateway to be in "Succeeded" state
func (vgc *VPNGatewayController) WaitForVPNGatewayReady(ctx context.Context, gatewayName, resourceGroup string) error {
	startTime := time.Now()
	vgc.logger.Infof("Waiting for VPN Gateway %s to be ready...", gatewayName)

	// Poll the gateway status every 30 seconds until it's ready
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	timeout := time.After(30 * time.Minute) // 30 minute timeout

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout:
			elapsed := time.Since(startTime)
			return fmt.Errorf("timeout waiting for VPN Gateway %s to be ready after %v", gatewayName, elapsed.Round(time.Second))
		case <-ticker.C:
			gatewayState, err := vgc.getVPNGatewayState(ctx, gatewayName, resourceGroup)
			if err != nil {
				elapsed := time.Since(startTime)
				vgc.logger.Warnf("Failed to check VPN Gateway status: %v, retrying... (elapsed: %v)", err, elapsed.Round(time.Second))
				continue
			}

			elapsed := time.Since(startTime)
			vgc.logger.Infof("VPN Gateway %s current state: %s (elapsed: %v)", gatewayName, gatewayState, elapsed.Round(time.Second))

			if gatewayState == "Succeeded" {
				vgc.logger.Infof("VPN Gateway %s is now ready! (total time: %v)", gatewayName, elapsed.Round(time.Second))
				return nil
			} else if gatewayState == "Failed" {
				return fmt.Errorf("VPN Gateway %s is in failed state after %v", gatewayName, elapsed.Round(time.Second))
			}

			// Continue waiting for other states like "Creating", "Updating", etc.
		}
	}
}

// getVPNGatewayState retrieves the current state of a VPN Gateway
func (vgc *VPNGatewayController) getVPNGatewayState(ctx context.Context, gatewayName, resourceGroup string) (string, error) {
	// Get management token
	token, err := vgc.arcManager.GetArcManagedIdentityToken(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get management token: %w", err)
	}

	// Get VPN Gateway status
	url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/virtualNetworkGateways/%s?api-version=2024-05-01",
		vgc.config.Azure.SubscriptionID, resourceGroup, gatewayName)

	client := &http.Client{Timeout: 60 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to get VPN Gateway: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get VPN Gateway, status: %d, body: %s", resp.StatusCode, string(body))
	}

	var gateway struct {
		Properties struct {
			ProvisioningState string `json:"provisioningState"`
		} `json:"properties"`
	}

	if err := json.Unmarshal(body, &gateway); err != nil {
		return "", fmt.Errorf("failed to parse gateway response: %w", err)
	}

	return gateway.Properties.ProvisioningState, nil
}
