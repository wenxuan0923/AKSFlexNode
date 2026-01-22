package vpn_gateway

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v5"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4"
	"github.com/Azure/go-autorest/autorest/to"
	"github.com/sirupsen/logrus"

	"go.goms.io/aks/AKSFlexNode/pkg/auth"
	"go.goms.io/aks/AKSFlexNode/pkg/config"
	"go.goms.io/aks/AKSFlexNode/pkg/utils"
)

// Installer handles VPN Gateway installation operations
type Installer struct {
	config         *config.Config
	logger         *logrus.Logger
	aksVnetClient  *armnetwork.VirtualNetworksClient
	vnetClient     *armnetwork.VirtualNetworksClient
	subnetsClient  *armnetwork.SubnetsClient
	vgwClient      *armnetwork.VirtualNetworkGatewaysClient
	publicIPClient *armnetwork.PublicIPAddressesClient
	apClient       *armcontainerservice.AgentPoolsClient
}

// NewInstaller creates a new VPN Gateway installer
func NewInstaller(logger *logrus.Logger) *Installer {
	return &Installer{
		config: config.GetConfig(),
		logger: logger,
	}
}

// Validate validates prerequisites for VPN Gateway installation
func (i *Installer) Validate(ctx context.Context) error {
	if !i.config.IsVPNGatewayEnabled() {
		i.logger.Info("VPN Gateway setup is not enabled in configuration, skipping Validate...")
		return nil
	}

	if i.config.Azure.VPNGateway.P2SGatewayCIDR == "" {
		return fmt.Errorf("P2S Gateway CIDR is not configured")
	}

	return nil
}

// GetName returns the step name
func (i *Installer) GetName() string {
	return "VPNGatewayInstaller"
}

type vnetResourceInfo struct {
	vnetID            string
	location          string
	resourceGroupName string
	subscriptionID    string
	vnet              *armnetwork.VirtualNetwork
}

// Execute performs VPN Gateway setup as part of the bootstrap process
// This method handles the whole VPN Gateway creation and configuration flow:
// 1. VPN Gateway provisioning
// 2. Certificate generation and upload
// 3. VPN client configuration download
// 4. VPN connection establishment
func (i *Installer) Execute(ctx context.Context) error {
	i.logger.Info("Starting VPN Gateway setup for bootstrap process")

	// Set up AKS clients
	if err := i.setUpAKSClients(ctx); err != nil {
		i.logger.Errorf("Failed to set up Azure clients: %v", err)
		return fmt.Errorf("vpn gateway setup failed at client setup: %w", err)
	}

	// Discover the VNet used by AKS cluster nodes - it can be either BYO VNet or AKS managed VNet
	// The VPN Gateway will be created in this VNet to establish connectivity between the flex node and AKS cluster nodes
	vnet, err := i.getAKSNodeVNet(ctx)
	if err != nil {
		i.logger.Errorf("Failed to get AKS managed VNet: %v", err)
		return fmt.Errorf("vpn gateway setup failed at VNet discovery: %w", err)
	}

	vnetInfo := vnetResourceInfo{
		vnetID:            to.String(vnet.ID),
		location:          to.String(vnet.Location),
		resourceGroupName: getResourceGroupFromResourceID(to.String(vnet.ID)),
		subscriptionID:    getSubscriptionIDFromResourceID(to.String(vnet.ID)),
		vnet:              vnet,
	}

	// // Set up Network clients using vnet subscription ID
	// if err := i.setUpNetClients(ctx, vnetInfo); err != nil {
	// 	i.logger.Errorf("Failed to set up Azure Network clients: %v", err)
	// 	return fmt.Errorf("vpn gateway setup failed at network client setup: %w", err)
	// }

	// Provision VPN Gateway in the AKS Node VNet
	_, err = i.provisionGateway(ctx, vnetInfo)
	if err != nil {
		i.logger.Errorf("Failed to provision VPN Gateway: %v", err)
		return fmt.Errorf("vpn gateway setup failed at gateway provisioning: %w", err)
	}

	// Setup VPN Gateway certificates (root and client)
	i.logger.Info("Setting up VPN certificates")
	if err := i.setupCertificates(ctx, vnetInfo); err != nil {
		i.logger.Errorf("Failed to setup certificates: %v", err)
		return fmt.Errorf("vpn gateway setup failed at certificate setup: %w", err)
	}
	i.logger.Info("VPN certificates setup completed")

	// Download VPN configuration
	i.logger.Info("Downloading VPN client configuration")
	configPath, err := i.downloadVPNConfig(ctx, vnetInfo)
	if err != nil {
		i.logger.Errorf("Failed to download VPN configuration: %v", err)
		return fmt.Errorf("vpn gateway setup failed at config download: %w", err)
	}
	i.logger.Infof("VPN configuration downloaded to: %s", configPath)

	// Establish VPN connection using the downloaded configuration
	i.logger.Info("Establishing VPN connection")
	connected, err := i.establishVPNConnection(ctx, configPath)
	if err != nil {
		i.logger.Errorf("Failed to establish VPN connection: %v", err)
		return fmt.Errorf("vpn gateway setup failed at connection establishment: %w", err)
	}

	if connected {
		i.logger.Info("VPN connection established successfully")
	}

	i.logger.Info("VPN Gateway setup completed successfully")
	return nil
}

// setUpAKSClients sets up Azure Container Service clients using the target cluster subscription ID
func (i *Installer) setUpAKSClients(ctx context.Context) error {
	cred, err := auth.NewAuthProvider().UserCredential(config.GetConfig())
	if err != nil {
		return fmt.Errorf("failed to get authentication credential: %w", err)
	}

	clusterSubID := i.config.GetTargetClusterSubscriptionID()
	aksClientFactory, err := armcontainerservice.NewClientFactory(clusterSubID, cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create Azure Container Service client factory: %w", err)
	}

	netClientFactory, err := armnetwork.NewClientFactory(clusterSubID, cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create Azure Network client factory: %w", err)
	}

	i.apClient = aksClientFactory.NewAgentPoolsClient()
	i.aksVnetClient = netClientFactory.NewVirtualNetworksClient()
	return nil
}

// setUpNetClients sets up Azure Network clients using the provided net subscription ID
func (i *Installer) setUpNetClients(ctx context.Context, vnetSubID string) error {
	cred, err := auth.NewAuthProvider().UserCredential(config.GetConfig())
	if err != nil {
		return fmt.Errorf("failed to get authentication credential: %w", err)
	}

	netClientFactory, err := armnetwork.NewClientFactory(vnetSubID, cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create Azure Network client factory: %w", err)
	}
	i.vnetClient = netClientFactory.NewVirtualNetworksClient()
	i.subnetsClient = netClientFactory.NewSubnetsClient()
	i.vgwClient = netClientFactory.NewVirtualNetworkGatewaysClient()
	i.publicIPClient = netClientFactory.NewPublicIPAddressesClient()
	return nil
}

// IsCompleted checks if VPN Gateway setup has been completed
func (i *Installer) IsCompleted(ctx context.Context) bool {
	if !i.config.IsVPNGatewayEnabled() {
		i.logger.Info("VPN Gateway setup is disabled in configuration, skipping installation...")
		return true
	}

	i.logger.Debug("Checking VPN Gateway setup completion status")

	// Check if VPN is connected
	if !i.isVPNConnected() {
		i.logger.Debug("VPN is not connected")
		return false
	}

	// // Check if VPN Gateway exists in Azure
	// if gateway, err := i.getVPNGateway(ctx); err != nil || gateway == nil {
	// 	i.logger.Debugf("VPN Gateway not found or not accessible: %v", err)
	// 	return false
	// }

	i.logger.Debug("VPN Gateway setup appears to be completed")
	return true
}

// provisionGateway handles VPN Gateway provisioning with idempotency
func (i *Installer) provisionGateway(ctx context.Context, vnetInfo vnetResourceInfo) (*armnetwork.VirtualNetworkGateway, error) {
	// Check if VPN Gateway already exists
	if gateway, err := i.getVPNGateway(ctx, vnetInfo); err == nil && gateway != nil {
		i.logger.Infof("VPN Gateway already exists: %s", to.String(gateway.Name))
		return gateway, nil
	}

	i.logger.Infof("Provisioning VPN Gateway in VNet: %s", vnetInfo.vnetID)

	// Ensure GatewaySubnet exists
	if err := i.ensureGatewaySubnet(ctx, vnetInfo); err != nil {
		return nil, fmt.Errorf("failed to ensure gateway subnet: %w", err)
	}

	// Create Public IP for VPN Gateway
	publicIP, err := i.createPublicIPForVPNGateway(ctx, vnetInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to create public IP: %w", err)
	}

	// Create VPN Gateway in the GatewaySubnet
	gateway, err := i.createVPNGateway(ctx, vnetInfo, publicIP)
	if err != nil {
		return nil, fmt.Errorf("failed to create VPN Gateway: %w", err)
	}

	i.logger.Infof("Successfully provisioned VPN Gateway: %s", to.String(gateway.Name))
	return gateway, nil
}

// createPublicIPForVPNGateway creates a public IP for the VPN Gateway
func (i *Installer) createPublicIPForVPNGateway(ctx context.Context, vnetInfo vnetResourceInfo) (string, error) {
	i.logger.Infof("Ensuring public IP exists: %s", PublicIPName)

	// Prepare Public IP parameters
	allocationMethod := armnetwork.IPAllocationMethodStatic
	skuName := armnetwork.PublicIPAddressSKUNameStandard
	skuTier := armnetwork.PublicIPAddressSKUTierRegional

	publicIPParams := armnetwork.PublicIPAddress{
		Location: &vnetInfo.location,
		SKU: &armnetwork.PublicIPAddressSKU{
			Name: &skuName,
			Tier: &skuTier,
		},
		Properties: &armnetwork.PublicIPAddressPropertiesFormat{
			PublicIPAllocationMethod: &allocationMethod,
		},
		Zones: []*string{
			&[]string{"1"}[0],
		},
	}

	// Create Public IP - this is a long-running operation
	poller, err := i.publicIPClient.BeginCreateOrUpdate(ctx, vnetInfo.resourceGroupName, PublicIPName, publicIPParams, nil)
	if err != nil {
		return "", fmt.Errorf("failed to start public IP creation: %w", err)
	}

	i.logger.Info("Public IP creation initiated. Waiting for completion...")

	// Wait for completion
	result, err := poller.PollUntilDone(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create public IP: %w", err)
	}

	i.logger.Infof("Successfully created public IP: %s", to.String(result.ID))
	return to.String(result.ID), nil
}

// setupCertificates handles certificate generation and upload
func (i *Installer) setupCertificates(ctx context.Context, vnetInfo vnetResourceInfo) error {
	i.logger.Info("Setting up VPN root certificates...")
	certData, err := i.generateCertificates()
	if err != nil {
		return fmt.Errorf("failed to generate VPN certificates: %w", err)
	}

	i.logger.Info("Uploading VPN root certificate to Azure VPN Gateway...")
	if err := i.uploadCertificateToAzure(ctx, certData, vnetInfo); err != nil {
		i.logger.Warnf("Certificate upload failed: %v", err)
		return fmt.Errorf("failed to upload certificate to Azure: %w", err)
	}
	i.logger.Info("Certificate uploaded to Azure VPN Gateway successfully")

	return nil
}

// downloadVPNConfig downloads and saves the VPN configuration
func (i *Installer) downloadVPNConfig(ctx context.Context, vnetInfo vnetResourceInfo) (string, error) {
	i.logger.Info("Downloading VPN client configuration...")
	configData, err := i.downloadVPNClientConfig(ctx, DefaultVPNGatewayName, vnetInfo.resourceGroupName)
	if err != nil {
		return "", fmt.Errorf("failed to download VPN client configuration: %w", err)
	}

	// Save configuration to file
	configPath, err := i.saveVPNConfig(configData)
	if err != nil {
		return "", fmt.Errorf("failed to save VPN config: %w", err)
	}

	return configPath, nil
}

// establishVPNConnection establishes the VPN connection
func (i *Installer) establishVPNConnection(ctx context.Context, configPath string) (bool, error) {
	i.logger.Info("Setting up OpenVPN with downloaded configuration...")
	if err := i.setupOpenVPN(configPath); err != nil {
		return false, fmt.Errorf("failed to setup OpenVPN: %w", err)
	}

	i.logger.Info("Waiting for VPN connection to establish...")
	if err := i.waitForVPNConnection(VPNConnectionTimeout); err != nil {
		return false, fmt.Errorf("VPN connection failed to establish: %w", err)
	}

	i.logger.Info("VPN connection established successfully")
	return true, nil
}

// waitForVPNConnection waits for VPN connection to be established
func (i *Installer) waitForVPNConnection(timeout time.Duration) error {
	i.logger.Infof("Waiting up to %v for VPN connection...", timeout)

	start := time.Now()
	for time.Since(start) < timeout {
		if i.isVPNConnected() {
			i.logger.Info("VPN connection established successfully")
			return nil
		}

		i.logger.Debug("VPN not connected yet, waiting...")
		time.Sleep(VPNConnectionCheckInterval)
	}

	return fmt.Errorf("VPN connection timeout after %v", timeout)
}

// saveVPNConfig saves VPN configuration to the appropriate directory
func (i *Installer) saveVPNConfig(configData string) (string, error) {
	configPath := GetVPNConfigPath()

	// Save VPN config to the persistent location atomically
	if err := utils.WriteFileAtomicSystem(configPath, []byte(configData), CertificateFilePerm); err != nil {
		return "", fmt.Errorf("failed to save VPN config file: %w", err)
	}

	i.logger.Infof("VPN configuration saved to: %s", configPath)
	return configPath, nil
}

// calculateGatewaySubnetCIDR calculates an appropriate GatewaySubnet CIDR
func (i *Installer) calculateGatewaySubnetCIDR(ctx context.Context, vnetInfo vnetResourceInfo) (string, error) {
	i.logger.Infof("Calculating GatewaySubnet CIDR for VNet: %s", vnetInfo.vnetID)

	// proactive checks, should not happen
	if vnetInfo.vnet.Properties == nil ||
		vnetInfo.vnet.Properties.AddressSpace == nil ||
		len(vnetInfo.vnet.Properties.AddressSpace.AddressPrefixes) == 0 {
		return "", fmt.Errorf("VNet has no address prefixes")
	}

	// Use the first address prefix for calculation
	vnetCIDR := vnetInfo.vnet.Properties.AddressSpace.AddressPrefixes[0]
	i.logger.Infof("VNet address space: %s", *vnetCIDR)

	// Calculate an available /27 subnet for GatewaySubnet
	gatewaySubnetCIDR, err := i.calculateAvailableSubnetInRange(*vnetCIDR, vnetInfo.vnet.Properties.Subnets, GatewaySubnetPrefix)
	if err != nil {
		return "", fmt.Errorf("failed to calculate available subnet: %w", err)
	}

	i.logger.Infof("Calculated GatewaySubnet CIDR: %s", gatewaySubnetCIDR)
	return gatewaySubnetCIDR, nil
}

// calculateAvailableSubnetInRange finds an available subnet within the VNet address space
func (i *Installer) calculateAvailableSubnetInRange(vnetCIDR string, existingSubnets []*armnetwork.Subnet, prefixLength int) (string, error) {
	// Parse VNet CIDR
	_, vnetNet, err := net.ParseCIDR(vnetCIDR)
	if err != nil {
		return "", fmt.Errorf("failed to parse VNet CIDR %s: %w", vnetCIDR, err)
	}

	// Convert existing subnets to IPNet for overlap checking
	var existingNets []*net.IPNet
	for _, subnet := range existingSubnets {
		if subnet.Properties.AddressPrefix != nil && *subnet.Properties.AddressPrefix != "" {
			_, subnetNet, err := net.ParseCIDR(*subnet.Properties.AddressPrefix)
			if err != nil {
				i.logger.Warnf("Failed to parse existing subnet CIDR %s: %v", *subnet.Properties.AddressPrefix, err)
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
	vnetMask := uint32(0xFFFFFFFF) << (32 - i.getNetworkPrefixLength(vnetNet))
	vnetEnd := vnetStart | (^vnetMask)

	// Start from a high address in the VNet range to avoid conflicts with existing subnets
	startAddress := vnetEnd - uint32(subnetSize) + 1
	startAddress = startAddress &^ (uint32(subnetSize) - 1) // Align to subnet boundary

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
			if i.subnetsOverlap(candidateNet, existing) {
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
func (i *Installer) getNetworkPrefixLength(network *net.IPNet) int {
	ones, _ := network.Mask.Size()
	return ones
}

// subnetsOverlap checks if two subnets overlap
func (i *Installer) subnetsOverlap(subnet1, subnet2 *net.IPNet) bool {
	return subnet1.Contains(subnet2.IP) || subnet2.Contains(subnet1.IP) ||
		subnet1.Contains(i.getLastIP(subnet2)) || subnet2.Contains(i.getLastIP(subnet1))
}

// getLastIP returns the last IP address in a subnet
func (i *Installer) getLastIP(network *net.IPNet) net.IP {
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

// AKS nodes can be in either BYO VNet or AKS managed VNet
func (i *Installer) getAKSNodeVNet(ctx context.Context) (*armnetwork.VirtualNetwork, error) {
	// First try to discover BYO VNet from agent pools
	vnetID, err := i.discoverBYOVNet(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to discover BYO VNet: %w", err)
	}
	if vnetID != "" {
		i.logger.Infof("Discovered BYO VNet for AKS cluster nodes: %s", vnetID)
		subscriptionID := getSubscriptionIDFromResourceID(vnetID)
		if err := i.setUpNetClients(ctx, subscriptionID); err != nil {
			return nil, fmt.Errorf("failed to set up Azure Network clients: %w", err)
		}
		// Get VNet details
		vnetResp, err := i.vnetClient.Get(ctx, getResourceGroupFromResourceID(vnetID), getResourceNameFromResourceID(vnetID), nil)
		if err != nil {
			return nil, fmt.Errorf("failed to get VNet details for VNet ID %s: %w", vnetID, err)
		}
		return &vnetResp.VirtualNetwork, nil
	}

	i.logger.Info("No BYO VNet found for AKS cluster nodes")
	if err := i.setUpNetClients(ctx, i.config.GetTargetClusterSubscriptionID()); err != nil {
		return nil, fmt.Errorf("failed to set up Azure Network clients: %w", err)
	}

	// Fallback to AKS managed VNet discovery
	i.logger.Infof("Failed to discover BYO VNet: %s, Falling back to discover AKS managed VNet...", err)

	vnet, err := i.discoverAKSManagedVNet(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to discover AKS managed VNet: %s", err)
	}
	if vnet == nil {
		return nil, fmt.Errorf("no VNet found for AKS cluster nodes")
	}

	i.logger.Infof("Discovered AKS managed VNet for cluster nodes: %s", to.String(vnet.Name))
	return vnet, nil
}

// discoverBYOVNet discovers the BYO VNet used by the AKS cluster node pools
func (i *Installer) discoverBYOVNet(ctx context.Context) (string, error) {
	// list agentpool in the target cluster, the property VnetSubnetID contains the VNet info
	pager := i.apClient.NewListPager(
		i.config.GetTargetClusterResourceGroup(),
		i.config.GetTargetClusterName(),
		nil,
	)
	// we only need to pick one agentpool to get the VNet info
	// since an AKS cluster can only be bound to one VNet
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return "", fmt.Errorf("failed to list agent pools: %w", err)
		}
		for _, ap := range page.Value {
			if ap.Properties != nil && ap.Properties.VnetSubnetID != nil {
				vnetID, err := getVNetIDFromSubnetID(*ap.Properties.VnetSubnetID)
				if err != nil {
					return "", fmt.Errorf("failed to get VNet ID from subnet ID: %w", err)
				}
				i.logger.Infof("Discovered BYO VNet ID from agent pool %s: %s", *ap.Name, vnetID)
				return vnetID, nil
			}
		}
	}

	return "", nil // No BYO VNet found
}

// discoverAKSManagedVNet finds the AKS managed VNet in the target cluster's node resource group
func (i *Installer) discoverAKSManagedVNet(ctx context.Context) (*armnetwork.VirtualNetwork, error) {
	nodeResourceGroup := i.config.GetTargetClusterNodeResourceGroup()
	if nodeResourceGroup == "" {
		return nil, fmt.Errorf("node resource group is not set in target cluster configuration")
	}

	// List all VNets in the node resource group
	// there should be only one VNet for AKS managed VNet
	var aksVNet *armnetwork.VirtualNetwork
	pager := i.vnetClient.NewListPager(nodeResourceGroup, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list virtual networks in resource group %s: %w", nodeResourceGroup, err)
		}

		for _, vnet := range page.Value {
			// Check for AKS-specific VNet naming pattern (aks-vnet-*)
			if vnet.Name != nil && strings.HasPrefix(*vnet.Name, "aks-vnet-") {
				i.logger.Infof("Found VNet with AKS naming pattern: %s in resource group %s", *vnet.Name, nodeResourceGroup)
				aksVNet = vnet
			}
		}
	}

	// Return the best candidate VNet found
	if aksVNet != nil {
		i.logger.Infof("Found AKS managed VNet: %s", *aksVNet.Name)
		return aksVNet, nil
	}

	return nil, fmt.Errorf("no VNet found in node resource group %s", nodeResourceGroup)
}

// getVPNGateway finds a VPN Gateway by name using Azure SDK
func (i *Installer) getVPNGateway(ctx context.Context, vnetInfo vnetResourceInfo) (*armnetwork.VirtualNetworkGateway, error) {
	// Get the specific VPN Gateway by name
	resp, err := i.vgwClient.Get(ctx, vnetInfo.resourceGroupName, DefaultVPNGatewayName, nil)
	if err != nil {
		if strings.Contains(err.Error(), "NotFound") {
			i.logger.Infof("VPN Gateway '%s' not found in resource group '%s'", DefaultVPNGatewayName, vnetInfo.resourceGroupName)
			return nil, errors.New("NotFound") // VPN Gateway not found
		}
		return nil, fmt.Errorf("failed to get VPN Gateway '%s' in resource group '%s': %w", DefaultVPNGatewayName, vnetInfo.resourceGroupName, err)
	}

	// Verify it's a VPN Gateway (GatewayType == "Vpn")
	if resp.Properties != nil &&
		resp.Properties.GatewayType != nil &&
		*resp.Properties.GatewayType == armnetwork.VirtualNetworkGatewayTypeVPN {

		i.logger.Infof("Found VPN Gateway '%s' with GatewayType 'Vpn' in resource group '%s'", DefaultVPNGatewayName, vnetInfo.resourceGroupName)
		return &resp.VirtualNetworkGateway, nil
	}

	i.logger.Infof("Gateway '%s' found but is not a VPN Gateway (GatewayType: %v)", DefaultVPNGatewayName, resp.Properties.GatewayType)
	return nil, errors.New("NotFound") // Gateway exists but is not a VPN Gateway
}

// createVPNGateway creates a VPN Gateway
func (i *Installer) createVPNGateway(ctx context.Context, vnetInfo vnetResourceInfo, publicIPID string) (*armnetwork.VirtualNetworkGateway, error) {
	i.logger.Infof("Creating VPN Gateway: %s in resource group: %s", VPNGatewayName, vnetInfo.resourceGroupName)

	// Construct gateway subnet ID
	gatewaySubnetID := fmt.Sprintf("%s/subnets/%s", vnetInfo.vnetID, GatewaySubnetName)

	// Prepare VPN Gateway configuration
	vpnGwSKU := armnetwork.VirtualNetworkGatewaySKUName("VpnGw2AZ")
	vpnGwTier := armnetwork.VirtualNetworkGatewaySKUTier("VpnGw2AZ")
	gatewayType := armnetwork.VirtualNetworkGatewayTypeVPN
	vpnType := armnetwork.VPNTypeRouteBased
	enableBgp := false
	activeActive := false

	// IP Configuration name
	ipConfigName := P2SConfigName

	// VPN Client Configuration
	p2sGatewayCIDR := i.config.Azure.VPNGateway.P2SGatewayCIDR
	vpnClientProtocol := armnetwork.VPNClientProtocolOpenVPN

	gatewayParams := armnetwork.VirtualNetworkGateway{
		Location: &vnetInfo.location,
		Properties: &armnetwork.VirtualNetworkGatewayPropertiesFormat{
			SKU: &armnetwork.VirtualNetworkGatewaySKU{
				Name: &vpnGwSKU,
				Tier: &vpnGwTier,
			},
			GatewayType: &gatewayType,
			VPNType:     &vpnType,
			EnableBgp:   &enableBgp,
			Active:      &activeActive,
			IPConfigurations: []*armnetwork.VirtualNetworkGatewayIPConfiguration{
				{
					Name: &ipConfigName,
					Properties: &armnetwork.VirtualNetworkGatewayIPConfigurationPropertiesFormat{
						PublicIPAddress: &armnetwork.SubResource{
							ID: &publicIPID,
						},
						Subnet: &armnetwork.SubResource{
							ID: &gatewaySubnetID,
						},
					},
				},
			},
			VPNClientConfiguration: &armnetwork.VPNClientConfiguration{
				VPNClientAddressPool: &armnetwork.AddressSpace{
					AddressPrefixes: []*string{&p2sGatewayCIDR},
				},
				VPNClientProtocols: []*armnetwork.VPNClientProtocol{&vpnClientProtocol},
			},
		},
	}

	// Create VPN Gateway - this is a long-running operation
	poller, err := i.vgwClient.BeginCreateOrUpdate(ctx, vnetInfo.resourceGroupName, VPNGatewayName, gatewayParams, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to start VPN Gateway creation: %w", err)
	}

	i.logger.Info("VPN Gateway creation initiated. Waiting for completion (this may take 20-30 minutes)...")

	resp, err := poller.PollUntilDone(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create VPN Gateway: %w", err)
	}

	i.logger.Infof("VPN Gateway creation completed: %s", *resp.Name)
	return &resp.VirtualNetworkGateway, nil
}

// ensureGatewaySubnet creates GatewaySubnet if it doesn't exist
func (i *Installer) ensureGatewaySubnet(ctx context.Context, vnetInfo vnetResourceInfo) error {
	// Check if GatewaySubnet already exists
	for _, subnet := range vnetInfo.vnet.Properties.Subnets {
		if strings.EqualFold(to.String(subnet.Name), GatewaySubnetName) {
			i.logger.Infof("GatewaySubnet already exists in VNet %s", vnetInfo.vnetID)
			return nil
		}
	}

	// Calculate a CIDR for GatewaySubnet to ensure no
	gatewaySubnetCIDR, err := i.calculateGatewaySubnetCIDR(ctx, vnetInfo)
	if err != nil {
		return fmt.Errorf("failed to calculate gateway subnet CIDR: %w", err)
	}

	i.logger.Infof("Creating GatewaySubnet with CIDR: %s", gatewaySubnetCIDR)

	gatewaySubnetParams := armnetwork.Subnet{
		Properties: &armnetwork.SubnetPropertiesFormat{
			AddressPrefix: &gatewaySubnetCIDR,
		},
	}

	// Create the subnet - this is a long-running operation
	poller, err := i.subnetsClient.BeginCreateOrUpdate(ctx, vnetInfo.resourceGroupName, to.String(vnetInfo.vnet.Name), GatewaySubnetName, gatewaySubnetParams, nil)
	if err != nil {
		return fmt.Errorf("failed to start GatewaySubnet creation: %w", err)
	}

	i.logger.Info("GatewaySubnet creation initiated. Waiting for completion...")

	// Wait for completion
	result, err := poller.PollUntilDone(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to create GatewaySubnet: %w", err)
	}

	i.logger.Infof("Successfully created GatewaySubnet: %s", *result.Name)
	return nil
}

func getVNetIDFromSubnetID(subnetID string) (string, error) {
	// Subnet ID format: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/virtualNetworks/{vnetName}/subnets/{subnetName}
	parts := strings.Split(subnetID, "/")
	if len(parts) < 9 {
		return "", fmt.Errorf("invalid subnet ID format: %s", subnetID)
	}
	vnetID := strings.Join(parts[:8], "/") // Up to virtualNetworks/{vnetName}
	return vnetID, nil
}

func getResourceGroupFromResourceID(resourceID string) string {
	parts := strings.Split(resourceID, "/")
	for i, part := range parts {
		if strings.EqualFold(part, "resourceGroups") && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

func getResourceNameFromResourceID(resourceID string) string {
	parts := strings.Split(resourceID, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return ""
}

func getSubscriptionIDFromResourceID(resourceID string) string {
	parts := strings.Split(resourceID, "/")
	for i, part := range parts {
		if strings.EqualFold(part, "subscriptions") && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}
