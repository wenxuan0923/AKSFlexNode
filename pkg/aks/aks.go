package aks

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
	"go.goms.io/aks/AKSFlexNode/pkg/config"
)

// ClusterInfo represents AKS cluster information
type ClusterInfo struct {
	ID                string    `json:"id"`
	Name              string    `json:"name"`
	Location          string    `json:"location"`
	ResourceGroup     string    `json:"resourceGroup"`
	SubscriptionID    string    `json:"subscriptionId"`
	KubernetesVersion string    `json:"kubernetesVersion"`
	FQDN              string    `json:"fqdn"`
	APIServerAddress  string    `json:"apiServerAddress"`
	CACert            string    `json:"caCert"`
	NodeResourceGroup string    `json:"nodeResourceGroup"`
	VNetInfo          *VNetInfo `json:"vnetInfo,omitempty"`
}

// VNetInfo represents Virtual Network information extracted from AKS cluster
type VNetInfo struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	ResourceGroup string `json:"resourceGroup"`
	NodeSubnetID  string `json:"nodeSubnetId"`
}

// Singleton instance for target cluster info
var targetClusterInfoInstance *ClusterInfo

// GetTargetClusterInfoFromConfig builds cluster info from target cluster configuration
// this is used before we assign ARC machine identity permissions to read cluster info from Azure
func GetTargetClusterInfoFromConfig(cfg *config.Config) *ClusterInfo {
	// Return cached instance if already computed
	if targetClusterInfoInstance != nil {
		return targetClusterInfoInstance
	}

	if cfg.Azure.Arc.TargetCluster.Name == "" {
		return nil
	}

	// Use target cluster resource group if specified, otherwise fall back to main resource group
	resourceGroup := cfg.Azure.Arc.TargetCluster.ResourceGroup
	if resourceGroup == "" {
		resourceGroup = cfg.Azure.ResourceGroup
	}

	// AKS node resource group follows the pattern: MC_{cluster-resource-group}_{cluster-name}_{location}
	mcResourceGroup := fmt.Sprintf("MC_%s_%s_%s",
		cfg.Azure.ResourceGroup,
		cfg.Azure.Arc.TargetCluster.Name,
		cfg.Azure.Location)

	// Build cluster info with what we know from config
	clusterInfo := &ClusterInfo{
		Name:              cfg.Azure.Arc.TargetCluster.Name,
		ResourceGroup:     resourceGroup,
		SubscriptionID:    cfg.Azure.SubscriptionID,
		Location:          cfg.Azure.Location,
		NodeResourceGroup: mcResourceGroup,
	}

	// Build the resource ID
	clusterInfo.ID = fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.ContainerService/managedClusters/%s",
		clusterInfo.SubscriptionID, clusterInfo.ResourceGroup, clusterInfo.Name)

	// Cache the result for future calls
	targetClusterInfoInstance = clusterInfo
	return clusterInfo
}

// GetTargetClusterInfoFromAzure gets cluster information using REST API with ARC machine managed identity token
func GetTargetClusterInfoFromAzure(ctx context.Context, accessToken string, cfg *ClusterInfo, logger *logrus.Logger) (*ClusterInfo, error) {
	// Get specific AKS cluster using REST API

	// return error if subscription ID, resource group, or name is missing
	if cfg.SubscriptionID == "" || cfg.ResourceGroup == "" || cfg.Name == "" {
		return nil, fmt.Errorf("missing required cluster information: subscription ID %s resource group %s,  name %s",
			cfg.SubscriptionID, cfg.ResourceGroup, cfg.Name)
	}

	url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.ContainerService/managedClusters/%s?api-version=2023-10-01",
		cfg.SubscriptionID, cfg.ResourceGroup, cfg.Name)

	client := &http.Client{Timeout: 60 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get AKS cluster: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get AKS cluster, status: %d, body: %s", resp.StatusCode, string(body))
	}

	var cluster struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		Location   string `json:"location"`
		Properties struct {
			KubernetesVersion string `json:"kubernetesVersion"`
			FQDN              string `json:"fqdn"`
			NodeResourceGroup string `json:"nodeResourceGroup"`
			AgentPoolProfiles []struct {
				Name         string `json:"name"`
				VnetSubnetID string `json:"vnetSubnetID"`
			} `json:"agentPoolProfiles"`
		} `json:"properties"`
	}

	if err := json.Unmarshal(body, &cluster); err != nil {
		return nil, fmt.Errorf("failed to parse cluster response: %w", err)
	}

	// Extract VNet information by searching aks managed VNet in MC_ resource group
	// custom VNet is NOT supported in this version
	var vnetInfo *VNetInfo
	// For clusters using default Azure-managed networking, try to find VNet in the managed resource group
	logger.Infof("Attempting to discover VNet in managed resource group: %s", cluster.Properties.NodeResourceGroup)

	// Try to discover VNet in the managed resource group
	if managedVNetInfo, err := discoverVNetInManagedResourceGroup(ctx, accessToken, cfg, logger); err == nil && managedVNetInfo != nil {
		vnetInfo = managedVNetInfo
		logger.Infof("Successfully discovered VNet in managed resource group: %s", vnetInfo.Name)
	} else {
		logger.Warnf("Could not discover VNet in managed resource group: %v", err)
		logger.Warnf("VPN Gateway provisioning may require manual VNet configuration")
	}

	clusterInfo := &ClusterInfo{
		ID:                cluster.ID,
		Name:              cluster.Name,
		Location:          cluster.Location,
		ResourceGroup:     cfg.ResourceGroup,
		SubscriptionID:    cfg.SubscriptionID,
		KubernetesVersion: cluster.Properties.KubernetesVersion,
		FQDN:              cluster.Properties.FQDN,
		NodeResourceGroup: cluster.Properties.NodeResourceGroup,
		VNetInfo:          vnetInfo,
	}

	logger.Infof("Found target cluster: %s (ID: %s)", clusterInfo.Name, clusterInfo.ID)
	logger.Infof("Debug: NodeResourceGroup = '%s', ResourceGroup = '%s'", clusterInfo.NodeResourceGroup, clusterInfo.ResourceGroup)
	return clusterInfo, nil
}

func discoverVNetInManagedResourceGroup(ctx context.Context, accessToken string, cfg *ClusterInfo, logger *logrus.Logger) (*VNetInfo, error) {
	// List VNets in the managed resource group
	url := fmt.Sprintf("https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/virtualNetworks?api-version=2024-05-01",
		cfg.SubscriptionID, cfg.NodeResourceGroup)

	client := &http.Client{Timeout: 60 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to list VNets: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to list VNets, status: %d, body: %s", resp.StatusCode, string(body))
	}

	var vnetList struct {
		Value []struct {
			ID         string `json:"id"`
			Name       string `json:"name"`
			Location   string `json:"location"`
			Properties struct {
				AddressSpace struct {
					AddressPrefixes []string `json:"addressPrefixes"`
				} `json:"addressSpace"`
				Subnets []struct {
					ID         string `json:"id"`
					Name       string `json:"name"`
					Properties struct {
						AddressPrefix string `json:"addressPrefix"`
					} `json:"properties"`
				} `json:"subnets"`
			} `json:"properties"`
		} `json:"value"`
	}

	if err := json.Unmarshal(body, &vnetList); err != nil {
		return nil, fmt.Errorf("failed to parse VNet list: %w", err)
	}

	if len(vnetList.Value) == 0 {
		return nil, fmt.Errorf("no VNets found in managed resource group: %s", cfg.NodeResourceGroup)
	}

	// Use the first VNet found (typically there's only one in AKS managed resource group)
	vnet := vnetList.Value[0]
	logger.Infof("Found VNet: %s in managed resource group", vnet.Name)

	// Find the node subnet (typically named "aks-subnet" or similar)
	var nodeSubnetID string
	for _, subnet := range vnet.Properties.Subnets {
		// Skip GatewaySubnet as it's reserved for VPN Gateway
		if subnet.Name != "GatewaySubnet" {
			nodeSubnetID = subnet.ID
			logger.Infof("Using subnet as node subnet: %s (%s)", subnet.Name, subnet.Properties.AddressPrefix)
			break
		}
	}

	vnetInfo := &VNetInfo{
		ID:            vnet.ID,
		Name:          vnet.Name,
		ResourceGroup: cfg.NodeResourceGroup,
		NodeSubnetID:  nodeSubnetID,
	}

	return vnetInfo, nil
}
