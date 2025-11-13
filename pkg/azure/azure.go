package azure

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v5"
	"github.com/sirupsen/logrus"

	"go.goms.io/aks/AKSFlexNode/pkg/config"
)

// GetClusterCredentials retrieves cluster kube admin credentials using Azure SDK
func GetClusterCredentials(ctx context.Context, cred azcore.TokenCredential, logger *logrus.Logger) ([]byte, error) {
	cfg := config.GetConfig()
	clusterResourceGroup := cfg.Azure.TargetCluster.ResourceGroup
	clusterName := cfg.Azure.TargetCluster.Name
	clusterSubID := cfg.Azure.TargetCluster.SubscriptionID
	// Create the Azure Container Service client using proper credentials
	clientFactory, err := armcontainerservice.NewClientFactory(clusterSubID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure Container Service client factory: %w", err)
	}

	mcClient := clientFactory.NewManagedClustersClient()

	// Get cluster admin credentials using the Azure SDK
	resp, err := mcClient.ListClusterAdminCredentials(ctx, clusterResourceGroup, clusterName, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get cluster admin credentials for %s in resource group %s: %w", clusterName, clusterResourceGroup, err)
	}

	if len(resp.Kubeconfigs) == 0 {
		return nil, fmt.Errorf("no kubeconfig found in cluster admin credentials response")
	}

	// Get the first kubeconfig (typically the admin config)
	kubeconfig := resp.Kubeconfigs[0]
	if kubeconfig.Value == nil {
		return nil, fmt.Errorf("kubeconfig value is nil")
	}

	// The Value field is already []byte containing the kubeconfig data, no decoding needed
	return kubeconfig.Value, nil
}
