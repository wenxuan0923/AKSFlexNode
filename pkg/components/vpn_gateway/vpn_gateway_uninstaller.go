package vpn_gateway

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4"
	"github.com/sirupsen/logrus"

	"go.goms.io/aks/AKSFlexNode/pkg/auth"
	"go.goms.io/aks/AKSFlexNode/pkg/config"
	"go.goms.io/aks/AKSFlexNode/pkg/utils"
)

// UnInstaller handles VPN Gateway cleanup operations
type UnInstaller struct {
	config       *config.Config
	logger       *logrus.Logger
	authProvider *auth.AuthProvider
}

// NewUnInstaller creates a new VPN Gateway uninstaller
func NewUnInstaller(logger *logrus.Logger) *UnInstaller {
	cfg := config.GetConfig()
	return &UnInstaller{
		config:       cfg,
		logger:       logger,
		authProvider: auth.NewAuthProvider(),
	}
}

// GetAuthProvider returns the auth provider (implements AuthProvider interface)
func (u *UnInstaller) GetAuthProvider() *auth.AuthProvider {
	return u.authProvider
}

// GetName returns the cleanup step name
func (u *UnInstaller) GetName() string {
	return "VPNGatewayCleanup"
}

// Execute performs VPN Gateway cleanup as part of the unbootstrap process
// This method is resilient to failures and continues cleanup even if some operations fail
func (u *UnInstaller) Execute(ctx context.Context) error {
	u.logger.Info("Starting VPN Gateway cleanup for unbootstrap process")

	// Step 1: Disconnect VPN connection
	u.logger.Info("Step 1: Disconnecting VPN connection")
	if err := u.disconnectVPN(); err != nil {
		u.logger.Warnf("Failed to disconnect VPN (continuing cleanup): %v", err)
	} else {
		u.logger.Info("Successfully disconnected VPN connection")
	}

	// Step 2: Clean up VPN configuration files
	u.logger.Info("Step 2: Cleaning up VPN configuration files")
	if err := u.cleanupVPNFiles(); err != nil {
		u.logger.Warnf("Failed to cleanup VPN files (continuing cleanup): %v", err)
	} else {
		u.logger.Info("Successfully cleaned up VPN configuration files")
	}

	// Step 3: Optionally clean up certificates (keep certificates as they might be reused)
	u.logger.Info("Step 3: Cleaning up VPN certificates")
	if err := u.cleanupCertificates(); err != nil {
		u.logger.Warnf("Failed to cleanup certificates (continuing cleanup): %v", err)
	} else {
		u.logger.Info("Successfully cleaned up VPN certificates")
	}

	// Note: We don't delete the VPN Gateway from Azure as it's expensive to recreate
	// and might be shared with other resources. The VPN Gateway will be left in Azure.
	u.logger.Info("VPN Gateway resources in Azure are preserved for potential reuse")

	if err := u.cleanupAzureResources(ctx); err != nil {
		u.logger.Warnf("Failed to cleanup Azure VPN Gateway resources: %v", err)
	} else {
		u.logger.Info("Successfully cleaned up Azure VPN Gateway resources")
	}

	u.logger.Info("VPN Gateway cleanup for unbootstrap completed")
	return nil
}

// IsCompleted checks if VPN Gateway cleanup has been completed
func (u *UnInstaller) IsCompleted(ctx context.Context) bool {
	if !u.config.IsVPNGatewayEnabled() {
		u.logger.Info("VPN Gateway is not enabled in configuration; skipping cleanup")
		return true
	}

	u.logger.Debug("Checking VPN Gateway cleanup completion status")

	// Check if VPN is still connected
	if u.isVPNConnected() {
		u.logger.Debug("VPN is still connected")
		return false
	}

	// Check if VPN configuration files still exist
	configPath := GetVPNConfigPath()
	if _, err := os.Stat(configPath); err == nil {
		u.logger.Debug("VPN configuration files still exist")
		return false
	}

	u.logger.Debug("VPN Gateway cleanup appears to be completed")
	return true
}

// disconnectVPN stops the VPN connection and OpenVPN service
func (u *UnInstaller) disconnectVPN() error {
	u.logger.Info("Disconnecting VPN connection")

	// Stop OpenVPN service
	if err := utils.StopService(OpenVPNServiceTemplate); err != nil {
		u.logger.Warnf("Failed to stop OpenVPN service: %v", err)
		// Continue with other cleanup steps
	}

	// Kill any remaining OpenVPN processes
	if err := utils.RunSystemCommand("pkill", "-f", "openvpn"); err != nil {
		u.logger.Warnf("Failed to kill OpenVPN processes: %v", err)
		// Continue with other cleanup steps
	}

	u.logger.Info("VPN disconnection completed")
	return nil
}

// cleanupVPNFiles removes VPN configuration files and directories
func (u *UnInstaller) cleanupVPNFiles() error {
	u.logger.Info("Cleaning up VPN configuration files")

	filesToCleanup := []string{
		GetVPNConfigPath(),
		GetVPNClientCertPath(),
		GetVPNClientKeyPath(),
	}

	for _, filePath := range filesToCleanup {
		if err := os.Remove(filePath); err != nil {
			if !os.IsNotExist(err) {
				u.logger.Warnf("Failed to remove file %s: %v", filePath, err)
			} else {
				u.logger.Debugf("File %s already removed or doesn't exist", filePath)
			}
		} else {
			u.logger.Infof("Removed file: %s", filePath)
		}
	}

	// Try to remove the certificates directory if it's empty
	if err := os.Remove(CertificatesDir); err != nil {
		if !os.IsNotExist(err) {
			u.logger.Debugf("Certificate directory not empty or removal failed: %v", err)
		}
	} else {
		u.logger.Infof("Removed directory: %s", CertificatesDir)
	}

	u.logger.Info("VPN files cleanup completed")
	return nil
}

// cleanupCertificates removes certificate files
func (u *UnInstaller) cleanupCertificates() error {
	u.logger.Info("Cleaning up VPN certificates")

	certificateFiles := []string{
		GetVPNClientCertPath(),
		GetVPNClientKeyPath(),
	}

	for _, certFile := range certificateFiles {
		if err := os.Remove(certFile); err != nil {
			if !os.IsNotExist(err) {
				u.logger.Warnf("Failed to remove certificate file %s: %v", certFile, err)
			} else {
				u.logger.Debugf("Certificate file %s already removed or doesn't exist", certFile)
			}
		} else {
			u.logger.Infof("Removed certificate file: %s", certFile)
		}
	}

	u.logger.Info("Certificate cleanup completed")
	return nil
}

// isVPNConnected checks if VPN connection is active
func (u *UnInstaller) isVPNConnected() bool {
	// Check if there's an active VPN interface
	output, err := utils.RunCommandWithOutput("ip", "route", "show")
	if err != nil {
		u.logger.Debugf("Failed to check VPN connection status: %v", err)
		return false
	}

	// Look for VPN-related routes (tun interfaces or routes through VPN gateway)
	vpnRoutePatterns := []string{"tun", "tap"}
	outputStr := string(output)

	for _, pattern := range vpnRoutePatterns {
		if strings.Contains(outputStr, pattern) {
			u.logger.Debugf("Found VPN-related route with pattern: %s", pattern)
			return true
		}
	}

	return false
}

// Optional: cleanupAzureResources removes VPN Gateway resources from Azure
// This is commented out because VPN Gateway deletion is expensive and might not be desired
// Uncomment and call this method if you want to also delete Azure resources
func (u *UnInstaller) cleanupAzureResources(ctx context.Context) error {
	u.logger.Info("Cleaning up VPN Gateway resources from Azure")

	// Delete VPN Gateway (this is a long-running operation)
	resourceGroup := u.config.GetTargetClusterNodeResourceGroup()

	cred, err := auth.NewAuthProvider().UserCredential(config.GetConfig())
	if err != nil {
		return fmt.Errorf("failed to get authentication credential: %w", err)
	}
	client, err := armnetwork.NewVirtualNetworkGatewaysClient(u.config.Azure.SubscriptionID, cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create VPN Gateway client: %w", err)
	}

	u.logger.Infof("Deleting VPN Gateway: %s (this may take 10-20 minutes)", DefaultVPNGatewayName)
	poller, err := client.BeginDelete(ctx, resourceGroup, DefaultVPNGatewayName, nil)
	if err != nil {
		return fmt.Errorf("failed to start VPN Gateway deletion: %w", err)
	}

	// Wait for deletion to complete
	_, err = poller.PollUntilDone(ctx, nil)
	if err != nil {
		return fmt.Errorf("VPN Gateway deletion failed: %w", err)
	}

	u.logger.Info("VPN Gateway successfully deleted from Azure")
	return nil
}
