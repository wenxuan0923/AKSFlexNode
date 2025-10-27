package arc

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/sirupsen/logrus"
	"go.goms.io/aks/AKSFlexNode/pkg/aks"
	"go.goms.io/aks/AKSFlexNode/pkg/auth"
	"go.goms.io/aks/AKSFlexNode/pkg/config"
	"go.goms.io/aks/AKSFlexNode/pkg/utils"
)

// ArcManager handles Azure Arc operations
type ArcManager struct {
	config       *config.Config
	logger       *logrus.Logger
	authProvider *auth.AuthProvider
}

// Singleton instance for target cluster info
var targetClusterInfoInstance *aks.ClusterInfo

// ArcMachineInfo represents Arc machine information
type ArcMachineInfo struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	Location          string   `json:"location"`
	ResourceGroup     string   `json:"resourceGroup"`
	SubscriptionID    string   `json:"subscriptionId"`
	Status            string   `json:"status"`
	OSType            string   `json:"osType"`
	OSVersion         string   `json:"osVersion"`
	AgentVersion      string   `json:"agentVersion"`
	LastHeartbeat     string   `json:"lastHeartbeat"`
	Identity          Identity `json:"identity"`
	ManagedIdentityID string   // This will be populated from Identity.PrincipalID
}

// Identity represents the managed identity information
type Identity struct {
	PrincipalID string `json:"principalId"`
	TenantID    string `json:"tenantId"`
	Type        string `json:"type"`
}

// NewArcManager creates a new Arc manager
func NewArcManager(cfg *config.Config, logger *logrus.Logger) *ArcManager {
	return &ArcManager{
		config:       cfg,
		logger:       logger,
		authProvider: auth.NewAuthProvider(cfg, logger),
	}
}

// InstallArcAgent installs the Azure Arc agent
func (a *ArcManager) InstallArcAgent(ctx context.Context) error {
	a.logger.Info("Installing Azure Arc agent")

	// Check if azcmagent is already installed
	if _, err := exec.LookPath("azcmagent"); err == nil {
		a.logger.Info("Azure Arc agent already installed")
		return nil
	}

	// Use wget to download (more reliable than custom download function) - needs sudo for temp file access
	cmd := exec.CommandContext(ctx, "sudo", "wget", arcAgentScriptURL, "-O", arcAgentTmpScriptPath)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to download Arc agent installation script: %w", err)
	}

	// Make script executable using sudo (since file was downloaded with sudo)
	cmd = exec.CommandContext(ctx, "sudo", "chmod", "755", arcAgentTmpScriptPath)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to make script executable: %w", err)
	}

	// Clean up
	defer func() {
		utils.RunCleanupCommand("rm", "-f", arcAgentTmpScriptPath)
	}()

	// Install prerequisites
	if err := a.installPrerequisites(); err != nil {
		return fmt.Errorf("failed to install prerequisites: %w", err)
	}

	// Run the installation script
	cmd = exec.CommandContext(ctx, "sudo", "bash", arcAgentTmpScriptPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to install Arc agent: %w, output: %s", err, string(output))
	}

	a.logger.Infof("Azure Arc agent installation completed: %s", string(output))

	// Verify installation was successful by checking if azcmagent is now available
	if _, err := exec.LookPath("azcmagent"); err != nil {
		// Check common installation paths
		commonPaths := []string{
			"/opt/azcmagent/bin/azcmagent",
			"/usr/local/bin/azcmagent",
			"/usr/bin/azcmagent",
		}

		var foundPath string
		for _, path := range commonPaths {
			if _, statErr := os.Stat(path); statErr == nil {
				foundPath = path
				break
			}
		}

		if foundPath != "" {
			// Automatically create symlink to make azcmagent available in PATH
			a.logger.Infof("Arc agent found at %s, creating symlink to /usr/local/bin/azcmagent", foundPath)
			cmd := exec.Command("sudo", "ln", "-sf", foundPath, "/usr/local/bin/azcmagent")
			if linkErr := cmd.Run(); linkErr != nil {
				return fmt.Errorf("Arc agent installed at %s but not in PATH. Failed to create symlink: %v. Please manually run: sudo ln -sf %s /usr/local/bin/azcmagent", foundPath, linkErr, foundPath)
			}
			a.logger.Info("Successfully created symlink for azcmagent")
		} else {
			return fmt.Errorf("Arc agent installation appeared to succeed but azcmagent is not available in PATH or common locations. You may need to restart your shell or update PATH manually. Installation output: %s", string(output))
		}
	}

	a.logger.Info("Azure Arc agent verification successful - azcmagent is available")
	return nil
}

// RegisterArcMachine registers the machine with Azure Arc
func (a *ArcManager) RegisterArcMachine(ctx context.Context) (*ArcMachineInfo, error) {
	a.logger.Info("Registering machine with Azure Arc")

	// Check if already registered
	if info, err := a.GetArcMachineInfo(ctx); err == nil && info != nil {
		a.logger.Infof("Machine already registered as Arc machine: %s", info.Name)
		return info, nil
	}

	// Verify azcmagent is available before attempting registration
	if _, err := exec.LookPath("azcmagent"); err != nil {
		return nil, fmt.Errorf("azcmagent is not installed or not in PATH. Please run 'aks-flex-node arc register' which includes automatic installation, or install the Azure Arc agent manually: %w", err)
	}

	// Get machine name
	machineName, err := getMachineName(a.config)
	if err != nil {
		return nil, fmt.Errorf("failed to get machine name: %w", err)
	}

	// Get access token from Azure CLI (current user need sufficient permissions)
	accessToken, err := a.authProvider.GetAccessTokenViaCLI(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("failed to get Azure CLI access token: %w", err)
	}

	// Register using azcmagent with access token
	args := []string{"connect",
		"--resource-group", a.config.Azure.ResourceGroup,
		"--subscription-id", a.config.Azure.SubscriptionID,
		"--tenant-id", a.config.Azure.TenantID,
		"--location", a.config.Azure.Location,
		"--cloud", "AzureCloud",
		"--access-token", accessToken,
		"--resource-name", machineName,
		"--tags", fmt.Sprintf("role=aks-edge-node,controller=aks-flex-node,version=%s", "1.0.0"),
	}

	// azcmagent connect typically requires sudo privileges
	cmd := exec.CommandContext(ctx, "sudo", append([]string{"azcmagent"}, args...)...)

	// Create a copy of the command for logging without the sensitive token
	logArgs := make([]string, len(cmd.Args))
	copy(logArgs, cmd.Args)
	for i := range logArgs {
		if i > 0 && logArgs[i-1] == "--access-token" {
			logArgs[i] = "[REDACTED]"
			break
		}
	}
	a.logger.Infof("Executing command: %s", cmd.String())
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to register Arc machine: %w, output: %s", err, string(output))
	}

	a.logger.Infof("Arc machine registration output: %s", string(output))

	// Wait for registration to complete
	time.Sleep(10 * time.Second)

	// Get machine info after registration
	return a.GetArcMachineInfo(ctx)
}

// GetArcMachineInfo retrieves Arc machine information
func (a *ArcManager) GetArcMachineInfo(ctx context.Context) (*ArcMachineInfo, error) {
	// Check if Arc agent is running
	if !a.IsArcAgentRunning() {
		return nil, fmt.Errorf("Arc agent is not running")
	}

	machineName, err := getMachineName(a.config)
	if err != nil {
		return nil, fmt.Errorf("failed to get machine name: %w", err)
	}

	a.logger.Infof("Looking up Arc machine with name: %s", machineName)

	// Get machine info using Azure CLI
	args := []string{"connectedmachine", "show",
		"--name", machineName,
		"--resource-group", a.config.Azure.ResourceGroup,
		"--subscription", a.config.Azure.SubscriptionID,
		"--output", "json",
	}

	cmd := utils.CreateAzureCliCommand(ctx, args...)
	a.logger.Infof("Executing command: %s", cmd.String())
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to get Arc machine info: %w, output: %s", err, string(output))
	}

	var info ArcMachineInfo
	if err := json.Unmarshal(output, &info); err != nil {
		return nil, fmt.Errorf("failed to parse Arc machine info: %w", err)
	}

	// Populate ManagedIdentityID from the Identity structure
	info.ManagedIdentityID = info.Identity.PrincipalID

	return &info, nil
}

// GetArcManagedIdentityToken gets a management token using the Arc managed identity
func (a *ArcManager) GetArcManagedIdentityToken(ctx context.Context) (string, error) {
	// Get management token using ARC managed identity
	token, err := a.authProvider.GetManagementToken(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get management token: %w", err)
	}
	return token, nil
}

// GetConnectedClusterInfoFromAzure gets target cluster info from Azure using ARC managed identity
func (a *ArcManager) GetConnectedClusterInfoFromAzure(ctx context.Context) (*aks.ClusterInfo, error) {
	// Get management token using ARC managed identity
	token, err := a.GetArcManagedIdentityToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get management token: %w", err)
	}

	configInfo := aks.GetTargetClusterInfoFromConfig(a.config)
	return aks.GetTargetClusterInfoFromAzure(ctx, token, configInfo, a.logger)
}

// IsArcAgentRunning checks if the Arc agent is running
func (a *ArcManager) IsArcAgentRunning() bool {
	// Check if Arc agent service is running
	if !utils.IsServiceActive("himdsd") {
		return false
	}

	// Check if Arc agent process is running
	cmd := exec.Command("pgrep", "-f", "azcmagent")
	if err := cmd.Run(); err != nil {
		return false
	}

	return true
}

// SetupRBACPermissions automatically assigns necessary permissions to the Arc machine managed identity
// using the user's Azure CLI credentials
func (a *ArcManager) SetupRBACPermissions(ctx context.Context, clusterInfo *aks.ClusterInfo) error {
	a.logger.Info("Auto-assigning permissions to Arc managed identity...")

	// Get Arc machine info to get the managed identity object ID
	arcInfo, err := a.GetArcMachineInfo(ctx)
	if err != nil {
		return fmt.Errorf("failed to get Arc machine info: %w", err)
	}
	if arcInfo.ManagedIdentityID == "" {
		return fmt.Errorf("Arc managed identity ID not found")
	}

	a.logger.Infof("Assigning permissions to managed identity: %s", arcInfo.ManagedIdentityID)

	// Assign Reader role on the specific AKS cluster
	clusterScope := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.ContainerService/managedClusters/%s",
		clusterInfo.SubscriptionID, clusterInfo.ResourceGroup, clusterInfo.Name)

	if err := a.assignRoleUsingAzCLI(ctx, arcInfo.ManagedIdentityID, "Reader", clusterScope); err != nil {
		return fmt.Errorf("failed to assign Reader role on cluster: %w", err)
	}

	// Assign Azure Kubernetes Service RBAC Cluster Admin role on the specific AKS cluster
	if err := a.assignRoleUsingAzCLI(ctx, arcInfo.ManagedIdentityID, "Azure Kubernetes Service RBAC Cluster Admin", clusterScope); err != nil {
		return fmt.Errorf("failed to assign Azure Kubernetes Service RBAC Cluster Admin role on cluster: %w", err)
	}

	// Assign Azure Kubernetes Service Cluster Admin Role for downloading cluster credentials
	if err := a.assignRoleUsingAzCLI(ctx, arcInfo.ManagedIdentityID, "Azure Kubernetes Service Cluster Admin Role", clusterScope); err != nil {
		return fmt.Errorf("failed to assign Azure Kubernetes Service Cluster Admin Role on cluster: %w", err)
	}

	// Assign Network Contributor role on the resource group for VPN Gateway provisioning
	rgScope := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s", clusterInfo.SubscriptionID, clusterInfo.ResourceGroup)

	if err := a.assignRoleUsingAzCLI(ctx, arcInfo.ManagedIdentityID, "Network Contributor", rgScope); err != nil {
		return fmt.Errorf("failed to assign Network Contributor role on resource group: %w", err)
	}

	// Also assign Contributor role on the managed resource group (for AKS managed VNet and resource management)
	a.logger.Infof("Debug: Checking managed resource group assignment - NodeResourceGroup='%s', ResourceGroup='%s'", clusterInfo.NodeResourceGroup, clusterInfo.ResourceGroup)
	if clusterInfo.NodeResourceGroup != "" && clusterInfo.NodeResourceGroup != clusterInfo.ResourceGroup {
		managedRGScope := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s", clusterInfo.SubscriptionID, clusterInfo.NodeResourceGroup)

		if err := a.assignRoleUsingAzCLI(ctx, arcInfo.ManagedIdentityID, "Contributor", managedRGScope); err != nil {
			a.logger.Warnf("Failed to assign Contributor role on managed resource group %s: %v", clusterInfo.NodeResourceGroup, err)
			a.logger.Warnf("VPN Gateway provisioning may fail if the VNet is in the managed resource group")
		} else {
			a.logger.Infof("Successfully assigned Contributor role on managed resource group: %s", clusterInfo.NodeResourceGroup)
		}
	} else {
		a.logger.Infof("Debug: Skipping managed resource group assignment - either empty or same as main resource group")
	}

	a.logger.Info("Successfully assigned permissions to Arc managed identity")
	return nil
}

// assignRoleUsingAzCLI assigns a role to the managed identity using Azure REST API
// This bypasses Conditional Access policy issues that affect Azure CLI
func (a *ArcManager) assignRoleUsingAzCLI(ctx context.Context, principalID, roleName, scope string) error {
	a.logger.Infof("Assigning role '%s' to principal '%s' on scope '%s'", roleName, principalID, scope)

	// Get access token using Azure CLI (this works even when role assignment via CLI fails)
	accessToken, err := a.authProvider.GetAccessTokenViaCLI(ctx, "")
	if err != nil {
		return fmt.Errorf("failed to get access token: %w", err)
	}

	roleDefinitionID, exists := roleDefinitionIDs[roleName]
	if !exists {
		return fmt.Errorf("unknown role name: %s", roleName)
	}

	// Generate a UUID for the role assignment
	assignmentID := a.generateUUID()

	// Construct the full role definition ID
	fullRoleDefinitionID := fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Authorization/roleDefinitions/%s",
		a.config.Azure.SubscriptionID, roleDefinitionID)

	// Prepare the request body
	requestBody := map[string]interface{}{
		"properties": map[string]interface{}{
			"roleDefinitionId": fullRoleDefinitionID,
			"principalId":      principalID,
			"principalType":    "ServicePrincipal",
		},
	}

	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return fmt.Errorf("failed to marshal request body: %w", err)
	}

	// Make the REST API call
	url := fmt.Sprintf("https://management.azure.com%s/providers/Microsoft.Authorization/roleAssignments/%s?api-version=2022-04-01",
		scope, assignmentID)

	req, err := http.NewRequestWithContext(ctx, "PUT", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to make REST API call: %w", err)
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	// Check for success or role assignment already exists
	if resp.StatusCode == 201 {
		a.logger.Infof("Successfully assigned role '%s' to principal '%s'", roleName, principalID)
		return nil
	} else if resp.StatusCode == 409 {
		// Role assignment already exists
		var errorResponse map[string]interface{}
		if err := json.Unmarshal(responseBody, &errorResponse); err == nil {
			if errorObj, ok := errorResponse["error"].(map[string]interface{}); ok {
				if code, ok := errorObj["code"].(string); ok && code == "RoleAssignmentExists" {
					a.logger.Infof("Role assignment already exists for role '%s' and principal '%s'", roleName, principalID)
					return nil
				}
			}
		}
		return fmt.Errorf("role assignment conflict: %s", string(responseBody))
	} else {
		return fmt.Errorf("role assignment failed with status %d: %s", resp.StatusCode, string(responseBody))
	}
}

// generateUUID generates a simple UUID for role assignments
func (a *ArcManager) generateUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// installPrerequisites installs required packages for Arc agent
func (a *ArcManager) installPrerequisites() error {
	packages := []string{"curl", "wget", "gnupg", "lsb-release", "jq", "net-tools"}

	// apt-get for Ubuntu/Debian
	if err := utils.RunSystemCommand("apt-get", "update"); err == nil {
		for _, pkg := range packages {
			if err := utils.RunSystemCommand("apt-get", "install", "-y", pkg); err != nil {
				a.logger.Warnf("Failed to install %s via apt-get: %v", pkg, err)
			}
		}
		return nil
	}

	return fmt.Errorf("unable to install prerequisites - no supported package manager found")
}

func getMachineName(config *config.Config) (string, error) {
	machineName := config.GetNodeName()
	if machineName == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return "", fmt.Errorf("failed to get hostname: %w", err)
		}
		machineName = hostname
	}
	return machineName, nil
}
