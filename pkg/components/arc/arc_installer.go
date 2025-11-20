package arc

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v3"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/hybridcompute/armhybridcompute"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"go.goms.io/aks/AKSFlexNode/pkg/utils"
)

// Installer handles Azure Arc installation operations
type Installer struct {
	*Base
}

// NewInstaller creates a new Arc installer
func NewInstaller(logger *logrus.Logger) *Installer {
	return &Installer{
		Base: NewBase(logger),
	}
}

// Validate validates prerequisites for Arc installation
func (i *Installer) Validate(ctx context.Context) error {
	// No specific prerequisites validation needed for Arc installation
	return nil
}

// GetName returns the step name
func (i *Installer) GetName() string {
	return "ArcInstall"
}

// Execute performs Arc setup as part of the bootstrap process
// This method is designed to be called from bootstrap steps and handles all Arc-related setup
// It stops on the first error to prevent partial setups
func (i *Installer) Execute(ctx context.Context) error {
	i.logger.Info("Starting Arc setup for bootstrap process")

	// Ensure authentication
	if err := i.ensureAuthentication(ctx); err != nil {
		return fmt.Errorf("Arc bootstrap setup failed at authentication: %w", err)
	}

	// Step 1: Validate Arc agent is available
	i.logger.Info("Step 1: Validating Arc agent availability")
	if err := i.validateArcAgent(ctx); err != nil {
		i.logger.Errorf("Arc agent validation failed: %v", err)
		return fmt.Errorf("Arc bootstrap setup failed at agent validation: %w", err)
	}
	i.logger.Info("Arc agent validation successful")

	// Step 2: Register Arc machine with Azure
	i.logger.Info("Step 2: Registering Arc machine with Azure")
	machine, err := i.registerArcMachine(ctx)
	if err != nil {
		i.logger.Errorf("Failed to register Arc machine: %v", err)
		return fmt.Errorf("Arc bootstrap setup failed at machine registration: %w", err)
	}
	i.logger.Info("Successfully registered Arc machine with Azure")

	// Step 3: Assign RBAC roles to managed identity (if enabled)
	if i.config.GetArcAutoRoleAssignment() {
		i.logger.Info("Step 3: Assigning RBAC roles to managed identity")
		// wait a moment to ensure machine info is fully propagated
		time.Sleep(10 * time.Second)
		if err := i.assignRBACRoles(ctx, machine); err != nil {
			i.logger.Errorf("Failed to assign RBAC roles: %v", err)
			return fmt.Errorf("Arc bootstrap setup failed at RBAC role assignment: %w", err)
		}
		i.logger.Info("Successfully assigned RBAC roles")
	} else {
		i.logger.Warn("Step 3: Skipping RBAC role assignment (autoRoleAssignment is disabled in config)")
		i.logger.Warn("⚠️  IMPORTANT: You must manually assign the following RBAC roles to the Arc managed identity:")
		managedIdentityID := getArcMachineIdentityID(machine)
		if managedIdentityID != "" {
			i.logger.Warnf("   Arc Managed Identity ID: %s", managedIdentityID)
			i.logger.Warnf("   Required roles on AKS cluster '%s':", i.config.Azure.TargetCluster.Name)
			i.logger.Warn("   - Azure Kubernetes Service RBAC Cluster Admin")
			i.logger.Warn("   - Azure Kubernetes Service Cluster Admin Role")
		}
	}

	// Step 4: Wait for permissions to become effective
	// Note: This step is needed regardless of autoRoleAssignment setting because:
	// - If autoRoleAssignment=true: we assigned roles and need to wait for them to be effective
	// - If autoRoleAssignment=false: customer must assign roles manually, and we still need to wait for them
	i.logger.Info("Step 4: Waiting for RBAC permissions to become effective")
	if err := i.waitForRBACPermissions(ctx, machine); err != nil {
		i.logger.Errorf("Failed while waiting for RBAC permissions: %v", err)
		return fmt.Errorf("Arc bootstrap setup failed while waiting for RBAC permissions: %w", err)
	}
	i.logger.Info("RBAC permissions are now effective")

	i.logger.Info("Arc setup for bootstrap completed successfully")
	return nil
}

// IsCompleted checks if Arc setup has been completed
// This can be used by bootstrap steps to verify completion status
func (i *Installer) IsCompleted(ctx context.Context) bool {
	i.logger.Debug("Checking Arc setup completion status")

	// Check if Arc agent is running
	if !isArcServicesRunning() {
		i.logger.Debug("Arc agent is not running")
		return false
	}

	// Check if machine is registered with Arc
	if _, err := i.getArcMachine(ctx); err != nil {
		i.logger.Debugf("Arc machine not registered or not accessible: %v", err)
		return false
	}

	i.logger.Debug("Arc setup appears to be completed")
	return true
}

// validateArcAgent ensures Arc agent is available (should be installed by install.sh)
func (i *Installer) validateArcAgent(ctx context.Context) error {
	if !isArcAgentInstalled() {
		return fmt.Errorf("Azure Arc agent not found - please run the installation script first:\n" +
			"curl -fsSL https://raw.githubusercontent.com/Azure/AKSFlexNode/main/scripts/install.sh | bash")
	}
	i.logger.Info("Azure Arc agent found and ready")
	return nil
}

// registerArcMachine registers the machine with Azure Arc using the Arc agent
func (i *Installer) registerArcMachine(ctx context.Context) (*armhybridcompute.Machine, error) {
	i.logger.Info("Registering machine with Azure Arc using Arc agent")

	// Check if already registered
	machine, err := i.getArcMachine(ctx)
	if err == nil && machine != nil {
		i.logger.Infof("Machine already registered as Arc machine: %s", *machine.Name)
		return machine, nil
	}

	// Register using Arc agent command
	if err := i.runArcAgentConnect(ctx); err != nil {
		return nil, fmt.Errorf("failed to register Arc machine using agent: %w", err)
	}

	// Wait a moment for registration to complete
	i.logger.Info("Waiting for Arc machine registration to complete...")
	time.Sleep(10 * time.Second)

	// Verify registration by retrieving the machine
	machine, err = i.getArcMachine(ctx)
	if err != nil {
		return nil, fmt.Errorf("Arc agent registration completed but failed to retrieve machine info: %w", err)
	}

	i.logger.Info("Arc machine registration completed successfully")
	return machine, nil
}

// runArcAgentConnect connects the machine to Azure Arc using the Arc agent
func (i *Installer) runArcAgentConnect(ctx context.Context) error {
	i.logger.Info("Connecting machine to Azure Arc using azcmagent")

	// Get Arc configuration details
	arcLocation := i.config.GetArcLocation()
	arcMachineName := i.config.GetArcMachineName()
	arcResourceGroup := i.config.GetArcResourceGroup()
	subscriptionID := i.config.GetSubscriptionID()
	tenantID := i.config.GetTenantID()

	// Build azcmagent connect command
	args := []string{
		"connect",
		"--resource-group", arcResourceGroup,
		"--tenant-id", tenantID,
		"--location", arcLocation,
		"--subscription-id", subscriptionID,
		"--resource-name", arcMachineName,
	}

	// Add Arc tags if any
	tags := i.config.GetArcTags()
	tagArgs := []string{}
	for key, value := range tags {
		tagArgs = append(tagArgs, "--tags", fmt.Sprintf("%s=%s", key, value))
	}
	args = append(args, tagArgs...)

	// Add authentication parameters
	// For CLI authentication, we need to preserve the user's environment
	if err := i.addAuthenticationArgs(ctx, &args); err != nil {
		return fmt.Errorf("failed to configure authentication for Arc agent: %w", err)
	}

	if err := utils.RunSystemCommand("azcmagent", args...); err != nil {
		return fmt.Errorf("failed to connect to Azure Arc: %w", err)
	}

	i.logger.Infof("Arc agent connect completed")
	return nil
}

// assignRBACRoles assigns required RBAC roles to the Arc machine's managed identity
func (i *Installer) assignRBACRoles(ctx context.Context, arcMachine *armhybridcompute.Machine) error {
	managedIdentityID := getArcMachineIdentityID(arcMachine)
	if managedIdentityID == "" {
		return fmt.Errorf("managed identity ID not found on Arc machine")
	}

	i.logger.Infof("🔐 Starting RBAC role assignment for Arc managed identity: %s", managedIdentityID)

	// Verify target cluster configuration
	if i.config.Azure.TargetCluster.ResourceID == "" {
		return fmt.Errorf("target cluster resource ID not configured - cannot assign roles")
	}
	i.logger.Infof("Target AKS cluster resource ID: %s", i.config.Azure.TargetCluster.ResourceID)

	// Create role assignments client
	client, err := i.createRoleAssignmentsClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to create role assignments client: %w", err)
	}

	// Get required role assignments
	requiredRoles := i.getRoleAssignments(arcMachine)
	i.logger.Infof("Need to assign %d RBAC roles", len(requiredRoles))

	// Track assignment results
	var assignmentErrors []error
	successCount := 0

	// Assign each required role
	for idx, role := range requiredRoles {
		i.logger.Infof("📋 [%d/%d] Assigning role '%s' on scope: %s", idx+1, len(requiredRoles), role.RoleName, role.Scope)

		if err := i.assignRole(ctx, client, managedIdentityID, role.RoleID, role.Scope, role.RoleName); err != nil {
			i.logger.Errorf("❌ Failed to assign role '%s': %v", role.RoleName, err)
			assignmentErrors = append(assignmentErrors, fmt.Errorf("role '%s': %w", role.RoleName, err))
		} else {
			i.logger.Infof("✅ Successfully assigned role '%s'", role.RoleName)
			successCount++
		}
	}

	// Report final results
	if len(assignmentErrors) > 0 {
		i.logger.Errorf("⚠️  RBAC role assignment completed with %d successes and %d failures", successCount, len(assignmentErrors))
		for _, err := range assignmentErrors {
			i.logger.Errorf("   - %v", err)
		}
		return fmt.Errorf("failed to assign %d out of %d RBAC roles", len(assignmentErrors), len(requiredRoles))
	}

	i.logger.Infof("🎉 All %d RBAC roles assigned successfully!", successCount)
	return nil
}

// assignRole creates a role assignment for the given principal, role, and scope
func (i *Installer) assignRole(ctx context.Context, client *armauthorization.RoleAssignmentsClient, principalID, roleDefinitionID, scope, roleName string) error {
	// Build the full role definition ID
	fullRoleDefinitionID := fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Authorization/roleDefinitions/%s",
		i.config.Azure.SubscriptionID, roleDefinitionID)

	i.logger.Debugf("Checking if role assignment already exists...")

	// Check if assignment already exists
	hasRole, err := i.checkRoleAssignment(ctx, client, principalID, roleDefinitionID, scope)
	if err != nil {
		i.logger.Warnf("⚠️  Error checking existing role assignment for %s: %v (will proceed with assignment)", roleName, err)
	} else if hasRole {
		i.logger.Infof("ℹ️  Role assignment already exists for role '%s' - skipping", roleName)
		return nil
	}

	// Generate a unique name for the role assignment (UUID format required)
	roleAssignmentName := uuid.New().String()
	i.logger.Debugf("Creating role assignment with ID: %s", roleAssignmentName)

	// Create the role assignment
	assignment := armauthorization.RoleAssignmentCreateParameters{
		Properties: &armauthorization.RoleAssignmentProperties{
			PrincipalID:      &principalID,
			RoleDefinitionID: &fullRoleDefinitionID,
		},
	}

	i.logger.Debugf("Calling Azure API to create role assignment...")
	_, err = client.Create(ctx, scope, roleAssignmentName, assignment, nil)
	if err != nil {
		// Provide more detailed error information
		i.logger.Errorf("❌ Role assignment creation failed:")
		i.logger.Errorf("   Principal ID: %s", principalID)
		i.logger.Errorf("   Role Definition ID: %s", fullRoleDefinitionID)
		i.logger.Errorf("   Scope: %s", scope)
		i.logger.Errorf("   Assignment Name: %s", roleAssignmentName)
		i.logger.Errorf("   Azure API Error: %v", err)

		// Check for common error patterns
		errStr := err.Error()
		if strings.Contains(errStr, "403") || strings.Contains(errStr, "Forbidden") {
			return fmt.Errorf("insufficient permissions to assign roles - ensure the user/service principal has Owner or User Access Administrator role on the target cluster: %w", err)
		}
		if strings.Contains(errStr, "RoleAssignmentExists") {
			i.logger.Info("ℹ️  Role assignment already exists (detected from error)")
			return nil
		}
		if strings.Contains(errStr, "PrincipalNotFound") {
			return fmt.Errorf("Arc managed identity not found - ensure Arc machine is properly registered: %w", err)
		}

		return fmt.Errorf("failed to create role assignment: %w", err)
	}

	i.logger.Debugf("✅ Role assignment created successfully")
	return nil
}

// waitForRBACPermissions waits for RBAC permissions to be available
func (i *Installer) waitForRBACPermissions(ctx context.Context, arcMachine *armhybridcompute.Machine) error {
	i.logger.Info("🕐 Step 4: Waiting for RBAC permissions to become effective...")

	// Get Arc machine info to get the managed identity object ID
	managedIdentityID := getArcMachineIdentityID(arcMachine)
	if managedIdentityID == "" {
		return fmt.Errorf("managed identity ID not found on Arc machine")
	}

	i.logger.Infof("Checking permissions for Arc managed identity: %s", managedIdentityID)
	i.logger.Infof("Target AKS cluster: %s", i.config.Azure.TargetCluster.Name)

	// Show required permissions for reference
	if i.config.GetArcAutoRoleAssignment() {
		i.logger.Info("ℹ️  Waiting for the following auto-assigned RBAC roles to become effective:")
	} else {
		i.logger.Warn("⚠️  Please ensure the following RBAC permissions are assigned manually:")
	}
	i.logger.Info("   • Reader role on the AKS cluster")
	i.logger.Info("   • Azure Kubernetes Service RBAC Cluster Admin role on the AKS cluster")
	i.logger.Info("   • Azure Kubernetes Service Cluster Admin Role on the AKS cluster")

	// Check permissions immediately first
	i.logger.Info("🔍 Performing initial permission check...")
	if hasPermissions := i.checkPermissionsWithLogging(ctx, managedIdentityID); hasPermissions {
		i.logger.Info("🎉 All required RBAC permissions are already available!")
		return nil
	}

	// Start polling for permissions (with retries and timeout)
	i.logger.Info("⏳ Starting permission polling (this may take a few minutes)...")
	return i.pollForPermissions(ctx, managedIdentityID)
}

// checkPermissionsWithLogging checks permissions and logs the result appropriately
func (i *Installer) checkPermissionsWithLogging(ctx context.Context, managedIdentityID string) bool {
	i.logger.Debug("Checking if required permissions are available...")

	hasPermissions, err := i.checkRequiredPermissions(ctx, managedIdentityID)
	if err != nil {
		i.logger.Warnf("⚠️  Error checking permissions (will retry): %v", err)
		return false
	}

	if !hasPermissions {
		i.logger.Debug("Some required permissions are still missing")
	}

	return hasPermissions
}

// pollForPermissions polls for RBAC permissions with timeout and interval
func (i *Installer) pollForPermissions(ctx context.Context, managedIdentityID string) error {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	maxWaitTime := 30 * time.Minute // Maximum wait time
	timeout := time.After(maxWaitTime)

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("context cancelled while waiting for permissions: %w", ctx.Err())
		case <-timeout:
			return fmt.Errorf("timeout after %v waiting for RBAC permissions to be assigned", maxWaitTime)
		case <-ticker.C:
			if hasPermissions := i.checkPermissionsWithLogging(ctx, managedIdentityID); hasPermissions {
				i.logger.Info("✅ All required RBAC permissions are now available!")
				return nil
			}
			i.logger.Info("⏳ Some permissions are still missing, will check again in 30 seconds...")
		}
	}
}

// addAuthenticationArgs adds appropriate authentication parameters to the azcmagent command
func (i *Installer) addAuthenticationArgs(ctx context.Context, args *[]string) error {
	cred, err := i.authProvider.UserCredential(ctx, i.config)
	if err != nil {
		return fmt.Errorf("failed to get Azure credentials: %w", err)
	}

	accessToken, err := i.authProvider.GetAccessToken(ctx, cred)
	if err != nil {
		return fmt.Errorf("failed to get access token for Arc agent authentication: %w", err)
	}

	i.logger.Info("Using access token authentication for Arc agent")
	*args = append(*args, "--access-token", accessToken)
	return nil
}
