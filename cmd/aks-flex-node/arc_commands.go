package main

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
	"go.goms.io/aks/AKSFlexNode/pkg/aks"
	"go.goms.io/aks/AKSFlexNode/pkg/arc"
	"go.goms.io/aks/AKSFlexNode/pkg/config"
	"go.goms.io/aks/AKSFlexNode/pkg/utils"
)

func newArcCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "arc",
		Short: "Azure Arc management commands",
		Long:  "Commands for managing Azure Arc registration, cluster discovery and RBAC setup",
	}

	cmd.AddCommand(
		newArcRegisterCommand(), // register the machine with Azure Arc
		newArcStatusCommand(),   // show Azure Arc status
	)

	return cmd
}

func newArcRegisterCommand() *cobra.Command {

	cmd := &cobra.Command{
		Use:   "register",
		Short: "Register machine with Azure Arc",
		Long:  "Register this machine as an Azure Arc-enabled server",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.LoadConfig(configPath)
			if err != nil {
				return fmt.Errorf("failed to load configuration: %w", err)
			}

			logger := utils.SetupLogger(cfg.Agent.LogLevel, cfg.Agent.LogFile)
			arcManager := arc.NewArcManager(cfg, logger)

			ctx := cmd.Context()

			// Install Arc agent if not already installed
			if err := arcManager.InstallArcAgent(ctx); err != nil {
				return fmt.Errorf("failed to install Arc agent: %w", err)
			}

			// Register the machine with Azure Arc and get registration info
			info, err := arcManager.RegisterArcMachine(ctx)
			if err != nil {
				return err
			}

			logger.Infof("Successfully registered Arc machine: %s (ID: %s)", info.Name, info.ID)

			clusterInfo := aks.GetTargetClusterInfoFromConfig(cfg)
			if clusterInfo != nil {
				logger.Info("Setting up RBAC permissions for target cluster...")
				if err := arcManager.SetupRBACPermissions(ctx, clusterInfo); err != nil {
					logger.Errorf("Failed to setup RBAC permissions: %v", err)
					logger.Warn("You may need to manually assign 'Azure Kubernetes Service Cluster User Role' to the Arc managed identity")
					logger.Warn("Or re-run 'arc register' again after ensuring you have sufficient permissions")
				} else {
					logger.Info("RBAC permissions configured successfully")
				}
			} else {
				logger.Info("No target cluster configured, skipping RBAC setup")
				logger.Info("Configure azure.arc.targetCluster in your config file to enable automatic RBAC setup")
			}

			return nil
		},
	}

	return cmd
}

func newArcStatusCommand() *cobra.Command {
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show Azure Arc status",
		Long:  "Display the current Azure Arc registration and authentication status",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			cfg, err := config.LoadConfig(configPath)
			if err != nil {
				return fmt.Errorf("failed to load configuration: %w", err)
			}

			logger := utils.SetupLogger(cfg.Agent.LogLevel, cfg.Agent.LogFile)
			arcManager := arc.NewArcManager(cfg, logger)

			// Build status information
			status := make(map[string]interface{})

			// Check if Arc agent is running
			status["agentRunning"] = arcManager.IsArcAgentRunning()

			// Get Arc machine info if available
			if machineInfo, err := arcManager.GetArcMachineInfo(ctx); err == nil && machineInfo != nil {
				status["registered"] = true
				status["resourceId"] = machineInfo.ID
				status["machineId"] = machineInfo.Name
				status["location"] = machineInfo.Location
				status["status"] = machineInfo.Status
				status["osType"] = machineInfo.OSType
				status["agentVersion"] = machineInfo.AgentVersion
				status["lastHeartbeat"] = machineInfo.LastHeartbeat
				status["managedIdentityId"] = machineInfo.ManagedIdentityID
			} else {
				status["registered"] = false
			}

			// Test authentication
			status["connectedClusters"] = []interface{}{}
			cluster, err := arcManager.GetConnectedClusterInfoFromAzure(ctx)
			if cluster != nil && err != nil {
				status["connectedClusters"] = []map[string]interface{}{
					{
						"name":     cluster.Name,
						"location": cluster.Location,
						"fqdn":     cluster.FQDN,
					},
				}
				status["authenticationWorking"] = true
			}

			if jsonOutput {
				output, err := json.MarshalIndent(status, "", "  ")
				if err != nil {
					return fmt.Errorf("failed to marshal status: %w", err)
				}
				fmt.Println(string(output))
			} else {
				printArcStatus(status)
			}

			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output in JSON format")
	return cmd
}

func printArcStatus(status map[string]interface{}) {
	fmt.Printf("Azure Arc Status\n")
	fmt.Printf("================\n")

	if registered, ok := status["registered"].(bool); ok {
		if registered {
			fmt.Printf("Registration: ✓ Registered\n")
		} else {
			fmt.Printf("Registration: ✗ Not Registered\n")
		}
	}

	if resourceID, ok := status["resourceId"].(string); ok && resourceID != "" {
		fmt.Printf("Resource ID: %s\n", resourceID)
	}

	if machineID, ok := status["machineId"].(string); ok && machineID != "" {
		fmt.Printf("Machine ID: %s\n", machineID)
	}

	if location, ok := status["location"].(string); ok && location != "" {
		fmt.Printf("Location: %s\n", location)
	}

	if authWorking, ok := status["authenticationWorking"].(bool); ok {
		if authWorking {
			fmt.Printf("Authentication: ✓ Working\n")
		} else {
			fmt.Printf("Authentication: ✗ Not Working\n")
		}
	}

	if connectedClusters, ok := status["connectedClusters"].([]interface{}); ok && len(connectedClusters) > 0 {
		fmt.Printf("\nConnected Clusters:\n")
		for _, cluster := range connectedClusters {
			if clusterMap, ok := cluster.(map[string]interface{}); ok {
				if name, ok := clusterMap["name"].(string); ok {
					fmt.Printf("  - %s", name)
					if location, ok := clusterMap["location"].(string); ok {
						fmt.Printf(" (%s)", location)
					}
					fmt.Printf("\n")
				}
			}
		}
	} else {
		fmt.Printf("\nConnected Clusters: None\n")
	}

	if agentRunning, ok := status["agentRunning"].(bool); ok {
		if agentRunning {
			fmt.Printf("Arc Agent: ✓ Running\n")
		} else {
			fmt.Printf("Arc Agent: ✗ Not Running\n")
		}
	}
}
