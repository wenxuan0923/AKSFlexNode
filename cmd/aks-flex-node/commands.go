package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"go.goms.io/aks/AKSFlexNode/pkg/bootstrap"
	"go.goms.io/aks/AKSFlexNode/pkg/config"
	"go.goms.io/aks/AKSFlexNode/pkg/utils"
	"go.goms.io/aks/AKSFlexNode/pkg/vpn"
)

// runBootstrapVPN is the main entry point for VPN bootstrap (auto-provision only)
func runBootstrapVPN(ctx context.Context, cfg *config.Config, logger *logrus.Logger, autoProvision bool) error {
	logger.Info("Starting VPN bootstrap...")

	if !autoProvision {
		return fmt.Errorf("bootstrap-vpn only supports auto-provisioning mode, use --auto-provision flag")
	}

	return runAutoProvisionVPN(ctx, cfg, logger)
}

// runAutoProvisionVPN handles VPN setup only with auto-provisioning using VPNGatewayController
func runAutoProvisionVPN(ctx context.Context, cfg *config.Config, logger *logrus.Logger) error {
	logger.Info("Auto-provision mode enabled - VPN setup only")

	// Use VPNGatewayController for VPN setup only
	vpnController := vpn.NewVPNGatewayController(cfg, logger)

	vpnResult, err := vpnController.ProvisionAndSetupVPN(ctx)
	if err != nil {
		return fmt.Errorf("VPN setup failed: %w", err)
	}

	logger.Info("VPN setup completed successfully")
	logger.Infof("VPN config saved at: %s", vpnResult.ConfigPath)
	logger.Info("Run 'bootstrap-node' command next to complete Kubernetes node bootstrapping")
	return nil
}

// runBootstrapNode handles Kubernetes node bootstrapping only
func runBootstrapNode(ctx context.Context, cfg *config.Config, logger *logrus.Logger) error {
	logger.Info("Starting Kubernetes node bootstrap...")

	bootstrapper := bootstrap.NewBootstrapper(cfg, logger)

	// Check if bootstrap is already completed
	if completed, err := bootstrapper.IsBootstrapCompleted(); err != nil {
		logger.Warnf("Could not check bootstrap status: %v", err)
	} else if completed {
		logger.Info("Node bootstrap already completed successfully")
		return nil
	}

	// Perform node bootstrap only (assumes VPN is already set up if needed)
	return bootstrapper.Bootstrap(ctx)
}

// runReset performs reset
func runReset(ctx context.Context, cfg *config.Config, logger *logrus.Logger, force bool) error {
	logger.Info("Starting reset...")

	bootstrapper := bootstrap.NewBootstrapper(cfg, logger)

	// Check current status for informational purposes only
	status, err := bootstrapper.GetBootstrapStatus(ctx)
	if err != nil {
		logger.Warnf("Could not check bootstrap status: %v", err)
		logger.Info("Proceeding with reset anyway to ensure complete cleanup")
	} else if len(status.CompletedSteps) == 0 {
		logger.Info("No bootstrap state found, but proceeding with cleanup to ensure system is clean")
	} else {
		logger.Infof("Found bootstrap state with %d completed steps, proceeding with reset", len(status.CompletedSteps))
	}

	return bootstrapper.Reset(ctx)
}

func runStatus(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	jsonOutput, _ := cmd.Flags().GetBool("json")

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	logger := utils.SetupLogger(cfg.Agent.LogLevel, cfg.Agent.LogFile)

	// Create bootstrapper to check status
	bootstrapper := bootstrap.NewBootstrapper(cfg, logger)

	status, err := bootstrapper.GetBootstrapStatus(ctx)
	if err != nil {
		return fmt.Errorf("failed to get bootstrap status: %w", err)
	}

	if jsonOutput {
		// Output JSON format
		jsonData, err := json.MarshalIndent(status, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal status to JSON: %w", err)
		}
		fmt.Println(string(jsonData))
		return nil
	}

	// Output human-readable format
	fmt.Printf("AKS Flex Node Bootstrap Status\n")
	fmt.Printf("====================================\n\n")

	fmt.Printf("Version: %s\n", status.Version)
	fmt.Printf("Started: %s\n", status.StartedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("Last Updated: %s\n", status.LastUpdated.Format("2006-01-02 15:04:05"))

	// Check if bootstrap is completed
	isCompleted := len(status.CompletedSteps) > 0 && status.CompletedSteps["bootstrap_completed"]
	if isCompleted {
		fmt.Printf("Status: ✅ COMPLETED\n\n")
	} else if len(status.FailedSteps) > 0 {
		fmt.Printf("Status: ❌ FAILED\n")
		fmt.Printf("Last Error: %s\n\n", status.LastError)
	} else if len(status.CompletedSteps) > 0 {
		fmt.Printf("Status: 🔄 IN PROGRESS\n\n")
	} else {
		fmt.Printf("Status: ⏳ NOT STARTED\n\n")
	}

	// Show VPN status
	fmt.Printf("VPN Connection: ")
	if status.VPNConnected {
		fmt.Printf("✅ Connected\n")
	} else {
		fmt.Printf("❌ Not Connected\n")
	}

	// Show Arc status
	fmt.Printf("Arc Registration: ")
	if status.ArcRegistered {
		fmt.Printf("✅ Registered\n")
	} else {
		fmt.Printf("❌ Not Registered\n")
	}

	// Show Kubelet status
	fmt.Printf("Kubelet Service: ")
	if status.KubeletRunning {
		fmt.Printf("✅ Running\n")
	} else {
		fmt.Printf("❌ Not Running\n")
	}

	fmt.Printf("\n")

	// Show completed steps
	if len(status.CompletedSteps) > 0 {
		fmt.Printf("Completed Steps (%d):\n", len(status.CompletedSteps))
		for step := range status.CompletedSteps {
			fmt.Printf("  ✅ %s\n", step)
		}
		fmt.Printf("\n")
	}

	// Show failed steps
	if len(status.FailedSteps) > 0 {
		fmt.Printf("Failed Steps (%d):\n", len(status.FailedSteps))
		for step, errorMsg := range status.FailedSteps {
			fmt.Printf("  ❌ %s: %s\n", step, errorMsg)
		}
		fmt.Printf("\n")
	}

	// Show configuration
	if len(status.Configuration) > 0 {
		fmt.Printf("Configuration:\n")
		for key, value := range status.Configuration {
			fmt.Printf("  %s: %s\n", key, value)
		}
		fmt.Printf("\n")
	}

	// Show next steps
	if !isCompleted {
		fmt.Printf("Next Steps:\n")
		if len(status.FailedSteps) > 0 {
			fmt.Printf("  • Run 'aks-flex-node bootstrap-vpn' to retry failed steps\n")
		} else if len(status.CompletedSteps) == 0 {
			// When nothing is started, suggest Arc registration first
			if !status.ArcRegistered {
				fmt.Printf("  • First: Register this node with Azure Arc using 'aks-flex-node arc register'\n")
				fmt.Printf("  • Then: Run 'aks-flex-node bootstrap-vpn' to start bootstrap\n")
			} else {
				fmt.Printf("  • Run 'aks-flex-node bootstrap-vpn' to start bootstrap\n")
			}
		} else {
			fmt.Printf("  • Bootstrap is in progress. Run 'aks-flex-node bootstrap-vpn' to continue\n")
		}
		fmt.Printf("  • Run 'aks-flex-node reset' to start over\n")
		fmt.Printf("  • Run 'aks-flex-node status --json' for machine-readable output\n")
	} else {
		fmt.Printf("Bootstrap completed successfully! 🎉\n")
	}

	return nil
}
