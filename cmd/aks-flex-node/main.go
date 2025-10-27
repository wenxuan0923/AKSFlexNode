package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"go.goms.io/aks/AKSFlexNode/pkg/config"
	"go.goms.io/aks/AKSFlexNode/pkg/utils"
)

var (
	configPath string
	version    = "1.0.0" // This should be set during build
	buildDate  = "unknown"
	gitCommit  = "unknown"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "aks-flex-node",
		Short: "AKS Flex Node Agent",
		Long: `AKS Flex Node Agent automates the deployment, configuration,
and management of AKS edge nodes.`,
		Version: fmt.Sprintf("%s (built %s, commit %s)", version, buildDate, gitCommit),
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true,
		},
	}

	rootCmd.PersistentFlags().StringVarP(&configPath, "config", "c", "", "Path to configuration file")

	// Add subcommands
	rootCmd.AddCommand(
		newArcCommand(),
		newBootstrapVPNCommand(),
		newBootstrapNodeCommand(),
		newResetCommand(),
		newStatusCommand(),
		newVersionCommand(),
	)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func newBootstrapVPNCommand() *cobra.Command {
	var autoProvision bool

	cmd := &cobra.Command{
		Use:   "bootstrap-vpn",
		Short: "Bootstrap VPN connection between node and AKS cluster",
		Long: "Setup VPN connection with certificate generation and OpenVPN configuration using idempotent state tracking. " +
			"Can resume from failures and skip completed steps. The VPN Gateway is auto-provisioned in MC_* resource group of the target AKS cluster. " +
			"This command only handles VPN setup - use 'bootstrap-node' afterwards for Kubernetes node bootstrapping.",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.LoadConfig(configPath)
			if err != nil {
				return fmt.Errorf("failed to load configuration: %w", err)
			}

			logger := utils.SetupLogger(cfg.Agent.LogLevel, cfg.Agent.LogFile)
			ctx := cmd.Context()

			return runBootstrapVPN(ctx, cfg, logger, autoProvision)
		},
	}

	cmd.Flags().BoolVar(&autoProvision, "auto-provision", false, "Automatically provision VPN Gateway in AKS cluster's VNet")
	return cmd
}

func newBootstrapNodeCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bootstrap-node",
		Short: "Bootstrap Kubernetes node components",
		Long: "Bootstrap the Kubernetes node with all required components using idempotent state tracking. " +
			"This includes installing container runtimes, Kubernetes components, downloading cluster credentials, " +
			"and configuring kubelet. Can resume from failures and skip completed steps. " +
			"Run this after 'bootstrap-vpn' to complete the full node setup.",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.LoadConfig(configPath)
			if err != nil {
				return fmt.Errorf("failed to load configuration: %w", err)
			}

			logger := utils.SetupLogger(cfg.Agent.LogLevel, cfg.Agent.LogFile)
			ctx := cmd.Context()

			return runBootstrapNode(ctx, cfg, logger)
		},
	}

	return cmd
}

func newResetCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "reset",
		Short: "Reset the node with idempotent state cleanup",
		Long:  "Reset the node configuration and remove all components with state tracking",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.LoadConfig(configPath)
			if err != nil {
				return fmt.Errorf("failed to load configuration: %w", err)
			}

			logger := utils.SetupLogger(cfg.Agent.LogLevel, cfg.Agent.LogFile)
			ctx := cmd.Context()

			force, _ := cmd.Flags().GetBool("force")
			return runReset(ctx, cfg, logger, force)
		},
	}

	cmd.Flags().Bool("force", false, "Force reset without confirmation")
	return cmd
}

func newVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show version information",
		Long:  "Display version, build date, and commit information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("AKS Flex Node Agent\n")
			fmt.Printf("Version: %s\n", version)
			fmt.Printf("Build Date: %s\n", buildDate)
			fmt.Printf("Git Commit: %s\n", gitCommit)
		},
	}
}

func newStatusCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show bootstrap status",
		Long:  "Display the current bootstrap status and progress",
		RunE:  runStatus,
	}

	cmd.Flags().Bool("json", false, "Output in JSON format")
	return cmd
}
