package cni

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sirupsen/logrus"
	"go.goms.io/aks/AKSFlexNode/pkg/config"
	"go.goms.io/aks/AKSFlexNode/pkg/utils"
)

// Installer handles CNI setup and installation operations
type Installer struct {
	config  *config.Config
	logger  *logrus.Logger
	Manager *Manager
}

// NewInstaller creates a new CNI setup Installer
func NewInstaller(logger *logrus.Logger) *Installer {
	cfg := config.GetConfig()
	return &Installer{
		config:  cfg,
		logger:  logger,
		Manager: NewManager(cfg),
	}
}

// GetName returns the step name
func (i *Installer) GetName() string {
	return "CNISetup"
}

// Execute configures the container network interface plugins and settings
func (i *Installer) Execute(ctx context.Context) error {
	i.logger.Info("Setting up Container Network Interface (CNI) configuration")

	// Validate prerequisites before CNI setup
	if err := i.validatePrerequisites(); err != nil {
		return fmt.Errorf("CNI setup prerequisites validation failed: %w", err)
	}

	// Setup Cilium CNI with enhanced error handling
	i.logger.Info("Setting up Cilium CNI components")
	if err := i.Manager.SetupCilium(); err != nil {
		i.logger.Errorf("Cilium CNI setup failed: %v", err)
		return fmt.Errorf("failed to setup Cilium: %w", err)
	}
	i.logger.Info("Cilium CNI setup completed successfully")

	// Install CNI plugins with version validation
	i.logger.Infof("Installing CNI plugins version %s", DefaultCNIVersion)
	if err := i.Manager.ExecuteCNIPlugins(DefaultCNIVersion); err != nil {
		i.logger.Errorf("CNI plugins installation failed: %v", err)
		return fmt.Errorf("failed to install CNI plugins version %s: %w", DefaultCNIVersion, err)
	}

	// Validate CNI plugins installation
	requiredPlugins := []string{BridgePlugin, HostLocalPlugin}
	for _, plugin := range requiredPlugins {
		pluginPath := filepath.Join(i.config.Paths.CNI.BinDir, plugin)
		if !utils.FileExists(pluginPath) {
			return fmt.Errorf("required CNI plugin not found after installation: %s", plugin)
		}
		i.logger.Debugf("Verified CNI plugin exists: %s", plugin)
	}
	i.logger.Info("CNI plugins installation completed and validated successfully")

	// Create bridge configuration for edge node (compatible with AKS Cilium)
	i.logger.Info("Creating bridge configuration for AKS Cilium compatibility")
	if err := i.Manager.CreateBridgeConfig(); err != nil {
		i.logger.Errorf("Bridge configuration creation failed: %v", err)
		return fmt.Errorf("failed to create bridge config: %w", err)
	}
	i.logger.Info("Bridge configuration created successfully")

	i.logger.Info("CNI setup completed successfully")
	return nil
}

// IsCompleted checks if CNI configuration has been set up properly
func (i *Installer) IsCompleted(ctx context.Context) bool {
	// Check if required CNI plugin binaries exist
	requiredPlugins := []string{BridgePlugin, HostLocalPlugin}
	for _, plugin := range requiredPlugins {
		pluginPath := filepath.Join(i.config.Paths.CNI.BinDir, plugin)
		if !utils.FileExists(pluginPath) {
			i.logger.Debugf("CNI plugin not found: %s", plugin)
			return false
		}
	}

	// Validate CNI configuration content
	if err := i.Manager.ValidateCNI(); err != nil {
		i.logger.Debugf("CNI configuration validation failed: %v", err)
		return false
	}

	// Validate bridge configuration content
	if err := i.Manager.ValidateBridgeConfig(); err != nil {
		i.logger.Debugf("CNI bridge configuration validation failed: %v", err)
		return false
	}

	i.logger.Debug("CNI setup validation passed - all components properly configured")
	return true
}

// Validate validates prerequisites for CNI setup
func (i *Installer) Validate(ctx context.Context) error {
	return i.validatePrerequisites()
}

// validatePrerequisites validates prerequisites before CNI setup
func (i *Installer) validatePrerequisites() error {
	i.logger.Debug("Validating prerequisites for CNI setup")

	// Validate CNI directories exist before setup
	cniDirs := []string{
		i.config.Paths.CNI.BinDir,
		i.config.Paths.CNI.ConfDir,
		i.config.Paths.CNI.LibDir,
	}

	for _, dir := range cniDirs {
		if !i.directoryExists(dir) {
			return fmt.Errorf("required CNI directory does not exist: %s", dir)
		}
	}

	return nil
}

// directoryExists checks if a directory exists
func (i *Installer) directoryExists(dir string) bool {
	info, err := os.Stat(dir)
	return err == nil && info.IsDir()
}
