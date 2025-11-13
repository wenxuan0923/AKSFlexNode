package containerd

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"
	"go.goms.io/aks/AKSFlexNode/pkg/utils"
)

// UnInstaller handles containerd Executeation operations
type UnInstaller struct {
	logger *logrus.Logger
}

// NewUnInstaller creates a new containerd unInstaller
func NewUnInstaller(logger *logrus.Logger) *UnInstaller {
	return &UnInstaller{
		logger: logger,
	}
}

// GetName returns the cleanup step name
func (u *UnInstaller) GetName() string {
	return "ContainerdExecuteed"
}

// Execute removes containerd container runtime and cleans up configuration
func (u *UnInstaller) Execute(ctx context.Context) error {
	u.logger.Info("Executeing containerd")

	// Step 1: Stop containerd services
	if err := u.stopContainerdServices(); err != nil {
		u.logger.Warnf("Failed to stop containerd services: %v (continuing)", err)
	}

	// Step 2: Remove containerd binaries
	if err := u.removeContainerdBinaries(); err != nil {
		return fmt.Errorf("failed to remove containerd binaries: %w", err)
	}

	// Step 3: Remove systemd service files
	if err := u.removeSystemdServices(); err != nil {
		return fmt.Errorf("failed to remove systemd services: %w", err)
	}

	// Step 4: Clean up configuration and data files
	if err := u.cleanupContainerdFiles(); err != nil {
		return fmt.Errorf("failed to cleanup containerd files: %w", err)
	}

	// Verify Executeation
	if err := u.validateExecuteation(); err != nil {
		return fmt.Errorf("containerd Executeation validation failed: %w", err)
	}

	u.logger.Info("Containerd Executeed successfully")
	return nil
}

// IsCompleted checks if containerd has been completely removed
func (u *UnInstaller) IsCompleted(ctx context.Context) bool {
	// Check if main binary exists
	if utils.BinaryExists("containerd") {
		return false
	}

	// Check if any containerd files still exist
	containerdFiles := []string{
		"/etc/containerd/config.toml",
		"/var/lib/containerd/",
	}

	for _, file := range containerdFiles {
		if utils.FileExists(file) {
			return false
		}
	}

	return true
}

// stopContainerdServices stops all containerd-related services
func (u *UnInstaller) stopContainerdServices() error {
	u.logger.Info("Ensuring containerd is stopped")

	if err := utils.StopService("containerd"); err != nil {
		u.logger.Warnf("Failed to stop containerd service: %v", err)
		return err
	}

	return nil
}

// removeContainerdBinaries removes all containerd binary files
func (u *UnInstaller) removeContainerdBinaries() error {
	u.logger.Info("Removing containerd binaries")

	binaries := []string{
		"/usr/bin/containerd",
		"/usr/local/bin/containerd",
		"/usr/bin/containerd-shim-runc-v2",
		"/usr/local/bin/containerd-shim-runc-v2",
		"/usr/bin/ctr",
		"/usr/local/bin/ctr",
	}

	if fileErrors := utils.RemoveFiles(binaries, u.logger); len(fileErrors) > 0 {
		for _, err := range fileErrors {
			u.logger.Warnf("Binary removal error: %v", err)
		}
	}

	return nil
}

// removeSystemdServices removes containerd systemd service files
func (u *UnInstaller) removeSystemdServices() error {
	u.logger.Info("Removing containerd systemd service")

	serviceFiles := []string{
		"/etc/systemd/system/containerd.service",
		"/lib/systemd/system/containerd.service",
		"/usr/lib/systemd/system/containerd.service",
	}

	if fileErrors := utils.RemoveFiles(serviceFiles, u.logger); len(fileErrors) > 0 {
		for _, err := range fileErrors {
			u.logger.Warnf("Service file removal error: %v", err)
		}
	}

	// Reload systemd
	if err := utils.ReloadSystemd(); err != nil {
		u.logger.Warnf("Failed to reload systemd: %v", err)
		return err
	}

	return nil
}

// cleanupContainerdFiles removes containerd configuration and data files
func (u *UnInstaller) cleanupContainerdFiles() error {
	u.logger.Info("Cleaning up containerd configuration and data files")

	containerdFiles := []string{
		"/etc/containerd/config.toml",
	}

	containerdDirectories := []string{
		"/var/lib/containerd/",
		"/etc/containerd/",
	}

	// Remove individual files
	if fileErrors := utils.RemoveFiles(containerdFiles, u.logger); len(fileErrors) > 0 {
		for _, err := range fileErrors {
			u.logger.Warnf("Configuration file removal error: %v", err)
		}
	}

	// Remove directories
	if dirErrors := utils.RemoveDirectories(containerdDirectories, u.logger); len(dirErrors) > 0 {
		for _, err := range dirErrors {
			u.logger.Warnf("Directory removal error: %v", err)
		}
	}

	return nil
}

// validateExecuteation validates that containerd was Executeed correctly
func (u *UnInstaller) validateExecuteation() error {
	// Check if main binary still exists
	if utils.FileExists(ContainerdBinaryPath) {
		return fmt.Errorf("containerd binary still found after Executeation")
	}

	// Check if binary is still available in PATH
	if utils.BinaryExists("containerd") {
		return fmt.Errorf("containerd binary still available in PATH after Executeation")
	}

	return nil
}
