package directories

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"
	"go.goms.io/aks/AKSFlexNode/pkg/config"
	"go.goms.io/aks/AKSFlexNode/pkg/utils"
)

// UnInstaller handles removing directories created during bootstrap
type UnInstaller struct {
	config *config.Config
	logger *logrus.Logger
}

// NewUnInstaller creates a new directories unInstaller
func NewUnInstaller(logger *logrus.Logger) *UnInstaller {
	return &UnInstaller{
		config: config.GetConfig(),
		logger: logger,
	}
}

// GetName returns the cleanup step name
func (u *UnInstaller) GetName() string {
	return "DirectoriesCleanup"
}

// Execute removes directories created during bootstrap
func (u *UnInstaller) Execute(ctx context.Context) error {
	u.logger.Info("Cleaning up directories")

	// Get directories to clean up (these should match what was created in bootstrap)
	dirsToCleanup := u.getDirectoriesToCleanup()

	// Also clean up any residual mount points in /var/lib/kubelet
	kubeletDir := "/var/lib/kubelet"
	if utils.DirectoryExists(kubeletDir) {
		u.logger.Info("Cleaning up any remaining kubelet mount points")
		// Find and unmount any remaining mount points with sudo
		if err := utils.RunSystemCommand("bash", "-c",
			fmt.Sprintf("findmnt -R %s | tail -n +2 | awk '{print $1}' | xargs -r -n1 sudo umount -l || true", kubeletDir)); err != nil {
			u.logger.Warnf("Failed to unmount some kubelet mount points: %v", err)
		}
	}

	// Remove directories using shared utility
	errors := utils.RemoveDirectories(dirsToCleanup, u.logger)

	if len(errors) > 0 {
		return fmt.Errorf("failed to clean up %d directories: %v", len(errors), errors[0])
	}

	u.logger.Info("Directory cleanup completed successfully")
	return nil
}

// IsCompleted checks if the directories have been cleaned up
func (u *UnInstaller) IsCompleted(ctx context.Context) bool {
	keyDirs := []string{
		"/etc/kubernetes",
		"/var/lib/kubelet",
		"/etc/containerd",
	}

	for _, dir := range keyDirs {
		if utils.DirectoryExists(dir) {
			// Directory still exists
			return false
		}
	}

	return true
}

// getDirectoriesToCleanup returns the list of directories to clean up
func (u *UnInstaller) getDirectoriesToCleanup() []string {
	return []string{
		"/etc/kubernetes",
		"/var/lib/kubelet",
		"/var/lib/containerd",
		"/etc/containerd",
		"/opt/cni/bin",
		"/etc/cni/net.d",
		"/var/log/pods",
		"/var/log/containers",
	}
}
