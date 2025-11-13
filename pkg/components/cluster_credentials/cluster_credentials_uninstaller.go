package cluster_credentials

import (
	"context"

	"github.com/sirupsen/logrus"
	"go.goms.io/aks/AKSFlexNode/pkg/config"
	"go.goms.io/aks/AKSFlexNode/pkg/utils"
)

// UnInstaller handles cleanup of cluster credentials
type UnInstaller struct {
	config *config.Config
	logger *logrus.Logger
}

// NewUnInstaller creates a new cluster credentials unInstaller
func NewUnInstaller(logger *logrus.Logger) *UnInstaller {
	return &UnInstaller{
		config: config.GetConfig(),
		logger: logger,
	}
}

// GetName returns the cleanup step name
func (u *UnInstaller) GetName() string {
	return "ClusterCredentialsCleanup"
}

// Execute removes cluster credential files
func (u *UnInstaller) Execute(ctx context.Context) error {
	u.logger.Info("Cleaning up cluster credentials")

	// Remove credential files
	for _, file := range CredentialFiles {
		if utils.FileExists(file) {
			if err := utils.RunSystemCommand("rm", "-rf", file); err != nil {
				u.logger.WithError(err).Warnf("Failed to remove credential file: %s", file)
				continue
			}
			u.logger.Infof("Removed credential file: %s", file)
		}
	}

	u.logger.Info("Cluster credentials cleanup completed")
	return nil
}

// IsCompleted checks if cluster credential files still exist
func (u *UnInstaller) IsCompleted(ctx context.Context) bool {
	for _, file := range CredentialFiles {
		if utils.FileExists(file) {
			return false
		}
	}
	return true
}
