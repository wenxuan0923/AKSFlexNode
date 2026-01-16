package kube_binaries

import (
	"context"

	"github.com/sirupsen/logrus"
	"go.goms.io/aks/AKSFlexNode/pkg/utils"
)

// UnInstaller handles Kubernetes components removal operations
type UnInstaller struct {
	logger *logrus.Logger
}

// NewUnInstaller creates a new Kubernetes components unInstaller
func NewUnInstaller(logger *logrus.Logger) *UnInstaller {
	return &UnInstaller{
		logger: logger,
	}
}

// GetName returns the cleanup step name
func (u *UnInstaller) GetName() string {
	return "KubernetesComponentsExecuteed"
}

// Execute removes Kubernetes components
func (u *UnInstaller) Execute(ctx context.Context) error {
	u.logger.Info("Removing Kubernetes binaries")

	// Remove Kubernetes binaries (rm -f handles non-existent files gracefully)
	binaryFiles := []string{
		kubeletPath,
		kubectlPath,
		kubeadmPath,
	}
	if fileErrors := utils.RemoveFiles(binaryFiles, u.logger); len(fileErrors) > 0 {
		for _, err := range fileErrors {
			u.logger.Warnf("Binary removal error: %v", err)
		}
	}

	u.logger.Info("Kubernetes binaries removal completed")
	return nil
}

// IsCompleted checks if Kubernetes components have been removed
func (u *UnInstaller) IsCompleted(ctx context.Context) bool {
	return !utils.BinaryExists(kubeletBinary)
}
