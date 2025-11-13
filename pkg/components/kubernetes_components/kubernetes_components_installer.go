package kubernetes_components

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/sirupsen/logrus"
	"go.goms.io/aks/AKSFlexNode/pkg/config"
	"go.goms.io/aks/AKSFlexNode/pkg/utils"
)

// Installer handles Kubernetes components installation operations
type Installer struct {
	config *config.Config
	logger *logrus.Logger
}

// NewInstaller creates a new Kubernetes components Installer
func NewInstaller(logger *logrus.Logger) *Installer {
	return &Installer{
		config: config.GetConfig(),
		logger: logger,
	}
}

// Execute downloads and installs Kubernetes components (kubelet, kubectl, kubeadm)
func (i *Installer) Execute(ctx context.Context) error {
	i.logger.Infof("Installing Kubernetes components version %s", i.config.Kubernetes.Version)

	binaries := []string{KubeletBinary, KubectlBinary, KubeadmBinary}

	// Check if Kubernetes components are already installed with correct version
	if i.areKubernetesComponentsInstalledWithCorrectVersion(binaries) {
		i.logger.Info("Kubernetes components are already installed with correct version, skipping installation")
		return nil
	}

	// Determine CPU architecture
	cpuArch := runtime.GOARCH
	if cpuArch == "amd64" {
		cpuArch = "amd64"
	} else if cpuArch == "arm64" {
		cpuArch = "arm64"
	} else {
		return fmt.Errorf("unsupported CPU architecture: %s", cpuArch)
	}
	i.logger.Infof("Detected CPU architecture: %s", cpuArch)

	// Create temporary directory for download and extraction
	tempDir, err := os.MkdirTemp("", "kubernetes-install-*")
	if err != nil {
		return fmt.Errorf("failed to create temporary directory: %w", err)
	}
	defer os.RemoveAll(tempDir)

	// Construct download URL
	url := fmt.Sprintf(i.config.Kubernetes.URLTemplate, i.config.Kubernetes.Version, cpuArch)
	tarFile := filepath.Join(tempDir, fmt.Sprintf("kubernetes-node-linux-%s.tar.gz", cpuArch))

	// Download Kubernetes components with validation
	i.logger.Infof("Downloading Kubernetes components from %s", url)
	if err := utils.DownloadFile(url, tarFile); err != nil {
		return fmt.Errorf("failed to download Kubernetes components from %s: %w", url, err)
	}

	// Verify downloaded file exists and has content
	info, err := os.Stat(tarFile)
	if err != nil {
		return fmt.Errorf("downloaded Kubernetes file not found: %w", err)
	}
	if info.Size() == 0 {
		return fmt.Errorf("downloaded Kubernetes file is empty")
	}
	i.logger.Infof("Downloaded Kubernetes archive (%d bytes)", info.Size())

	// Change to temp directory for extraction
	originalDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current directory: %w", err)
	}
	defer os.Chdir(originalDir)

	if err := os.Chdir(tempDir); err != nil {
		return fmt.Errorf("failed to change to temp directory: %w", err)
	}

	// Extract specific Kubernetes binaries
	i.logger.Info("Extracting Kubernetes binaries")
	extractPaths := make([]string, 0, len(binaries))
	for _, binary := range binaries {
		extractPaths = append(extractPaths, fmt.Sprintf("kubernetes/node/bin/%s", binary))
	}

	extractArgs := append([]string{"-xzf", filepath.Base(tarFile)}, extractPaths...)
	if err := utils.RunSystemCommand("tar", extractArgs...); err != nil {
		return fmt.Errorf("failed to extract Kubernetes binaries: %w", err)
	}

	// Verify extracted binaries exist
	for _, binary := range binaries {
		extractedPath := filepath.Join("kubernetes/node/bin", binary)
		if !utils.FileExists(extractedPath) {
			return fmt.Errorf("extracted Kubernetes binary not found: %s", binary)
		}
	}

	// Install binaries to BinDir with proper permissions
	i.logger.Infof("Installing Kubernetes binaries to %s/", BinDir)
	for _, binary := range binaries {
		srcPath := filepath.Join("kubernetes/node/bin", binary)
		dstPath := filepath.Join(BinDir, binary)

		i.logger.Debugf("Installing %s to %s", srcPath, dstPath)

		// Copy binary with proper permissions
		if err := utils.RunSystemCommand("cp", srcPath, dstPath); err != nil {
			return fmt.Errorf("failed to copy %s to %s: %w", srcPath, dstPath, err)
		}

		// Set executable permissions
		if err := utils.RunSystemCommand("chmod", "755", dstPath); err != nil {
			return fmt.Errorf("failed to set executable permissions on %s: %w", dstPath, err)
		}

		// Set proper ownership
		if err := utils.RunSystemCommand("chown", "root:root", dstPath); err != nil {
			i.logger.Warnf("Failed to set ownership on %s: %v", dstPath, err)
		}
	}

	// Verify installation
	if err := i.validateKubernetesInstallation(binaries); err != nil {
		return fmt.Errorf("Kubernetes installation validation failed: %w", err)
	}

	i.logger.Infof("Kubernetes components version %s installed successfully", i.config.Kubernetes.Version)
	return nil
}

// IsCompleted checks if all Kubernetes components are installed
func (i *Installer) IsCompleted(ctx context.Context) bool {
	binaries := []string{KubeletBinary, KubectlBinary, KubeadmBinary}
	for _, binary := range binaries {
		if !utils.FileExists(filepath.Join(BinDir, binary)) {
			return false
		}
	}
	return true
}

// Validate validates prerequisites for Kubernetes components installation
func (i *Installer) Validate(ctx context.Context) error {
	i.logger.Debug("Validating prerequisites for Kubernetes components installation")
	// No specific prerequisites for Kubernetes components installation
	return nil
}

// areKubernetesComponentsInstalledWithCorrectVersion checks if all Kubernetes components are installed with the correct version
func (i *Installer) areKubernetesComponentsInstalledWithCorrectVersion(binaries []string) bool {
	for _, binary := range binaries {
		binaryPath := filepath.Join(BinDir, binary)
		if !utils.FileExists(binaryPath) {
			i.logger.Debugf("Kubernetes binary not found: %s", binary)
			return false
		}

		// Check version for kubelet (main component)
		if binary == KubeletBinary {
			if !i.isKubeletVersionCorrect() {
				i.logger.Debugf("Kubelet version is incorrect")
				return false
			}
		}
	}
	return true
}

// isKubeletVersionCorrect checks if the installed kubelet version matches the expected version
func (i *Installer) isKubeletVersionCorrect() bool {
	output, err := utils.RunCommandWithOutput(KubeletPath, "--version")
	if err != nil {
		i.logger.Debugf("Failed to get kubelet version: %v", err)
		return false
	}

	// Check if version output contains expected version
	return strings.Contains(string(output), i.config.Kubernetes.Version)
}

// validateKubernetesInstallation validates that Kubernetes components were installed correctly and are functional
func (i *Installer) validateKubernetesInstallation(binaries []string) error {
	for _, binary := range binaries {
		binaryPath := filepath.Join(BinDir, binary)

		// Check if binary exists
		if !utils.FileExists(binaryPath) {
			return fmt.Errorf("Kubernetes binary not found after installation: %s", binary)
		}

		// Check if binary is executable - use appropriate version command for each binary
		var args []string
		switch binary {
		case KubectlBinary:
			args = []string{"version", "--client"}
		case KubeletBinary:
			args = []string{"--version"}
		case KubeadmBinary:
			args = []string{"version"}
		default:
			args = []string{"--version"}
		}

		if err := utils.RunSystemCommand(binaryPath, args...); err != nil {
			return fmt.Errorf("Kubernetes binary %s is not executable or functional: %w", binary, err)
		}

		i.logger.Debugf("Verified Kubernetes component: %s", binary)
	}

	// Verify kubelet version specifically
	if !i.isKubeletVersionCorrect() {
		return fmt.Errorf("installed kubelet version does not match expected version %s", i.config.Kubernetes.Version)
	}

	return nil
}

// GetName returns the step name
func (i *Installer) GetName() string {
	return "KubernetesComponentsInstaller"
}
