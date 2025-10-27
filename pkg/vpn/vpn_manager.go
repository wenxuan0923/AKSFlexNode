package vpn

import (
	"archive/zip"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"go.goms.io/aks/AKSFlexNode/pkg/config"
	"go.goms.io/aks/AKSFlexNode/pkg/utils"
)

// VPNManager handles VPN certificate generation and OpenVPN setup
type VPNManager struct {
	config *config.Config
}

// NewVPNManager creates a new VPN manager
func NewVPNManager(cfg *config.Config) *VPNManager {
	return &VPNManager{
		config: cfg,
	}
}

// GenerateCertificates generates VPN certificates for P2S connection
func (v *VPNManager) GenerateCertificates() (string, error) {
	certDir, err := v.setupCertificateDirectory()
	if err != nil {
		return "", err
	}

	// Check if certificates already exist
	if certBase64, exists := v.loadExistingCertificate(certDir); exists {
		return certBase64, nil
	}

	logrus.Info("Generating new VPN certificates...")
	return v.generateNewCertificate(certDir)
}

// setupCertificateDirectory creates and configures the certificate directory
func (v *VPNManager) setupCertificateDirectory() (string, error) {
	var certDir string

	if os.Geteuid() == 0 {
		// Running as root - use system directory
		certDir = filepath.Join(v.config.Paths.DataDir, "certs")
		if err := utils.RunSystemCommand("mkdir", "-p", certDir); err != nil {
			return "", fmt.Errorf("failed to create certificates directory: %w", err)
		}
		// Ensure proper ownership and permissions for the certificates directory
		if err := utils.RunSystemCommand("chown", "root:root", certDir); err != nil {
			logrus.Warnf("Failed to set ownership on certificates directory: %v", err)
		}
		if err := utils.RunSystemCommand("chmod", "700", certDir); err != nil {
			logrus.Warnf("Failed to set permissions on certificates directory: %v", err)
		}
	} else {
		// Running as regular user - use user home directory
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("failed to get user home directory: %w", err)
		}
		certDir = filepath.Join(homeDir, ".aks-flex-node", "certs")
		if err := os.MkdirAll(certDir, 0700); err != nil {
			return "", fmt.Errorf("failed to create certificates directory: %w", err)
		}
		logrus.Infof("Using user certificate directory: %s", certDir)
	}

	return certDir, nil
}

// loadExistingCertificate checks for existing certificates and returns base64 data if found
func (v *VPNManager) loadExistingCertificate(certDir string) (string, bool) {
	certPath := filepath.Join(certDir, "vpn-client.crt")
	keyPath := filepath.Join(certDir, "vpn-client.key")

	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			logrus.Info("VPN certificates already exist, using existing certificates")

			// Read existing certificate and return base64 data
			certData, err := os.ReadFile(certPath)
			if err != nil {
				logrus.Warnf("Failed to read existing certificate: %v", err)
				return "", false
			}

			// Parse certificate to get DER data for base64 encoding
			block, _ := pem.Decode(certData)
			if block == nil {
				logrus.Warnf("Failed to parse existing certificate PEM")
				return "", false
			}

			certBase64 := base64.StdEncoding.EncodeToString(block.Bytes)
			logrus.Info("Using existing VPN certificates")
			return certBase64, true
		}
	}

	return "", false
}

// generateNewCertificate creates new certificate and private key
func (v *VPNManager) generateNewCertificate(certDir string) (string, error) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create certificate
	certDER, err := v.createCertificate(privateKey)
	if err != nil {
		return "", err
	}

	// Save private key and certificate to files
	keyPath := filepath.Join(certDir, "vpn-client.key")
	certPath := filepath.Join(certDir, "vpn-client.crt")

	if err := v.savePrivateKey(keyPath, privateKey); err != nil {
		return "", err
	}

	if err := v.saveCertificate(certPath, certDER); err != nil {
		return "", err
	}

	// Return base64-encoded certificate for upload to Azure
	certBase64 := base64.StdEncoding.EncodeToString(certDER)

	logrus.Info("VPN certificates generated successfully")

	return certBase64, nil
}

// createCertificate generates the X.509 certificate
func (v *VPNManager) createCertificate(privateKey *rsa.PrivateKey) ([]byte, error) {
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "VPN CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	return certDER, nil
}

// savePrivateKey saves the private key to file with proper permissions
func (v *VPNManager) savePrivateKey(keyPath string, privateKey *rsa.PrivateKey) error {
	keyFile, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create key file: %w", err)
	}
	defer keyFile.Close()

	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	if err := pem.Encode(keyFile, privateKeyPEM); err != nil {
		return fmt.Errorf("failed to encode private key: %w", err)
	}

	// Set proper ownership on key file (only if running as root)
	if os.Geteuid() == 0 {
		if err := utils.RunSystemCommand("chown", "root:root", keyPath); err != nil {
			logrus.Warnf("Failed to set ownership on key file: %v", err)
		}
	}

	return nil
}

// saveCertificate saves the certificate to file with proper permissions
func (v *VPNManager) saveCertificate(certPath string, certDER []byte) error {
	certFile, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to create certificate file: %w", err)
	}
	defer certFile.Close()

	certPEM := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}
	if err := pem.Encode(certFile, certPEM); err != nil {
		return fmt.Errorf("failed to encode certificate: %w", err)
	}

	// Set proper ownership on certificate file (only if running as root)
	if os.Geteuid() == 0 {
		if err := utils.RunSystemCommand("chown", "root:root", certPath); err != nil {
			logrus.Warnf("Failed to set ownership on certificate file: %v", err)
		}
	}

	return nil
}

// processVPNConfig processes VPN config file and replaces certificate placeholders using sed (matching reference script)
func (v *VPNManager) processVPNConfig(sourcePath, destPath string) error {
	logrus.Info("Processing VPN configuration with certificate data...")

	// Ensure certificates exist - use the same directory logic as GenerateCertificates
	certDir, err := v.setupCertificateDirectory()
	if err != nil {
		return fmt.Errorf("failed to setup certificate directory: %w", err)
	}

	clientCertPath := filepath.Join(certDir, "vpn-client.crt")
	clientKeyPath := filepath.Join(certDir, "vpn-client.key")

	// Check if certificates exist, if not generate them
	if _, err := os.Stat(clientCertPath); os.IsNotExist(err) {
		logrus.Info("Client certificates not found, generating new certificates...")
		if _, err := v.GenerateCertificates(); err != nil {
			return fmt.Errorf("failed to generate certificates: %w", err)
		}
	}

	// Create a temporary working copy of the VPN config
	tempConfig, err := os.CreateTemp("", "vpnconfig-*.ovpn")
	if err != nil {
		return fmt.Errorf("failed to create temporary config file: %w", err)
	}
	tempConfigPath := tempConfig.Name()
	defer os.Remove(tempConfigPath)
	tempConfig.Close()

	// Copy source to temp file
	if err := utils.RunSystemCommand("cp", sourcePath, tempConfigPath); err != nil {
		return fmt.Errorf("failed to copy VPN config to temp file: %w", err)
	}

	// Insert certificate content between <cert> and </cert> tags
	if err := utils.RunSystemCommand("sed", "-i", "-e", fmt.Sprintf("/<cert>/r %s", clientCertPath), tempConfigPath); err != nil {
		return fmt.Errorf("failed to insert client certificate: %w", err)
	}

	// Insert private key content between <key> and </key> tags
	if err := utils.RunSystemCommand("sed", "-i", "-e", fmt.Sprintf("/<key>/r %s", clientKeyPath), tempConfigPath); err != nil {
		return fmt.Errorf("failed to insert private key: %w", err)
	}

	// Copy processed config to final destination
	if strings.HasPrefix(destPath, "/etc/") || strings.HasPrefix(destPath, "/usr/") || strings.HasPrefix(destPath, "/var/") {
		// Create destination directory if it doesn't exist
		destDir := filepath.Dir(destPath)
		if err := utils.RunSystemCommand("mkdir", "-p", destDir); err != nil {
			return fmt.Errorf("failed to create destination directory: %w", err)
		}

		// Copy temp file to destination with sudo
		if err := utils.RunSystemCommand("cp", tempConfigPath, destPath); err != nil {
			return fmt.Errorf("failed to copy VPN config to %s: %w", destPath, err)
		}

		// Set proper permissions and ownership with sudo
		if err := utils.RunSystemCommand("chmod", "600", destPath); err != nil {
			logrus.Warnf("Failed to set permissions on VPN config: %v", err)
		}

		if err := utils.RunSystemCommand("chown", "root:root", destPath); err != nil {
			logrus.Warnf("Failed to set ownership on VPN config: %v", err)
		}
	} else {
		// Destination is in user directory, copy directly
		if err := utils.RunSystemCommand("cp", tempConfigPath, destPath); err != nil {
			return fmt.Errorf("failed to copy VPN config to %s: %w", destPath, err)
		}
	}

	logrus.Info("VPN configuration processed successfully")
	return nil
}

// SetupOpenVPN installs and configures OpenVPN
func (v *VPNManager) SetupOpenVPN(configPath string) error {
	logrus.Info("Setting up OpenVPN...")

	// Check if VPN connection is already established
	if v.IsVPNConnected() {
		logrus.Info("VPN connection is already established, skipping OpenVPN setup")
		return nil
	}

	// Install OpenVPN
	// Check if OpenVPN is already installed
	if err := utils.RunCommand("which", "openvpn"); err == nil {
		logrus.Info("OpenVPN is already installed, skipping installation")
	} else {
		if err := utils.RunSystemCommand("apt", "update"); err != nil {
			return fmt.Errorf("failed to update package list: %w", err)
		}

		if err := utils.RunSystemCommand("apt", "install", "-y", "openvpn"); err != nil {
			return fmt.Errorf("failed to install OpenVPN: %w", err)
		}
	}

	// Copy and process VPN config file
	if configPath != "" {
		vpnConfigDir := "/etc/openvpn"
		if err := utils.RunSystemCommand("mkdir", "-p", vpnConfigDir); err != nil {
			return fmt.Errorf("failed to create OpenVPN config directory: %w", err)
		}

		destPath := filepath.Join(vpnConfigDir, "vpnconfig.conf")

		// Process VPN config with certificate data
		if err := v.processVPNConfig(configPath, destPath); err != nil {
			return fmt.Errorf("failed to process VPN config: %w", err)
		}

		// Start OpenVPN service
		if err := utils.RunSystemCommand("systemctl", "enable", "openvpn@vpnconfig"); err != nil {
			return fmt.Errorf("failed to enable OpenVPN service: %w", err)
		}

		if err := utils.RunSystemCommand("systemctl", "start", "openvpn@vpnconfig"); err != nil {
			return fmt.Errorf("failed to start OpenVPN service: %w", err)
		}
	}

	logrus.Info("OpenVPN setup completed")
	return nil
}

// GetVPNInterface returns the VPN interface name (typically tun0)
func (v *VPNManager) GetVPNInterface() (string, error) {
	// Check for tun interfaces
	for i := 0; i < 10; i++ {
		iface := fmt.Sprintf("tun%d", i)
		if _, err := os.Stat(fmt.Sprintf("/sys/class/net/%s", iface)); err == nil {
			return iface, nil
		}
	}
	return "", fmt.Errorf("no VPN interface found")
}

// GetVPNIP returns the IP address of the VPN interface
func (v *VPNManager) GetVPNIP(iface string) (string, error) {
	output, err := utils.RunCommandWithOutput("ip", "addr", "show", iface)
	if err != nil {
		return "", fmt.Errorf("failed to get interface info: %w", err)
	}

	// Parse IP address from output (simplified)
	// In a real implementation, you'd want more robust parsing
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "inet ") && !strings.Contains(line, "inet6") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				ip := strings.Split(fields[1], "/")[0]
				return ip, nil
			}
		}
	}

	return "", fmt.Errorf("no IP address found for interface %s", iface)
}

// IsVPNConnected checks if VPN connection is active
func (v *VPNManager) IsVPNConnected() bool {
	iface, err := v.GetVPNInterface()
	if err != nil {
		return false
	}

	_, err = v.GetVPNIP(iface)
	return err == nil
}

// UploadCertificateToAzure uploads the root certificate to Azure VPN Gateway
func (v *VPNManager) UploadCertificateToAzure(certData, gatewayName, resourceGroup string) error {
	logrus.Info("Uploading VPN certificate to Azure VPN Gateway...")

	// Create a temporary file for the certificate data since Azure CLI expects it as file content
	tempFile, err := os.CreateTemp("", "vpn-cert-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temporary certificate file: %w", err)
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

	// Write certificate data to temporary file
	if _, err := tempFile.WriteString(certData); err != nil {
		return fmt.Errorf("failed to write certificate data to temporary file: %w", err)
	}
	tempFile.Close()

	// Use Azure CLI to upload the certificate with file path
	// Create command with proper environment inheritance
	cmd := exec.Command("az", "network", "vnet-gateway", "root-cert", "create",
		"--gateway-name", gatewayName,
		"--resource-group", resourceGroup,
		"--name", "VPNClientRootCert",
		"--public-cert-data", tempFile.Name())

	// Inherit current environment to preserve Azure CLI authentication
	cmd.Env = os.Environ()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to upload certificate to Azure: %w", err)
	}

	logrus.Info("VPN certificate uploaded to Azure successfully")
	return nil
}

// DownloadVPNClientConfig downloads the VPN client configuration from Azure
func (v *VPNManager) DownloadVPNClientConfig(gatewayName, resourceGroup string) (string, error) {
	logrus.Info("Downloading VPN client configuration from Azure VPN Gateway...")

	// Generate VPN client configuration using Azure CLI
	cmd := exec.Command("az", "network", "vnet-gateway", "vpn-client", "generate",
		"--name", gatewayName,
		"--resource-group", resourceGroup,
		"--authentication-method", "EAPTLS")

	// Inherit current environment to preserve Azure CLI authentication
	cmd.Env = os.Environ()

	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to generate VPN client config: %w", err)
	}

	// The output might be a direct URL string or JSON object
	outputStr := strings.TrimSpace(string(output))
	var downloadURL string

	// Try to parse as JSON first
	var result struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(output, &result); err == nil && result.URL != "" {
		downloadURL = result.URL
	} else {
		// If JSON parsing fails, treat the output as a direct URL
		// Remove quotes if present
		downloadURL = strings.Trim(outputStr, `"`)
	}

	if downloadURL == "" {
		return "", fmt.Errorf("no VPN client configuration URL returned from Azure. Output: %s", outputStr)
	}

	logrus.Infof("VPN client configuration URL: %s", downloadURL)

	// Download the configuration file
	configData, err := v.downloadConfigFromURL(downloadURL)
	if err != nil {
		return "", fmt.Errorf("failed to download VPN client configuration: %w", err)
	}

	return configData, nil
}

// validateZipPath validates that a ZIP file entry path is safe to extract
func validateZipPath(filePath, destDir string) error {
	// Clean the file path to resolve any ".." or "." elements
	cleanPath := filepath.Clean(filePath)

	// Check for absolute paths
	if filepath.IsAbs(cleanPath) {
		return fmt.Errorf("absolute path not allowed: %s", filePath)
	}

	// Check for path traversal attempts
	if strings.Contains(cleanPath, "..") {
		return fmt.Errorf("path traversal attempt detected: %s", filePath)
	}

	// Ensure the resolved path is within the destination directory
	fullPath := filepath.Join(destDir, cleanPath)
	if !strings.HasPrefix(fullPath, filepath.Clean(destDir)+string(os.PathSeparator)) &&
		fullPath != filepath.Clean(destDir) {
		return fmt.Errorf("path escapes destination directory: %s", filePath)
	}

	return nil
}

// downloadConfigFromURL downloads the VPN client configuration from the provided URL
func (v *VPNManager) downloadConfigFromURL(url string) (string, error) {
	// Create temporary file for ZIP download
	tempZipFile, err := os.CreateTemp("", "vpnconfig-*.zip")
	if err != nil {
		return "", fmt.Errorf("failed to create temporary ZIP file: %w", err)
	}
	defer os.Remove(tempZipFile.Name())
	defer tempZipFile.Close()

	// Download the ZIP file using HTTP client
	logrus.Info("Downloading VPN configuration ZIP file...")
	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("failed to download VPN config ZIP: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to download VPN config ZIP: HTTP %d", resp.StatusCode)
	}

	// Copy response body to temporary file
	_, err = io.Copy(tempZipFile, resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to save VPN config ZIP: %w", err)
	}
	tempZipFile.Close()

	// Create temporary directory for extraction
	tempDir, err := os.MkdirTemp("", "vpnconfig-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temporary directory: %w", err)
	}
	defer os.RemoveAll(tempDir)

	// Extract the ZIP file using Go's archive/zip
	logrus.Info("Extracting VPN configuration ZIP file...")
	reader, err := zip.OpenReader(tempZipFile.Name())
	if err != nil {
		return "", fmt.Errorf("failed to open VPN config ZIP: %w", err)
	}
	defer reader.Close()

	// Extract all files
	for _, file := range reader.File {
		// Validate file path to prevent ZIP slip vulnerability
		if err := validateZipPath(file.Name, tempDir); err != nil {
			return "", fmt.Errorf("invalid file path in ZIP archive: %w", err)
		}

		path := filepath.Join(tempDir, file.Name)

		// Create directory if needed
		if file.FileInfo().IsDir() {
			os.MkdirAll(path, file.FileInfo().Mode())
			continue
		}

		// Create parent directories
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return "", fmt.Errorf("failed to create directory for %s: %w", path, err)
		}

		// Extract file
		fileReader, err := file.Open()
		if err != nil {
			return "", fmt.Errorf("failed to open file %s in ZIP: %w", file.Name, err)
		}

		targetFile, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.FileInfo().Mode())
		if err != nil {
			fileReader.Close()
			return "", fmt.Errorf("failed to create file %s: %w", path, err)
		}

		_, err = io.Copy(targetFile, fileReader)
		fileReader.Close()
		targetFile.Close()

		if err != nil {
			return "", fmt.Errorf("failed to extract file %s: %w", file.Name, err)
		}
	}

	// Find the OpenVPN configuration file in the extracted directory
	var ovpnPath string
	var configData []byte

	// Try common paths for the OpenVPN config file
	possiblePaths := []string{
		filepath.Join(tempDir, "OpenVPN", "vpnconfig.ovpn"),
		filepath.Join(tempDir, "Generic", "VpnSettings.xml"),
		filepath.Join(tempDir, "vpnconfig.ovpn"),
	}

	// Walk through the extracted directory to find .ovpn files
	err = filepath.Walk(tempDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if strings.HasSuffix(strings.ToLower(info.Name()), ".ovpn") {
			ovpnPath = path
			logrus.Infof("Found OpenVPN config file: %s", path)
			return filepath.SkipDir // Stop walking once we find the file
		}
		return nil
	})

	if err != nil {
		return "", fmt.Errorf("failed to search for OpenVPN config: %w", err)
	}

	// If we found an .ovpn file during the walk, read it
	if ovpnPath != "" {
		configData, err = os.ReadFile(ovpnPath)
		if err != nil {
			return "", fmt.Errorf("failed to read OpenVPN config from %s: %w", ovpnPath, err)
		}
	} else {
		// If no .ovpn file found, try the traditional paths
		for _, path := range possiblePaths {
			configData, err = os.ReadFile(path)
			if err == nil {
				ovpnPath = path
				logrus.Infof("Found OpenVPN config at: %s", path)
				break
			}
		}

		if ovpnPath == "" {
			// List the contents of the extracted directory for debugging
			logrus.Error("OpenVPN config file not found. Listing extracted contents:")
			filepath.Walk(tempDir, func(path string, info os.FileInfo, err error) error {
				if err == nil {
					relPath, _ := filepath.Rel(tempDir, path)
					logrus.Errorf("  %s", relPath)
				}
				return nil
			})
			return "", fmt.Errorf("OpenVPN configuration file not found in extracted ZIP")
		}
	}

	logrus.Info("VPN configuration extracted successfully")
	return string(configData), nil
}

// NodeIPManager handles node IP address updates for VPN connectivity
type NodeIPManager struct {
	config *config.Config
}

// NewNodeIPManager creates a new node IP manager
func NewNodeIPManager(cfg *config.Config) *NodeIPManager {
	return &NodeIPManager{
		config: cfg,
	}
}

// UpdateNodeIP updates the node's internal IP address to match VPN interface
func (n *NodeIPManager) UpdateNodeIP(vpnInterface string) error {
	logrus.Infof("Updating node IP address for interface %s...", vpnInterface)

	// Get VPN interface IP address
	vpnIP, err := n.getInterfaceIP(vpnInterface)
	if err != nil {
		return fmt.Errorf("failed to get VPN IP: %w", err)
	}

	logrus.Infof("VPN interface %s has IP: %s", vpnInterface, vpnIP)

	// Update kubelet configuration with VPN IP
	if err := n.updateKubeletNodeIP(vpnIP); err != nil {
		return fmt.Errorf("failed to update kubelet node IP: %w", err)
	}

	// Restart kubelet to apply changes
	if err := utils.RunSystemCommand("systemctl", "restart", "kubelet"); err != nil {
		return fmt.Errorf("failed to restart kubelet: %w", err)
	}

	logrus.Info("Node IP update completed successfully")
	return nil
}

// getInterfaceIP gets the IP address of a network interface
func (n *NodeIPManager) getInterfaceIP(iface string) (string, error) {
	output, err := utils.RunCommandWithOutput("ip", "addr", "show", iface)
	if err != nil {
		return "", fmt.Errorf("failed to get interface info: %w", err)
	}

	// Parse IP address from output
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "inet ") && !strings.Contains(line, "inet6") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				// Extract IP address without CIDR notation
				ip := strings.Split(fields[1], "/")[0]
				return ip, nil
			}
		}
	}

	return "", fmt.Errorf("no IP address found for interface %s", iface)
}

// updateKubeletNodeIP updates the kubelet service to use the specified node IP
func (n *NodeIPManager) updateKubeletNodeIP(nodeIP string) error {
	serviceFile := "/etc/systemd/system/kubelet.service"

	// Read current service file
	content, err := os.ReadFile(serviceFile)
	if err != nil {
		return fmt.Errorf("failed to read kubelet service file: %w", err)
	}

	serviceContent := string(content)
	lines := strings.Split(serviceContent, "\n")

	// Update or add --node-ip flag
	for i, line := range lines {
		if strings.Contains(line, "ExecStart=/usr/local/bin/kubelet") {
			// Check if --node-ip is already present
			if strings.Contains(line, "--node-ip=") {
				// Replace existing node-ip
				lines[i] = replaceNodeIP(line, nodeIP)
			} else {
				// Add node-ip flag
				lines[i] = addNodeIP(line, nodeIP)
			}
			break
		}
	}

	// Write updated service file atomically
	updatedContent := strings.Join(lines, "\n")
	if err := utils.WriteFileAtomicSystem(serviceFile, []byte(updatedContent), 0644); err != nil {
		return fmt.Errorf("failed to write updated kubelet service file: %w", err)
	}

	// Reload systemd
	if err := utils.RunSystemCommand("systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("failed to reload systemd: %w", err)
	}

	return nil
}

// replaceNodeIP replaces existing --node-ip flag with new IP
func replaceNodeIP(line, newIP string) string {
	// Find and replace --node-ip=<old-ip> with --node-ip=<new-ip>
	parts := strings.Fields(line)
	for i, part := range parts {
		if strings.HasPrefix(part, "--node-ip=") {
			parts[i] = fmt.Sprintf("--node-ip=%s", newIP)
			break
		}
	}
	return strings.Join(parts, " ")
}

// addNodeIP adds --node-ip flag to kubelet command line
func addNodeIP(line, nodeIP string) string {
	// Add --node-ip flag before other flags
	if strings.Contains(line, " \\") {
		// Multi-line format
		return strings.Replace(line, " \\", fmt.Sprintf(" \\\n        --node-ip=%s \\", nodeIP), 1)
	}
	// Single line format - add at the end
	return fmt.Sprintf("%s --node-ip=%s", line, nodeIP)
}

// SetupCronJob sets up a cron job to periodically update node IP
func (n *NodeIPManager) SetupCronJob(vpnInterface, schedule string) error {
	logrus.Infof("Setting up cron job for node IP updates (interface: %s, schedule: %s)", vpnInterface, schedule)

	// Create update script
	scriptPath := "/usr/local/bin/update-node-ip.sh"
	scriptContent := fmt.Sprintf(`#!/bin/bash
# Auto-generated script to update node IP address

VPN_INTERFACE="%s"
LOG_FILE="/var/log/aks-flex-node/node-ip-update.log"

# Function to log with timestamp
log() {
    echo "$(date '+%%Y-%%m-%%d %%H:%%M:%%S') $1" >> "$LOG_FILE"
}

# Get VPN IP address
VPN_IP=$(ip addr show "$VPN_INTERFACE" 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d'/' -f1)

if [ -z "$VPN_IP" ]; then
    log "ERROR: Could not get IP for interface $VPN_INTERFACE"
    exit 1
fi

# Update kubelet node IP
log "INFO: Updating node IP to $VPN_IP"

# Use the node controller to update IP
/usr/local/bin/aks-flex-node update-node-ip --interface="$VPN_INTERFACE" >> "$LOG_FILE" 2>&1

if [ $? -eq 0 ]; then
    log "INFO: Node IP update completed successfully"
else
    log "ERROR: Node IP update failed"
    exit 1
fi
`, vpnInterface)

	if err := utils.WriteFileAtomicSystem(scriptPath, []byte(scriptContent), 0755); err != nil {
		return fmt.Errorf("failed to create update script: %w", err)
	}

	// Add cron job
	cronEntry := fmt.Sprintf("%s root %s", schedule, scriptPath)
	cronFile := "/etc/cron.d/aks-node-ip-update"

	if err := utils.WriteFileAtomicSystem(cronFile, []byte(cronEntry+"\n"), 0644); err != nil {
		return fmt.Errorf("failed to create cron job: %w", err)
	}

	// Restart cron service
	if err := utils.RunSystemCommand("systemctl", "restart", "cron"); err != nil {
		logrus.Warnf("Failed to restart cron service: %v", err)
	}

	logrus.Info("Cron job for node IP updates set up successfully")
	return nil
}

// RemoveCronJob removes the node IP update cron job
func (n *NodeIPManager) RemoveCronJob() error {
	cronFile := "/etc/cron.d/aks-node-ip-update"
	scriptPath := "/usr/local/bin/update-node-ip.sh"

	// Remove cron file
	if err := os.Remove(cronFile); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove cron job: %w", err)
	}

	// Remove script
	if err := os.Remove(scriptPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove update script: %w", err)
	}

	// Restart cron service
	if err := utils.RunSystemCommand("systemctl", "restart", "cron"); err != nil {
		logrus.Warnf("Failed to restart cron service: %v", err)
	}

	logrus.Info("Node IP update cron job removed successfully")
	return nil
}

// ValidateVPNConnectivity checks if VPN interface is available and has IP
func (n *NodeIPManager) ValidateVPNConnectivity(vpnInterface string) error {
	// Check if interface exists
	if _, err := os.Stat(fmt.Sprintf("/sys/class/net/%s", vpnInterface)); err != nil {
		return fmt.Errorf("VPN interface %s not found", vpnInterface)
	}

	// Check if interface has IP
	_, err := n.getInterfaceIP(vpnInterface)
	if err != nil {
		return fmt.Errorf("VPN interface %s has no IP address: %w", vpnInterface, err)
	}

	logrus.Infof("VPN connectivity validated for interface %s", vpnInterface)
	return nil
}
