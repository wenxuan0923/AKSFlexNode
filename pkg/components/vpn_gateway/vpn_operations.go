package vpn_gateway

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4"
	"go.goms.io/aks/AKSFlexNode/pkg/utils"
)

// VPN certificate and connection management functions for the Installer

// generateCertificates generates VPN certificates for P2S connection
func (i *Installer) generateCertificates() (string, error) {
	_, err := i.setupCertificateDirectory()
	if err != nil {
		return "", err
	}

	// Check if certificates already exist
	if certBase64, exists := i.loadExistingCertificate(); exists {
		return certBase64, nil
	}

	i.logger.Info("Generating new VPN certificates...")
	certBase64, err := i.generateNewCertificate()
	if err != nil {
		return "", err
	}
	return certBase64, nil // new certificate generated
}

// setupCertificateDirectory creates and configures the certificate directory
func (i *Installer) setupCertificateDirectory() (string, error) {
	certDir := CertificatesDir
	if err := utils.RunSystemCommand("mkdir", "-p", certDir); err != nil {
		return "", fmt.Errorf("failed to create certificates directory: %w", err)
	}

	// Set proper permissions on the directory
	if err := utils.RunSystemCommand("chmod", fmt.Sprintf("%o", CertificatesDirPerm), certDir); err != nil {
		return "", fmt.Errorf("failed to set permissions on certificates directory: %w", err)
	}

	i.logger.Infof("Using system certificate directory: %s", certDir)

	return certDir, nil
}

// loadExistingCertificate checks for existing certificates and returns root certificate base64 data if found
func (i *Installer) loadExistingCertificate() (string, bool) {
	certPath := GetVPNClientCertPath()
	keyPath := GetVPNClientKeyPath()
	rootCertPath := GetVPNRootCertPath()

	// Check if all required files exist
	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			if _, err := os.Stat(rootCertPath); err == nil {
				i.logger.Info("VPN certificates already exist, using existing certificates")

				// Read existing root certificate and return base64 data for Azure comparison
				rootCertData, err := os.ReadFile(rootCertPath)
				if err != nil {
					i.logger.Warnf("Failed to read existing root certificate: %v", err)
					return "", false
				}

				// Parse certificate to get DER data for base64 encoding
				block, _ := pem.Decode(rootCertData)
				if block == nil {
					i.logger.Warnf("Failed to parse existing root certificate PEM")
					return "", false
				}

				rootCertBase64 := base64.StdEncoding.EncodeToString(block.Bytes)
				i.logger.Info("Using existing VPN certificates")
				return rootCertBase64, true
			}
		}
	}

	return "", false
}

// generateNewCertificate creates a proper CA hierarchy with root CA and client certificate
func (i *Installer) generateNewCertificate() (string, error) {
	// Generate root CA private key
	rootPrivateKey, err := rsa.GenerateKey(rand.Reader, CertificateKeySize)
	if err != nil {
		return "", fmt.Errorf("failed to generate root CA private key: %w", err)
	}

	// Create root CA certificate
	rootCertDER, err := i.createRootCACertificate(rootPrivateKey)
	if err != nil {
		return "", fmt.Errorf("failed to create root CA certificate: %w", err)
	}

	// Generate client private key
	clientPrivateKey, err := rsa.GenerateKey(rand.Reader, CertificateKeySize)
	if err != nil {
		return "", fmt.Errorf("failed to generate client private key: %w", err)
	}

	// Create client certificate signed by root CA
	clientCertDER, err := i.createClientCertificate(clientPrivateKey, rootPrivateKey, rootCertDER)
	if err != nil {
		return "", fmt.Errorf("failed to create client certificate: %w", err)
	}

	// Save certificate and key to files
	clientKeyPath := GetVPNClientKeyPath()
	clientCertPath := GetVPNClientCertPath()
	rootCertPath := GetVPNRootCertPath()

	// Save the client private key
	if err := i.savePrivateKey(clientKeyPath, clientPrivateKey); err != nil {
		return "", err
	}

	// Save the client certificate
	if err := i.saveCertificate(clientCertPath, clientCertDER); err != nil {
		return "", err
	}

	// Save the root CA certificate (for Azure upload)
	if err := i.saveCertificate(rootCertPath, rootCertDER); err != nil {
		return "", err
	}

	// Return base64-encoded root certificate for upload to Azure
	rootCertBase64 := base64.StdEncoding.EncodeToString(rootCertDER)

	i.logger.Info("VPN certificate hierarchy generated successfully (root CA + client cert)")

	return rootCertBase64, nil
}

// createRootCACertificate generates a root CA certificate
func (i *Installer) createRootCACertificate(privateKey *rsa.PrivateKey) ([]byte, error) {
	// Generate SubjectKeyIdentifier for the root CA
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}
	subjectKeyId := sha1.Sum(publicKeyBytes)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: CertificateCommonName,
		},
		NotBefore:             time.Now().Add(-10 * time.Minute),
		NotAfter:              time.Now().Add(CertificateValidYears * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,            // This is a CA certificate
		SubjectKeyId:          subjectKeyId[:], // Required for chain validation
	}

	// Self-signed root CA: template is both the certificate to create and the issuer
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create root CA certificate: %w", err)
	}

	return certDER, nil
}

// createClientCertificate generates a client certificate signed by the root CA
func (i *Installer) createClientCertificate(clientPrivateKey, rootPrivateKey *rsa.PrivateKey, rootCertDER []byte) ([]byte, error) {
	// Parse the root certificate to use as issuer
	rootCert, err := x509.ParseCertificate(rootCertDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse root certificate: %w", err)
	}

	// Ensure the root certificate has SubjectKeyId (should be set from createRootCACertificate)
	if len(rootCert.SubjectKeyId) == 0 {
		return nil, fmt.Errorf("root certificate is missing SubjectKeyId")
	}

	// Generate SubjectKeyIdentifier for the client certificate
	clientPublicKeyBytes, err := x509.MarshalPKIXPublicKey(&clientPrivateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal client public key: %w", err)
	}
	clientSubjectKeyId := sha1.Sum(clientPublicKeyBytes)

	template := x509.Certificate{
		SerialNumber: big.NewInt(2), // Different serial number for client cert
		Subject: pkix.Name{
			CommonName: "VPN Client",
		},
		NotBefore:             time.Now().Add(-10 * time.Minute),
		NotAfter:              time.Now().Add(CertificateValidYears * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,                 // This is NOT a CA certificate
		SubjectKeyId:          clientSubjectKeyId[:], // Required for chain validation
		AuthorityKeyId:        rootCert.SubjectKeyId, // MUST match root's SubjectKeyId exactly
	}

	i.logger.Infof("Creating client certificate with AuthorityKeyId matching root SubjectKeyId: %x", rootCert.SubjectKeyId)

	// Client certificate signed by root CA
	certDER, err := x509.CreateCertificate(rand.Reader, &template, rootCert, &clientPrivateKey.PublicKey, rootPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create client certificate: %w", err)
	}

	return certDER, nil
}

// savePrivateKey saves the private key to file with proper permissions
func (i *Installer) savePrivateKey(keyPath string, privateKey *rsa.PrivateKey) error {
	privateKeyPEM := &pem.Block{
		Type:  RSAPrivateKeyType,
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	// Encode PEM to bytes
	var keyBuffer bytes.Buffer
	if err := pem.Encode(&keyBuffer, privateKeyPEM); err != nil {
		return fmt.Errorf("failed to encode private key: %w", err)
	}

	// Write file using system-level file operations
	if err := utils.WriteFileAtomicSystem(keyPath, keyBuffer.Bytes(), PrivateKeyFilePerm); err != nil {
		return fmt.Errorf("failed to create key file: %w", err)
	}

	return nil
}

// saveCertificate saves the certificate to file with proper permissions
func (i *Installer) saveCertificate(certPath string, certDER []byte) error {
	certPEM := &pem.Block{
		Type:  CertificateType,
		Bytes: certDER,
	}

	// Encode PEM to bytes
	var certBuffer bytes.Buffer
	if err := pem.Encode(&certBuffer, certPEM); err != nil {
		return fmt.Errorf("failed to encode certificate: %w", err)
	}

	// Write file using system-level file operations
	if err := utils.WriteFileAtomicSystem(certPath, certBuffer.Bytes(), CertificateFilePerm); err != nil {
		return fmt.Errorf("failed to create certificate file: %w", err)
	}

	return nil
}

// processVPNConfig processes VPN config file and embeds certificates using sed (matching working implementation)
func (i *Installer) processVPNConfig(sourcePath, destPath string) error {
	i.logger.Info("Processing VPN configuration with certificate data...")

	// Ensure certificates exist - use the same directory logic as GenerateCertificates
	_, err := i.setupCertificateDirectory()
	if err != nil {
		return fmt.Errorf("failed to setup certificate directory: %w", err)
	}

	clientCertPath := GetVPNClientCertPath()
	clientKeyPath := GetVPNClientKeyPath()

	// Check if certificates exist, if not generate them
	if _, err := os.Stat(clientCertPath); os.IsNotExist(err) {
		i.logger.Info("Client certificates not found, generating new certificates...")
		if _, err := i.generateCertificates(); err != nil {
			return fmt.Errorf("failed to generate certificates: %w", err)
		}
	}

	// Create a temporary working copy of the VPN config
	tempConfig, err := os.CreateTemp("", TempVPNConfigPattern)
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

	// Read certificate and key content using system commands
	certContent, err := utils.RunCommandWithOutput("cat", clientCertPath)
	if err != nil {
		return fmt.Errorf("failed to read certificate file: %w", err)
	}

	keyContent, err := utils.RunCommandWithOutput("cat", clientKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read private key file: %w", err)
	}

	// Read the config file content
	configContent, err := utils.RunCommandWithOutput("cat", tempConfigPath)
	if err != nil {
		return fmt.Errorf("failed to read temp config file: %w", err)
	}

	// Replace placeholders with actual content (trim to remove any trailing whitespace)
	processedConfig := strings.ReplaceAll(configContent, "$CLIENTCERTIFICATE", strings.TrimSpace(certContent))
	processedConfig = strings.ReplaceAll(processedConfig, "$PRIVATEKEY", strings.TrimSpace(keyContent))

	// Write processed config back to temp file using system command
	if err := utils.WriteFileAtomicSystem(tempConfigPath, []byte(processedConfig), 0600); err != nil {
		return fmt.Errorf("failed to write processed config: %w", err)
	}

	// Copy processed config to final destination
	if strings.HasPrefix(destPath, SystemEtcPrefix) || strings.HasPrefix(destPath, SystemUsrPrefix) || strings.HasPrefix(destPath, SystemVarPrefix) {
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
			i.logger.Warnf("Failed to set permissions on VPN config: %v", err)
		}

		if err := utils.RunSystemCommand("chown", "root:root", destPath); err != nil {
			i.logger.Warnf("Failed to set ownership on VPN config: %v", err)
		}
	} else {
		// Destination is in user directory, copy directly
		if err := utils.RunSystemCommand("cp", tempConfigPath, destPath); err != nil {
			return fmt.Errorf("failed to copy VPN config to %s: %w", destPath, err)
		}
	}

	i.logger.Info("VPN configuration processed successfully")
	return nil
}

// setupOpenVPN installs and configures OpenVPN
func (i *Installer) setupOpenVPN(configPath string) error {
	i.logger.Info("Setting up OpenVPN...")

	// Check if VPN connection is already established
	if i.isVPNConnected() {
		i.logger.Info("VPN connection is already established, skipping OpenVPN setup")
		return nil
	}

	// Install OpenVPN
	// Check if OpenVPN is already installed
	if err := utils.RunSystemCommand("which", "openvpn"); err == nil {
		i.logger.Info("OpenVPN is already installed, skipping installation")
	} else {
		i.logger.Info("Installing OpenVPN...")
		if err := utils.RunSystemCommand("apt", "install", "-y", "openvpn"); err != nil {
			return fmt.Errorf("failed to install OpenVPN: %w", err)
		}
	}

	// Always ensure certificates are embedded in the OpenVPN config
	destPath := GetOpenVPNConfigPath()

	// If configPath is provided, process it; otherwise process existing config
	sourceConfigPath := configPath
	if sourceConfigPath == "" {
		sourceConfigPath = destPath // Process existing config in place
	}

	// Copy and process VPN config file
	if sourceConfigPath != "" {
		vpnConfigDir := OpenVPNConfigDir
		if err := utils.RunSystemCommand("mkdir", "-p", vpnConfigDir); err != nil {
			return fmt.Errorf("failed to create OpenVPN config directory: %w", err)
		}

		// Process VPN config with certificate data
		if err := i.processVPNConfig(sourceConfigPath, destPath); err != nil {
			return fmt.Errorf("failed to process VPN config: %w", err)
		}

		// Enable and restart OpenVPN service to ensure it uses the updated configuration
		if err := utils.EnableService(OpenVPNServiceTemplate); err != nil {
			return fmt.Errorf("failed to enable OpenVPN service: %w", err)
		}

		i.logger.Info("Restarting OpenVPN service to apply updated configuration...")
		if err := utils.RestartService(OpenVPNServiceTemplate); err != nil {
			return fmt.Errorf("failed to restart OpenVPN service: %w", err)
		}

		// Give OpenVPN a moment to start before checking status
		time.Sleep(2 * time.Second)

		// Check if OpenVPN service started successfully
		if !utils.IsServiceActive(OpenVPNServiceTemplate) {
			i.logger.Warn("OpenVPN service is not active, please check the service status for details")
		} else {
			i.logger.Info("OpenVPN service restarted successfully")
		}
	}
	return nil
}

// getVPNInterface returns the VPN interface name (typically tun0)
func (i *Installer) getVPNInterface() (string, error) {
	// Check for tun interfaces
	for j := 0; j < MaxVPNInterfaces; j++ {
		iface := fmt.Sprintf("%s%d", VPNInterfacePrefix, j)
		if _, err := os.Stat(fmt.Sprintf("/sys/class/net/%s", iface)); err == nil {
			return iface, nil
		}
	}
	return "", fmt.Errorf("no VPN interface found")
}

// getVPNIP returns the IP address of the VPN interface
func (i *Installer) getVPNIP(iface string) (string, error) {
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

// isVPNConnected checks if VPN connection is active
func (i *Installer) isVPNConnected() bool {
	iface, err := i.getVPNInterface()
	if err != nil {
		return false
	}

	_, err = i.getVPNIP(iface)
	return err == nil
}

// uploadCertificateToAzure uploads the root certificate to Azure VPN Gateway using Azure SDK
func (i *Installer) uploadCertificateToAzure(ctx context.Context, certData string, vnetInfo vnetResourceInfo) error {
	// Get the current VPN Gateway to update its configuration
	gateway, err := i.vgwClient.Get(ctx, vnetInfo.resourceGroupName, DefaultVPNGatewayName, nil)
	if err != nil {
		return fmt.Errorf("failed to get VPN Gateway: %w", err)
	}

	// Check if VPN client configuration exists
	// Look for our specific certificate by name and data
	for _, cert := range gateway.Properties.VPNClientConfiguration.VPNClientRootCertificates {
		if cert.Name != nil && *cert.Name == VPNClientRootCertName {
			if cert.Properties != nil && cert.Properties.PublicCertData != nil {
				// Compare certificate data to ensure it's the same certificate
				if *cert.Properties.PublicCertData == certData {
					i.logger.Info("VPN certificate already exists on Azure VPN Gateway, skipping upload")
					return nil // Certificate already exists and matches, no need to upload
				}
			}
		}
	}

	// Ensure the VPN client configuration section exists with required address pool
	if gateway.Properties.VPNClientConfiguration == nil {
		p2sGatewayCIDR := i.config.Azure.VPNGateway.P2SGatewayCIDR
		vpnClientProtocol := armnetwork.VPNClientProtocolOpenVPN

		gateway.Properties.VPNClientConfiguration = &armnetwork.VPNClientConfiguration{
			VPNClientAddressPool: &armnetwork.AddressSpace{
				AddressPrefixes: []*string{&p2sGatewayCIDR},
			},
			VPNClientProtocols: []*armnetwork.VPNClientProtocol{&vpnClientProtocol},
		}
	}

	// Create root certificate parameters
	certName := VPNClientRootCertName
	rootCert := armnetwork.VPNClientRootCertificate{
		Name: &certName,
		Properties: &armnetwork.VPNClientRootCertificatePropertiesFormat{
			PublicCertData: &certData,
		},
	}

	// Update the root certificate in the VPN client configuration
	gateway.Properties.VPNClientConfiguration.VPNClientRootCertificates = []*armnetwork.VPNClientRootCertificate{&rootCert}

	// Update the VPN Gateway with the new certificate configuration
	poller, err := i.vgwClient.BeginCreateOrUpdate(ctx, vnetInfo.resourceGroupName, DefaultVPNGatewayName, gateway.VirtualNetworkGateway, nil)
	if err != nil {
		return fmt.Errorf("failed to start VPN Gateway update: %w", err)
	}

	// Wait for the operation to complete
	_, err = poller.PollUntilDone(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to update VPN Gateway with certificate: %w", err)
	}

	i.logger.Info("VPN certificate uploaded to Azure successfully")
	return nil

}

// downloadVPNClientConfig downloads the VPN client configuration from Azure using Azure SDK
func (i *Installer) downloadVPNClientConfig(ctx context.Context, gatewayName, resourceGroup string) (string, error) {
	i.logger.Info("Downloading VPN client configuration from Azure VPN Gateway...")

	// Generate VPN client configuration
	authMethod := armnetwork.AuthenticationMethodEAPTLS
	req := armnetwork.VPNClientParameters{
		AuthenticationMethod: &authMethod,
	}

	poller, err := i.vgwClient.BeginGenerateVPNProfile(ctx, resourceGroup, gatewayName, req, nil)
	if err != nil {
		return "", fmt.Errorf("failed to start VPN client config generation: %w", err)
	}

	// Wait for the operation to complete
	result, err := poller.PollUntilDone(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("failed to generate VPN client config: %w", err)
	}

	if result.Value == nil || *result.Value == "" {
		return "", fmt.Errorf("no VPN client configuration URL returned from Azure")
	}

	downloadURL := *result.Value
	i.logger.Infof("VPN client configuration URL: %s", downloadURL)

	// Download the configuration file
	configData, err := i.downloadConfigFromURL(downloadURL)
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
func (i *Installer) downloadConfigFromURL(url string) (string, error) {
	// Create temporary file for ZIP download
	tempZipFile, err := os.CreateTemp("", TempVPNZipPattern)
	if err != nil {
		return "", fmt.Errorf("failed to create temporary ZIP file: %w", err)
	}
	defer os.Remove(tempZipFile.Name())
	defer tempZipFile.Close()

	// Download the ZIP file using HTTP client
	i.logger.Info("Downloading VPN configuration ZIP file...")
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
	tempDir, err := os.MkdirTemp("", TempVPNExtractPrefix+"*")
	if err != nil {
		return "", fmt.Errorf("failed to create temporary directory: %w", err)
	}
	defer os.RemoveAll(tempDir)

	// Extract the ZIP file using Go's archive/zip
	i.logger.Info("Extracting VPN configuration ZIP file...")
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
		if err := os.MkdirAll(filepath.Dir(path), ConfigDirPerm); err != nil {
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
		filepath.Join(tempDir, OpenVPNConfigPath),
		filepath.Join(tempDir, GenericVPNConfigPath),
		filepath.Join(tempDir, VPNConfigFileName),
	}

	// Walk through the extracted directory to find .ovpn files
	err = filepath.Walk(tempDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if strings.HasSuffix(strings.ToLower(info.Name()), ".ovpn") {
			ovpnPath = path
			i.logger.Infof("Found OpenVPN config file: %s", path)
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
				i.logger.Infof("Found OpenVPN config at: %s", path)
				break
			}
		}

		if ovpnPath == "" {
			// List the contents of the extracted directory for debugging
			i.logger.Error("OpenVPN config file not found. Listing extracted contents:")
			filepath.Walk(tempDir, func(path string, info os.FileInfo, err error) error {
				if err == nil {
					relPath, _ := filepath.Rel(tempDir, path)
					i.logger.Errorf("  %s", relPath)
				}
				return nil
			})
			return "", fmt.Errorf("OpenVPN configuration file not found in extracted ZIP")
		}
	}

	i.logger.Info("VPN configuration extracted successfully")
	return string(configData), nil
}
