package vpn_gateway

import (
	"context"
	"path/filepath"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"go.goms.io/aks/AKSFlexNode/pkg/auth"
)

const (
	// VPN Gateway default name
	DefaultVPNGatewayName = "vpn-gateway"

	// Azure VPN Gateway configuration
	VPNClientRootCertName = "VPNClientRootCert"
	GatewaySubnetName     = "GatewaySubnet"
	GatewaySubnetPrefix   = 27 // /27 subnet for GatewaySubnet

	// Directory paths
	SystemConfigDir  = "/etc/aks-flex-node"
	CertificatesDir  = "/etc/aks-flex-node/certs"
	OpenVPNConfigDir = "/etc/openvpn"

	// File names
	VPNConfigFileName     = "vpn-config.ovpn"
	VPNClientCertFileName = "vpn-client.crt"
	VPNClientKeyFileName  = "vpn-client.key"
	VPNRootCertFileName   = "vpn-root-ca.crt"
	OpenVPNConfigFileName = "vpnconfig.conf"

	// File permissions
	CertificatesDirPerm = 0700
	ConfigDirPerm       = 0755
	PrivateKeyFilePerm  = 0600
	CertificateFilePerm = 0644

	// Certificate configuration
	CertificateKeySize    = 2048
	CertificateValidYears = 10
	CertificateCommonName = "VPN CA"

	// PEM block types
	RSAPrivateKeyType = "RSA PRIVATE KEY"
	CertificateType   = "CERTIFICATE"

	// Timeouts and intervals
	GatewayProvisioningTimeout = 30 * time.Minute // VPN Gateway provisioning timeout
	GatewayStatusCheckInterval = 30 * time.Second // Polling interval for gateway status
	VPNConnectionTimeout       = 1 * time.Minute  // VPN connection establishment timeout
	VPNConnectionCheckInterval = 2 * time.Second  // Interval for VPN connection checks

	// System paths for validation
	SystemEtcPrefix = "/etc/"
	SystemUsrPrefix = "/usr/"
	SystemVarPrefix = "/var/"

	// Temporary file patterns
	TempVPNConfigPattern = "vpnconfig-*.ovpn"
	TempVPNCertPattern   = "vpn-cert-*.tmp"
	TempVPNZipPattern    = "vpnconfig-*.zip"
	TempVPNExtractPrefix = "vpnconfig-"

	// OpenVPN configuration paths in extracted ZIP
	OpenVPNConfigPath    = "OpenVPN/vpnconfig.ovpn"
	GenericVPNConfigPath = "Generic/VpnSettings.xml"

	// OpenVPN service template
	OpenVPNServiceTemplate = "openvpn@vpnconfig"
	OpenVPNServiceName     = "vpnconfig"

	// Public IP naming pattern
	GatewayPublicIPName = "vpn-gateway-ip"
	VPNGatewayName      = "vpn-gateway"

	// Point-to-Site configuration name
	P2SConfigName = "P2SConfig"
)

// AuthProvider interface defines the contract for types that can provide authentication
type AuthProvider interface {
	GetAuthProvider() *auth.AuthProvider
}

// Helper functions for common path construction patterns

// GetVPNClientCertPath returns the full path to the VPN client certificate file
func GetVPNClientCertPath() string {
	return filepath.Join(CertificatesDir, VPNClientCertFileName)
}

// GetVPNClientKeyPath returns the full path to the VPN client private key file
func GetVPNClientKeyPath() string {
	return filepath.Join(CertificatesDir, VPNClientKeyFileName)
}

// GetVPNRootCertPath returns the full path to the VPN root CA certificate file
func GetVPNRootCertPath() string {
	return filepath.Join(CertificatesDir, VPNRootCertFileName)
}

// GetOpenVPNConfigPath returns the full path to the OpenVPN configuration file
func GetOpenVPNConfigPath() string {
	return filepath.Join(OpenVPNConfigDir, OpenVPNConfigFileName)
}

// GetVPNConfigPath returns the full path to the VPN configuration file in system config directory
func GetVPNConfigPath() string {
	return filepath.Join(SystemConfigDir, VPNConfigFileName)
}

// WithArcCredential is a helper function that executes a function with Azure credentials
// This eliminates the need to repeatedly call getAzureCredential and handle errors
func WithArcCredential[T any](ctx context.Context, provider AuthProvider, fn func(cred azcore.TokenCredential) (T, error)) (T, error) {
	var zero T
	// cred, err := provider.GetAuthProvider().ArcCredential()
	cred, err := azidentity.NewAzureCLICredential(nil) // TODO: fix this!!!
	if err != nil {
		return zero, err
	}
	return fn(cred)
}

// WithArcCredentialErr is a helper function for operations that only return an error
func WithArcCredentialErr(ctx context.Context, provider AuthProvider, fn func(cred azcore.TokenCredential) error) error {
	// cred, err := provider.GetAuthProvider().ArcCredential()
	cred, err := azidentity.NewAzureCLICredential(nil) // TODO: fix this!!!
	if err != nil {
		return err
	}
	return fn(cred)
}
