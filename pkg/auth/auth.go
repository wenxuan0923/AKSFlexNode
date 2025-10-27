package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"go.goms.io/aks/AKSFlexNode/pkg/config"
	"go.goms.io/aks/AKSFlexNode/pkg/utils"
)

// AuthProvider handles authentication with Azure services
type AuthProvider struct {
	config     *config.Config
	logger     *logrus.Logger
	tokenCache map[string]*TokenInfo
	httpClient *http.Client
}

// TokenInfo represents cached token information
type TokenInfo struct {
	AccessToken string    `json:"access_token"`
	ExpiresOn   int64     `json:"expires_on"`
	Resource    string    `json:"resource"`
	TokenType   string    `json:"token_type"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// NewAuthProvider creates a new authentication provider
func NewAuthProvider(cfg *config.Config, logger *logrus.Logger) *AuthProvider {
	return &AuthProvider{
		config:     cfg,
		logger:     logger,
		tokenCache: make(map[string]*TokenInfo),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// getManagedIdentityToken retrieves a token using ARC managed identity (internal method)
func (a *AuthProvider) getManagedIdentityToken(ctx context.Context, resource string) (string, error) {
	// Check cache first
	if token, exists := a.tokenCache[resource]; exists {
		if time.Now().Before(token.ExpiresAt.Add(-5 * time.Minute)) {
			a.logger.Debugf("Using cached token for resource: %s", resource)
			return token.AccessToken, nil
		}
		// Token is expired or about to expire, remove from cache
		delete(a.tokenCache, resource)
	}

	// Try Arc HIMDS first (most reliable for Arc machines)
	if token, err := a.getArcManagedIdentityToken(ctx, resource); err == nil {
		a.cacheToken(resource, token)
		return token.AccessToken, nil
	} else {
		a.logger.Warnf("Arc HIMDS token acquisition failed: %v", err)
	}

	// Try Service Principal if configured
	a.logger.Info("Attempting to get token using Service Principal...")
	if token, err := a.getServicePrincipalToken(ctx, resource); err == nil {
		a.cacheToken(resource, token)
		return token.AccessToken, nil
	} else {
		a.logger.Warnf("Service Principal token acquisition failed: %v", err)
	}

	return "", fmt.Errorf("unable to obtain access token for resource %s using any available method (Arc HIMDS, Azure IMDS, Service Principal, or Azure CLI)", resource)
}

// getArcManagedIdentityToken gets token from Arc HIMDS
func (a *AuthProvider) getArcManagedIdentityToken(ctx context.Context, resource string) (*TokenInfo, error) {
	a.logger.Infof("Attempting to get Arc managed identity token for resource: %s", resource)

	tokenURL := fmt.Sprintf("http://127.0.0.1:40342/metadata/identity/oauth2/token?api-version=2019-11-01&resource=%s", resource)
	a.logger.Infof("Arc HIMDS token URL: %s", tokenURL)

	// First request to get challenge token
	req, err := http.NewRequestWithContext(ctx, "GET", tokenURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Metadata", "true")

	a.logger.Info("Making initial request to Arc HIMDS for challenge token...")
	resp, err := a.httpClient.Do(req)
	if err != nil {
		a.logger.Errorf("Failed to connect to Arc HIMDS: %v", err)
		return nil, fmt.Errorf("failed to get challenge token: %w", err)
	}
	defer resp.Body.Close()

	a.logger.Infof("Arc HIMDS challenge response: status=%d", resp.StatusCode)

	// Log response headers for debugging
	for key, values := range resp.Header {
		a.logger.Debugf("Challenge response header %s: %v", key, values)
	}

	// Get challenge token path from WWW-Authenticate header
	authHeader := resp.Header.Get("Www-Authenticate")
	a.logger.Infof("WWW-Authenticate header: %s", authHeader)

	if authHeader == "" {
		return nil, fmt.Errorf("no challenge token provided")
	}

	challengeTokenPath := strings.TrimPrefix(authHeader, "Basic realm=")
	challengeTokenPath = strings.Trim(challengeTokenPath, "\"")
	a.logger.Infof("Challenge token path: %s", challengeTokenPath)

	// Read challenge token (may require elevated privileges)
	a.logger.Infof("Reading challenge token from: %s", challengeTokenPath)
	challengeToken, err := a.readChallengeTokenFile(challengeTokenPath)
	if err != nil {
		a.logger.Errorf("Failed to read challenge token from %s: %v", challengeTokenPath, err)
		return nil, fmt.Errorf("failed to read challenge token: %w", err)
	}

	a.logger.Infof("Challenge token length: %d bytes", len(challengeToken))

	// Make authenticated request
	req2, err := http.NewRequestWithContext(ctx, "GET", tokenURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create authenticated request: %w", err)
	}
	req2.Header.Set("Metadata", "true")
	req2.Header.Set("Authorization", fmt.Sprintf("Basic %s", string(challengeToken)))

	a.logger.Info("Making authenticated request to Arc HIMDS with challenge token...")
	resp2, err := a.httpClient.Do(req2)
	if err != nil {
		a.logger.Errorf("Failed authenticated request to Arc HIMDS: %v", err)
		return nil, fmt.Errorf("failed to get token: %w", err)
	}
	defer resp2.Body.Close()

	body, err := io.ReadAll(resp2.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read token response: %w", err)
	}

	if resp2.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Arc HIMDS returned status %d: %s", resp2.StatusCode, string(body))
	}

	// Arc HIMDS returns expires_on as string, so we need a separate struct
	var arcResponse struct {
		AccessToken string `json:"access_token"`
		ExpiresOn   string `json:"expires_on"`
		Resource    string `json:"resource"`
		TokenType   string `json:"token_type"`
	}

	if err := json.Unmarshal(body, &arcResponse); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	// Convert expires_on string to int64
	expiresOn, err := strconv.ParseInt(arcResponse.ExpiresOn, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse expires_on: %w", err)
	}

	// Create TokenInfo with proper types
	tokenInfo := TokenInfo{
		AccessToken: arcResponse.AccessToken,
		ExpiresOn:   expiresOn,
		Resource:    arcResponse.Resource,
		TokenType:   arcResponse.TokenType,
		ExpiresAt:   time.Unix(expiresOn, 0),
	}

	a.logger.Infof("Successfully obtained Arc managed identity token for resource: %s", resource)
	return &tokenInfo, nil
}

// getServicePrincipalToken gets token using service principal credentials
func (a *AuthProvider) getServicePrincipalToken(ctx context.Context, resource string) (*TokenInfo, error) {
	clientID := os.Getenv("AZURE_CLIENT_ID")
	clientSecret := os.Getenv("AZURE_CLIENT_SECRET")
	tenantID := a.config.Azure.TenantID

	if clientID == "" || clientSecret == "" || tenantID == "" {
		return nil, fmt.Errorf("service principal credentials not configured")
	}

	tokenURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/token", tenantID)

	data := fmt.Sprintf("grant_type=client_credentials&client_id=%s&client_secret=%s&resource=%s",
		clientID, clientSecret, resource)

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token request failed with status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read token response: %w", err)
	}

	var response struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}

	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	tokenInfo := &TokenInfo{
		AccessToken: response.AccessToken,
		TokenType:   response.TokenType,
		Resource:    resource,
		ExpiresAt:   time.Now().Add(time.Duration(response.ExpiresIn) * time.Second),
	}

	return tokenInfo, nil
}

// cacheToken caches a token for future use
func (a *AuthProvider) cacheToken(resource string, token *TokenInfo) {
	a.tokenCache[resource] = token
	a.logger.Debugf("Cached token for resource: %s, expires at: %s", resource, token.ExpiresAt.Format(time.RFC3339))
}

// readChallengeTokenFile reads the Arc HIMDS challenge token file, using sudo if necessary
func (a *AuthProvider) readChallengeTokenFile(filePath string) ([]byte, error) {
	// First try to read normally
	if data, err := os.ReadFile(filePath); err == nil {
		return data, nil
	}

	// If normal read fails, try with sudo (Arc challenge tokens are often root-owned)
	a.logger.Info("Challenge token file requires elevated privileges, attempting to read with sudo...")

	// Use sudo to read the file
	cmd := exec.Command("sudo", "cat", filePath)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to read challenge token file with sudo: %w", err)
	}

	return output, nil
}

// GetManagementToken gets a token for Azure Resource Manager access
func (a *AuthProvider) GetManagementToken(ctx context.Context) (string, error) {
	return a.getManagedIdentityToken(ctx, "https://management.azure.com/")
}

// WriteTokenScript writes a token script for kubelet authentication
func (a *AuthProvider) WriteTokenScript(scriptPath string) error {
	script := `#!/bin/bash

# Fetch an AAD token from Azure Arc HIMDS and output it in the ExecCredential format
# https://learn.microsoft.com/azure/azure-arc/servers/managed-identity-authentication

set -euo pipefail

TOKEN_URL="http://127.0.0.1:40342/metadata/identity/oauth2/token?api-version=2019-11-01&resource=6dae42f8-4368-4678-94ff-3960e28e3630"
EXECCREDENTIAL='{
  "kind": "ExecCredential",
  "apiVersion": "client.authentication.k8s.io/v1beta1",
  "spec": {
    "interactive": false
  },
  "status": {
    "expirationTimestamp": (.expires_on | tonumber | todate),
    "token": .access_token
  }
}'

# Arc IMDS requires a challenge token from a file only readable by root for security
CHALLENGE_TOKEN_PATH=$(curl -s -D - -H "Metadata:true" "$TOKEN_URL" | grep -i "www-authenticate" | cut -d "=" -f 2 | tr -d "[:cntrl:]")

if [ -z "$CHALLENGE_TOKEN_PATH" ]; then
    echo "Could not retrieve challenge token path" >&2
    exit 1
fi

CHALLENGE_TOKEN=$(cat "$CHALLENGE_TOKEN_PATH" 2>/dev/null)
if [ $? -ne 0 ]; then
    echo "Could not retrieve challenge token, ensure this command is run with root privileges." >&2
    exit 1
fi

# Get the token using the challenge token
curl -s -H "Metadata:true" -H "Authorization: Basic $CHALLENGE_TOKEN" "$TOKEN_URL" | jq -r "$EXECCREDENTIAL"
`

	if err := utils.WriteFileAtomicSystem(scriptPath, []byte(script), 0755); err != nil {
		return fmt.Errorf("failed to write token script: %w", err)
	}

	return nil
}

// GetAccessTokenViaCLI retrieves an Azure access token using Azure CLI with proper sudo handling
func (a *AuthProvider) GetAccessTokenViaCLI(ctx context.Context, resource string) (string, error) {
	var args []string
	if resource != "" {
		args = []string{"account", "get-access-token", "--resource", resource, "--query", "accessToken", "--output", "tsv"}
	} else {
		args = []string{"account", "get-access-token", "--query", "accessToken", "-o", "tsv"}
	}

	cmd := utils.CreateAzureCliCommand(ctx, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to get Azure CLI access token: %w, output: %s", err, string(output))
	}

	accessToken := strings.TrimSpace(string(output))
	if accessToken == "" {
		return "", fmt.Errorf("empty access token received from Azure CLI")
	}

	return accessToken, nil
}
