package config

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/viper"
)

// Config represents the agent configuration
type Config struct {
	Cluster    ClusterConfig    `yaml:"cluster"`
	Azure      AzureConfig      `yaml:"azure"`
	Node       NodeConfig       `yaml:"node"`
	Containerd ContainerdConfig `yaml:"containerd"`
	Kubernetes KubernetesConfig `yaml:"kubernetes"`
	Runc       RuntimeConfig    `yaml:"runc"`
	Agent      AgentConfig      `yaml:"agent"`
	Paths      PathsConfig      `yaml:"paths"`
}

type ClusterConfig struct {
	ResourceID string `yaml:"resourceId"`
}

type AzureConfig struct {
	SubscriptionID string    `yaml:"subscriptionId"`
	ResourceGroup  string    `yaml:"resourceGroup"`
	TenantID       string    `yaml:"tenantId"`
	Location       string    `yaml:"location"`
	Cloud          string    `yaml:"cloud"`
	Arc            ArcConfig `yaml:"arc"`
	VPN            VPNConfig `yaml:"vpn"`
}

type ArcConfig struct {
	AutoRegister  bool                `yaml:"autoRegister"`
	MachineName   string              `yaml:"machineName"`
	Tags          map[string]string   `yaml:"tags"`
	TargetCluster TargetClusterConfig `yaml:"targetCluster"`
}

type TargetClusterConfig struct {
	Name          string `yaml:"name"`
	ResourceGroup string `yaml:"resourceGroup"`
	// If not specified, will use the Azure.ResourceGroup from parent config
}

type VPNConfig struct {
	Enabled           bool   `yaml:"enabled"`
	AutoProvision     bool   `yaml:"autoProvision"`
	GatewaySubnetCIDR string `yaml:"gatewaySubnetCIDR"`
	P2SGatewayCIDR    string `yaml:"p2sGatewayCIDR"`
	GatewaySKU        string `yaml:"gatewaySKU"`
}

type NodeConfig struct {
	Name    string            `yaml:"name"`
	MaxPods int               `yaml:"maxPods"`
	Labels  map[string]string `yaml:"labels"`
	Taints  []string          `yaml:"taints"`
	Kubelet KubeletConfig     `yaml:"kubelet"`
}

type KubeletConfig struct {
	KubeReserved         map[string]string `yaml:"kubeReserved"`
	EvictionHard         map[string]string `yaml:"evictionHard"`
	ImageGCHighThreshold int               `yaml:"imageGCHighThreshold"`
	ImageGCLowThreshold  int               `yaml:"imageGCLowThreshold"`
}

type ContainerdConfig struct {
	Version        string `yaml:"version"`
	PauseImage     string `yaml:"pauseImage"`
	MetricsAddress string `yaml:"metricsAddress"`
}

type KubernetesConfig struct {
	Version     string `yaml:"version"`
	URLTemplate string `yaml:"urlTemplate"`
}

type RuntimeConfig struct {
	Version string `yaml:"version"`
	URL     string `yaml:"url"`
}

type AgentConfig struct {
	LogLevel              string        `yaml:"logLevel"`
	LogFile               string        `yaml:"logFile"`
	HealthCheckInterval   time.Duration `yaml:"healthCheckInterval"`
	ConfigRefreshInterval time.Duration `yaml:"configRefreshInterval"`
	BootstrapTimeout      time.Duration `yaml:"bootstrapTimeout"`
	MetricsEnabled        bool          `yaml:"metricsEnabled"`
	MetricsPort           int           `yaml:"metricsPort"`
	PidFile               string        `yaml:"pidFile"`
}

type PathsConfig struct {
	ConfigDir  string                `yaml:"configDir"`
	DataDir    string                `yaml:"dataDir"`
	LogDir     string                `yaml:"logDir"`
	Kubernetes KubernetesPathsConfig `yaml:"kubernetes"`
	CNI        CNIPathsConfig        `yaml:"cni"`
}

type KubernetesPathsConfig struct {
	ConfigDir       string `yaml:"configDir"`
	CertsDir        string `yaml:"certsDir"`
	ManifestsDir    string `yaml:"manifestsDir"`
	VolumePluginDir string `yaml:"volumePluginDir"`
	KubeletDir      string `yaml:"kubeletDir"`
}

type CNIPathsConfig struct {
	BinDir  string `yaml:"binDir"`
	ConfDir string `yaml:"confDir"`
	LibDir  string `yaml:"libDir"`
}

// LoadConfig loads configuration from file and environment
func LoadConfig(configPath string) (*Config, error) {
	// Use default config path if none specified
	if configPath == "" {
		configPath = "/etc/aks-flex-node/config.yaml"
	}

	config := &Config{}

	// Set up viper
	v := viper.New()
	v.SetConfigType("yaml")
	v.AutomaticEnv()
	v.SetEnvPrefix("AKS_NODE_CONTROLLER")

	// Load the specified config file
	v.SetConfigFile(configPath)
	if err := v.ReadInConfig(); err != nil {
		if configPath == "/etc/aks-flex-node/config.yaml" {
			return nil, fmt.Errorf("default config file not found at %s. Please create the config file or specify a custom path with --config", configPath)
		}
		return nil, fmt.Errorf("error reading config file %s: %w", configPath, err)
	}

	// Unmarshal config
	if err := v.Unmarshal(config); err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %w", err)
	}

	// Validate and set defaults
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return config, nil
}

// Validate validates the configuration and ensures all required fields are set
func (c *Config) Validate() error {
	// Validate required Azure configuration (core requirements for Arc discovery)
	if c.Azure.SubscriptionID == "" {
		return fmt.Errorf("azure.subscriptionId is required")
	}
	if c.Azure.ResourceGroup == "" {
		return fmt.Errorf("azure.resourceGroup is required")
	}
	if c.Azure.TenantID == "" {
		return fmt.Errorf("azure.tenantId is required")
	}
	if c.Azure.Location == "" {
		return fmt.Errorf("azure.location is required")
	}

	// Set default paths if not provided
	if c.Paths.ConfigDir == "" {
		c.Paths.ConfigDir = "/etc/aks-flex-node"
	}
	if c.Paths.DataDir == "" {
		c.Paths.DataDir = "/var/lib/aks-flex-node"
	}
	if c.Paths.LogDir == "" {
		c.Paths.LogDir = "/var/log/aks-flex-node"
	}

	// Set default agent configuration if not provided
	if c.Agent.LogLevel == "" {
		c.Agent.LogLevel = "info"
	}
	if c.Agent.LogFile == "" {
		c.Agent.LogFile = "/var/log/aks-flex-node/agent.log"
	}

	// Set default paths for Kubernetes components if not provided
	if c.Paths.Kubernetes.ConfigDir == "" {
		c.Paths.Kubernetes.ConfigDir = "/etc/kubernetes"
	}
	if c.Paths.Kubernetes.CertsDir == "" {
		c.Paths.Kubernetes.CertsDir = "/etc/kubernetes/certs"
	}
	if c.Paths.Kubernetes.ManifestsDir == "" {
		c.Paths.Kubernetes.ManifestsDir = "/etc/kubernetes/manifests"
	}
	if c.Paths.Kubernetes.VolumePluginDir == "" {
		c.Paths.Kubernetes.VolumePluginDir = "/etc/kubernetes/volumeplugins"
	}
	if c.Paths.Kubernetes.KubeletDir == "" {
		c.Paths.Kubernetes.KubeletDir = "/var/lib/kubelet"
	}

	// Set default paths for CNI if not provided
	if c.Paths.CNI.BinDir == "" {
		c.Paths.CNI.BinDir = "/opt/cni/bin"
	}
	if c.Paths.CNI.ConfDir == "" {
		c.Paths.CNI.ConfDir = "/etc/cni/net.d"
	}
	if c.Paths.CNI.LibDir == "" {
		c.Paths.CNI.LibDir = "/var/lib/cni"
	}

	// Set default node configuration if not provided
	if c.Node.MaxPods == 0 {
		c.Node.MaxPods = 110 // Default Kubernetes node pod limit
	}

	// Set default kubelet configuration if not provided
	if c.Node.Kubelet.ImageGCHighThreshold == 0 {
		c.Node.Kubelet.ImageGCHighThreshold = 85 // Default: start GC when disk usage > 85%
	}
	if c.Node.Kubelet.ImageGCLowThreshold == 0 {
		c.Node.Kubelet.ImageGCLowThreshold = 80 // Default: stop GC when disk usage < 80%
	}
	// Initialize default kubelet resource reservations if not provided
	if c.Node.Kubelet.KubeReserved == nil {
		c.Node.Kubelet.KubeReserved = make(map[string]string)
	}
	if c.Node.Kubelet.EvictionHard == nil {
		c.Node.Kubelet.EvictionHard = make(map[string]string)
	}

	// Set default container runtime configuration if not provided
	if c.Containerd.Version == "" {
		c.Containerd.Version = "1.7.20"
	}
	if c.Containerd.PauseImage == "" {
		c.Containerd.PauseImage = "mcr.microsoft.com/oss/kubernetes/pause:3.6"
	}
	if c.Containerd.MetricsAddress == "" {
		c.Containerd.MetricsAddress = "0.0.0.0:10257"
	}

	// Set default Kubernetes configuration if not provided
	if c.Kubernetes.Version == "" {
		c.Kubernetes.Version = "1.32.7"
	}
	if c.Kubernetes.URLTemplate == "" {
		c.Kubernetes.URLTemplate = "https://acs-mirror.azureedge.net/kubernetes/v%s/binaries/kubernetes-node-linux-%s.tar.gz"
	}

	// Set default runc configuration if not provided
	if c.Runc.Version == "" {
		c.Runc.Version = "1.1.12"
	}
	if c.Runc.URL == "" {
		c.Runc.URL = "https://github.com/opencontainers/runc/releases/download/v1.1.12/runc.amd64"
	}

	// Set default agent configuration for missing fields
	if c.Agent.HealthCheckInterval == 0 {
		c.Agent.HealthCheckInterval = 30 * time.Second
	}
	if c.Agent.ConfigRefreshInterval == 0 {
		c.Agent.ConfigRefreshInterval = 5 * time.Minute
	}
	if c.Agent.BootstrapTimeout == 0 {
		c.Agent.BootstrapTimeout = 30 * time.Minute
	}
	if c.Agent.MetricsPort == 0 {
		c.Agent.MetricsPort = 8080
	}
	if c.Agent.PidFile == "" {
		c.Agent.PidFile = "/var/run/aks-flex-node/agent.pid"
	}

	// Set default Azure cloud if not provided
	if c.Azure.Cloud == "" {
		c.Azure.Cloud = "AzurePublicCloud"
	}

	// Set default VPN configuration if enabled
	if c.Azure.VPN.Enabled {
		if c.Azure.VPN.GatewaySubnetCIDR == "" {
			c.Azure.VPN.GatewaySubnetCIDR = "10.0.1.0/24"
		}
		if c.Azure.VPN.P2SGatewayCIDR == "" {
			c.Azure.VPN.P2SGatewayCIDR = "192.168.100.0/24"
		}
		if c.Azure.VPN.GatewaySKU == "" {
			c.Azure.VPN.GatewaySKU = "VpnGw2AZ"
		}
	}

	// Validate that low threshold is less than high threshold
	if c.Node.Kubelet.ImageGCLowThreshold >= c.Node.Kubelet.ImageGCHighThreshold {
		return fmt.Errorf("node.kubelet.imageGCLowThreshold (%d) must be less than imageGCHighThreshold (%d)",
			c.Node.Kubelet.ImageGCLowThreshold, c.Node.Kubelet.ImageGCHighThreshold)
	}

	return nil
}

// GetNodeName returns the node name, using hostname if not configured
func (c *Config) GetNodeName() string {
	if c.Node.Name != "" {
		return c.Node.Name
	}

	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}

// IsDebugEnabled returns true if debug logging is enabled
func (c *Config) IsDebugEnabled() bool {
	return c.Agent.LogLevel == "debug"
}
