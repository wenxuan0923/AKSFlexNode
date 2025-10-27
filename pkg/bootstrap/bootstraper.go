package bootstrap

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"go.goms.io/aks/AKSFlexNode/pkg/aks"
	"go.goms.io/aks/AKSFlexNode/pkg/arc"
	"go.goms.io/aks/AKSFlexNode/pkg/auth"
	"go.goms.io/aks/AKSFlexNode/pkg/cni"
	"go.goms.io/aks/AKSFlexNode/pkg/config"
	"go.goms.io/aks/AKSFlexNode/pkg/state"
	"go.goms.io/aks/AKSFlexNode/pkg/utils"
	"go.goms.io/aks/AKSFlexNode/pkg/vpn"
	"gopkg.in/yaml.v3"
)

// Bootstrapper handles node bootstrap operations with state management
type Bootstrapper struct {
	config       *config.Config
	logger       *logrus.Logger
	authProvider *auth.AuthProvider
	vpnManager   *vpn.VPNManager
	cniManager   *cni.CNIManager
	vpnIPMgr     *vpn.NodeIPManager
	stateManager *state.StateManager
	arcManager   *arc.ArcManager
}

// NewBootstrapper creates a new bootstrapper instance
func NewBootstrapper(cfg *config.Config, logger *logrus.Logger) *Bootstrapper {
	return &Bootstrapper{
		config:       cfg,
		logger:       logger,
		authProvider: auth.NewAuthProvider(cfg, logger),
		vpnManager:   vpn.NewVPNManager(cfg),
		cniManager:   cni.NewCNIManager(cfg),
		vpnIPMgr:     vpn.NewNodeIPManager(cfg),
		stateManager: state.NewStateManager(logger),
		arcManager:   arc.NewArcManager(cfg, logger),
	}
}

// Bootstrap performs complete node bootstrap with state management
func (b *Bootstrapper) Bootstrap(ctx context.Context) error {
	// Load current state
	currentState, err := b.stateManager.LoadState()
	if err != nil {
		return fmt.Errorf("failed to load bootstrap state: %w", err)
	}

	b.logger.Infof("Starting node bootstrap (state file: %s)", b.stateManager.GetStateFilePath())

	// Perform bootstrap steps with state tracking
	if err := b.performBootstrapSteps(ctx, currentState); err != nil {
		return err
	}

	// Mark overall bootstrap as completed
	if err := b.stateManager.MarkStepCompleted(currentState, "bootstrap_completed"); err != nil {
		return fmt.Errorf("failed to mark bootstrap as completed: %w", err)
	}

	b.logger.Info("Node bootstrap completed successfully")
	return nil
}

// performBootstrapSteps handles bootstrap steps with state tracking
func (b *Bootstrapper) performBootstrapSteps(ctx context.Context, currentState *state.BootstrapState) error {
	steps := []struct {
		name string
		fn   func(context.Context) error
	}{
		{"kubelet_stopped", b.stopKubelet},
		{"directories_created", b.createDirectories},
		{"cni_setup", b.setupCNI},
		{"runc_installed", b.installRunc},
		{"containerd_installed", b.installContainerd},
		{"kubernetes_components_installed", b.installKubernetes},
		{"system_configured", b.configureSystem},
		{"containerd_configured", b.configureContainerd},
		{"cluster_credentials_downloaded", b.downloadClusterCredentials},
		{"kubelet_configured", b.configureKubelet},
		{"arc_auth_setup", b.setupArcAuth},
		{"services_enabled", b.enableServices},
	}

	for _, step := range steps {
		stepCompleted := b.stateManager.IsStepCompleted(currentState, step.name)
		stepValid := b.isStepActuallyValid(step.name)

		b.logger.Debugf("Step %s: completed=%t, valid=%t", step.name, stepCompleted, stepValid)

		if !stepCompleted || !stepValid {
			if stepCompleted && !stepValid {
				b.logger.Infof("Re-executing bootstrap step (invalid): %s", step.name)
			} else {
				b.logger.Infof("Executing bootstrap step: %s", step.name)
			}

			if err := step.fn(ctx); err != nil {
				b.stateManager.MarkStepFailed(currentState, step.name, err.Error())
				return fmt.Errorf("bootstrap step '%s' failed: %w", step.name, err)
			}
			if err := b.stateManager.MarkStepCompleted(currentState, step.name); err != nil {
				return err
			}
		} else {
			b.logger.Infof("Skipping completed bootstrap step: %s", step.name)
		}
	}

	return nil
}

func (b *Bootstrapper) stopKubelet(ctx context.Context) error {
	// Stop and disable kubelet if it exists
	utils.RunSystemCommand("systemctl", "stop", "kubelet")
	utils.RunSystemCommand("systemctl", "disable", "kubelet")
	return nil
}

func (b *Bootstrapper) createDirectories(ctx context.Context) error {
	dirs := []string{
		b.config.Paths.CNI.LibDir,
		b.config.Paths.CNI.BinDir,
		b.config.Paths.CNI.ConfDir,
		b.config.Paths.Kubernetes.VolumePluginDir,
		b.config.Paths.Kubernetes.CertsDir,
		b.config.Paths.Kubernetes.ManifestsDir,
		"/etc/containerd",
		"/etc/systemd/system/kubelet.service.d",
		b.config.Paths.Kubernetes.KubeletDir,
		b.config.Paths.DataDir,
		b.config.Paths.LogDir,
	}

	for _, dir := range dirs {
		if err := utils.RunSystemCommand("mkdir", "-p", dir); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	return nil
}

func (b *Bootstrapper) installRunc(ctx context.Context) error {
	b.logger.Info("Installing runc")

	// Check if runc is already installed
	if utils.FileExists("/usr/bin/runc") {
		b.logger.Info("runc is already installed, skipping installation")
		return nil
	}

	// Download runc
	if err := utils.DownloadFile(b.config.Runc.URL, "/tmp/runc"); err != nil {
		return fmt.Errorf("failed to download runc: %w", err)
	}

	// Install runc
	if err := utils.RunSystemCommand("install", "-m", "0555", "/tmp/runc", "/usr/bin/runc"); err != nil {
		return fmt.Errorf("failed to install runc: %w", err)
	}

	// Clean up
	os.Remove("/tmp/runc")

	return nil
}

func (b *Bootstrapper) installContainerd(ctx context.Context) error {
	b.logger.Info("Installing containerd")

	// Check if containerd is already installed
	if utils.FileExists("/usr/bin/containerd") {
		b.logger.Info("containerd is already installed, skipping installation")
		return nil
	}

	// Download containerd
	url := fmt.Sprintf("https://github.com/containerd/containerd/releases/download/v%s/containerd-%s-linux-amd64.tar.gz",
		b.config.Containerd.Version, b.config.Containerd.Version)

	// Use home directory instead of /tmp to avoid space issues
	homeDir := os.Getenv("HOME")
	if homeDir == "" {
		homeDir = "/tmp" // fallback to /tmp if HOME not set
	}
	tarFile := fmt.Sprintf("%s/containerd-%s-linux-amd64.tar.gz", homeDir, b.config.Containerd.Version)

	if err := utils.DownloadFile(url, tarFile); err != nil {
		return fmt.Errorf("failed to download containerd: %w", err)
	}

	// Extract containerd to temporary directory first (using home directory to avoid space issues)
	tmpDir := homeDir + "/containerd-extract"
	if err := utils.RunSystemCommand("mkdir", "-p", tmpDir); err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}

	// Ensure cleanup happens even on error
	defer func() {
		os.Remove(tarFile)
		os.RemoveAll(tmpDir)
	}()

	if err := utils.RunSystemCommand("tar", "-xzf", tarFile, "-C", tmpDir); err != nil {
		return fmt.Errorf("failed to extract containerd to temp directory: %w", err)
	}

	// Verify extraction worked before copying
	if _, err := os.Stat(tmpDir + "/bin"); err != nil {
		return fmt.Errorf("containerd extraction failed, bin directory not found: %w", err)
	}

	// Copy binaries to /usr/bin using bash for proper glob expansion
	// Since we're copying to /usr/bin, we need to ensure sudo privileges
	copyCmd := fmt.Sprintf("cp -r %s/bin/* /usr/bin/", tmpDir)
	if err := utils.RunSystemCommand("bash", "-c", copyCmd, "/usr/bin/"); err != nil {
		return fmt.Errorf("failed to copy containerd binaries: %w", err)
	}

	return nil
}

func (b *Bootstrapper) installKubernetes(ctx context.Context) error {
	b.logger.Info("Installing Kubernetes components")

	// Check if Kubernetes components are already installed
	binaries := []string{"kubelet", "kubectl", "kubeadm"}
	allInstalled := true
	for _, binary := range binaries {
		dst := fmt.Sprintf("/usr/local/bin/%s", binary)
		if !utils.FileExists(dst) {
			allInstalled = false
			break
		}
	}

	if allInstalled {
		b.logger.Info("Kubernetes components are already installed, skipping installation")
		return nil
	}

	// Determine CPU architecture
	cpuArch := runtime.GOARCH
	if cpuArch == "amd64" {
		cpuArch = "amd64"
	}

	// Download Kubernetes components
	url := fmt.Sprintf(b.config.Kubernetes.URLTemplate, b.config.Kubernetes.Version, cpuArch)
	tarFile := fmt.Sprintf("/tmp/kubernetes-node-linux-%s.tar.gz", cpuArch)

	if err := utils.DownloadFile(url, tarFile); err != nil {
		return fmt.Errorf("failed to download Kubernetes components: %w", err)
	}

	// Extract specific binaries
	if err := utils.RunSystemCommand("tar", "-xvzf", tarFile, "kubernetes/node/bin/kubelet", "kubernetes/node/bin/kubectl", "kubernetes/node/bin/kubeadm"); err != nil {
		return fmt.Errorf("failed to extract Kubernetes binaries: %w", err)
	}

	// Move binaries to /usr/local/bin
	for _, binary := range binaries {
		src := fmt.Sprintf("kubernetes/node/bin/%s", binary)
		dst := fmt.Sprintf("/usr/local/bin/%s", binary)
		if err := utils.RunSystemCommand("mv", src, dst); err != nil {
			return fmt.Errorf("failed to move %s: %w", binary, err)
		}
	}

	// Clean up
	os.RemoveAll("kubernetes")
	os.Remove(tarFile)

	return nil
}

func (b *Bootstrapper) configureSystem(ctx context.Context) error {
	b.logger.Info("Configuring system settings")

	// Fix resolv.conf link
	utils.RunSystemCommand("ln", "-sf", "/run/systemd/resolve/resolv.conf", "/etc/resolv.conf")

	// Create and install sysctl configuration
	if err := b.createSysctlConfigFile(); err != nil {
		return err
	}

	// Apply sysctl settings
	if err := utils.RunSystemCommand("sysctl", "--system"); err != nil {
		b.logger.Warnf("Failed to apply sysctl settings: %v", err)
	}

	return nil
}

// createSysctlConfigFile creates the sysctl configuration file for Kubernetes
func (b *Bootstrapper) createSysctlConfigFile() error {
	sysctlConfig := `# container networking
net.ipv4.ip_forward = 1
net.ipv4.conf.all.forwarding = 1
net.ipv6.conf.all.forwarding = 1
net.bridge.bridge-nf-call-iptables = 1

# refer to https://github.com/kubernetes/kubernetes/blob/75d45bdfc9eeda15fb550e00da662c12d7d37985/pkg/kubelet/cm/container_manager_linux.go#L359-L397
vm.overcommit_memory = 1
kernel.panic = 10
kernel.panic_on_oops = 1
# to ensure node stability, we set this to the PID_MAX_LIMIT on 64-bit systems: refer to https://kubernetes.io/docs/concepts/policy/pid-limiting/
kernel.pid_max = 4194304
# https://github.com/Azure/AKS/issues/772
fs.inotify.max_user_watches = 1048576
# Ubuntu 22.04 has inotify_max_user_instances set to 128, where as Ubuntu 18.04 had 1024.
fs.inotify.max_user_instances = 1024

# This is a partial workaround to this upstream Kubernetes issue:
# https://github.com/kubernetes/kubernetes/issues/41916#issuecomment-312428731
net.ipv4.tcp_retries2=8
net.core.message_burst=80
net.core.message_cost=40
net.core.somaxconn=16384
net.ipv4.tcp_max_syn_backlog=16384
net.ipv4.neigh.default.gc_thresh1=4096
net.ipv4.neigh.default.gc_thresh2=8192
net.ipv4.neigh.default.gc_thresh3=16384`

	// Create sysctl config file using sudo-aware approach
	tempSysctlFile, err := utils.CreateTempFile("sysctl-aks-*.conf", []byte(sysctlConfig))
	if err != nil {
		return fmt.Errorf("failed to create temporary sysctl config file: %w", err)
	}
	defer utils.CleanupTempFile(tempSysctlFile.Name())

	// Ensure /etc/sysctl.d directory exists
	if err := utils.RunSystemCommand("mkdir", "-p", "/etc/sysctl.d"); err != nil {
		return fmt.Errorf("failed to create /etc/sysctl.d directory: %w", err)
	}

	// Copy the temp file to the final location using sudo
	if err := utils.RunSystemCommand("cp", tempSysctlFile.Name(), "/etc/sysctl.d/999-sysctl-aks.conf"); err != nil {
		return fmt.Errorf("failed to install sysctl config file: %w", err)
	}

	// Set proper permissions
	if err := utils.RunSystemCommand("chmod", "644", "/etc/sysctl.d/999-sysctl-aks.conf"); err != nil {
		return fmt.Errorf("failed to set sysctl config file permissions: %w", err)
	}

	return nil
}

func (b *Bootstrapper) configureContainerd(ctx context.Context) error {
	b.logger.Info("Configuring containerd")

	// Create containerd systemd service
	if err := b.createContainerdServiceFile(); err != nil {
		return err
	}

	// Create containerd configuration
	if err := b.createContainerdConfigFile(); err != nil {
		return err
	}

	// Create kubenet template
	if err := b.createKubenetTemplateFile(); err != nil {
		return err
	}

	// Reload systemd to pick up the new containerd service configuration
	b.logger.Info("Reloading systemd to pick up containerd configuration changes")
	if err := utils.RunSystemCommand("systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("failed to reload systemd after containerd configuration: %w", err)
	}

	return nil
}

// createContainerdServiceFile creates the containerd systemd service file
func (b *Bootstrapper) createContainerdServiceFile() error {
	containerdService := `[Unit]
Description=containerd container runtime
Documentation=https://containerd.io
After=network.target local-fs.target
[Service]
ExecStartPre=-/sbin/modprobe overlay
ExecStart=/usr/bin/containerd
Type=notify
Delegate=yes
KillMode=process
Restart=always
RestartSec=5
# Having non-zero Limit*s causes performance problems due to accounting overhead
# in the kernel. We recommend using cgroups to do container-local accounting.
LimitNPROC=infinity
LimitCORE=infinity
LimitNOFILE=infinity
# Comment TasksMax if your systemd version does not supports it.
# Only systemd 226 and above support this version.
TasksMax=infinity
OOMScoreAdjust=-999
[Install]
WantedBy=multi-user.target`

	// Create containerd service file using sudo-aware approach
	tempFile, err := utils.CreateTempFile("containerd-service-*.service", []byte(containerdService))
	if err != nil {
		return fmt.Errorf("failed to create temporary containerd service file: %w", err)
	}
	defer utils.CleanupTempFile(tempFile.Name())

	// Copy the temp file to the final location using sudo
	if err := utils.RunSystemCommand("cp", tempFile.Name(), "/etc/systemd/system/containerd.service"); err != nil {
		return fmt.Errorf("failed to install containerd service file: %w", err)
	}

	// Set proper permissions
	if err := utils.RunSystemCommand("chmod", "644", "/etc/systemd/system/containerd.service"); err != nil {
		return fmt.Errorf("failed to set containerd service file permissions: %w", err)
	}

	return nil
}

// createContainerdConfigFile creates the containerd configuration file
func (b *Bootstrapper) createContainerdConfigFile() error {
	containerdConfig := fmt.Sprintf(`version = 2
oom_score = 0
[plugins."io.containerd.grpc.v1.cri"]
	sandbox_image = "%s"
	[plugins."io.containerd.grpc.v1.cri".containerd]
		default_runtime_name = "runc"
		[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc]
			runtime_type = "io.containerd.runc.v2"
		[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc.options]
			BinaryName = "/usr/bin/runc"
			SystemdCgroup = true
		[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.untrusted]
			runtime_type = "io.containerd.runc.v2"
		[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.untrusted.options]
			BinaryName = "/usr/bin/runc"
	[plugins."io.containerd.grpc.v1.cri".cni]
		bin_dir = "%s"
		conf_dir = "%s"
		conf_template = "/etc/containerd/kubenet_template.conf"
	[plugins."io.containerd.grpc.v1.cri".registry]
		config_path = "/etc/containerd/certs.d"
	[plugins."io.containerd.grpc.v1.cri".registry.headers]
		X-Meta-Source-Client = ["azure/aks"]
[metrics]
	address = "%s"`,
		b.config.Containerd.PauseImage,
		b.config.Paths.CNI.BinDir,
		b.config.Paths.CNI.ConfDir,
		b.config.Containerd.MetricsAddress)

	// Create containerd config file using sudo-aware approach
	tempConfigFile, err := utils.CreateTempFile("containerd-config-*.toml", []byte(containerdConfig))
	if err != nil {
		return fmt.Errorf("failed to create temporary containerd config file: %w", err)
	}
	defer utils.CleanupTempFile(tempConfigFile.Name())

	// Ensure /etc/containerd directory exists
	if err := utils.RunSystemCommand("mkdir", "-p", "/etc/containerd"); err != nil {
		return fmt.Errorf("failed to create containerd config directory: %w", err)
	}

	// Copy the temp file to the final location using sudo
	if err := utils.RunSystemCommand("cp", tempConfigFile.Name(), "/etc/containerd/config.toml"); err != nil {
		return fmt.Errorf("failed to install containerd config file: %w", err)
	}

	// Set proper permissions
	if err := utils.RunSystemCommand("chmod", "644", "/etc/containerd/config.toml"); err != nil {
		return fmt.Errorf("failed to set containerd config file permissions: %w", err)
	}

	return nil
}

// createKubenetTemplateFile creates the kubenet CNI template file
func (b *Bootstrapper) createKubenetTemplateFile() error {
	kubenetTemplate := `{
    "cniVersion": "0.3.1",
    "name": "kubenet",
    "plugins": [{
    "type": "bridge",
    "bridge": "cbr0",
    "mtu": 1500,
    "addIf": "eth0",
    "isGateway": true,
    "ipMasq": false,
    "promiscMode": true,
    "hairpinMode": false,
    "ipam": {
        "type": "host-local",
        "ranges": [{{range $i, $range := .PodCIDRRanges}}{{if $i}}, {{end}}[{"subnet": "{{$range}}"}]{{end}}],
        "routes": [{{range $i, $route := .Routes}}{{if $i}}, {{end}}{"dst": "{{$route}}"}{{end}}]
    }
    },
    {
    "type": "portmap",
    "capabilities": {"portMappings": true},
    "externalSetMarkChain": "KUBE-MARK-MASQ"
    }]
}`

	// Create kubenet template file using sudo-aware approach
	tempTemplateFile, err := utils.CreateTempFile("kubenet-template-*.conf", []byte(kubenetTemplate))
	if err != nil {
		return fmt.Errorf("failed to create temporary kubenet template file: %w", err)
	}
	defer utils.CleanupTempFile(tempTemplateFile.Name())

	// Copy the temp file to the final location using sudo
	if err := utils.RunSystemCommand("cp", tempTemplateFile.Name(), "/etc/containerd/kubenet_template.conf"); err != nil {
		return fmt.Errorf("failed to install kubenet template file: %w", err)
	}

	// Set proper permissions
	if err := utils.RunSystemCommand("chmod", "644", "/etc/containerd/kubenet_template.conf"); err != nil {
		return fmt.Errorf("failed to set kubenet template file permissions: %w", err)
	}

	return nil
}

func (b *Bootstrapper) configureKubelet(ctx context.Context) error {
	b.logger.Info("Configuring kubelet")

	// Create kubelet defaults file
	if err := b.createKubeletDefaultsFile(); err != nil {
		return err
	}

	// Create kubelet containerd configuration
	if err := b.createKubeletContainerdConfig(); err != nil {
		return err
	}

	// Create main kubelet service
	if err := b.createKubeletServiceFile(); err != nil {
		return err
	}

	// Reload systemd to pick up the new kubelet configuration files
	b.logger.Info("Reloading systemd to pick up kubelet configuration changes")
	if err := utils.RunSystemCommand("systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("failed to reload systemd after kubelet configuration: %w", err)
	}

	return nil
}

// createKubeletDefaultsFile creates the kubelet defaults configuration file
func (b *Bootstrapper) createKubeletDefaultsFile() error {
	// Create kubelet default config
	labels := make([]string, 0, len(b.config.Node.Labels))
	for k, v := range b.config.Node.Labels {
		labels = append(labels, fmt.Sprintf("%s=%s", k, v))
	}

	kubeletDefaults := fmt.Sprintf(`KUBELET_NODE_LABELS="%s"
KUBELET_FLAGS="\
  --address=0.0.0.0 \
  --anonymous-auth=false \
  --authentication-token-webhook=true \
  --authorization-mode=Webhook \
  --cgroup-driver=systemd \
  --cgroups-per-qos=true \
  --enforce-node-allocatable=pods \
  --event-qps=0  \
  --eviction-hard=%s  \
  --kube-reserved=%s  \
  --image-gc-high-threshold=%d  \
  --image-gc-low-threshold=%d  \
  --max-pods=%d  \
  --node-status-update-frequency=10s  \
  --pod-infra-container-image=%s  \
  --pod-max-pids=-1  \
  --protect-kernel-defaults=true  \
  --read-only-port=0  \
  --resolv-conf=/run/systemd/resolve/resolv.conf  \
  --streaming-connection-idle-timeout=4h  \
  --tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_GCM_SHA256 \
  "`,
		strings.Join(labels, ","),
		utils.MapToEvictionThresholds(b.config.Node.Kubelet.EvictionHard, ","),
		utils.MapToKeyValuePairs(b.config.Node.Kubelet.KubeReserved, ","),
		b.config.Node.Kubelet.ImageGCHighThreshold,
		b.config.Node.Kubelet.ImageGCLowThreshold,
		b.config.Node.MaxPods,
		b.config.Containerd.PauseImage)

	// Create kubelet defaults file using sudo-aware approach
	tempKubeletFile, err := utils.CreateTempFile("kubelet-defaults-*", []byte(kubeletDefaults))
	if err != nil {
		return fmt.Errorf("failed to create temporary kubelet defaults file: %w", err)
	}
	defer utils.CleanupTempFile(tempKubeletFile.Name())

	// Ensure /etc/default directory exists
	if err := utils.RunSystemCommand("mkdir", "-p", "/etc/default"); err != nil {
		return fmt.Errorf("failed to create /etc/default directory: %w", err)
	}

	// Copy the temp file to the final location using sudo
	if err := utils.RunSystemCommand("cp", tempKubeletFile.Name(), "/etc/default/kubelet"); err != nil {
		return fmt.Errorf("failed to install kubelet defaults file: %w", err)
	}

	// Set proper permissions
	if err := utils.RunSystemCommand("chmod", "644", "/etc/default/kubelet"); err != nil {
		return fmt.Errorf("failed to set kubelet defaults file permissions: %w", err)
	}

	return nil
}

// createKubeletContainerdConfig creates the kubelet containerd configuration
func (b *Bootstrapper) createKubeletContainerdConfig() error {
	containerdConf := `[Service]
Environment=KUBELET_CONTAINERD_FLAGS="--runtime-request-timeout=15m --container-runtime-endpoint=unix:///run/containerd/containerd.sock"`

	// Create kubelet containerd config file using sudo-aware approach
	tempContainerdConf, err := utils.CreateTempFile("kubelet-containerd-*.conf", []byte(containerdConf))
	if err != nil {
		return fmt.Errorf("failed to create temporary kubelet containerd config file: %w", err)
	}
	defer utils.CleanupTempFile(tempContainerdConf.Name())

	// Ensure kubelet service.d directory exists
	if err := utils.RunSystemCommand("mkdir", "-p", "/etc/systemd/system/kubelet.service.d"); err != nil {
		return fmt.Errorf("failed to create kubelet service.d directory: %w", err)
	}

	// Copy the temp file to the final location using sudo
	if err := utils.RunSystemCommand("cp", tempContainerdConf.Name(), "/etc/systemd/system/kubelet.service.d/10-containerd.conf"); err != nil {
		return fmt.Errorf("failed to install kubelet containerd config file: %w", err)
	}

	// Set proper permissions
	if err := utils.RunSystemCommand("chmod", "644", "/etc/systemd/system/kubelet.service.d/10-containerd.conf"); err != nil {
		return fmt.Errorf("failed to set kubelet containerd config file permissions: %w", err)
	}

	return nil
}

// createKubeletServiceFile creates the main kubelet systemd service file
func (b *Bootstrapper) createKubeletServiceFile() error {
	kubeletService := `[Unit]
Description=Kubelet
ConditionPathExists=/usr/local/bin/kubelet
[Service]
Restart=always
EnvironmentFile=/etc/default/kubelet
SuccessExitStatus=143
# Ace does not recall why this is done
ExecStartPre=/bin/bash -c "if [ $(mount | grep \"/var/lib/kubelet\" | wc -l) -le 0 ] ; then /bin/mount --bind /var/lib/kubelet /var/lib/kubelet ; fi"
ExecStartPre=/bin/mount --make-shared /var/lib/kubelet
ExecStartPre=-/sbin/ebtables -t nat --list
ExecStartPre=-/sbin/iptables -t nat --numeric --list
ExecStart=/usr/local/bin/kubelet \
        --enable-server \
        --node-labels="${KUBELET_NODE_LABELS}" \
        --v=2 \
        --volume-plugin-dir=/etc/kubernetes/volumeplugins \
        --pod-manifest-path=/etc/kubernetes/manifests/ \
        $KUBELET_TLS_BOOTSTRAP_FLAGS \
        $KUBELET_CONFIG_FILE_FLAGS \
        $KUBELET_CONTAINERD_FLAGS \
        $KUBELET_FLAGS
[Install]
WantedBy=multi-user.target`

	// Create kubelet service file using sudo-aware approach
	tempKubeletService, err := utils.CreateTempFile("kubelet-service-*.service", []byte(kubeletService))
	if err != nil {
		return fmt.Errorf("failed to create temporary kubelet service file: %w", err)
	}
	defer utils.CleanupTempFile(tempKubeletService.Name())

	// Copy the temp file to the final location using sudo
	if err := utils.RunSystemCommand("cp", tempKubeletService.Name(), "/etc/systemd/system/kubelet.service"); err != nil {
		return fmt.Errorf("failed to install kubelet service file: %w", err)
	}

	// Set proper permissions
	if err := utils.RunSystemCommand("chmod", "644", "/etc/systemd/system/kubelet.service"); err != nil {
		return fmt.Errorf("failed to set kubelet service file permissions: %w", err)
	}

	return nil
}

func (b *Bootstrapper) setupArcAuth(ctx context.Context) error {
	b.logger.Info("Setting up Azure Arc authentication")

	// Create token script for Azure Arc authentication using centralized AuthProvider
	tokenPath := filepath.Join(b.config.Paths.Kubernetes.KubeletDir, "token.sh")

	if err := b.authProvider.WriteTokenScript(tokenPath); err != nil {
		return fmt.Errorf("failed to create token script: %w", err)
	}

	// Create TLS bootstrap config for kubelet
	tlsBootstrapConf := `[Service]
Environment=KUBELET_TLS_BOOTSTRAP_FLAGS="--kubeconfig /var/lib/kubelet/kubeconfig"`

	// Create TLS bootstrap config file using sudo-aware approach
	tempTLSFile, err := utils.CreateTempFile("tls-bootstrap-*.conf", []byte(tlsBootstrapConf))
	if err != nil {
		return fmt.Errorf("failed to create temporary TLS bootstrap config file: %w", err)
	}
	defer utils.CleanupTempFile(tempTLSFile.Name())

	// Copy the temp file to the final location using sudo
	if err := utils.RunSystemCommand("cp", tempTLSFile.Name(), "/etc/systemd/system/kubelet.service.d/10-tlsbootstrap.conf"); err != nil {
		return fmt.Errorf("failed to install TLS bootstrap config file: %w", err)
	}

	// Set proper permissions
	if err := utils.RunSystemCommand("chmod", "644", "/etc/systemd/system/kubelet.service.d/10-tlsbootstrap.conf"); err != nil {
		return fmt.Errorf("failed to set TLS bootstrap config file permissions: %w", err)
	}

	// Create kubelet kubeconfig
	kubeconfigPath := filepath.Join(b.config.Paths.Kubernetes.KubeletDir, "kubeconfig")

	// Try to create kubeconfig from downloaded admin kubeconfig
	adminKubeconfigPath := filepath.Join(b.config.Paths.Kubernetes.ConfigDir, "admin.conf")
	if err := b.createKubeletKubeconfigFromAdmin(adminKubeconfigPath, kubeconfigPath, tokenPath); err != nil {
		b.logger.Warnf("Failed to create kubelet kubeconfig from admin kubeconfig: %v", err)
		b.logger.Info("Kubelet will attempt to bootstrap TLS certificates on first run")
	}

	// Create Azure configuration file
	if err := b.createAzureConfig(); err != nil {
		return fmt.Errorf("failed to create Azure config: %w", err)
	}

	// Reload systemd to pick up the TLS bootstrap configuration changes
	b.logger.Info("Reloading systemd to pick up TLS bootstrap configuration changes")
	if err := utils.RunSystemCommand("systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("failed to reload systemd after TLS bootstrap configuration: %w", err)
	}

	// Restart kubelet to pick up the new kubeconfig file
	b.logger.Info("Restarting kubelet to pick up new kubeconfig")
	if err := utils.RunSystemCommand("systemctl", "restart", "kubelet"); err != nil {
		b.logger.Warnf("Failed to restart kubelet: %v", err)
		// Don't fail the step, just warn - kubelet will be started in services_enabled step
	}

	return nil
}

func (b *Bootstrapper) createAzureConfig() error {
	b.logger.Info("Creating Azure configuration file")

	// Create empty Azure configuration file (like in the reference script)
	// This file is typically populated with Azure-specific configuration
	// but can start empty for Arc-based authentication
	azureJSONPath := "/etc/kubernetes/azure.json"

	// Create the file with proper permissions using sudo-aware approach
	tempAzureFile, err := utils.CreateTempFile("azure-json-*", []byte(""))
	if err != nil {
		return fmt.Errorf("failed to create temporary azure.json file: %w", err)
	}
	defer utils.CleanupTempFile(tempAzureFile.Name())

	// Copy the temp file to the final location using sudo
	if err := utils.RunSystemCommand("cp", tempAzureFile.Name(), azureJSONPath); err != nil {
		return fmt.Errorf("failed to create azure.json file: %w", err)
	}

	// Set proper permissions (restricted access)
	if err := utils.RunSystemCommand("chmod", "600", azureJSONPath); err != nil {
		return fmt.Errorf("failed to set azure.json file permissions: %w", err)
	}

	// Set proper ownership to root using sudo
	if err := utils.RunSystemCommand("chown", "root:root", azureJSONPath); err != nil {
		return fmt.Errorf("failed to set ownership on azure.json: %w", err)
	}

	b.logger.Infof("Created Azure configuration file at %s", azureJSONPath)
	return nil
}

// createKubeletKubeconfigFromAdmin creates a kubelet kubeconfig by extracting cluster info from admin kubeconfig
func (b *Bootstrapper) createKubeletKubeconfigFromAdmin(adminKubeconfigPath, kubeletKubeconfigPath, tokenPath string) error {
	b.logger.Info("Creating kubelet kubeconfig from admin kubeconfig")

	// Parse admin kubeconfig and extract cluster information
	clusterInfo, err := b.parseAdminKubeconfigClusterInfo(adminKubeconfigPath)
	if err != nil {
		return err
	}

	// Install CA certificate
	caCertPath, err := b.installClusterCACertificate(clusterInfo.CertificateAuthorityData)
	if err != nil {
		return err
	}

	// Create kubelet kubeconfig file
	if err := b.createKubeletKubeconfigFile(clusterInfo.Server, caCertPath, tokenPath, kubeletKubeconfigPath); err != nil {
		return err
	}

	b.logger.Infof("Created kubelet kubeconfig at %s", kubeletKubeconfigPath)
	return nil
}

// ClusterInfo holds cluster configuration details
type ClusterInfo struct {
	Server                   string
	CertificateAuthorityData string
}

// parseAdminKubeconfigClusterInfo extracts cluster information from admin kubeconfig
func (b *Bootstrapper) parseAdminKubeconfigClusterInfo(adminKubeconfigPath string) (*ClusterInfo, error) {
	// Check if admin kubeconfig exists
	if _, err := os.Stat(adminKubeconfigPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("admin kubeconfig not found at %s", adminKubeconfigPath)
	}

	// Read and parse the admin kubeconfig using sudo-aware approach
	adminKubeconfigDataBytes, err := utils.RunCommandWithOutput("cat", adminKubeconfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read admin kubeconfig: %w", err)
	}
	adminKubeconfigData := []byte(adminKubeconfigDataBytes)

	// Parse the kubeconfig to extract cluster information
	var adminConfig struct {
		APIVersion string `yaml:"apiVersion"`
		Clusters   []struct {
			Name    string `yaml:"name"`
			Cluster struct {
				Server                   string `yaml:"server"`
				CertificateAuthorityData string `yaml:"certificate-authority-data"`
			} `yaml:"cluster"`
		} `yaml:"clusters"`
	}

	if err := yaml.Unmarshal(adminKubeconfigData, &adminConfig); err != nil {
		return nil, fmt.Errorf("failed to parse admin kubeconfig: %w", err)
	}

	if len(adminConfig.Clusters) == 0 {
		return nil, fmt.Errorf("no clusters found in admin kubeconfig")
	}

	cluster := adminConfig.Clusters[0]
	if cluster.Cluster.Server == "" {
		return nil, fmt.Errorf("no server URL found in admin kubeconfig")
	}

	return &ClusterInfo{
		Server:                   cluster.Cluster.Server,
		CertificateAuthorityData: cluster.Cluster.CertificateAuthorityData,
	}, nil
}

// installClusterCACertificate installs the cluster CA certificate and returns its path
func (b *Bootstrapper) installClusterCACertificate(certAuthorityData string) (string, error) {
	var caCertPath string

	if certAuthorityData != "" {
		caCertData, err := base64.StdEncoding.DecodeString(certAuthorityData)
		if err != nil {
			return "", fmt.Errorf("failed to decode certificate authority data: %w", err)
		}

		caCertPath = filepath.Join(b.config.Paths.Kubernetes.CertsDir, "ca.crt")
		tempCACertFile, err := utils.CreateTempFile("ca-cert-*", caCertData)
		if err != nil {
			return "", fmt.Errorf("failed to create temporary CA cert file: %w", err)
		}
		defer utils.CleanupTempFile(tempCACertFile.Name())
		defer tempCACertFile.Close()

		// Copy the CA cert to the final location
		if err := utils.RunSystemCommand("cp", tempCACertFile.Name(), caCertPath); err != nil {
			return "", fmt.Errorf("failed to install CA certificate: %w", err)
		}

		// Set proper permissions
		if err := utils.RunSystemCommand("chmod", "644", caCertPath); err != nil {
			return "", fmt.Errorf("failed to set CA certificate permissions: %w", err)
		}
	} else {
		caCertPath = "/etc/ssl/certs/ca-certificates.crt" // fallback to system CA bundle
	}

	return caCertPath, nil
}

// createKubeletKubeconfigFile creates the kubelet kubeconfig file with exec authentication
func (b *Bootstrapper) createKubeletKubeconfigFile(serverURL, caCertPath, tokenPath, kubeletKubeconfigPath string) error {
	// Create kubelet kubeconfig with exec authentication
	kubeconfig := fmt.Sprintf(`apiVersion: v1
clusters:
- cluster:
    certificate-authority: %s
    server: %s
  name: default-cluster
contexts:
- context:
    cluster: default-cluster
    namespace: default
    user: default-auth
  name: default-context
current-context: default-context
kind: Config
preferences: {}
users:
- name: default-auth
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      command: %s
      env: null
      provideClusterInfo: false`,
		caCertPath,
		serverURL,
		tokenPath)

	// Create kubeconfig file using sudo-aware approach
	tempKubeconfigFile, err := utils.CreateTempFile("kubeconfig-*", []byte(kubeconfig))
	if err != nil {
		return fmt.Errorf("failed to create temporary kubeconfig file: %w", err)
	}
	defer utils.CleanupTempFile(tempKubeconfigFile.Name())

	// Copy the temp file to the final location using sudo
	if err := utils.RunSystemCommand("cp", tempKubeconfigFile.Name(), kubeletKubeconfigPath); err != nil {
		return fmt.Errorf("failed to install kubeconfig file: %w", err)
	}

	// Set proper permissions (restricted access)
	if err := utils.RunSystemCommand("chmod", "600", kubeletKubeconfigPath); err != nil {
		return fmt.Errorf("failed to set kubeconfig file permissions: %w", err)
	}

	return nil
}

func (b *Bootstrapper) enableServices(ctx context.Context) error {
	b.logger.Info("Enabling and starting services")

	// Reload systemd
	if err := utils.RunSystemCommand("systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("failed to reload systemd: %w", err)
	}

	// Enable and start containerd
	if err := utils.RunSystemCommand("systemctl", "enable", "--now", "containerd"); err != nil {
		return fmt.Errorf("failed to enable containerd: %w", err)
	}

	// Enable and start kubelet
	if err := utils.RunSystemCommand("systemctl", "enable", "--now", "kubelet"); err != nil {
		return fmt.Errorf("failed to enable kubelet: %w", err)
	}

	// Wait for kubelet to start and validate it's running properly
	b.logger.Info("Waiting for kubelet to start...")
	if err := utils.WaitForService("kubelet", 30*time.Second, b.logger); err != nil {
		return fmt.Errorf("kubelet failed to start properly: %w", err)
	}

	b.logger.Info("Kubelet started successfully")
	return nil
}

// downloadClusterCredentials downloads cluster credentials from Azure and updates configuration
func (b *Bootstrapper) downloadClusterCredentials(ctx context.Context) error {
	b.logger.Info("Downloading cluster credentials from Azure")

	// Get target cluster info from configuration
	clusterInfo, err := b.arcManager.GetConnectedClusterInfoFromAzure(ctx)
	if err != nil {
		return fmt.Errorf("failed to get target cluster info: %w", err)
	}

	b.logger.Infof("Downloading credentials for cluster: %s in resource group: %s",
		clusterInfo.Name, clusterInfo.ResourceGroup)

	// Download cluster credentials
	if err := b.GetAKSClusterCredentials(ctx, clusterInfo); err != nil {
		return fmt.Errorf("failed to download cluster credentials: %w", err)
	}

	b.logger.Infof("Successfully downloaded cluster credentials")
	return nil
}

// GetAKSClusterCredentials retrieves AKS cluster credentials
func (b *Bootstrapper) GetAKSClusterCredentials(ctx context.Context, clusterInfo *aks.ClusterInfo) error {
	b.logger.Infof("Getting credentials for AKS cluster: %s", clusterInfo.Name)

	// Get management token
	token, err := b.arcManager.GetArcManagedIdentityToken(ctx)
	if err != nil {
		return fmt.Errorf("failed to get management token: %w", err)
	}

	// Fetch cluster credentials from Azure
	kubeconfigData, err := b.fetchClusterCredentials(ctx, token, clusterInfo.ID)
	if err != nil {
		return err
	}

	// Save kubeconfig to file
	if err := b.saveKubeconfigFile(kubeconfigData); err != nil {
		return err
	}

	b.logger.Infof("Cluster credentials saved successfully")
	return nil
}

// fetchClusterCredentials retrieves cluster credentials from Azure API
func (b *Bootstrapper) fetchClusterCredentials(ctx context.Context, token, clusterID string) ([]byte, error) {
	url := fmt.Sprintf("https://management.azure.com%s/listClusterAdminCredential?api-version=2023-10-01", clusterID)

	client := &http.Client{Timeout: 60 * time.Second}
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get cluster credentials: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get cluster credentials, status: %d, body: %s", resp.StatusCode, string(body))
	}

	var response struct {
		Kubeconfigs []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"kubeconfigs"`
	}

	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to parse credentials response: %w", err)
	}

	if len(response.Kubeconfigs) == 0 {
		return nil, fmt.Errorf("no kubeconfig found in response")
	}

	// Decode base64 kubeconfig content
	kubeconfigData, err := base64.StdEncoding.DecodeString(response.Kubeconfigs[0].Value)
	if err != nil {
		return nil, fmt.Errorf("failed to decode kubeconfig: %w", err)
	}

	return kubeconfigData, nil
}

// saveKubeconfigFile saves the kubeconfig data to the admin.conf file
func (b *Bootstrapper) saveKubeconfigFile(kubeconfigData []byte) error {
	kubeconfigPath := filepath.Join(b.config.Paths.Kubernetes.ConfigDir, "admin.conf")

	// Ensure the kubernetes config directory exists
	if err := utils.RunSystemCommand("mkdir", "-p", b.config.Paths.Kubernetes.ConfigDir); err != nil {
		return fmt.Errorf("failed to create kubernetes config directory: %w", err)
	}

	// Write kubeconfig using a temporary file and sudo to handle permissions
	tempFile, err := utils.CreateTempFile("kubeconfig-*.conf", kubeconfigData)
	if err != nil {
		return fmt.Errorf("failed to create temporary kubeconfig file: %w", err)
	}
	defer utils.CleanupTempFile(tempFile.Name())
	defer tempFile.Close()

	// Copy the temporary file to the final location with proper permissions
	if err := utils.RunSystemCommand("cp", tempFile.Name(), kubeconfigPath); err != nil {
		return fmt.Errorf("failed to copy kubeconfig to final location: %w", err)
	}

	// Set proper ownership and permissions
	if err := utils.RunSystemCommand("chmod", "600", kubeconfigPath); err != nil {
		return fmt.Errorf("failed to set kubeconfig permissions: %w", err)
	}

	return nil
}

// GetBootstrapStatus returns the current bootstrap status with real-time checks
func (b *Bootstrapper) GetBootstrapStatus(ctx context.Context) (*state.BootstrapState, error) {
	// Load saved state
	bootstrapState, err := b.stateManager.LoadState()
	if err != nil {
		return nil, err
	}

	// Check real-time Arc registration status
	bootstrapState.ArcRegistered = b.checkRealTimeArcStatus(ctx)

	// Check real-time VPN connection status
	bootstrapState.VPNConnected = b.vpnManager.IsVPNConnected()

	// Check real-time Kubelet service status
	bootstrapState.KubeletRunning = b.checkKubeletStatus()

	return bootstrapState, nil
}

// IsBootstrapCompleted checks if bootstrap has been completed and kubelet is healthy
func (b *Bootstrapper) IsBootstrapCompleted() (bool, error) {
	currentState, err := b.stateManager.LoadState()
	if err != nil {
		return false, err
	}

	// First check if bootstrap was marked as completed
	bootstrapMarkedComplete := b.stateManager.IsStepCompleted(currentState, "bootstrap_completed")
	if !bootstrapMarkedComplete {
		return false, nil
	}

	// Also verify that kubelet is actually running and healthy
	if !b.isKubeletHealthy() {
		b.logger.Warn("Bootstrap was marked complete but kubelet is not healthy - will re-run bootstrap")
		return false, nil
	}

	return true, nil
}

// isKubeletHealthy checks if kubelet service is running and healthy
func (b *Bootstrapper) isKubeletHealthy() bool {
	// First check if the kubelet configuration is valid
	if !b.isKubeletConfigurationValid() {
		b.logger.Warn("Kubelet configuration is invalid, will regenerate")
		return false
	}

	// Check if kubelet service is active
	cmd := utils.RunSystemCommand("systemctl", "is-active", "kubelet")
	if cmd != nil {
		b.logger.Debugf("Kubelet service is not active: %v", cmd)
		return false
	}

	// Check if kubelet is actually running (not just enabled but failed)
	cmd = utils.RunSystemCommand("systemctl", "is-failed", "kubelet")
	if cmd == nil {
		// If is-failed returns 0, the service is in failed state
		b.logger.Debug("Kubelet service is in failed state")
		return false
	}

	return true
}

// isKubeletConfigurationValid checks if the kubelet configuration has valid values
func (b *Bootstrapper) isKubeletConfigurationValid() bool {
	// Check if admin kubeconfig file exists (required for kubelet kubeconfig generation)
	adminKubeconfigPath := filepath.Join(b.config.Paths.Kubernetes.ConfigDir, "admin.conf")
	if _, err := os.Stat(adminKubeconfigPath); os.IsNotExist(err) {
		b.logger.Warnf("Admin kubeconfig file missing: %s", adminKubeconfigPath)
		// Reset both cluster credentials and arc auth setup steps
		if err := b.resetClusterCredentialsAndArcAuthState(); err != nil {
			b.logger.Errorf("Failed to reset states: %v", err)
		}
		return false
	}

	// Check if kubelet kubeconfig file exists (created by arc_auth_setup step)
	kubeletKubeconfigPath := "/var/lib/kubelet/kubeconfig"
	if _, err := os.Stat(kubeletKubeconfigPath); os.IsNotExist(err) {
		b.logger.Warnf("Kubelet kubeconfig file missing: %s", kubeletKubeconfigPath)
		// Reset the arc_auth_setup state to force regeneration
		if err := b.resetArcAuthSetupState(); err != nil {
			b.logger.Errorf("Failed to reset arc_auth_setup state: %v", err)
		}
		return false
	}

	// Check if kubelet configuration file exists and has valid image GC thresholds
	kubeletDefaultsPath := "/etc/default/kubelet"

	// Use utils.RunCommandWithOutput to read the file content with proper permissions
	output, err := utils.RunCommandWithOutput("cat", kubeletDefaultsPath)
	if err != nil {
		b.logger.Debugf("Cannot read kubelet configuration file %s: %v", kubeletDefaultsPath, err)
		// Reset the kubelet_configured state to force regeneration of config files
		if err := b.resetKubeletConfiguredState(); err != nil {
			b.logger.Errorf("Failed to reset kubelet_configured state: %v", err)
		}
		return false
	}

	configContent := string(output)

	// Check for the invalid configuration pattern (both thresholds = 0)
	if strings.Contains(configContent, "--image-gc-high-threshold=0") &&
		strings.Contains(configContent, "--image-gc-low-threshold=0") {
		b.logger.Warn("Detected invalid kubelet configuration: both image GC thresholds are 0")
		// Reset the kubelet_configured state to force regeneration
		if err := b.resetKubeletConfiguredState(); err != nil {
			b.logger.Errorf("Failed to reset kubelet_configured state: %v", err)
		}
		return false
	}

	return true
}

// resetKubeletConfiguredState resets the kubelet_configured step to force regeneration
func (b *Bootstrapper) resetKubeletConfiguredState() error {
	currentState, err := b.stateManager.LoadState()
	if err != nil {
		return fmt.Errorf("failed to load state: %w", err)
	}

	// Remove the kubelet_configured step from completed steps
	if currentState.CompletedSteps != nil {
		delete(currentState.CompletedSteps, "kubelet_configured")
		b.logger.Info("Reset kubelet_configured state - will regenerate kubelet configuration")
	}

	// Save the updated state
	return b.stateManager.SaveState(currentState)
}

// resetClusterCredentialsAndKubeletState resets both cluster_credentials_downloaded and kubelet_configured steps
func (b *Bootstrapper) resetClusterCredentialsAndKubeletState() error {
	currentState, err := b.stateManager.LoadState()
	if err != nil {
		return fmt.Errorf("failed to load state: %w", err)
	}

	// Remove both steps from completed steps to force regeneration
	if currentState.CompletedSteps != nil {
		delete(currentState.CompletedSteps, "cluster_credentials_downloaded")
		delete(currentState.CompletedSteps, "kubelet_configured")
		b.logger.Info("Reset cluster_credentials_downloaded and kubelet_configured states - will re-download credentials and regenerate kubelet configuration")
	}

	// Save the updated state
	return b.stateManager.SaveState(currentState)
}

// resetClusterCredentialsAndArcAuthState resets cluster_credentials_downloaded and arc_auth_setup steps
func (b *Bootstrapper) resetClusterCredentialsAndArcAuthState() error {
	currentState, err := b.stateManager.LoadState()
	if err != nil {
		return fmt.Errorf("failed to load state: %w", err)
	}

	// Remove both steps from completed steps to force regeneration
	if currentState.CompletedSteps != nil {
		delete(currentState.CompletedSteps, "cluster_credentials_downloaded")
		delete(currentState.CompletedSteps, "arc_auth_setup")
		b.logger.Info("Reset cluster_credentials_downloaded and arc_auth_setup states - will re-download credentials and regenerate arc authentication")
	}

	// Save the updated state
	return b.stateManager.SaveState(currentState)
}

// resetArcAuthSetupState resets the arc_auth_setup step to force regeneration
func (b *Bootstrapper) resetArcAuthSetupState() error {
	currentState, err := b.stateManager.LoadState()
	if err != nil {
		return fmt.Errorf("failed to load state: %w", err)
	}

	// Remove the arc_auth_setup step from completed steps
	if currentState.CompletedSteps != nil {
		delete(currentState.CompletedSteps, "arc_auth_setup")
		b.logger.Info("Reset arc_auth_setup state - will regenerate arc authentication and kubelet kubeconfig")
	}

	// Save the updated state
	return b.stateManager.SaveState(currentState)
}

// isStepActuallyValid checks if a bootstrap step is actually completed properly
func (b *Bootstrapper) isStepActuallyValid(stepName string) bool {
	switch stepName {
	case "cluster_credentials_downloaded":
		// Check if admin kubeconfig file exists
		adminKubeconfigPath := filepath.Join(b.config.Paths.Kubernetes.ConfigDir, "admin.conf")
		b.logger.Warnf("Checking admin kubeconfig for step %s at path: %s", stepName, adminKubeconfigPath)
		if _, err := os.Stat(adminKubeconfigPath); os.IsNotExist(err) {
			b.logger.Warnf("Admin kubeconfig missing for step %s: %s", stepName, adminKubeconfigPath)
			return false
		}
		b.logger.Debugf("Admin kubeconfig exists for step %s: %s", stepName, adminKubeconfigPath)
		return true

	case "kubelet_configured":
		// Check kubelet configuration files (NOT kubeconfig - that's created in arc_auth_setup)
		// Check kubelet defaults file
		kubeletDefaultsPath := "/etc/default/kubelet"
		if _, err := os.Stat(kubeletDefaultsPath); os.IsNotExist(err) {
			b.logger.Warnf("Kubelet defaults file missing for step %s: %s", stepName, kubeletDefaultsPath)
			return false
		}

		// Check kubelet service file
		kubeletServicePath := "/etc/systemd/system/kubelet.service"
		if _, err := os.Stat(kubeletServicePath); os.IsNotExist(err) {
			b.logger.Warnf("Kubelet service file missing for step %s: %s", stepName, kubeletServicePath)
			return false
		}

		// Also check for invalid kubelet configuration patterns
		return b.isKubeletConfigurationValidForStep()

	case "arc_auth_setup":
		// Check if kubelet kubeconfig file exists (created by this step)
		kubeletKubeconfigPath := "/var/lib/kubelet/kubeconfig"
		if _, err := os.Stat(kubeletKubeconfigPath); os.IsNotExist(err) {
			b.logger.Warnf("Kubelet kubeconfig missing for step %s: %s", stepName, kubeletKubeconfigPath)
			return false
		}

		// Check if token script exists
		tokenPath := filepath.Join(b.config.Paths.Kubernetes.KubeletDir, "token.sh")
		if _, err := os.Stat(tokenPath); os.IsNotExist(err) {
			b.logger.Warnf("Token script missing for step %s: %s", stepName, tokenPath)
			return false
		}

		return true

	default:
		// For other steps, we assume they're valid if marked complete
		b.logger.Debugf("Step %s assumed valid (no specific validation)", stepName)
		return true
	}
}

// isKubeletConfigurationValidForStep checks kubelet config without file existence checks (used by step validation)
func (b *Bootstrapper) isKubeletConfigurationValidForStep() bool {
	kubeletDefaultsPath := "/etc/default/kubelet"

	// Use utils.RunCommandWithOutput to read the file content with proper permissions
	output, err := utils.RunCommandWithOutput("cat", kubeletDefaultsPath)
	if err != nil {
		b.logger.Debugf("Cannot read kubelet configuration file %s: %v", kubeletDefaultsPath, err)
		return false
	}

	configContent := string(output)

	// Check for the invalid configuration pattern (both thresholds = 0)
	if strings.Contains(configContent, "--image-gc-high-threshold=0") &&
		strings.Contains(configContent, "--image-gc-low-threshold=0") {
		b.logger.Debugf("Detected invalid kubelet configuration: both image GC thresholds are 0")
		return false
	}

	return true
}

// checkRealTimeArcStatus checks the actual current Arc registration status
func (b *Bootstrapper) checkRealTimeArcStatus(ctx context.Context) bool {
	// First check if Arc agent is running
	if !b.arcManager.IsArcAgentRunning() {
		b.logger.Debug("Arc agent is not running")
		return false
	}

	// Try to get Arc machine info to verify registration
	_, err := b.arcManager.GetArcMachineInfo(ctx)
	if err != nil {
		b.logger.Debugf("Failed to get Arc machine info: %v", err)
		return false
	}

	return true
}

// checkKubeletStatus checks if the kubelet service is currently active
func (b *Bootstrapper) checkKubeletStatus() bool {
	// Check if kubelet service is active using systemctl
	return utils.IsServiceActive("kubelet")
}

// Reset removes all bootstrap configuration with state cleanup
func (b *Bootstrapper) Reset(ctx context.Context) error {
	b.logger.Info("Starting idempotent reset...")

	// Load current state to understand what needs cleanup
	currentState, err := b.stateManager.LoadState()
	if err != nil {
		b.logger.Warnf("Could not load state for reset: %v", err)
		// Continue with reset anyway
	} else if len(currentState.CompletedSteps) > 0 {
		b.logger.Infof("Found %d completed steps to reset", len(currentState.CompletedSteps))
	}

	// Perform reset operations in logical order
	b.logger.Info("Resetting node configuration")

	// Step 1: Clean up cluster-side resources (RBAC, node registration)
	b.logger.Info("Cleaning up cluster resources...")
	b.cleanupClusterResources(ctx)

	// Step 2: Stop services and disconnect external connections
	b.resetServicesAndConnections()

	// Step 3: Remove files and directories
	b.cleanupFilesAndDirectories()

	// Step 4: Reset network and system configurations
	b.resetNetworkAndSystemConfig()

	// Clear the state file
	if err := b.stateManager.ClearState(); err != nil {
		return fmt.Errorf("failed to clear state: %w", err)
	}

	b.logger.Info("Complete node reset completed - Arc disconnected, cluster credentials removed, all services cleaned up")
	return nil
}

// resetServicesAndConnections stops services and disconnects external connections
func (b *Bootstrapper) resetServicesAndConnections() {
	// Disconnect from Azure Arc (if registered)
	b.logger.Info("Disconnecting from Azure Arc...")
	utils.RunCleanupCommand("azcmagent", "disconnect", "--force-local-only")

	// Stop VPN connections (if any)
	b.logger.Info("Stopping VPN connections...")
	utils.RunCleanupCommand("systemctl", "stop", "openvpn@vpnconfig")
	utils.RunCleanupCommand("systemctl", "disable", "openvpn@vpnconfig")

	// Stop and disable services
	b.logger.Info("Stopping Kubernetes services...")
	utils.RunCleanupCommand("systemctl", "stop", "kubelet")
	utils.RunCleanupCommand("systemctl", "stop", "containerd")
	utils.RunCleanupCommand("systemctl", "disable", "kubelet")
	utils.RunCleanupCommand("systemctl", "disable", "containerd")
}

// cleanupFilesAndDirectories removes configuration files, binaries, and directories
func (b *Bootstrapper) cleanupFilesAndDirectories() {
	// Remove configuration files
	b.logger.Info("Removing configuration files...")
	b.removeConfigurationFiles()

	// Remove binaries
	b.logger.Info("Removing binaries...")
	b.removeBinaries()

	// Clean up directories
	b.logger.Info("Cleaning up directories...")
	b.cleanupDirectories()

	// Clean up user configurations
	b.logger.Info("Cleaning up user configurations...")
	b.cleanupUserConfigurations()

	// Remove certificates and CNI configurations
	b.cleanupCertificatesAndCNI()
}

// removeConfigurationFiles removes systemd services and configuration files
func (b *Bootstrapper) removeConfigurationFiles() {
	filesToRemove := []string{
		// Systemd service files
		"/etc/systemd/system/kubelet.service",
		"/etc/systemd/system/containerd.service",
		"/etc/systemd/system/kubelet.service.d/10-containerd.conf",
		"/etc/systemd/system/kubelet.service.d/10-tlsbootstrap.conf",
		"/etc/default/kubelet",
		// Container runtime configs
		"/etc/containerd/config.toml",
		"/etc/containerd/kubenet_template.conf",
		// System configuration
		"/etc/sysctl.d/999-sysctl-aks.conf",
		// Cluster credentials and certificates
		"/etc/kubernetes/certs/ca.crt",
		"/etc/kubernetes/admin.conf",
		"/etc/kubernetes/arc.conf",
		"/etc/kubernetes/config",
		"/etc/kubernetes/azure.json",
		// VPN configurations
		"/etc/openvpn/vpnconfig.conf",
		"/etc/openvpn/client.conf",
		// aks-flex-node configuration
		"/etc/aks-flex-node/config.yaml",
	}

	for _, file := range filesToRemove {
		utils.RunCleanupCommand("rm", "-f", file)
	}
}

// removeBinaries removes installed Kubernetes and container runtime binaries
func (b *Bootstrapper) removeBinaries() {
	binariesToRemove := []string{
		"/usr/local/bin/kubelet",
		"/usr/local/bin/kubectl",
		"/usr/local/bin/kubeadm",
		"/usr/bin/containerd",
		"/usr/bin/runc",
	}

	for _, binary := range binariesToRemove {
		utils.RunCleanupCommand("rm", "-f", binary)
	}
}

// cleanupDirectories removes bootstrap-related directories
func (b *Bootstrapper) cleanupDirectories() {
	dirsToClean := []string{
		b.config.Paths.Kubernetes.KubeletDir,
		b.config.Paths.Kubernetes.ManifestsDir,
		b.config.Paths.Kubernetes.ConfigDir,
		"/etc/containerd",
		"/etc/systemd/system/kubelet.service.d",
		"/etc/kubernetes/certs",
		"/var/lib/etcd",
		"/var/lib/dockershim",
		"/var/lib/cni",
		"/var/run/secrets/kubernetes.io",
		"/opt/cni",
		// aks-flex-node directories
		"/etc/aks-flex-node",
		b.config.Paths.DataDir,
	}

	for _, dir := range dirsToClean {
		utils.RunCleanupCommand("rm", "-rf", dir)
	}
}

// cleanupUserConfigurations removes user-specific configurations
func (b *Bootstrapper) cleanupUserConfigurations() {
	homeDir := os.Getenv("HOME")
	if homeDir != "" {
		userKubeDir := filepath.Join(homeDir, ".kube")
		utils.RunCleanupCommand("rm", "-rf", userKubeDir)
	}
}

// cleanupCertificatesAndCNI removes VPN certificates and CNI configurations
func (b *Bootstrapper) cleanupCertificatesAndCNI() {
	// Remove VPN certificates (if any)
	utils.RunCleanupCommand("rm", "-rf", "/etc/openvpn/certs")
	utils.RunCleanupCommand("rm", "-rf", "/etc/openvpn/keys")
	// Remove VPN certificates from data directory
	certDir := filepath.Join(b.config.Paths.DataDir, "certs")
	utils.RunCleanupCommand("rm", "-rf", certDir)

	// Clean up CNI configurations
	utils.RunCleanupCommand("rm", "-rf", "/etc/cni/net.d")
}

// resetNetworkAndSystemConfig resets network interfaces and system configurations
func (b *Bootstrapper) resetNetworkAndSystemConfig() {
	// Reset network interfaces (remove any bridge configurations)
	b.logger.Info("Resetting network configurations...")
	utils.RunCleanupCommand("ip", "link", "delete", "cbr0")
	utils.RunCleanupCommand("ip", "link", "delete", "docker0")

	// Reload systemd and reset
	utils.RunCleanupCommand("systemctl", "daemon-reload")
	utils.RunCleanupCommand("systemctl", "reset-failed")

	// Restore original sysctl settings
	b.logger.Info("Restoring system settings...")
	utils.RunCleanupCommand("sysctl", "--system")
}

// cleanupClusterResources removes cluster-side resources like RBAC bindings and node registration
func (b *Bootstrapper) cleanupClusterResources(ctx context.Context) {
	b.logger.Info("Attempting to clean up cluster-side resources")

	// Step 1: Clean up Azure RBAC role assignments for the Arc machine
	b.cleanupAzureRBACAssignments(ctx)

	// Step 2: Delete the Arc machine from Azure
	b.deleteArcMachine(ctx)

	// Step 3: Clean up Kubernetes cluster resources
	// Get the node name (hostname)
	hostname, err := os.Hostname()
	if err != nil {
		b.logger.Warnf("Failed to get hostname for cluster cleanup: %v", err)
		return
	}

	// Try to delete the node from the cluster (requires admin kubeconfig)
	adminKubeconfig := "/etc/kubernetes/admin.conf"
	if utils.FileExists(adminKubeconfig) {
		b.logger.Infof("Removing node '%s' from cluster", hostname)
		utils.RunCleanupCommand("kubectl", "--kubeconfig", adminKubeconfig, "delete", "node", hostname)

		// Clean up any cluster role bindings for this Arc machine
		// The Arc machine identity is typically system:node:<hostname>
		arcIdentity := fmt.Sprintf("system:node:%s", hostname)
		b.logger.Infof("Removing cluster role bindings for Arc identity: %s", arcIdentity)

		// Remove common Arc-related cluster role bindings
		arcRoleBindings := []string{
			"aks-node-reader",
			"aks-node-writer",
			"system:node-bootstrapper",
			"system:certificates.k8s.io:certificatesigningrequests:nodeclient",
		}

		for _, roleBinding := range arcRoleBindings {
			utils.RunCleanupCommand("kubectl", "--kubeconfig", adminKubeconfig, "delete", "clusterrolebinding",
				fmt.Sprintf("%s-%s", roleBinding, hostname))
		}

		// Also try to remove any namespace-specific role bindings in kube-system
		utils.RunCleanupCommand("kubectl", "--kubeconfig", adminKubeconfig, "delete", "rolebinding",
			"-n", "kube-system", fmt.Sprintf("arc-node-%s", hostname))
	} else {
		b.logger.Warn("Admin kubeconfig not found, skipping Kubernetes cluster cleanup")
		b.logger.Info("To manually clean up, run: kubectl delete node <node-name> from cluster admin")
	}
}

// cleanupAzureRBACAssignments removes Azure RBAC role assignments for the Arc machine using REST API
func (b *Bootstrapper) cleanupAzureRBACAssignments(ctx context.Context) {
	b.logger.Info("Cleaning up Azure RBAC role assignments for Arc machine")

	// First, try Azure CLI approach if available (works even when Arc is disconnected)
	if b.tryAzureCLIRBACCleanup(ctx) {
		return
	}

	// Try REST API cleanup approach
	if err := b.cleanupRBACViaRestAPI(ctx); err != nil {
		b.logger.Warnf("REST API cleanup failed: %v", err)
		b.provideManualCleanupInstructions()
	}
}

// cleanupRBACViaRestAPI handles RBAC cleanup using Azure REST API
func (b *Bootstrapper) cleanupRBACViaRestAPI(ctx context.Context) error {
	// Get the Arc machine resource ID (principal ID)
	arcPrincipalID, err := b.getArcPrincipalID(ctx)
	if err != nil {
		return fmt.Errorf("failed to get Arc principal ID: %w", err)
	}

	b.logger.Infof("Removing Azure RBAC assignments for Arc principal: %s", arcPrincipalID)

	// Get management token
	token, err := b.getManagementToken(ctx)
	if err != nil {
		return fmt.Errorf("failed to get management token: %w", err)
	}

	// Build resource scopes for cleanup
	scopes := b.buildAzureResourceScopes()

	// Clean up role assignments at all scopes
	b.cleanupRoleAssignmentsAtScopes(ctx, token, arcPrincipalID, scopes)

	b.logger.Info("Azure RBAC cleanup completed for AKS cluster, MC resource group, and subscription")
	return nil
}

// buildAzureResourceScopes constructs the Azure resource scopes for RBAC cleanup
func (b *Bootstrapper) buildAzureResourceScopes() map[string]string {
	scopes := make(map[string]string)

	// AKS cluster resource ID
	scopes["AKS cluster"] = fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.ContainerService/managedClusters/%s",
		b.config.Azure.SubscriptionID,
		b.config.Azure.ResourceGroup,
		b.config.Azure.Arc.TargetCluster.Name)

	// MC (Managed Cluster) resource group ID
	scopes["MC resource group"] = fmt.Sprintf("/subscriptions/%s/resourceGroups/MC_%s_%s_%s",
		b.config.Azure.SubscriptionID,
		b.config.Azure.ResourceGroup,
		b.config.Azure.Arc.TargetCluster.Name,
		b.config.Azure.Location)

	// Subscription scope (in case assignments were made at subscription level)
	scopes["subscription"] = fmt.Sprintf("/subscriptions/%s", b.config.Azure.SubscriptionID)

	return scopes
}

// cleanupRoleAssignmentsAtScopes removes role assignments at all specified scopes
func (b *Bootstrapper) cleanupRoleAssignmentsAtScopes(ctx context.Context, token, arcPrincipalID string, scopes map[string]string) {
	for scopeType, scopeID := range scopes {
		b.logger.Infof("%s: %s", scopeType, scopeID)
		b.logger.Infof("Cleaning up %s role assignments...", scopeType)
		b.deleteRoleAssignmentsByPrincipal(ctx, token, scopeID, arcPrincipalID)
	}
}

// deleteArcMachine deletes the Arc machine from Azure using REST API
func (b *Bootstrapper) deleteArcMachine(ctx context.Context) {
	b.logger.Info("Deleting Arc machine from Azure")

	// Get the Arc machine resource ID
	arcResourceID, err := b.getArcResourceID()
	if err != nil {
		b.logger.Warnf("Failed to get Arc resource ID: %v", err)
		b.logger.Info("Skipping Arc machine deletion - please manually delete from Azure portal")
		return
	}

	b.logger.Infof("Deleting Arc machine: %s", arcResourceID)

	// Get management token
	token, err := b.getManagementToken(ctx)
	if err != nil {
		b.logger.Warnf("Failed to get management token: %v", err)
		b.logger.Info("Skipping Arc machine deletion - please manually delete from Azure portal")
		return
	}

	// Delete the Arc machine using REST API
	deleteURL := fmt.Sprintf("https://management.azure.com%s?api-version=2023-10-03-preview", arcResourceID)

	req, err := http.NewRequestWithContext(ctx, "DELETE", deleteURL, nil)
	if err != nil {
		b.logger.Warnf("Failed to create Arc machine delete request: %v", err)
		return
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 120 * time.Second} // Longer timeout for deletion
	resp, err := client.Do(req)
	if err != nil {
		b.logger.Warnf("Failed to delete Arc machine: %v", err)
		return
	}
	defer resp.Body.Close()

	// Azure DELETE operations return 200, 202 (accepted), or 204 (no content) for success
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusNoContent {
		b.logger.Info("✓ Arc machine deletion initiated successfully")
		if resp.StatusCode == http.StatusAccepted {
			b.logger.Info("Arc machine deletion is being processed asynchronously")
		}
	} else if resp.StatusCode == http.StatusNotFound {
		b.logger.Info("Arc machine not found (may have been already deleted)")
	} else {
		body, _ := io.ReadAll(resp.Body)
		b.logger.Warnf("Failed to delete Arc machine, status: %d, response: %s", resp.StatusCode, string(body))
		b.logger.Info("Please manually delete the Arc machine from Azure portal")
	}
}

// tryAzureCLIRBACCleanup attempts to clean up RBAC assignments using Azure CLI
func (b *Bootstrapper) tryAzureCLIRBACCleanup(ctx context.Context) bool {
	b.logger.Info("Attempting Azure CLI RBAC cleanup...")

	// Get the hostname to identify the Arc machine
	hostname := b.getHostname()

	// Check if Azure CLI is available and authenticated
	if _, err := utils.RunCommandWithOutput("az", "account", "show"); err != nil {
		b.logger.Debug("Azure CLI not available or not authenticated")
		return false
	}

	// Get the MC resource group name
	mcResourceGroup := fmt.Sprintf("MC_%s_%s_%s",
		b.config.Azure.ResourceGroup,
		b.config.Azure.Arc.TargetCluster.Name,
		b.config.Azure.Location)

	b.logger.Infof("Attempting to remove RBAC assignments for Arc machine '%s' from MC resource group '%s'", hostname, mcResourceGroup)

	// Try to remove role assignments using Azure CLI
	success := false

	// Remove assignments from MC resource group
	cmd := fmt.Sprintf("az role assignment delete --assignee '%s' --resource-group '%s' --output none 2>/dev/null || true", hostname, mcResourceGroup)
	if err := utils.RunSystemCommand("bash", "-c", cmd); err == nil {
		b.logger.Info("✓ Attempted to remove MC resource group role assignments via Azure CLI")
		success = true
	}

	// Also try to remove assignments from AKS cluster
	clusterCmd := fmt.Sprintf("az role assignment delete --assignee '%s' --scope '/subscriptions/%s/resourceGroups/%s/providers/Microsoft.ContainerService/managedClusters/%s' --output none 2>/dev/null || true",
		hostname,
		b.config.Azure.SubscriptionID,
		b.config.Azure.ResourceGroup,
		b.config.Azure.Arc.TargetCluster.Name)
	if err := utils.RunSystemCommand("bash", "-c", clusterCmd); err == nil {
		b.logger.Info("✓ Attempted to remove AKS cluster role assignments via Azure CLI")
		success = true
	}

	// Try to delete the Arc machine itself
	deleteCmd := fmt.Sprintf("az connectedmachine delete --machine-name '%s' --resource-group '%s' --yes --output none 2>/dev/null || true",
		hostname, b.config.Azure.ResourceGroup)
	if err := utils.RunSystemCommand("bash", "-c", deleteCmd); err == nil {
		b.logger.Info("✓ Attempted to delete Arc machine via Azure CLI")
		success = true
	}

	// Clean up VPN Gateway resources if they exist
	b.cleanupVPNGatewayResources(mcResourceGroup)

	if success {
		b.logger.Info("Azure CLI cleanup completed")
	}
	return success
}

// provideManualCleanupInstructions provides instructions for manual cleanup
func (b *Bootstrapper) provideManualCleanupInstructions() {
	hostname := b.getHostname()
	mcResourceGroup := fmt.Sprintf("MC_%s_%s_%s",
		b.config.Azure.ResourceGroup,
		b.config.Azure.Arc.TargetCluster.Name,
		b.config.Azure.Location)

	clusterName := b.config.Azure.Arc.TargetCluster.Name
	vpnGatewayName := fmt.Sprintf("%s-vpn-gateway", clusterName)
	vpnPublicIPName := fmt.Sprintf("%s-vpn-gateway-ip", clusterName)

	b.logger.Info("=== MANUAL CLEANUP REQUIRED ===")
	b.logger.Info("Please manually remove the following Azure resources:")
	b.logger.Infof("1. Arc machine RBAC assignments:")
	b.logger.Infof("   - Go to Azure Portal > Resource Groups > %s", mcResourceGroup)
	b.logger.Infof("   - Click 'Access control (IAM)' > 'Role assignments'")
	b.logger.Infof("   - Find and remove assignments for '%s'", hostname)
	b.logger.Infof("2. Arc machine resource:")
	b.logger.Infof("   - Go to Azure Portal > Resource Groups > %s", b.config.Azure.ResourceGroup)
	b.logger.Infof("   - Find and delete the Arc machine '%s'", hostname)
	b.logger.Infof("3. VPN Gateway resources (if created):")
	b.logger.Infof("   - Go to Azure Portal > Resource Groups > %s", mcResourceGroup)
	b.logger.Infof("   - Delete VPN Gateway '%s' and Public IP '%s'", vpnGatewayName, vpnPublicIPName)
	b.logger.Info("4. Alternative CLI commands:")
	b.logger.Infof("   az role assignment delete --assignee '%s' --resource-group '%s'", hostname, mcResourceGroup)
	b.logger.Infof("   az connectedmachine delete --machine-name '%s' --resource-group '%s' --yes", hostname, b.config.Azure.ResourceGroup)
	b.logger.Infof("   az network vnet-gateway delete --name '%s' --resource-group '%s'", vpnGatewayName, mcResourceGroup)
	b.logger.Infof("   az network public-ip delete --name '%s' --resource-group '%s'", vpnPublicIPName, mcResourceGroup)
	b.logger.Info("================================")
}

// getArcResourceID retrieves the Azure Arc machine resource ID
func (b *Bootstrapper) getArcResourceID() (string, error) {
	// Try to get the Arc resource ID from azcmagent
	output, err := utils.RunCommandWithOutput("azcmagent", "show")
	if err != nil {
		return "", fmt.Errorf("failed to get Arc machine info: %w", err)
	}

	// Parse the JSON output to extract the resource ID
	var arcInfo struct {
		ResourceID string `json:"resourceId"`
	}

	if err := json.Unmarshal([]byte(output), &arcInfo); err != nil {
		b.logger.Warnf("Failed to parse azcmagent output, falling back to constructed resource ID: %v", err)
		// Fallback: construct the resource ID based on configuration
		arcResourceID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.HybridCompute/machines/%s",
			b.config.Azure.SubscriptionID,
			b.config.Azure.ResourceGroup,
			b.getHostname())
		return arcResourceID, nil
	}

	if arcInfo.ResourceID == "" {
		return "", fmt.Errorf("resourceId not found in azcmagent output")
	}

	b.logger.Debugf("Retrieved Arc machine resource ID: %s", arcInfo.ResourceID)
	return arcInfo.ResourceID, nil
}

// getHostname returns the machine hostname, used as Arc machine name
func (b *Bootstrapper) getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}

// setupCNI configures container networking interface
func (b *Bootstrapper) setupCNI(ctx context.Context) error {
	b.logger.Info("Setting up CNI configuration")

	// Setup Cilium CNI
	if err := b.cniManager.SetupCilium(); err != nil {
		return fmt.Errorf("failed to setup Cilium: %w", err)
	}

	// Install CNI plugins (matching reference script version)
	if err := b.cniManager.InstallCNIPlugins("1.5.1"); err != nil {
		return fmt.Errorf("failed to install CNI plugins: %w", err)
	}

	// Create bridge configuration for edge node (compatible with AKS Cilium)
	if err := b.cniManager.CreateBridgeConfig(); err != nil {
		return fmt.Errorf("failed to create bridge config: %w", err)
	}

	return nil
}

// GenerateVPNCertificates generates certificates for VPN connection
func (b *Bootstrapper) GenerateVPNCertificates() (string, error) {
	return b.vpnManager.GenerateCertificates()
}

// getManagementToken retrieves an Azure management token using Arc managed identity
func (b *Bootstrapper) getManagementToken(ctx context.Context) (string, error) {
	// Check if Arc agent is connected first
	output, err := utils.RunCommandWithOutput("azcmagent", "show")
	if err != nil {
		return "", fmt.Errorf("Arc agent not available: %w", err)
	}

	// Check if agent is connected
	if strings.Contains(output, "Agent Status                        : Disconnected") {
		b.logger.Warn("Arc agent is disconnected, cannot get management token via IMDS")
		return "", fmt.Errorf("Arc agent is disconnected")
	}

	// Use the centralized AuthProvider to get management token
	return b.authProvider.GetManagementToken(ctx)
}

// deleteRoleAssignmentsByPrincipal removes all role assignments for a specific principal at a given scope
func (b *Bootstrapper) deleteRoleAssignmentsByPrincipal(ctx context.Context, token, scope, principalID string) {
	b.logger.Infof("Looking for role assignments at scope: %s for principal: %s", scope, principalID)

	// List all role assignments at this scope
	assignments, err := b.listRoleAssignments(ctx, token, scope)
	if err != nil {
		b.logger.Warnf("Failed to list role assignments: %v", err)
		return
	}

	b.logger.Infof("Found %d total role assignments at scope", len(assignments))

	// Delete matching assignments
	b.deleteMatchingRoleAssignments(ctx, token, assignments, principalID)
}

// listRoleAssignments retrieves all role assignments at the given scope
func (b *Bootstrapper) listRoleAssignments(ctx context.Context, token, scope string) ([]RoleAssignment, error) {
	listURL := fmt.Sprintf("https://management.azure.com%s/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01", scope)

	req, err := http.NewRequestWithContext(ctx, "GET", listURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create list request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute list request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("list request failed with status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var listResponse struct {
		Value []RoleAssignment `json:"value"`
	}

	if err := json.Unmarshal(body, &listResponse); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return listResponse.Value, nil
}

// RoleAssignment represents an Azure role assignment
type RoleAssignment struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Properties struct {
		PrincipalID      string `json:"principalId"`
		RoleDefinitionID string `json:"roleDefinitionId"`
	} `json:"properties"`
}

// deleteMatchingRoleAssignments deletes role assignments that match the principal ID
func (b *Bootstrapper) deleteMatchingRoleAssignments(ctx context.Context, token string, assignments []RoleAssignment, principalID string) {
	deletedCount := 0
	matchingAssignments := 0
	client := &http.Client{Timeout: 60 * time.Second}

	for _, assignment := range assignments {
		if assignment.Properties.PrincipalID == principalID {
			matchingAssignments++
			b.logger.Infof("Found matching role assignment: %s (ID: %s, Role: %s)",
				assignment.Name, assignment.ID, assignment.Properties.RoleDefinitionID)

			if b.deleteRoleAssignment(ctx, client, token, assignment) {
				deletedCount++
			}
		}
	}

	if matchingAssignments > 0 {
		b.logger.Infof("Found %d role assignments for Arc machine, successfully deleted %d", matchingAssignments, deletedCount)
	} else {
		b.logger.Info("No role assignments found for the Arc machine at this scope")
	}
}

// deleteRoleAssignment deletes a single role assignment
func (b *Bootstrapper) deleteRoleAssignment(ctx context.Context, client *http.Client, token string, assignment RoleAssignment) bool {
	deleteURL := fmt.Sprintf("https://management.azure.com%s?api-version=2022-04-01", assignment.ID)

	deleteReq, err := http.NewRequestWithContext(ctx, "DELETE", deleteURL, nil)
	if err != nil {
		b.logger.Warnf("Failed to create delete request for assignment %s: %v", assignment.Name, err)
		return false
	}

	deleteReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	deleteResp, err := client.Do(deleteReq)
	if err != nil {
		b.logger.Warnf("Failed to delete role assignment %s: %v", assignment.Name, err)
		return false
	}
	defer deleteResp.Body.Close()

	if deleteResp.StatusCode == http.StatusOK || deleteResp.StatusCode == http.StatusNoContent {
		b.logger.Infof("✓ Deleted role assignment: %s", assignment.Name)
		return true
	}

	deleteBody, _ := io.ReadAll(deleteResp.Body)
	b.logger.Warnf("Failed to delete role assignment %s, status: %d, response: %s",
		assignment.Name, deleteResp.StatusCode, string(deleteBody))
	return false
}

// cleanupVPNGatewayResources removes VPN Gateway and Public IP resources from MC resource group
func (b *Bootstrapper) cleanupVPNGatewayResources(mcResourceGroup string) {
	b.logger.Info("Cleaning up VPN Gateway resources...")

	// VPN Gateway naming pattern from arc.go auto-provisioning:
	// Gateway: {cluster-name}-vpn-gateway
	// Public IP: {cluster-name}-vpn-gateway-ip
	clusterName := b.config.Azure.Arc.TargetCluster.Name
	vpnGatewayName := fmt.Sprintf("%s-vpn-gateway", clusterName)
	vpnPublicIPName := fmt.Sprintf("%s-vpn-gateway-ip", clusterName)

	b.logger.Infof("Attempting to delete VPN Gateway '%s' and Public IP '%s' from resource group '%s'",
		vpnGatewayName, vpnPublicIPName, mcResourceGroup)

	// Delete VPN Gateway (this will take several minutes)
	gatewayDeleteCmd := fmt.Sprintf("az network vnet-gateway delete --name '%s' --resource-group '%s' --output none 2>/dev/null || true",
		vpnGatewayName, mcResourceGroup)

	b.logger.Info("Initiating VPN Gateway deletion (this may take several minutes)...")
	if err := utils.RunSystemCommand("bash", "-c", gatewayDeleteCmd); err == nil {
		b.logger.Info("✓ VPN Gateway deletion initiated")
	} else {
		b.logger.Warnf("Failed to initiate VPN Gateway deletion: %v", err)
	}

	// Delete Public IP
	publicIPDeleteCmd := fmt.Sprintf("az network public-ip delete --name '%s' --resource-group '%s' --output none 2>/dev/null || true",
		vpnPublicIPName, mcResourceGroup)

	if err := utils.RunSystemCommand("bash", "-c", publicIPDeleteCmd); err == nil {
		b.logger.Info("✓ VPN Gateway Public IP deletion initiated")
	} else {
		b.logger.Warnf("Failed to delete VPN Gateway Public IP: %v", err)
	}

	b.logger.Info("VPN Gateway cleanup completed (deletion may continue asynchronously)")
}

// getArcPrincipalID gets the principal ID of the Arc machine from azcmagent
func (b *Bootstrapper) getArcPrincipalID(ctx context.Context) (string, error) {
	// Try to get the Arc principal ID from azcmagent
	output, err := utils.RunCommandWithOutput("azcmagent", "show")
	if err != nil {
		return "", fmt.Errorf("failed to get Arc machine info: %w", err)
	}

	// Parse the JSON output to extract the principal ID
	var arcInfo struct {
		Identity struct {
			PrincipalID string `json:"principalId"`
		} `json:"identity"`
	}

	if err := json.Unmarshal([]byte(output), &arcInfo); err != nil {
		b.logger.Debug("Failed to parse azcmagent JSON output, using alternative method")

		// If JSON parsing fails, try to extract principal ID from text output
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			if strings.Contains(line, "Principal ID") || strings.Contains(line, "principalId") {
				parts := strings.Split(line, ":")
				if len(parts) >= 2 {
					principalID := strings.TrimSpace(parts[1])
					principalID = strings.Trim(principalID, `"`)
					if principalID != "" {
						b.logger.Debugf("Extracted principal ID from text: %s", principalID)
						return principalID, nil
					}
				}
			}
		}
		return "", fmt.Errorf("could not extract principal ID from azcmagent output")
	}

	if arcInfo.Identity.PrincipalID == "" {
		return "", fmt.Errorf("principal ID not found in Arc machine info")
	}

	return arcInfo.Identity.PrincipalID, nil
}
