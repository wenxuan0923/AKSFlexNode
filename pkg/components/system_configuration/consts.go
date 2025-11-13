package system_configuration

const (
	// System directories
	SysctlDir = "/etc/sysctl.d"

	// Configuration file paths
	SysctlConfigPath = "/etc/sysctl.d/999-sysctl-aks.conf"
	ResolvConfPath   = "/etc/resolv.conf"
	ResolvConfSource = "/run/systemd/resolve/resolv.conf"

	// Legacy configuration files to clean up
	LegacySysctlConfig   = "/etc/sysctl.d/99-kubernetes-ci.conf"
	LegacyContainerdConf = "/etc/modules-load.d/containerd.conf"
)
