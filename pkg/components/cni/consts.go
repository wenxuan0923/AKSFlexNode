package cni

const (
	// CNI directories
	DefaultCNIBinDir  = "/opt/cni/bin"
	DefaultCNIConfDir = "/etc/cni/net.d"
	DefaultCNILibDir  = "/var/lib/cni"

	// CNI configuration files
	BridgeConfigFile = "10-bridge.conf"

	// Required CNI plugins
	BridgePlugin    = "bridge"
	HostLocalPlugin = "host-local"
	LoopbackPlugin  = "loopback"
	PortmapPlugin   = "portmap"
	BandwidthPlugin = "bandwidth"
	TuningPlugin    = "tuning"

	// CNI version
	DefaultCNIVersion = "1.5.1"
)
