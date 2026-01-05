package containerd

const (
	systemBinDir               = "/usr/bin"
	defaultContainerdBinaryDir = "/usr/bin/containerd"
	defaultContainerdConfigDir = "/etc/containerd"
	containerdConfigFile       = "/etc/containerd/config.toml"
	containerdServiceFile      = "/etc/systemd/system/containerd.service"
	containerdDataDir          = "/var/lib/containerd"
)

var containerdDirs = []string{
	defaultContainerdConfigDir,
}

var containerdBinaries = []string{
	"ctr",
	"containerd",
	"containerd-shim",
	"containerd-shim-runc-v1",
	"containerd-shim-runc-v2",
	"containerd-stress",
}

var (
	containerdFileName    = "containerd-%s-linux-%s.tar.gz"
	containerdDownloadURL = "https://github.com/containerd/containerd/releases/download/v%s/" + containerdFileName
)
