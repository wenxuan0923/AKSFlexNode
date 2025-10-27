package utils

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// RunCommand executes a system command
func RunCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// sudoCommandLists holds the command lists for sudo determination
var (
	alwaysNeedsSudo = []string{"apt", "apt-get", "systemctl", "mount", "umount", "modprobe", "sysctl", "azcmagent"}
	conditionalSudo = []string{"mkdir", "cp", "chmod", "chown", "mv", "tar", "rm", "bash", "install", "ln", "cat"}
	systemPaths     = []string{"/etc/", "/usr/", "/var/", "/opt/", "/boot/", "/sys/"}
)

// requiresSudoAccess determines if a command needs sudo based on command name and arguments
func requiresSudoAccess(name string, args []string) bool {
	// Check if this command always needs sudo
	for _, sudoCmd := range alwaysNeedsSudo {
		if name == sudoCmd {
			return true
		}
	}

	// Check if this command needs sudo based on the paths involved
	for _, sudoCmd := range conditionalSudo {
		if name == sudoCmd {
			// Check if any argument involves system paths
			for _, arg := range args {
				for _, sysPath := range systemPaths {
					if strings.HasPrefix(arg, sysPath) {
						return true
					}
				}
			}
			break
		}
	}

	return false
}

// createCommand creates an exec.Cmd with appropriate sudo handling
func createCommand(name string, args []string) *exec.Cmd {
	if requiresSudoAccess(name, args) && os.Geteuid() != 0 {
		// Run with sudo, preserving environment for Azure CLI
		allArgs := append([]string{"-E", name}, args...)
		return exec.Command("sudo", allArgs...)
	}
	// Run directly (either doesn't need sudo or already running as root)
	return exec.Command(name, args...)
}

// RunSystemCommand executes a system command with sudo when needed for privileged operations
func RunSystemCommand(name string, args ...string) error {
	cmd := createCommand(name, args)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// RunCommandWithOutput executes a command and returns output with sudo when needed
func RunCommandWithOutput(name string, args ...string) (string, error) {
	cmd := createCommand(name, args)
	output, err := cmd.Output()
	return string(output), err
}

// DownloadFile downloads a file from URL to destination
func DownloadFile(url, destination string) error {
	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 10 * time.Minute,
	}

	// Make request
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download from %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed with status %d for %s", resp.StatusCode, url)
	}

	// Create destination file
	out, err := os.Create(destination)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", destination, err)
	}
	defer out.Close()

	// Copy response body to file
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to write file %s: %w", destination, err)
	}

	return nil
}

// FileExists checks if a file exists
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

// IsServiceActive checks if a systemd service is active
func IsServiceActive(serviceName string) bool {
	output, err := RunCommandWithOutput("systemctl", "is-active", serviceName)
	if err != nil {
		return false
	}
	return strings.TrimSpace(output) == "active"
}

// EnableService enables a systemd service
func EnableService(serviceName string) error {
	return RunSystemCommand("systemctl", "enable", serviceName)
}

// ignorableCleanupErrors defines patterns for errors that should be ignored during cleanup operations
var ignorableCleanupErrors = []string{
	"Unit .* not loaded",
	"Unit file .* does not exist",
	"No such file or directory",
	"cannot remove",
	"cannot stat",
	"Failed to stop .*: Unit .* not loaded",
	"Failed to disable unit: Unit file .* does not exist",
}

// shouldIgnoreCleanupError checks if an error should be ignored during cleanup operations
func shouldIgnoreCleanupError(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()
	for _, pattern := range ignorableCleanupErrors {
		if matched, _ := regexp.MatchString(pattern, errStr); matched {
			return true
		}
	}
	return false
}

// RunCleanupCommand executes a system command with sudo when needed, ignoring common "not found" errors
// This is specifically designed for cleanup operations where missing files/services should not be treated as errors
func RunCleanupCommand(name string, args ...string) {
	cmd := createCommand(name, args)
	cmd.Stdout = os.Stdout
	err := cmd.Run()

	// For cleanup operations, ignore common "not found" type errors
	if err != nil && !shouldIgnoreCleanupError(err) {
		// Only show stderr for actual errors, not "not found" cases
		cmd.Stderr = os.Stderr
	}
}

// CreateTempFile creates a temporary file with given pattern and content
func CreateTempFile(pattern string, content []byte) (*os.File, error) {
	tempFile, err := os.CreateTemp("", pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary file: %w", err)
	}

	if _, err := tempFile.Write(content); err != nil {
		tempFile.Close()
		os.Remove(tempFile.Name())
		return nil, fmt.Errorf("failed to write to temporary file: %w", err)
	}

	if err := tempFile.Close(); err != nil {
		os.Remove(tempFile.Name())
		return nil, fmt.Errorf("failed to close temporary file: %w", err)
	}

	// Reopen for reading
	reopened, err := os.Open(tempFile.Name())
	if err != nil {
		os.Remove(tempFile.Name())
		return nil, fmt.Errorf("failed to reopen temporary file: %w", err)
	}

	return reopened, nil
}

// CleanupTempFile removes a temporary file
func CleanupTempFile(filePath string) {
	if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
		logrus.Warnf("Failed to cleanup temporary file %s: %v", filePath, err)
	}
}

// MapToKeyValuePairs converts a map to key=value pairs joined by separator
func MapToKeyValuePairs(m map[string]string, separator string) string {
	pairs := make([]string, 0, len(m))
	for k, v := range m {
		pairs = append(pairs, fmt.Sprintf("%s=%s", k, v))
	}
	return strings.Join(pairs, separator)
}

// MapToEvictionThresholds converts a map to key<value pairs for kubelet eviction thresholds
func MapToEvictionThresholds(m map[string]string, separator string) string {
	pairs := make([]string, 0, len(m))
	for k, v := range m {
		pairs = append(pairs, fmt.Sprintf("%s<%s", k, v))
	}
	return strings.Join(pairs, separator)
}

// SetupLogger creates a logger with specified level and optional log file
func SetupLogger(level, logFile string) *logrus.Logger {
	logger := logrus.New()

	// Set log level
	logLevel, err := logrus.ParseLevel(level)
	if err != nil {
		logLevel = logrus.InfoLevel
	}
	logger.SetLevel(logLevel)

	// Set log file if specified
	if logFile != "" {
		file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err == nil {
			logger.SetOutput(file)
		}
	}

	return logger
}

// WriteFileAtomic writes data to a file atomically using a temporary file and rename operation
// This prevents partial writes and corruption during system failures
func WriteFileAtomic(filename string, data []byte, perm os.FileMode) error {
	// Create temporary file in the same directory as the target file
	dir := filepath.Dir(filename)
	tmpFile, err := os.CreateTemp(dir, ".tmp-"+filepath.Base(filename)+"-*")
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	}

	tmpPath := tmpFile.Name()
	defer func() {
		tmpFile.Close()
		os.Remove(tmpPath) // Clean up temp file on error
	}()

	// Write data to temporary file
	if _, err := tmpFile.Write(data); err != nil {
		return fmt.Errorf("failed to write to temporary file: %w", err)
	}

	// Ensure data is flushed to disk
	if err := tmpFile.Sync(); err != nil {
		return fmt.Errorf("failed to sync temporary file: %w", err)
	}

	// Close the temporary file
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temporary file: %w", err)
	}

	// Set the correct permissions
	if err := os.Chmod(tmpPath, perm); err != nil {
		return fmt.Errorf("failed to set file permissions: %w", err)
	}

	// Atomic rename to final location
	if err := os.Rename(tmpPath, filename); err != nil {
		return fmt.Errorf("failed to rename temporary file: %w", err)
	}

	return nil
}

// WriteFileAtomicSystem writes data to a file atomically with system-level permissions
// Uses sudo for privileged paths that require elevated permissions
func WriteFileAtomicSystem(filename string, data []byte, perm os.FileMode) error {
	// For system paths, use the temporary file approach with sudo copy/move
	if requiresSudoAccess("cp", []string{filename}) {
		// Create temp file in user-writable location
		tempFile, err := CreateTempFile("atomic-write-*.tmp", data)
		if err != nil {
			return fmt.Errorf("failed to create temporary file: %w", err)
		}
		defer CleanupTempFile(tempFile.Name())

		// Close the temp file before sudo operations
		tempFile.Close()

		// Create temporary file in target directory using sudo
		tempPath := filename + ".tmp"
		if err := RunSystemCommand("cp", tempFile.Name(), tempPath); err != nil {
			return fmt.Errorf("failed to copy to temporary location: %w", err)
		}

		// Set proper permissions
		if err := RunSystemCommand("chmod", fmt.Sprintf("%o", perm), tempPath); err != nil {
			return fmt.Errorf("failed to set permissions: %w", err)
		}

		// Atomic rename
		if err := RunSystemCommand("mv", tempPath, filename); err != nil {
			return fmt.Errorf("failed to rename to final location: %w", err)
		}

		return nil
	}

	// For non-privileged paths, use regular atomic write
	return WriteFileAtomic(filename, data, perm)
}

// CreateAzureCliCommand creates an exec.Cmd for Azure CLI with sudo handling
func CreateAzureCliCommand(ctx context.Context, args ...string) *exec.Cmd {
	actualUser := os.Getenv("SUDO_USER")
	if actualUser != "" {
		// We're running under sudo, so run the az command as the original user
		cmdArgs := append([]string{"-u", actualUser, "az"}, args...)
		cmd := exec.CommandContext(ctx, "sudo", cmdArgs...)
		return cmd
	}
	// Not running under sudo, run normally
	cmd := exec.CommandContext(ctx, "az", args...)
	return cmd
}

// WaitForService waits for a systemd service to be active and running
func WaitForService(serviceName string, timeout time.Duration, logger *logrus.Logger) error {
	logger.Debugf("Waiting for service %s to be active (timeout: %v)", serviceName, timeout)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for service %s to start", serviceName)
		case <-ticker.C:
			// Check if service is active
			if err := RunSystemCommand("systemctl", "is-active", serviceName); err == nil {
				logger.Debugf("Service %s is active", serviceName)
				return nil
			}

			// Log current status for debugging
			if output, err := RunCommandWithOutput("systemctl", "status", serviceName); err == nil {
				logger.Debugf("Service %s status: %s", serviceName, output)
			}
		}
	}
}
