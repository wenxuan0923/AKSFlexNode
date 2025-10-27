# Development Guide

This guide covers how to develop, build, test, and contribute to the AKS Flex Node Agent.

## Table of Contents

- [Development Environment Setup](#development-environment-setup)
- [Project Structure](#project-structure)
- [Building](#building)
- [Testing](#testing)
- [Debugging](#debugging)
- [Contributing](#contributing)
- [Release Process](#release-process)

## Development Environment Setup

### Prerequisites

1. **Go 1.21 or later**
   ```bash
   # Install Go
   wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
   sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
   export PATH=$PATH:/usr/local/go/bin
   ```

2. **Development tools**
   ```bash
   # Install make
   sudo apt install -y build-essential

   # Install golangci-lint for linting
   go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

   # Install development dependencies
   make dev-tools
   ```

3. **Docker (optional, for container builds)**
   ```bash
   sudo apt install -y docker.io
   sudo usermod -aG docker $USER
   ```

4. **Debian packaging tools (for package builds)**
   ```bash
   sudo apt install -y debhelper devscripts
   ```

### Clone and Setup

```bash
# Clone repository
git clone https://github.com/Azure/aks-one.git
cd aks-one/aks-flex-node

# Install dependencies
make deps

# Build the project
make build
```

## Project Structure

```
aks-flex-node/
├── cmd/
│   └── aks-flex-node/     # Main application entry point
├── pkg/
│   ├── agent/                   # Core agent implementation
│   ├── bootstrap/               # Node bootstrap functionality
│   ├── config/                  # Configuration management
│   ├── health/                  # Health monitoring
│   └── utils/                   # Utility functions
├── configs/                     # Configuration files
│   ├── aks-flex-node.yaml # Default configuration
│   └── systemd/                 # Systemd service files
├── debian/                      # Debian packaging files
├── scripts/                     # Installation and utility scripts
├── docs/                        # Documentation
├── Makefile                     # Build automation
├── go.mod                       # Go module definition
└── README.md                    # Project overview
```

### Package Organization

- **`cmd/aks-flex-node`**: Main application with CLI interface
- **`pkg/agent`**: Core agent logic and HTTP server
- **`pkg/bootstrap`**: Node bootstrap and reset functionality
- **`pkg/config`**: Configuration loading and validation
- **`pkg/health`**: Health monitoring and recovery
- **`pkg/utils`**: Shared utility functions

## Building

### Build Commands

```bash
# Build for local architecture
make build

# Build for all supported architectures
make build-all

# Build with custom flags
go build -ldflags "-X main.version=dev" -o build/aks-flex-node ./cmd/aks-flex-node
```

### Build Variables

The build process sets several variables:
- `main.version`: Version string (from git tags or "dev")
- `main.buildDate`: Build timestamp
- `main.gitCommit`: Git commit hash

### Cross-Compilation

```bash
# Linux AMD64
GOOS=linux GOARCH=amd64 make build

# Linux ARM64
GOOS=linux GOARCH=arm64 make build
```

## Testing

### Running Tests

```bash
# Run all tests
make test

# Run tests with coverage
make test-coverage

# Run specific package tests
go test ./pkg/config -v

# Run tests with race detection
go test -race ./...
```

### Test Structure

```bash
# Unit tests
pkg/config/config_test.go
pkg/utils/utils_test.go

# Integration tests
tests/integration/
├── bootstrap_test.go
├── health_test.go
└── agent_test.go

# End-to-end tests
tests/e2e/
└── full_lifecycle_test.go
```

### Writing Tests

Example unit test:
```go
package config

import (
    "testing"
    "github.com/stretchr/testify/assert"
)

func TestLoadConfig(t *testing.T) {
    cfg, err := LoadConfig("testdata/valid-config.yaml")
    assert.NoError(t, err)
    assert.Equal(t, "info", cfg.Agent.LogLevel)
}
```

Example integration test:
```go
//go:build integration
// +build integration

package integration

import (
    "context"
    "testing"
    "time"
)

func TestBootstrap(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping integration test in short mode")
    }

    // Test bootstrap functionality
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
    defer cancel()

    // Test implementation...
}
```

### Test Coverage

```bash
# Generate coverage report
make test-coverage

# View coverage in browser
open build/coverage.html
```

## Debugging

### Development Mode

```bash
# Run in development mode with debug logging
make dev

# Run with custom configuration
sudo ./build/bin/aks-flex-node daemon --config ./test-config.yaml
```

### Debug Configuration

Create a debug configuration file:
```yaml
# debug-config.yaml
agent:
  logLevel: "debug"
  healthCheckInterval: "10s"
  metricsEnabled: true
  metricsPort: 8080

features:
  autoBootstrap: false  # Disable for manual testing
  autoRecovery: false   # Disable for debugging
```

### Using Debugger

1. **Delve (dlv)**
   ```bash
   # Install delve
   go install github.com/go-delve/delve/cmd/dlv@latest

   # Debug the application
   sudo dlv exec ./build/bin/aks-flex-node -- daemon --config debug-config.yaml
   ```

2. **VS Code Debug Configuration**
   ```json
   {
     "version": "0.2.0",
     "configurations": [
       {
         "name": "Debug AKS Flex Node",
         "type": "go",
         "request": "launch",
         "mode": "debug",
         "program": "./cmd/aks-flex-node",
         "args": ["daemon", "--config", "debug-config.yaml"],
         "env": {},
         "cwd": "${workspaceFolder}",
         "console": "integratedTerminal"
       }
     ]
   }
   ```

### Debug Endpoints

When running with `metricsEnabled: true`:

```bash
# Health endpoint
curl http://localhost:8080/health

# Status endpoint
curl http://localhost:8080/status

# Metrics endpoint
curl http://localhost:8080/metrics
```

### Logging

Add debug logging in code:
```go
package main

import (
    "github.com/sirupsen/logrus"
)

func main() {
    logger := logrus.New()
    logger.SetLevel(logrus.DebugLevel)

    logger.Debug("Debug message")
    logger.Info("Info message")
    logger.Warn("Warning message")
    logger.Error("Error message")
}
```

## Contributing

### Code Style

1. **Go formatting**
   ```bash
   # Format code
   make fmt

   # Or manually
   go fmt ./...
   gofmt -s -w .
   ```

2. **Linting**
   ```bash
   # Run linter
   make lint

   # Or manually
   golangci-lint run
   ```

3. **Naming conventions**
   - Use camelCase for variables and functions
   - Use PascalCase for exported types and functions
   - Use descriptive names
   - Avoid abbreviations

### Git Workflow

1. **Fork and clone**
   ```bash
   git clone https://github.com/your-username/aks-one.git
   cd aks-one/aks-flex-node
   ```

2. **Create feature branch**
   ```bash
   git checkout -b feature/new-feature
   ```

3. **Make changes and test**
   ```bash
   # Make changes
   make test
   make lint
   ```

4. **Commit changes**
   ```bash
   git add .
   git commit -m "feat: add new feature description"
   ```

5. **Push and create PR**
   ```bash
   git push origin feature/new-feature
   # Create pull request on GitHub
   ```

### Commit Message Format

Use conventional commits:
```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes
- `refactor`: Code refactoring
- `test`: Test changes
- `chore`: Build/tooling changes

Examples:
```
feat(bootstrap): add support for custom container runtime
fix(health): resolve memory leak in health checker
docs(config): update configuration examples
```

### Pull Request Guidelines

1. **PR Title**: Use conventional commit format
2. **Description**: Explain what and why
3. **Testing**: Include test results
4. **Documentation**: Update docs if needed
5. **Breaking Changes**: Call out any breaking changes

### Code Review Process

1. Automated checks must pass
2. At least one reviewer approval required
3. All conversations must be resolved
4. Update branch if needed
5. Squash and merge

## Release Process

### Version Management

Version follows semantic versioning (SemVer):
- `MAJOR.MINOR.PATCH`
- `1.0.0`, `1.1.0`, `1.1.1`, etc.

### Creating a Release

1. **Update version**
   ```bash
   # Update version in relevant files
   git tag v1.1.0
   git push origin v1.1.0
   ```

2. **Build release artifacts**
   ```bash
   # Build for all architectures
   make build-all

   # Create packages
   make package
   ```

3. **Create GitHub release**
   - Use GitHub releases page
   - Upload binary artifacts
   - Include changelog

### Automated Releases

The project uses GitHub Actions for automated releases:
- Triggered by version tags
- Builds for multiple architectures
- Creates GitHub release with artifacts
- Updates package repositories

### Package Distribution

1. **Debian packages**
   - Built automatically
   - Uploaded to package repository
   - Available via `apt install`

2. **Binary releases**
   - Available on GitHub releases
   - Multiple architectures supported
   - Checksums provided

### Hotfix Process

For urgent fixes:
1. Create hotfix branch from main
2. Make minimal fix
3. Test thoroughly
4. Create patch release
5. Merge back to develop

Example:
```bash
git checkout -b hotfix/security-fix main
# Make fix
git tag v1.1.1
git push origin v1.1.1
```

## Development Best Practices

### Error Handling

```go
// Good: Wrap errors with context
if err := doSomething(); err != nil {
    return fmt.Errorf("failed to do something: %w", err)
}

// Good: Check for specific error types
if os.IsNotExist(err) {
    // Handle file not found
}
```

### Logging

```go
// Good: Structured logging
logger.WithFields(logrus.Fields{
    "component": "bootstrap",
    "operation": "install-kubelet",
    "version": "1.32.7",
}).Info("Installing kubelet")

// Good: Different log levels
logger.Debug("Detailed debug information")
logger.Info("General information")
logger.Warn("Warning message")
logger.Error("Error occurred")
```

### Configuration

```go
// Good: Use struct tags for validation
type Config struct {
    Port int `yaml:"port" validate:"min=1,max=65535"`
    Host string `yaml:"host" validate:"required"`
}
```

### Testing

```go
// Good: Table-driven tests
func TestValidateConfig(t *testing.T) {
    tests := []struct {
        name    string
        config  Config
        wantErr bool
    }{
        {"valid config", Config{Port: 8080, Host: "localhost"}, false},
        {"invalid port", Config{Port: 0, Host: "localhost"}, true},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            err := validateConfig(tt.config)
            if (err != nil) != tt.wantErr {
                t.Errorf("validateConfig() error = %v, wantErr %v", err, tt.wantErr)
            }
        })
    }
}
```

### Documentation

- Comment exported functions and types
- Include examples in documentation
- Keep README up to date
- Document configuration options
- Provide troubleshooting guides