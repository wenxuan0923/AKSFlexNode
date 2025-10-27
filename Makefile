# AKS Flex Node Makefile

# Build variables
BINARY_NAME := aks-flex-node
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "1.0.0")
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Go build variables
GO_VERSION := 1.21
GOPATH := $(shell go env GOPATH)
GOOS := $(shell go env GOOS)
GOARCH := $(shell go env GOARCH)

# Linker flags
LDFLAGS := -X main.version=$(VERSION) \
           -X main.buildDate=$(BUILD_DATE) \
           -X main.gitCommit=$(GIT_COMMIT) \
           -w -s

# Build flags
BUILD_FLAGS := -ldflags "$(LDFLAGS)" -trimpath

# Directories
BUILD_DIR := build
DIST_DIR := dist
BIN_DIR := $(BUILD_DIR)/bin
PKG_DIR := $(BUILD_DIR)/pkg

# Package variables
DEB_VERSION := $(VERSION)-1
DEB_FILE := $(DIST_DIR)/$(BINARY_NAME)_$(DEB_VERSION)_$(GOARCH).deb

.PHONY: all build test clean install uninstall package package-deb run dev deps fmt lint help

# Default target
all: build

# Build the binary
build: deps
	@echo "Building $(BINARY_NAME) $(VERSION)..."
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 go build $(BUILD_FLAGS) -o $(BIN_DIR)/$(BINARY_NAME) ./cmd/$(BINARY_NAME)
	@echo "Build complete: $(BIN_DIR)/$(BINARY_NAME)"

# Run tests
test: deps
	@echo "Running tests..."
	go test -v -race -cover ./...

# Run tests with coverage
test-coverage: deps
	@echo "Running tests with coverage..."
	@mkdir -p $(BUILD_DIR)
	go test -v -race -coverprofile=$(BUILD_DIR)/coverage.out ./...
	go tool cover -html=$(BUILD_DIR)/coverage.out -o $(BUILD_DIR)/coverage.html
	@echo "Coverage report: $(BUILD_DIR)/coverage.html"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR) $(DIST_DIR)
	go clean -cache -testcache -modcache

# Install dependencies
deps:
	@echo "Installing dependencies..."
	go mod download
	go mod tidy

# Install the binary
install: build
	@echo "Installing $(BINARY_NAME)..."
	sudo install -D -m 0755 $(BIN_DIR)/$(BINARY_NAME) /usr/bin/$(BINARY_NAME)
	sudo install -D -m 0644 configs/config.yaml /etc/$(BINARY_NAME)/config.yaml
	sudo install -D -m 0644 configs/systemd/$(BINARY_NAME).service /lib/systemd/system/$(BINARY_NAME).service
	sudo mkdir -p /var/lib/$(BINARY_NAME) /var/log/$(BINARY_NAME)
	sudo chown root:root /var/lib/$(BINARY_NAME) /var/log/$(BINARY_NAME)
	sudo chmod 755 /var/lib/$(BINARY_NAME) /var/log/$(BINARY_NAME)
	sudo systemctl daemon-reload
	@echo "Installation complete!"
	@echo ""
	@echo "Service installed:"
	@echo "  • $(BINARY_NAME).service - AKS node connection service (oneshot)"
	@echo ""
	@echo "To configure and start:"
	@echo "  1. Configure Azure: az login"
	@echo "  2. Edit config: /etc/$(BINARY_NAME)/config.yaml"
	@echo "  3. Enable service: sudo systemctl enable $(BINARY_NAME)"
	@echo "  4. Start service: sudo systemctl start $(BINARY_NAME)"
	@echo "  5. Check status: sudo systemctl status $(BINARY_NAME)"
	@echo "  6. View logs: sudo journalctl -u $(BINARY_NAME) -f"

# Uninstall the binary
uninstall:
	@echo "Uninstalling $(BINARY_NAME)..."
	sudo systemctl stop $(BINARY_NAME) || true
	sudo systemctl disable $(BINARY_NAME) || true
	sudo rm -f /usr/bin/$(BINARY_NAME)
	sudo rm -f /lib/systemd/system/$(BINARY_NAME).service
	sudo rm -rf /etc/$(BINARY_NAME)
	sudo rm -rf /var/lib/$(BINARY_NAME)
	sudo systemctl daemon-reload
	@echo "Uninstallation complete."

# Create packages
package: package-deb

# Create Debian package
package-deb: build
	@echo "Creating Debian package..."
	@mkdir -p $(DIST_DIR)
	dpkg-buildpackage -us -uc -b
	mv ../$(BINARY_NAME)_$(DEB_VERSION)_$(GOARCH).deb $(DEB_FILE)
	@echo "Debian package created: $(DEB_FILE)"

# Run the binary in development mode
run: build
	@echo "Running $(BINARY_NAME) in development mode..."
	sudo $(BIN_DIR)/$(BINARY_NAME) daemon --config configs/$(BINARY_NAME).yaml

# Run in development mode with verbose logging
dev: build
	@echo "Running $(BINARY_NAME) in development mode with debug logging..."
	sudo $(BIN_DIR)/$(BINARY_NAME) daemon --config configs/$(BINARY_NAME).yaml

# Format code
fmt:
	@echo "Formatting code..."
	go fmt ./...
	gofmt -s -w .

# Lint code
lint:
	@echo "Linting code..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not installed, skipping..."; \
		echo "Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
	fi

# Build for multiple architectures
build-all: deps
	@echo "Building for multiple architectures..."
	@mkdir -p $(DIST_DIR)

	# Linux AMD64
	@echo "Building for linux/amd64..."
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build $(BUILD_FLAGS) \
		-o $(DIST_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/$(BINARY_NAME)

	# Linux ARM64
	@echo "Building for linux/arm64..."
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build $(BUILD_FLAGS) \
		-o $(DIST_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/$(BINARY_NAME)

# Install development tools
dev-tools:
	@echo "Installing development tools..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install github.com/goreleaser/goreleaser@latest

# Check if running as root (required for some operations)
check-root:
	@if [ "$$(id -u)" != "0" ]; then \
		echo "This operation requires root privileges. Please run with sudo."; \
		exit 1; \
	fi

# Bootstrap a node (requires root)
bootstrap: build check-root
	@echo "Bootstrapping node..."
	$(BIN_DIR)/$(BINARY_NAME) bootstrap --config configs/$(BINARY_NAME).yaml

# Reset a node (requires root)
reset: build check-root
	@echo "Resetting node..."
	$(BIN_DIR)/$(BINARY_NAME) reset --config configs/$(BINARY_NAME).yaml --force

# Check health
health: build
	@echo "Checking node health..."
	$(BIN_DIR)/$(BINARY_NAME) health --config configs/$(BINARY_NAME).yaml

# Show status
status: build
	@echo "Showing node status..."
	$(BIN_DIR)/$(BINARY_NAME) status --config configs/$(BINARY_NAME).yaml

# Show version
version: build
	@echo "Version information:"
	$(BIN_DIR)/$(BINARY_NAME) version

# Help target
help:
	@echo "AKS Flex Node Makefile"
	@echo ""
	@echo "Usage:"
	@echo "  make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  build         Build the binary"
	@echo "  test          Run tests"
	@echo "  test-coverage Run tests with coverage report"
	@echo "  clean         Clean build artifacts"
	@echo "  deps          Install dependencies"
	@echo "  install       Install the binary and service (requires sudo)"
	@echo "  uninstall     Uninstall the binary and service (requires sudo)"
	@echo "  package       Create packages (currently only deb)"
	@echo "  package-deb   Create Debian package"
	@echo "  run           Run in development mode (requires sudo)"
	@echo "  dev           Run in development mode with debug logging (requires sudo)"
	@echo "  fmt           Format code"
	@echo "  lint          Lint code"
	@echo "  build-all     Build for multiple architectures"
	@echo "  dev-tools     Install development tools"
	@echo "  bootstrap     Bootstrap a node (requires sudo)"
	@echo "  reset         Reset a node (requires sudo)"
	@echo "  health        Check node health"
	@echo "  status        Show node status"
	@echo "  version       Show version information"
	@echo "  help          Show this help message"
	@echo ""
	@echo "Variables:"
	@echo "  VERSION=$(VERSION)"
	@echo "  BUILD_DATE=$(BUILD_DATE)"
	@echo "  GIT_COMMIT=$(GIT_COMMIT)"