# AKS FlexNode Makefile
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

# Build flags to inject version information
LDFLAGS := -X main.Version=$(VERSION) -X main.GitCommit=$(GIT_COMMIT) -X main.BuildTime=$(BUILD_DATE) -w -s

# Default build for current platform
.PHONY: build
build:
	@echo "Building for current platform..."
	@go build -ldflags "$(LDFLAGS)" -o aks-flex-node .

# Cross-platform builds for supported architectures
.PHONY: build-linux-amd64
build-linux-amd64:
	@echo "Building for Linux AMD64..."
	@GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o aks-flex-node-linux-amd64 .

.PHONY: build-linux-arm64
build-linux-arm64:
	@echo "Building for Linux ARM64..."
	@GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o aks-flex-node-linux-arm64 .

# Build all supported platforms
.PHONY: build-all
build-all: build-linux-amd64 build-linux-arm64
	@echo "Built binaries for all supported platforms"

# Create release archives
.PHONY: package-linux-amd64
package-linux-amd64: build-linux-amd64
	@echo "Packaging Linux AMD64 binary..."
	@tar -czf aks-flex-node-linux-amd64.tar.gz aks-flex-node-linux-amd64

.PHONY: package-linux-arm64
package-linux-arm64: build-linux-arm64
	@echo "Packaging Linux ARM64 binary..."
	@tar -czf aks-flex-node-linux-arm64.tar.gz aks-flex-node-linux-arm64

# Package all supported platforms
.PHONY: package-all
package-all: package-linux-amd64 package-linux-arm64
	@echo "Packaged all supported platforms"
	@ls -la *.tar.gz

.PHONY: test
test:
	@go test ./...

.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	@go clean
	@rm -f aks-flex-node-*
	@rm -f *.tar.gz

.PHONY: update-build-metadata
update-build-metadata:
	@echo "📅 Build Date: $(BUILD_DATE)"
	@echo "🎯 Git Commit: $(GIT_COMMIT)"
	@echo "🏷️  Version: $(VERSION)"

# Help target
.PHONY: help
help:
	@echo "AKS Flex Node Makefile"
	@echo "======================"
	@echo ""
	@echo "Targets:"
	@echo "  build              Build for current platform"
	@echo "  build-linux-amd64  Build for Linux AMD64"
	@echo "  build-linux-arm64  Build for Linux ARM64"
	@echo "  build-all          Build for all supported platforms"
	@echo "  package-linux-amd64 Package Linux AMD64 binary"
	@echo "  package-linux-arm64 Package Linux ARM64 binary"
	@echo "  package-all        Package all supported platforms"
	@echo "  test               Run tests"
	@echo "  clean              Clean build artifacts"
	@echo "  update-build-metadata Show build metadata"
	@echo "  help               Show this help message"