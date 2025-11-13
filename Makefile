# AKS FlexNode Makefile
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

# Build flags to inject version information
LDFLAGS := -X main.Version=$(VERSION) -X main.GitCommit=$(GIT_COMMIT) -X main.BuildTime=$(BUILD_DATE)

.PHONY: build
build:
	@go build -ldflags "$(LDFLAGS)" -o aks-flex-node .

.PHONY: test
test:
	@go test ./...

.PHONY: clean
clean:
	@go clean

.PHONY: update-build-metadata
update-build-metadata:
	@echo "📅 Build Date: $(BUILD_DATE)"
	@echo "🎯 Git Commit: $(GIT_COMMIT)"