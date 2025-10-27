# AKS Flex Node APT Package Distribution Guide

This guide covers how to package the aks-flex-node as an Ubuntu APT package and distribute it through your own APT repository.

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Package Structure Setup](#package-structure-setup)
3. [Debian Control Files](#debian-control-files)
4. [Build Scripts](#build-scripts)
5. [Creating the Package](#creating-the-package)
6. [Setting Up APT Repository](#setting-up-apt-repository)
7. [Automated CI/CD Pipeline](#automated-cicd-pipeline)
8. [Package Installation](#package-installation)
9. [Troubleshooting](#troubleshooting)

## Prerequisites

### Required Tools
```bash
# Install packaging tools
sudo apt update
sudo apt install -y \
    build-essential \
    devscripts \
    debhelper \
    dh-make \
    fakeroot \
    lintian \
    reprepro \
    gnupg \
    dpkg-dev \
    apt-utils
```

### Go Build Environment
```bash
# Ensure Go is installed (version 1.19+)
go version

# Install Go if needed
wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
```

## Package Structure Setup

### 1. Create Package Directory Structure
```bash
# Create packaging directory
mkdir -p ~/aks-flex-node-packaging
cd ~/aks-flex-node-packaging

# Create standard Debian package structure
mkdir -p aks-flex-node-1.0.0/debian
mkdir -p aks-flex-node-1.0.0/usr/bin
mkdir -p aks-flex-node-1.0.0/etc/aks-flex-node
mkdir -p aks-flex-node-1.0.0/etc/systemd/system
mkdir -p aks-flex-node-1.0.0/usr/share/doc/aks-flex-node
mkdir -p aks-flex-node-1.0.0/var/log/aks-flex-node
```

### 2. Copy Source Files
```bash
# Copy your aks-flex-node source
cp -r /path/to/aks-flex-node/* aks-flex-node-1.0.0/

# Build the binary
cd aks-flex-node-1.0.0
go mod tidy
go build -o usr/bin/aks-flex-node ./cmd/aks-flex-node
```

## Debian Control Files

### 1. Create debian/control
```bash
cat > aks-flex-node-1.0.0/debian/control << 'EOF'
Source: aks-flex-node
Section: admin
Priority: optional
Maintainer: Your Name <your.email@company.com>
Build-Depends: debhelper-compat (= 13), golang-go (>= 2:1.19~)
Standards-Version: 4.6.0
Homepage: https://github.com/your-org/aks-flex-node
Vcs-Git: https://github.com/your-org/aks-flex-node.git
Vcs-Browser: https://github.com/your-org/aks-flex-node

Package: aks-flex-node
Architecture: amd64
Depends: ${shlibs:Depends}, ${misc:Depends},
         systemd,
         openvpn,
         curl,
         jq,
         ca-certificates
Recommends: docker.io | containerd
Description: Azure Kubernetes Service Edge Node Controller
 AKS Flex Node is a tool for managing Azure Kubernetes Service (AKS)
 edge nodes with VPN connectivity. It provides automated bootstrapping,
 certificate management, and CNI configuration for edge computing scenarios.
 .
 Key features include:
 - Automated node bootstrapping and registration
 - VPN certificate generation and management
 - CNI configuration with Cilium support
 - Node IP management for VPN interfaces
 - Integration with Azure Arc for hybrid scenarios
EOF
```

### 2. Create debian/changelog
```bash
cat > aks-flex-node-1.0.0/debian/changelog << 'EOF'
aks-flex-node (1.0.0-1) focal; urgency=medium

  * Initial release of AKS Flex Node
  * Support for VPN-based edge node connectivity
  * Automated certificate generation and management
  * CNI configuration with Cilium
  * ExpressRoute support for enterprise scenarios
  * Streamlined architecture without OpenYurt dependency

 -- Your Name <your.email@company.com>  Mon, 21 Oct 2024 10:00:00 +0000
EOF
```

### 3. Create debian/rules
```bash
cat > aks-flex-node-1.0.0/debian/rules << 'EOF'
#!/usr/bin/make -f

export DH_VERBOSE = 1
export DH_GOPKG := github.com/your-org/aks-flex-node

%:
	dh $@ --buildsystem=golang --with=golang

override_dh_auto_build:
	go mod tidy
	go build -v -o aks-flex-node ./cmd/aks-flex-node

override_dh_auto_install:
	# Install binary
	install -D -m 755 aks-flex-node $(CURDIR)/debian/aks-flex-node/usr/bin/aks-flex-node

	# Install configuration directory
	install -D -m 755 -d $(CURDIR)/debian/aks-flex-node/etc/aks-flex-node

	# Install systemd service
	install -D -m 644 scripts/systemd/aks-flex-node.service \
		$(CURDIR)/debian/aks-flex-node/etc/systemd/system/aks-flex-node.service

	# Install documentation
	install -D -m 644 README.md \
		$(CURDIR)/debian/aks-flex-node/usr/share/doc/aks-flex-node/README.md
	install -D -m 644 docs/*.md \
		$(CURDIR)/debian/aks-flex-node/usr/share/doc/aks-flex-node/

	# Create log directory
	install -D -m 755 -d $(CURDIR)/debian/aks-flex-node/var/log/aks-flex-node

override_dh_auto_test:
	# Skip tests for now
	@echo "Skipping tests"

override_dh_builddeb:
	dh_builddeb -- -Zxz
EOF

chmod +x aks-flex-node-1.0.0/debian/rules
```

### 4. Create debian/compat
```bash
echo "13" > aks-flex-node-1.0.0/debian/compat
```

### 5. Create debian/copyright
```bash
cat > aks-flex-node-1.0.0/debian/copyright << 'EOF'
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: aks-flex-node
Upstream-Contact: Your Name <your.email@company.com>
Source: https://github.com/your-org/aks-flex-node

Files: *
Copyright: 2024 Your Organization
License: Apache-2.0

License: Apache-2.0
 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at
 .
 http://www.apache.org/licenses/LICENSE-2.0
 .
 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 .
 On Debian systems, the complete text of the Apache version 2.0 license
 can be found in "/usr/share/common-licenses/Apache-2.0".
EOF
```

### 6. Create debian/postinst
```bash
cat > aks-flex-node-1.0.0/debian/postinst << 'EOF'
#!/bin/bash
set -e

case "$1" in
    configure)
        # Create aks-flex-node user if it doesn't exist
        if ! getent passwd aks-flex-node >/dev/null; then
            useradd --system --home-dir /var/lib/aks-flex-node \
                    --shell /bin/false --user-group \
                    --comment "AKS Flex Node service user" \
                    aks-flex-node
        fi

        # Set permissions
        chown -R aks-flex-node:aks-flex-node /var/log/aks-flex-node
        chmod 755 /var/log/aks-flex-node

        # Enable and start systemd service
        systemctl daemon-reload
        systemctl enable aks-flex-node.service

        echo "AKS Flex Node installed successfully!"
        echo "Configuration files are in /etc/aks-flex-node/"
        echo "Logs will be written to /var/log/aks-flex-node/"
        echo ""
        echo "To get started:"
        echo "1. Configure your settings in /etc/aks-flex-node/config.yaml"
        echo "2. Generate VPN certificates: aks-flex-node vpn generate-certs"
        echo "3. Bootstrap the node: aks-flex-node bootstrap"
        echo ""
        echo "For detailed setup instructions, see:"
        echo "/usr/share/doc/aks-flex-node/AKS_EDGE_NODE_SETUP_GUIDE.md"
        ;;
esac

#DEBHELPER#

exit 0
EOF

chmod 755 aks-flex-node-1.0.0/debian/postinst
```

### 7. Create debian/prerm
```bash
cat > aks-flex-node-1.0.0/debian/prerm << 'EOF'
#!/bin/bash
set -e

case "$1" in
    remove|upgrade|deconfigure)
        # Stop and disable service
        if systemctl is-active --quiet aks-flex-node.service; then
            systemctl stop aks-flex-node.service
        fi
        if systemctl is-enabled --quiet aks-flex-node.service; then
            systemctl disable aks-flex-node.service
        fi
        ;;
esac

#DEBHELPER#

exit 0
EOF

chmod 755 aks-flex-node-1.0.0/debian/prerm
```

## Build Scripts

### 1. Create Systemd Service File
```bash
mkdir -p aks-flex-node-1.0.0/scripts/systemd

cat > aks-flex-node-1.0.0/scripts/systemd/aks-flex-node.service << 'EOF'
[Unit]
Description=AKS Flex Node
Documentation=https://github.com/your-org/aks-flex-node
After=network.target
Wants=network.target

[Service]
Type=notify
User=aks-flex-node
Group=aks-flex-node
ExecStart=/usr/bin/aks-flex-node daemon --config /etc/aks-flex-node/config.yaml
ExecReload=/bin/kill -HUP $MAINPID
KillMode=process
Restart=on-failure
RestartSec=5
TimeoutStopSec=30
LimitNOFILE=1048576
LimitNPROC=1048576
LimitCORE=infinity
TasksMax=infinity
OOMScoreAdjust=-999

# Security settings
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/aks-flex-node /etc/aks-flex-node /var/lib/aks-flex-node
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true

[Install]
WantedBy=multi-user.target
EOF
```

### 2. Create Build Script
```bash
cat > build-package.sh << 'EOF'
#!/bin/bash
set -e

VERSION=${1:-1.0.0}
PACKAGE_NAME="aks-flex-node"
BUILD_DIR="${PACKAGE_NAME}-${VERSION}"

echo "Building ${PACKAGE_NAME} version ${VERSION}"

# Clean previous builds
rm -rf ${BUILD_DIR}*.deb ${BUILD_DIR}*.tar.gz ${BUILD_DIR}*.dsc ${BUILD_DIR}*.changes

# Build source package
cd ${BUILD_DIR}
debuild -S -sa

# Build binary package
debuild -b -uc -us

cd ..

echo "Package built successfully!"
echo "Files generated:"
ls -la ${PACKAGE_NAME}*${VERSION}*

# Validate package
echo "Validating package with lintian..."
lintian ${PACKAGE_NAME}_${VERSION}-1_amd64.deb || true

echo "Package validation complete!"
EOF

chmod +x build-package.sh
```

## Creating the Package

### 1. Build the Package
```bash
# Build the package
./build-package.sh 1.0.0

# This will create:
# - aks-flex-node_1.0.0-1_amd64.deb (binary package)
# - aks-flex-node_1.0.0-1.dsc (source description)
# - aks-flex-node_1.0.0.orig.tar.gz (original source)
# - aks-flex-node_1.0.0-1.debian.tar.xz (debian packaging)
# - aks-flex-node_1.0.0-1_amd64.changes (changes file)
```

### 2. Test Package Installation
```bash
# Test install locally
sudo dpkg -i aks-flex-node_1.0.0-1_amd64.deb

# Fix dependencies if needed
sudo apt-get install -f

# Verify installation
aks-flex-node --version
systemctl status aks-flex-node
```

## Setting Up APT Repository

### 1. Create Repository Structure
```bash
# Create repository directory
mkdir -p ~/apt-repository/{conf,dists,pool}
cd ~/apt-repository

# Create repository configuration
cat > conf/distributions << 'EOF'
Origin: Your Organization
Label: AKS Flex Node Repository
Codename: focal
Architectures: amd64 arm64
Components: main
Description: APT repository for AKS Flex Node
SignWith: YOUR_GPG_KEY_ID
EOF
```

### 2. Generate GPG Key for Signing
```bash
# Generate GPG key for package signing
gpg --full-generate-key

# Export public key
gpg --armor --export YOUR_EMAIL > aks-repo-key.gpg

# List keys to get key ID
gpg --list-secret-keys --keyid-format LONG
```

### 3. Add Package to Repository
```bash
# Install reprepro
sudo apt install reprepro

# Add package to repository
reprepro -b . includedeb focal ../aks-flex-node_1.0.0-1_amd64.deb

# Verify repository structure
find . -type f | head -20
```

### 4. Host Repository (Option A: Simple HTTP Server)
```bash
# Serve repository via HTTP (for testing)
python3 -m http.server 8080 --bind 0.0.0.0

# Repository will be available at http://your-server:8080
```

### 5. Host Repository (Option B: Nginx)
```bash
# Install nginx
sudo apt install nginx

# Copy repository to web root
sudo cp -r ~/apt-repository /var/www/html/

# Configure nginx
sudo tee /etc/nginx/sites-available/apt-repo << 'EOF'
server {
    listen 80;
    server_name your-domain.com;
    root /var/www/html/apt-repository;

    location / {
        autoindex on;
        autoindex_exact_size off;
        autoindex_localtime on;
    }

    location ~ /(.*)/conf {
        deny all;
        return 404;
    }
}
EOF

# Enable site
sudo ln -s /etc/nginx/sites-available/apt-repo /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

## Automated CI/CD Pipeline

### 1. GitHub Actions Workflow
```bash
mkdir -p .github/workflows

cat > .github/workflows/build-package.yml << 'EOF'
name: Build and Publish APT Package

on:
  push:
    tags:
      - 'v*'
  workflow_dispatch:

jobs:
  build-package:
    runs-on: ubuntu-latest

    steps:
    - name: Checkout code
      uses: actions/checkout@v3

    - name: Set up Go
      uses: actions/setup-go@v3
      with:
        go-version: 1.21

    - name: Install packaging tools
      run: |
        sudo apt update
        sudo apt install -y build-essential devscripts debhelper dh-make fakeroot lintian

    - name: Get version
      id: version
      run: echo "VERSION=${GITHUB_REF#refs/tags/v}" >> $GITHUB_OUTPUT

    - name: Build package
      run: |
        # Create package structure
        mkdir -p packaging/aks-flex-node-${{ steps.version.outputs.VERSION }}
        cp -r . packaging/aks-flex-node-${{ steps.version.outputs.VERSION }}/
        cd packaging

        # Build binary
        cd aks-flex-node-${{ steps.version.outputs.VERSION }}
        go mod tidy
        go build -v -o aks-flex-node ./cmd/aks-flex-node

        # Build package
        debuild -b -uc -us

    - name: Upload package artifacts
      uses: actions/upload-artifact@v3
      with:
        name: deb-package
        path: packaging/*.deb

    - name: Publish to repository
      if: github.event_name == 'push' && startsWith(github.ref, 'refs/tags/')
      run: |
        # Add logic to upload to your APT repository
        echo "Publishing package to repository..."
        # scp packaging/*.deb user@your-server:/path/to/repo/
        # ssh user@your-server "cd /path/to/repo && reprepro includedeb focal *.deb"
EOF
```

### 2. Automated Repository Update Script
```bash
cat > update-repository.sh << 'EOF'
#!/bin/bash
set -e

PACKAGE_FILE=$1
CODENAME=${2:-focal}
REPO_DIR=${3:-~/apt-repository}

if [[ -z "$PACKAGE_FILE" ]]; then
    echo "Usage: $0 <package.deb> [codename] [repo_dir]"
    exit 1
fi

if [[ ! -f "$PACKAGE_FILE" ]]; then
    echo "Package file not found: $PACKAGE_FILE"
    exit 1
fi

cd "$REPO_DIR"

# Add package to repository
reprepro -b . includedeb "$CODENAME" "$PACKAGE_FILE"

# Update repository metadata
reprepro -b . export

echo "Package added to repository successfully!"
echo "Repository updated for codename: $CODENAME"

# Show repository contents
echo "Current packages in repository:"
reprepro -b . list "$CODENAME"
EOF

chmod +x update-repository.sh
```

## Package Installation

### 1. Client-Side Repository Setup
```bash
# Add repository key
curl -fsSL http://your-domain.com/aks-repo-key.gpg | sudo apt-key add -

# Add repository to sources
echo "deb http://your-domain.com/ focal main" | sudo tee /etc/apt/sources.list.d/aks-flex-node.list

# Update package list
sudo apt update
```

### 2. Install Package
```bash
# Install aks-flex-node
sudo apt install aks-flex-node

# Verify installation
aks-flex-node --version
systemctl status aks-flex-node
```

### 3. Update Package
```bash
# Update to latest version
sudo apt update
sudo apt upgrade aks-flex-node
```

## Troubleshooting

### Common Build Issues

#### Missing Dependencies
```bash
# If Go modules fail to download
go mod tidy
go mod download

# If debian tools are missing
sudo apt install -y devscripts build-essential debhelper
```

#### Permission Issues
```bash
# Fix file permissions
find debian/ -type f -name "*.sh" -exec chmod +x {} \;
chmod +x debian/rules
```

#### Lintian Warnings
```bash
# Check for common issues
lintian --info --display-info --display-experimental --pedantic package.deb

# Fix common warnings:
# - Add proper copyright file
# - Fix file permissions
# - Add proper package descriptions
```

### Repository Issues

#### GPG Signing Problems
```bash
# Verify GPG key
gpg --list-secret-keys

# Export key properly
gpg --armor --export YOUR_KEY_ID > key.gpg

# Re-sign repository
reprepro -b . export
```

#### Repository Corruption
```bash
# Clear and rebuild repository
rm -rf dists/ pool/
reprepro -b . export
reprepro -b . includedeb focal package.deb
```

### Installation Issues

#### Dependency Conflicts
```bash
# Force dependency resolution
sudo apt install -f

# Check dependency tree
apt-cache depends aks-flex-node
```

#### Service Start Failures
```bash
# Check service logs
journalctl -u aks-flex-node.service -f

# Verify configuration
aks-flex-node --config /etc/aks-flex-node/config.yaml --dry-run
```

## Advanced Configuration

### 1. Multi-Architecture Support
```bash
# Build for multiple architectures
cat > conf/distributions << 'EOF'
Origin: Your Organization
Label: AKS Flex Node Repository
Codename: focal
Architectures: amd64 arm64
Components: main
Description: APT repository for AKS Flex Node
SignWith: YOUR_GPG_KEY_ID
EOF

# Cross-compile for ARM64
GOOS=linux GOARCH=arm64 go build -o aks-flex-node-arm64 ./cmd/aks-flex-node
```

### 2. Multiple Ubuntu Versions
```bash
# Support multiple Ubuntu releases
cat > conf/distributions << 'EOF'
Origin: Your Organization
Label: AKS Flex Node Repository
Codename: focal
Architectures: amd64 arm64
Components: main
Description: APT repository for AKS Flex Node (Ubuntu 20.04)
SignWith: YOUR_GPG_KEY_ID

Origin: Your Organization
Label: AKS Flex Node Repository
Codename: jammy
Architectures: amd64 arm64
Components: main
Description: APT repository for AKS Flex Node (Ubuntu 22.04)
SignWith: YOUR_GPG_KEY_ID
EOF
```

### 3. Package Versioning Strategy
```bash
# Use semantic versioning
# Format: MAJOR.MINOR.PATCH-REVISION
# Example: 1.2.3-1ubuntu1

# For development builds
VERSION="1.0.0~dev$(date +%Y%m%d%H%M%S)-1"

# For release candidates
VERSION="1.0.0~rc1-1"

# For stable releases
VERSION="1.0.0-1"
```

This comprehensive guide provides everything needed to package and distribute the aks-flex-node as a professional Ubuntu APT package. The automated CI/CD pipeline ensures consistent builds and easy distribution to your users.