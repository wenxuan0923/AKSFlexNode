# 🚀 AKS Flex Node Agent [Work IN Progress]

<div align="center">

![AKS Flex Node](https://img.shields.io/badge/AKS-Flex%20Node-blue?style=for-the-badge&logo=kubernetes)
![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen?style=for-the-badge)

**A comprehensive agent that automates AKS edge node deployment, configuration, and lifecycle operations with advanced networking and security features.**

</div>

## 📋 Table of Contents

- [🚀 AKS Flex Node Agent \[Work IN Progress\]](#-aks-flex-node-agent-work-in-progress)
  - [📋 Table of Contents](#-table-of-contents)
  - [🎯 Overview](#-overview)
    - [🌟 Core Capabilities](#-core-capabilities)
    - [🔄 System Flow](#-system-flow)
  - [✨ Key Features](#-key-features)
    - [🚀 Core Functionality](#-core-functionality)
    - [🌐 Advanced Networking](#-advanced-networking)
    - [🛡️ Security \& Authentication](#️-security--authentication)
  - [🔄 Workflows](#-workflows)
    - [🚀 Auto-Discovery Workflow](#-auto-discovery-workflow)
    - [🔐 VPN Setup Flow](#-vpn-setup-flow)
    - [🏗️ Project Architecture](#️-project-architecture)
  - [🤝 Contributing](#-contributing)
  - [📄 License](#-license)

## 🎯 Overview

The **AKS Flex Node Agent** is a next-generation Kubernetes edge node management solution designed for enterprise-grade AKS deployments. It provides seamless integration between edge nodes and Azure Kubernetes Service clusters with advanced networking, security, and automation capabilities.

### 🌟 Core Capabilities

```mermaid
graph TD
    A[🚀 AKS Flex Node Agent] --> B[📦 Node Bootstrap]
    A --> C[🔐 VPN Connectivity]
    A --> D[🌐 CNI Management]
    A --> E[☁️ Azure Arc Integration]
    A --> F[💚 Health Monitoring]

    B --> B1[⚙️ Containerd Setup]
    B --> B2[🔧 Kubelet Config]
    B --> B3[📋 Component Install]

    C --> C1[🔑 Certificate Gen]
    C --> C2[🔗 OpenVPN Setup]
    C --> C3[🌍 IP Management]

    D --> D1[🕷️ Cilium CNI]
    D --> D2[🛡️ Network Policies]
    D --> D3[🔒 Encryption]

    E --> E1[🔍 Cluster Discovery]
    E --> E2[🌉 VPN Gateway]
    E --> E3[📝 Registration]

    F --> F1[💓 Health Checks]
    F --> F2[🔄 Self-Healing]
    F --> F3[📊 Metrics]
```

### 🔄 System Flow

```mermaid
sequenceDiagram
    participant User as 👤 Administrator
    participant Agent as 🤖 AKS Flex Node
    participant Azure as ☁️ Azure Cloud
    participant AKS as 🎯 AKS Cluster

    User->>Agent: 🚀 Bootstrap Command
    Agent->>Azure: 🔍 Discover Arc Machine
    Azure-->>Agent: 📋 Machine Details
    Agent->>Azure: 🔍 Discover AKS Clusters
    Azure-->>Agent: 📋 Cluster List
    Agent->>Azure: 🌉 Provision VPN Gateway
    Azure-->>Agent: 🔑 VPN Configuration
    Agent->>Agent: 🔧 Configure Node
    Agent->>AKS: 🤝 Join Cluster
    AKS-->>Agent: ✅ Node Registered
    Agent->>User: 🎉 Bootstrap Complete
```

## ✨ Key Features

### 🚀 Core Functionality

| Feature | Description | Status |
|---------|-------------|---------|
| 🤖 **Auto Bootstrap** | Complete node setup with all components | ✅ Ready |
| 🔍 **Arc Discovery** | Automatic cluster detection and provisioning | ✅ Ready |
| 🌐 **VNet Integration** | Dynamic VNet discovery and configuration | ✅ Ready |
| 💚 **Health Monitoring** | Continuous health checks with self-healing | ✅ Ready |
| ⚙️ **Config Management** | Declarative YAML configuration | ✅ Ready |

### 🌐 Advanced Networking

```mermaid
graph LR
    subgraph "🏢 On-Premises"
        Node[🖥️ Edge Node]
        VPN[🔐 OpenVPN Client]
    end

    subgraph "☁️ Azure Cloud"
        Gateway[🌉 VPN Gateway]
        VNet[🌐 Virtual Network]
        AKS[🎯 AKS Cluster]
    end

    Node --> VPN
    VPN -.->|🔒 Encrypted| Gateway
    Gateway --> VNet
    VNet --> AKS

    style Node fill:#e1f5fe
    style VPN fill:#fff3e0
    style Gateway fill:#f3e5f5
    style AKS fill:#e8f5e8
```

### 🛡️ Security & Authentication

- 🔑 **Certificate Management**: Automated VPN certificate generation
- 🔐 **Secure Authentication**: Token-based Arc authentication
- 🛡️ **Network Security**: Advanced CNI policies and encryption
- 👥 **RBAC Integration**: Kubernetes role-based access control

## 🔄 Workflows

### 🚀 Auto-Discovery Workflow

```mermaid
flowchart TD
    Start([🏁 Start Bootstrap]) --> Check{🔍 Arc Registered?}
    Check -->|❌ No| Register[📝 Register Arc Machine]
    Check -->|✅ Yes| Discover[🔍 Discover Clusters]
    Register --> Discover
    Discover --> Found{🎯 Clusters Found?}
    Found -->|❌ No| Error([❌ No Clusters])
    Found -->|✅ Yes| Provision[🌉 Provision VPN Gateway]
    Provision --> Certs[🔑 Generate Certificates]
    Certs --> Config[⚙️ Configure Node]
    Config --> Join[🤝 Join Cluster]
    Join --> Success([🎉 Success])

    style Start fill:#e8f5e8
    style Success fill:#e8f5e8
    style Error fill:#ffebee
```

### 🔐 VPN Setup Flow

```mermaid
stateDiagram-v2
    [*] --> GenerateCerts: 🔑 Generate Certificates
    GenerateCerts --> UploadCert: 📤 Upload to Azure
    UploadCert --> DownloadConfig: 📥 Download OVPN Config
    DownloadConfig --> Bootstrap: 🚀 Bootstrap with VPN
    Bootstrap --> UpdateIP: 🌍 Update Node IP
    UpdateIP --> SetupCron: ⏰ Setup Cron Jobs
    SetupCron --> [*]: ✅ Complete
```

### 🏗️ Project Architecture

```mermaid
graph TD
    CLI[🎯 CLI Interface] --> Bootstrap[🚀 Bootstrap Package]
    CLI --> Arc[☁️ Arc Package]
    CLI --> VPN[🔐 VPN Package]

    Bootstrap --> Config[⚙️ Config]
    Bootstrap --> Health[💚 Health]
    Bootstrap --> Auth[🔑 Auth]
    Bootstrap --> State[💾 State]

    Arc --> RBAC[👥 RBAC]
    Arc --> Utils[🛠️ Utils]

    VPN --> CNI[🌐 CNI]
    VPN --> Utils

    style CLI fill:#e3f2fd
    style Bootstrap fill:#f3e5f5
    style Arc fill:#e8f5e8
    style VPN fill:#fff3e0
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md).

1. 🍴 Fork the repository
2. 🌟 Create a feature branch
3. ✅ Add tests for new functionality
4. 📝 Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<div align="center">

**🚀 Built with ❤️ for the Kubernetes community**

![Made with Go](https://img.shields.io/badge/Made%20with-Go-00ADD8?style=flat-square&logo=go)
![Kubernetes](https://img.shields.io/badge/Kubernetes-Ready-326CE5?style=flat-square&logo=kubernetes)
![Azure](https://img.shields.io/badge/Azure-Integrated-0078D4?style=flat-square&logo=microsoftazure)

</div>