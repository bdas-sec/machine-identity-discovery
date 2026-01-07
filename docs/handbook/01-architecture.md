# Chapter 1: Architecture

## System Overview

The Machine Identity Security Testbed provides a containerized environment for demonstrating and detecting Non-Human Identity (NHI) security threats using Wazuh SIEM.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              HOST MACHINE                                   │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │                         DOCKER NETWORK                                 │ │
│  │                                                                        │ │
│  │  ┌────────────────── MANAGEMENT NETWORK (172.40.0.0/24) ────────────┐ │ │
│  │  │                                                                   │ │ │
│  │  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │ │ │
│  │  │  │   Wazuh     │  │   Wazuh     │  │   Wazuh     │              │ │ │
│  │  │  │   Manager   │  │   Indexer   │  │  Dashboard  │              │ │ │
│  │  │  │  :55000     │  │   :9200     │  │   :8443     │              │ │ │
│  │  │  │ 172.40.0.11 │  │ 172.40.0.10 │  │ 172.40.0.12 │              │ │ │
│  │  │  └──────┬──────┘  └─────────────┘  └─────────────┘              │ │ │
│  │  │         │                                                        │ │ │
│  │  └─────────┼────────────────────────────────────────────────────────┘ │ │
│  │            │                                                           │ │
│  │  ┌─────────┴─────────────────────────────────────────────────────────┐ │ │
│  │  │                     WAZUH AGENT CONNECTIONS                        │ │ │
│  │  └─────────┬───────────────┬───────────────┬─────────────────────────┘ │ │
│  │            │               │               │                           │ │
│  │  ┌─────────┴───────────────┴───────────────┴─────────────────────────┐ │ │
│  │  │                                                                    │ │ │
│  │  │  ┌──────────── CLOUD NETWORK (172.41.0.0/24) ──────────────────┐  │ │ │
│  │  │  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │  │ │ │
│  │  │  │  │ Cloud       │  │ Vulnerable  │  │   Vault     │         │  │ │ │
│  │  │  │  │ Workload    │  │    App      │  │   :8200     │         │  │ │ │
│  │  │  │  │ 172.41.0.10 │  │ 172.41.0.20 │  │ 172.41.0.200│         │  │ │ │
│  │  │  │  └─────────────┘  └─────────────┘  └─────────────┘         │  │ │ │
│  │  │  │  ┌─────────────┐  ┌─────────────┐                          │  │ │ │
│  │  │  │  │  Mock IMDS  │  │  AI Agent   │                          │  │ │ │
│  │  │  │  │   :1338     │  │   :8000     │                          │  │ │ │
│  │  │  │  │ 172.41.0.100│  │ 172.41.0.30 │                          │  │ │ │
│  │  │  │  └─────────────┘  └─────────────┘                          │  │ │ │
│  │  │  └────────────────────────────────────────────────────────────┘  │ │ │
│  │  │                                                                    │ │ │
│  │  │  ┌──────────── CI/CD NETWORK (172.42.0.0/24) ──────────────────┐  │ │ │
│  │  │  │  ┌─────────────┐  ┌─────────────┐                          │  │ │ │
│  │  │  │  │ CI/CD       │  │  Mock CI/CD │                          │  │ │ │
│  │  │  │  │ Runner      │  │   Server    │                          │  │ │ │
│  │  │  │  │ 172.42.0.10 │  │ 172.42.0.100│                          │  │ │ │
│  │  │  │  └─────────────┘  └─────────────┘                          │  │ │ │
│  │  │  └────────────────────────────────────────────────────────────┘  │ │ │
│  │  │                                                                    │ │ │
│  │  │  ┌──────────── K8S NETWORK (172.43.0.0/24) ────────────────────┐  │ │ │
│  │  │  │  ┌─────────────┐                                            │  │ │ │
│  │  │  │  │  K8s Node   │                                            │  │ │ │
│  │  │  │  │ (simulated) │                                            │  │ │ │
│  │  │  │  │ 172.43.0.10 │                                            │  │ │ │
│  │  │  │  └─────────────┘                                            │  │ │ │
│  │  │  └────────────────────────────────────────────────────────────┘  │ │ │
│  │  │                                                                    │ │ │
│  │  └────────────────────────────────────────────────────────────────────┘ │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Network Topology

### Management Network (172.40.0.0/24)
- **Purpose**: Wazuh stack internal communication
- **Components**:
  - Wazuh Manager (172.40.0.11)
  - Wazuh Indexer (172.40.0.10)
  - Wazuh Dashboard (172.40.0.12)

### Cloud Network (172.41.0.0/24)
- **Purpose**: Simulates cloud workload environment
- **Components**:
  - Cloud Workload Agent (172.41.0.10)
  - Vulnerable App (172.41.0.20)
  - Mock IMDS (172.41.0.100)
  - HashiCorp Vault (172.41.0.200)
  - AI Agent (172.41.0.30)

### CI/CD Network (172.42.0.0/24)
- **Purpose**: Simulates CI/CD pipeline environment
- **Components**:
  - CI/CD Runner (172.42.0.10)
  - Mock CI/CD Server (172.42.0.100)

### Kubernetes Network (172.43.0.0/24)
- **Purpose**: Simulates Kubernetes cluster
- **Components**:
  - K8s Node Simulation (172.43.0.10)

## Component Details

### Wazuh Stack

#### Wazuh Manager
- **Image**: `wazuh/wazuh-manager:4.9.2`
- **Ports**:
  - 1514/TCP: Agent registration
  - 1515/TCP: Agent communication (TLS)
  - 55000/TCP: REST API
- **Responsibilities**:
  - Agent management
  - Event processing
  - Alert generation
  - Custom rule execution

#### Wazuh Indexer
- **Image**: `wazuh/wazuh-indexer:4.9.2`
- **Port**: 9200/TCP
- **Based on**: OpenSearch
- **Responsibilities**:
  - Alert storage
  - Full-text search
  - Data indexing

#### Wazuh Dashboard
- **Image**: `wazuh/wazuh-dashboard:4.9.2`
- **Port**: 8443/TCP (HTTPS) - for rootless Podman compatibility
- **Responsibilities**:
  - Web interface
  - Visualization
  - Alert investigation

### Agent Containers

Each agent container includes:
- Ubuntu 22.04 base image
- Wazuh agent 4.9.2
- Scenario-specific tools
- Custom ossec.conf for log collection

| Agent | Network | Purpose |
|-------|---------|---------|
| cloud-workload | cloud_net | AWS CLI, cloud SDK demos |
| vulnerable-app | cloud_net | Intentionally vulnerable Flask app |
| cicd-runner | cicd_net | GitHub/GitLab runner simulation |
| k8s-node | k8s_net | Kubernetes node simulation |
| ai-agent | cloud_net | AI agent with tools |

### Mock Services

#### Mock IMDS (172.41.0.100:1338)
- Simulates AWS EC2 Instance Metadata Service
- Returns fake IAM credentials
- Supports IMDSv1 and IMDSv2
- Logs all access for detection

#### Mock CI/CD Server (172.42.0.100:8080)
- Simulates GitHub Actions / GitLab CI APIs
- Returns fake tokens and secrets
- Logs token requests

#### HashiCorp Vault (172.41.0.200:8200)
- Dev mode deployment
- Demonstrates secrets management
- Integration with agents

## Data Flow

### Attack Detection Flow

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Attacker   │────▶│  Target      │────▶│  Wazuh       │
│   (Demo)     │     │  System      │     │  Agent       │
└──────────────┘     └──────────────┘     └──────┬───────┘
                                                  │
                                                  │ Events
                                                  ▼
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Wazuh      │◀────│   Wazuh      │◀────│   Wazuh      │
│  Dashboard   │     │   Indexer    │     │   Manager    │
│              │     │              │     │              │
│  - Alerts    │     │  - Storage   │     │  - Rules     │
│  - Reports   │     │  - Search    │     │  - Decoders  │
└──────────────┘     └──────────────┘     └──────────────┘
```

### Log Collection

1. **File Monitoring**: `<localfile>` configuration watches:
   - Application logs
   - System logs
   - Custom NHI event logs

2. **Command Monitoring**: `<command>` configuration executes:
   - Credential file checks
   - Process enumeration
   - Network monitoring

3. **Audit Logs**: When available:
   - Linux auditd
   - Container events
   - Kubernetes audit logs

## Security Boundaries

### Isolation
- Each network is isolated via container networks (Podman/Docker)
- Agents cannot directly access Wazuh internals
- Mock services only accessible within their networks

### Credentials
- All credentials in this testbed are FAKE
- Clearly marked as demonstration only
- Follow realistic patterns for detection testing

### Network Policies
- Default deny between networks
- Explicit allow for required paths
- Wazuh Manager bridges networks for agent collection

## Resource Requirements

| Component | vCPU | Memory | Storage |
|-----------|------|--------|---------|
| Wazuh Manager | 1 | 1 GB | 5 GB |
| Wazuh Indexer | 2 | 2 GB | 10 GB |
| Wazuh Dashboard | 0.5 | 512 MB | 1 GB |
| Agent (each) | 0.25 | 256 MB | 500 MB |
| Mock Service (each) | 0.1 | 128 MB | 100 MB |
| **Total** | ~5 | ~6 GB | ~20 GB |

## Scalability Considerations

The testbed is designed for demonstration, not production:

- **Single node**: All containers run on one host
- **No HA**: No clustering or failover
- **Limited retention**: Alerts retained for demo duration
- **Fake data**: No real sensitive data

For production deployments, see:
- [Wazuh Production Deployment Guide](https://documentation.wazuh.com/current/deployment-options/index.html)
