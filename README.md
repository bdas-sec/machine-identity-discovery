# Machine Identity Security Testbed

**NDC Security 2026 - "Who Gave the Agent Admin Rights?! Securing Cloud & AI Machine Identities"**

A comprehensive testbed for demonstrating and detecting Non-Human Identity (NHI) security threats using Wazuh SIEM.

## Overview

This testbed provides a local, containerized environment for demonstrating:
- Cloud credential theft via Instance Metadata Service (IMDS)
- API key and secret exposure in applications
- CI/CD pipeline token abuse
- Kubernetes service account compromise
- AI agent security vulnerabilities

All attacks are contained and use fake credentials for safe demonstration.

## Quick Start

```bash
# Prerequisites
sudo sysctl -w vm.max_map_count=262144

# Start the testbed
./scripts/start.sh

# Access Wazuh Dashboard
# URL: https://localhost:8443
# User: admin
# Password: admin
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         TESTBED ARCHITECTURE                            │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────────────── WAZUH STACK ───────────────────────┐         │
│  │  Manager (:55000)  │  Indexer (:9200)  │  Dashboard (:8443)│         │
│  └────────────────────────────────────────────────────────────┘         │
│                              │                                          │
│  ┌──────────┬───────────────┼───────────────┬──────────────┐           │
│  │          │               │               │              │           │
│  ▼          ▼               ▼               ▼              ▼           │
│ ┌────────┐ ┌────────┐ ┌──────────┐ ┌──────────┐ ┌────────────┐        │
│ │Cloud   │ │Vuln    │ │CI/CD     │ │K8s Nodes │ │AI Agent    │        │
│ │Workload│ │App     │ │Runner    │ │(optional)│ │(optional)  │        │
│ │Agent   │ │Agent   │ │Agent     │ │          │ │            │        │
│ └────────┘ └────────┘ └──────────┘ └──────────┘ └────────────┘        │
│                                                                         │
│  ┌─────────────────── MOCK SERVICES ────────────────────────┐          │
│  │  IMDS (:1338)  │  Vault (:8200)  │  CI/CD Server (:8080) │          │
│  └──────────────────────────────────────────────────────────┘          │
└─────────────────────────────────────────────────────────────────────────┘
```

## Components

| Component | Port | Description |
|-----------|------|-------------|
| Wazuh Dashboard | 8443 | SIEM visualization and alerts |
| Wazuh API | 55000 | Management API |
| Wazuh Indexer | 9200 | OpenSearch data storage |
| Mock IMDS | 1338 | AWS/Azure metadata simulation |
| HashiCorp Vault | 8200 | Secrets management |
| Mock CI/CD | 8080 | GitHub/GitLab API simulation |
| Vulnerable App | 8888 | App with exposed secrets |

## Attack Scenarios

### Category 1: API Keys & Secrets
- S1-01: Hardcoded credentials in source code
- S1-02: Exposed .env file via web server
- S1-03: Git history credential leak
- S1-04: Environment variable exposure via /proc

### Category 2: Cloud Service Accounts
- S2-01: IMDS credential theft (169.254.169.254)
- S2-02: Over-permissioned IAM role exploitation
- S2-03: Cross-account role assumption abuse
- S2-04: Service account key exfiltration

### Category 3: CI/CD Pipeline
- S3-01: Stolen GitHub Actions runner token
- S3-02: Pipeline injection via PR
- S3-03: OIDC token abuse

### Category 4: Kubernetes
- S4-01: Privileged pod escape
- S4-02: Service account token theft
- S4-03: RBAC misconfiguration exploitation
- S4-04: Secrets mounted in pod

### Category 5: AI Agents
- S5-01: Prompt injection leading to credential disclosure
- S5-02: Agent with excessive API permissions
- S5-03: Tool-use SSRF abuse
- S5-04: Memory/context poisoning

## Wazuh Detection Rules

Custom rules for NHI detection (Rule IDs 100600-100999):

| Range | Category |
|-------|----------|
| 100600-100649 | Credential Discovery |
| 100650-100699 | Cloud Metadata (IMDS) |
| 100700-100749 | Service Account Misuse |
| 100750-100799 | Kubernetes Security |
| 100800-100849 | CI/CD Pipeline |
| 100850-100899 | AI Agent Anomalies |
| 100900-100949 | Secret Pattern Detection |
| 100950-100999 | Correlation Rules |

## Usage

### Start with all optional services

```bash
./scripts/start.sh --all
```

### Run demo scenarios

```bash
# Using the NHI Assistant skill
python .claude/skills/nhi-assistant/scripts/run_demo.py --list    # List scenarios
python .claude/skills/nhi-assistant/scripts/run_demo.py --all     # Run all scenarios
python .claude/skills/nhi-assistant/scripts/run_demo.py --level 2 # Run Level 2 only
python .claude/skills/nhi-assistant/scripts/run_demo.py --scenario s2-01  # Specific scenario

# Or manually execute attacks
podman exec -it cloud-workload curl http://mock-imds:1338/latest/meta-data/iam/security-credentials/
```

### View alerts in Wazuh Dashboard

1. Navigate to https://localhost:8443
2. Go to Security Events
3. Filter by rule.groups: "nhi"

### Stop the testbed

```bash
./scripts/stop.sh        # Keep data
./scripts/stop.sh --clean # Remove all data
```

## Requirements

- **Container Runtime**: Podman 4.0+ (recommended) or Docker 24+
- **Compose**: podman-compose or Docker Compose V2
- **RAM**: 8GB (minimum 6GB)
- **Disk**: 20GB disk space
- **OS**: Linux host (vm.max_map_count must be >= 262144)

**Note**: The testbed auto-detects Podman or Docker. For rootless Podman, port 8443 is used instead of 443.

## Directory Structure

```
machine-identity-discovery/
├── docker-compose.yml          # Main orchestration
├── agents/                     # Wazuh agent containers
│   ├── cloud-workload/
│   ├── vulnerable-app/
│   ├── cicd-runner/
│   ├── k8s-node/
│   └── ai-agent/
├── mock-services/              # Mock cloud services
│   ├── imds/
│   └── cicd-server/
├── wazuh/                      # Wazuh configuration
│   ├── rules/
│   ├── decoders/
│   └── certs/
├── scenarios/                  # Attack scenario definitions
├── scripts/                    # Utility scripts
└── docs/                       # Documentation
    └── handbook/
```

## Documentation

See [docs/handbook/](docs/handbook/) for comprehensive documentation:

- [00-introduction.md](docs/handbook/00-introduction.md) - Project overview
- [01-architecture.md](docs/handbook/01-architecture.md) - System architecture
- [02-installation.md](docs/handbook/02-installation.md) - Setup guide
- [03-wazuh-rules-reference.md](docs/handbook/03-wazuh-rules-reference.md) - Rule documentation
- [04-scenario-catalog.md](docs/handbook/04-scenario-catalog.md) - All attack scenarios
- [08-troubleshooting.md](docs/handbook/08-troubleshooting.md) - Troubleshooting guide

## NHI Assistant Skill

A Claude skill is included for testbed management:

```
.claude/skills/nhi-assistant/
├── SKILL.md                    # Skill definition
├── scripts/
│   ├── run_demo.py            # Demo scenario runner
│   └── health_check.py        # Health verification
└── references/
    ├── architecture.md        # Network topology
    ├── scenarios.md           # 24 attack scenarios
    ├── troubleshooting.md     # Issue solutions
    └── wazuh-rules.md         # Detection rules
```

## License

Internal use - RUDRA Cybersecurity

## Author

Bodhisattva Das - NDC Security Oslo 2026
