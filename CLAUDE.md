# CLAUDE.md
## Project: Machine Identity Security Testbed

### Purpose

A comprehensive testbed for demonstrating and detecting Non-Human Identity (NHI) security threats using Wazuh SIEM. Developed for **NDC Security 2026** talk: "Who Gave the Agent Admin Rights?! Securing Cloud & AI Machine Identities"

---

## Quick Start

```bash
# Prerequisites
sudo sysctl -w vm.max_map_count=262144

# Start the testbed
./scripts/start.sh

# Run health check
python .claude/skills/nhi-assistant/scripts/health_check.py

# Access Wazuh Dashboard
# URL: https://localhost:8443
# User: admin
# Password: admin

# Run demo scenarios
python .claude/skills/nhi-assistant/scripts/run_demo.py --list    # List all scenarios
python .claude/skills/nhi-assistant/scripts/run_demo.py --all     # Run all 24 scenarios
python .claude/skills/nhi-assistant/scripts/run_demo.py --level 2 # Run Level 2 only
```

---

## Project Structure

```
machine-identity-discovery/
├── README.md                    # Project overview
├── CLAUDE.md                    # This file - Claude Code instructions
├── docker-compose.yml           # Main orchestration
├── .claude/skills/nhi-assistant/  # NHI Assistant skill
│   ├── SKILL.md                 # Skill definition
│   ├── scripts/
│   │   ├── run_demo.py          # Demo scenario runner (24 scenarios)
│   │   └── health_check.py      # Health verification with auto-fix
│   └── references/              # Troubleshooting and architecture docs
├── agents/                      # Wazuh agent containers
│   ├── cloud-workload/          # Cloud environment simulation
│   ├── vulnerable-app/          # Intentionally vulnerable Flask app
│   └── cicd-runner/             # CI/CD runner simulation
├── mock-services/               # Mock cloud services
│   └── imds/                    # AWS IMDS simulation
├── wazuh/                       # Wazuh configuration
│   ├── rules/                   # Custom NHI detection rules
│   ├── decoders/                # Custom decoders
│   └── certs/                   # TLS certificates
├── scenarios/                   # Attack scenario definitions
├── scripts/                     # start.sh, stop.sh utilities
├── docs/                        # Documentation
│   ├── handbook/                # Comprehensive setup guide
│   └── ndc-talk/                # Presentation materials
└── tests/                       # Smoke tests
```

---

## Container Runtime

The testbed supports both **Podman** (preferred) and **Docker**:

- Uses `podman-compose` or `docker compose`
- Wazuh Dashboard runs on port **8443** (rootless compatible)
- Auto-detection of runtime in start/stop scripts

---

## Key Components

| Component | Port | Description |
|-----------|------|-------------|
| Wazuh Dashboard | 8443 | SIEM visualization and alerts |
| Wazuh API | 55000 | Management API |
| Wazuh Indexer | 9200 | OpenSearch data storage |
| Mock IMDS | 1338 | AWS metadata simulation |
| HashiCorp Vault | 8200 | Secrets management |
| Vulnerable App | 8888 | App with exposed secrets |

---

## Wazuh Custom Rules

NHI detection rules (Rule IDs 100600-100999):

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

---

## Attack Scenarios

24 scenarios across 5 levels:

- **Level 1**: Credential Discovery (S1-01 to S1-05)
- **Level 2**: Credential Theft (S2-01 to S2-05)
- **Level 3**: Privilege Escalation (S3-01 to S3-05)
- **Level 4**: Lateral Movement (S4-01 to S4-05)
- **Level 5**: Persistence (S5-01 to S5-04)

---

## Wazuh Agent Groups

Required groups (created automatically by start.sh):
- cloud, cicd, runner, ephemeral, vulnerable, demo, ubuntu, production

---

## Common Issues

### Agent enrollment "Invalid group" error
Groups must exist before agent enrollment:
```bash
python .claude/skills/nhi-assistant/scripts/health_check.py --fix
```

### Dashboard not accessible
Ensure port 8443 is used: `https://localhost:8443`

### Low memory for OpenSearch
```bash
sudo sysctl -w vm.max_map_count=262144
```

---

## Claude's Responsibilities

When working on this project, Claude should:

1. **Use the NHI Assistant skill** for testbed management and troubleshooting
2. **Run health checks** before demos: `python .claude/skills/nhi-assistant/scripts/health_check.py`
3. **Use Podman commands** by default (podman, podman-compose)
4. **Reference the correct port** (8443 for dashboard)
5. **Update documentation** when making changes to the testbed
6. **Follow RUDRA documentation standards** for reports

---

## Testing

```bash
# Run smoke tests
python -m pytest tests/smoke/ -v

# Run all tests
python -m pytest tests/ -v
```

---

## Documentation

- [README.md](README.md) - Quick start guide
- [docs/handbook/](docs/handbook/) - Comprehensive documentation
- [.claude/skills/nhi-assistant/](/.claude/skills/nhi-assistant/) - NHI Assistant skill with troubleshooting guides
