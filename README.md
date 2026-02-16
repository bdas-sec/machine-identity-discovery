<div align="center">

# NHI Security Testbed

**The open-source kill chain for non-human identity threats**

[![License: Non-Commercial](https://img.shields.io/badge/License-Non--Commercial-red.svg)]()
[![Wazuh 4.9.2](https://img.shields.io/badge/Wazuh-4.9.2-blue.svg)]()
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Mapped-orange.svg)]()
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED.svg)]()
[![Scenarios](https://img.shields.io/badge/Scenarios-24-green.svg)]()
[![Detection Rules](https://img.shields.io/badge/Detection%20Rules-48-purple.svg)]()
[![Sigma Rules](https://img.shields.io/badge/Sigma%20Rules-60%2B-yellow.svg)]()

*Demonstrate, detect, and defend against the exploitation of service accounts,
IAM roles, CI/CD tokens, and AI agent credentials.*

[Quick Start](#quick-start) |
[Kill Chain](#the-kill-chain) |
[Scenarios](#attack-scenarios) |
[Detection Rules](#detection-rules) |
[Architecture](#architecture) |
[Workshop Guide](#workshop-guide) |
[Contributing](#contributing)

</div>

---

## The Problem

Non-human identities outnumber humans **50:1** in cloud environments.
They carry `AdministratorAccess` by default. They never rotate.
They are never audited. And they are the #1 target for cloud attackers.

**This testbed lets you attack them, detect the attacks, and build the defences.**

---

## Quick Start

```bash
# 1. Set kernel parameter (required for OpenSearch)
sudo sysctl -w vm.max_map_count=262144

# 2. Start the testbed
./scripts/start.sh

# 3. Open Wazuh Dashboard
open https://localhost:8443  # admin / admin
```

The testbed deploys in under 3 minutes. All credentials are fake.

---

## The Kill Chain

Five-stage offensive methodology mapped to MITRE ATT&CK:

| Stage | Technique | MITRE ATT&CK | What Happens |
|-------|-----------|---------------|--------------|
| 1. Discovery | Endpoint enumeration, SSRF identification | T1190 | Find the machine identities |
| 2. Credential Theft | SSRF to IMDS, env var harvesting | T1552.005 | Steal the credentials |
| 3. Privilege Escalation | Over-permissioned IAM roles | T1078.004 | Discover admin access |
| 4. Lateral Movement | Cloud to CI/CD pivot | T1528 | Compromise the pipeline |
| 5. Persistence | Cloud-native API abuse | T1078 | Maintain access invisibly |

**Zero malware. Zero exploits. Just default permissions on machine identities.**

---

## Architecture

```
┌─────────────── Management Network ───────────────┐
│  Wazuh Manager  │  Wazuh Indexer  │  Dashboard    │
└──────────────────────┬───────────────────────────┘
                       │
    ┌──────────────────┼──────────────────┐
    │                  │                  │
┌───┴─── Cloud ────┐ ┌┴── CI/CD ───┐ ┌──┴── K8s ──┐
│ Vulnerable App   │ │ CI/CD Runner│ │ K8s Nodes  │
│ Cloud Workload   │ │ Mock CI/CD  │ │ RBAC Sim   │
│ Mock IMDS        │ │ Server      │ │            │
│ Vault            │ └─────────────┘ └────────────┘
│ AI Agent         │
└──────────────────┘
```

Four isolated Docker networks simulate real cloud segmentation.
48 detection rules fire in real time as you execute attacks.

| Component | Port | Description |
|-----------|------|-------------|
| Wazuh Dashboard | 8443 | SIEM visualization and alerts |
| Wazuh API | 55000 | Management API |
| Wazuh Indexer | 9200 | OpenSearch data storage |
| Mock IMDS | 1338 | AWS/Azure metadata simulation |
| HashiCorp Vault | 8200 | Secrets management |
| Mock CI/CD | 8080 | GitHub/GitLab API simulation |
| Vulnerable App | 8888 | App with exposed secrets |

---

## Attack Scenarios

24 scenarios across 5 progressive levels:

| Level | Focus | Scenarios | Difficulty |
|-------|-------|-----------|------------|
| 1 | Credential Discovery | S1-01 to S1-05 | Beginner |
| 2 | Cloud Credential Theft | S2-01 to S2-05 | Intermediate |
| 3 | CI/CD Pipeline Attacks | S3-01 to S3-05 | Intermediate |
| 4 | Kubernetes Security | S4-01 to S4-05 | Advanced |
| 5 | AI Agent Exploitation | S5-01 to S5-04 | Advanced |

```bash
# Run all scenarios
python .claude/skills/nhi-assistant/scripts/run_demo.py --all

# Run a specific level
python .claude/skills/nhi-assistant/scripts/run_demo.py --level 2

# Run a single scenario
python .claude/skills/nhi-assistant/scripts/run_demo.py --scenario s2-01

# List all available scenarios
python .claude/skills/nhi-assistant/scripts/run_demo.py --list
```

---

## Detection Rules

48 custom Wazuh rules with full MITRE ATT&CK coverage:

| Category | Rule IDs | What It Detects |
|----------|----------|-----------------|
| Credential Discovery | 100600-100609 | .env access, AWS creds, SSH keys, credential harvesting |
| Cloud Metadata (IMDS) | 100650-100658 | AWS/GCP/Azure IMDS abuse, credential theft, burst access |
| Service Account Misuse | 100700-100749 | Service account anomalies, unusual API patterns |
| Kubernetes | 100750-100756 | SA token theft, RBAC probing, etcd access, secrets enum |
| CI/CD Pipeline | 100800-100805 | GitHub/GitLab tokens, runner creds, pipeline tampering |
| AI Agent | 100850-100854 | Shell execution, SSRF, prompt injection, cred access |
| Secret Patterns | 100900-100905 | AWS keys, GitHub tokens, OpenAI keys, private keys |
| Correlation | 100950-100954 | Multi-stage attack chains, supply chain, AI compromise |

### Sigma Rules

60+ rules in [Sigma YAML format](sigma/rules/) for cross-SIEM deployment:

- **Splunk** SPL via pySigma
- **Microsoft Sentinel** KQL
- **Elastic Security** EQL
- **Google Chronicle** YARA-L

Same detection logic, any SIEM. See `sigma/rules/` for the full library.

---

## Use Cases

- **Red Team Training**: Practice NHI exploitation techniques in a safe environment
- **Detection Engineering**: Write and test SIEM rules against realistic NHI attack traffic
- **Purple Team Exercises**: Run attacks and validate detection coverage simultaneously
- **Security Awareness**: Demonstrate to developers why `AdministratorAccess` on service accounts is dangerous
- **Conference Workshops**: Instructor-led hands-on labs with progressive difficulty

---

## Requirements

- **Container Runtime**: Docker 24+ or Podman 4.0+
- **Compose**: Docker Compose V2 or podman-compose
- **RAM**: 8 GB minimum (6 GB allocated to containers)
- **Disk**: 20 GB free space
- **OS**: Linux, macOS (via Docker Desktop/Colima), or WSL2

The testbed auto-detects Podman or Docker. For rootless Podman, port 8443 is used instead of 443.

---

## Documentation

| Document | Description |
|----------|-------------|
| [Handbook](docs/handbook/) | Complete setup, architecture, and scenario guides |
| [Rule Reference](docs/handbook/03-wazuh-rules-reference.md) | Detection rule documentation |
| [Scenario Catalog](docs/handbook/04-scenario-catalog.md) | All 24 attack scenarios |
| [Troubleshooting](docs/handbook/08-troubleshooting.md) | Common issues and fixes |
| [Sigma Rules](sigma/rules/) | 60+ cross-SIEM detection rules |

### NHI Assistant Skill

A Claude Code skill is included for testbed management:

```
.claude/skills/nhi-assistant/
├── SKILL.md                    # Skill definition
├── scripts/
│   ├── run_demo.py            # Demo scenario runner (24 scenarios)
│   └── health_check.py        # Health verification with auto-fix
└── references/                # Architecture, scenarios, troubleshooting
```

---

## Directory Structure

```
machine-identity-discovery/
├── docker-compose.yml          # Main orchestration
├── agents/                     # Wazuh agent containers
│   ├── cloud-workload/         # Cloud environment simulation
│   ├── vulnerable-app/         # Intentionally vulnerable Flask app
│   ├── cicd-runner/            # CI/CD runner simulation
│   ├── k8s-node/               # Kubernetes simulation
│   └── ai-agent/               # AI agent simulation
├── mock-services/              # Mock cloud services
│   └── imds/                   # AWS IMDS simulation
├── wazuh/                      # Wazuh configuration
│   ├── rules/                  # Custom NHI detection rules
│   ├── decoders/               # Custom decoders
│   └── certs/                  # TLS certificates
├── sigma/                      # Sigma detection rules
│   └── rules/                  # 60+ rules across 7 categories
├── scenarios/                  # Attack scenario definitions
├── scripts/                    # start.sh, stop.sh utilities
├── api/                        # FastAPI backend
├── docs/                       # Documentation
│   └── handbook/               # Comprehensive setup guide
└── tests/                      # Smoke and E2E tests
```

---

## Contributing

We welcome contributions. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Priority areas:
- New attack scenarios (especially Levels 4-5)
- Detection rules for additional NHI patterns
- Sigma rule translations for cross-SIEM portability
- Documentation improvements

---

## Presented At

- **CyberWiseCon Europe 2026** — "From Admin by Design to Breach by Default"
- **NDC Security 2026** — "Who Gave the Agent Admin Rights?!"

---

## Author

**Bodhisattva Das**
- GitHub: [@bdas-sec](https://github.com/bdas-sec)
- LinkedIn: [bdas1201](https://linkedin.com/in/bdas1201)
- Twitter: [@bdas1201](https://twitter.com/bdas1201)

---

## License

Non-Commercial Use License. Free for personal, educational, research, and
security training purposes. Commercial use requires a separate license.
See [LICENSE](LICENSE) for full terms.
