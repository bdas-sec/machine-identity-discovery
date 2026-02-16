# Contributing to NHI Security Testbed

Thank you for your interest in contributing to the NHI Security Testbed — a purple team framework for non-human identity security.

## Table of Contents

- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Code Style](#code-style)
- [Adding Attack Scenarios](#adding-attack-scenarios)
- [Adding Detection Rules](#adding-detection-rules)
- [Running Tests](#running-tests)
- [Project Architecture](#project-architecture)
- [Pull Request Process](#pull-request-process)
- [License](#license)

---

## Getting Started

### Prerequisites

- Python 3.11+
- Docker or Podman (Podman preferred for rootless operation)
- Docker Compose / podman-compose
- Git

### Setup

```bash
# Clone the repository
git clone https://github.com/bdas-sec/machine-identity-discovery.git
cd machine-identity-discovery

# Install all dependencies (API, Sigma pipeline, tests, dev tools)
pip install -e ".[all]"

# Set vm.max_map_count for OpenSearch (required)
sudo sysctl -w vm.max_map_count=262144

# Start the testbed
./scripts/start.sh

# Verify everything is running
python .claude/skills/nhi-assistant/scripts/health_check.py
```

### Dependency Groups

The project uses optional dependency groups defined in `pyproject.toml`:

| Group | Install Command | Contents |
|-------|----------------|----------|
| `api` | `pip install -e ".[api]"` | FastAPI, uvicorn, pydantic, httpx |
| `sigma` | `pip install -e ".[sigma]"` | pySigma, Splunk/Sentinel/Elastic backends |
| `test` | `pip install -e ".[test]"` | pytest, pytest-cov, docker, lxml, jsonschema |
| `dev` | `pip install -e ".[dev]"` | ruff, mypy, pre-commit |
| `all` | `pip install -e ".[all]"` | All of the above |

---

## Development Workflow

1. **Fork** the repository and create a feature branch:
   ```bash
   git checkout -b feat/your-feature-name
   ```

2. **Branch naming conventions**:
   - `feat/` — New features or scenarios
   - `fix/` — Bug fixes
   - `docs/` — Documentation changes
   - `rules/` — New or updated detection rules
   - `test/` — Test additions or improvements

3. **Make your changes**, ensuring tests pass locally.

4. **Commit** with a clear, descriptive message:
   ```bash
   git commit -m "Add S6-01 OAuth token theft scenario with Sigma + Wazuh rules"
   ```

5. **Push** and open a Pull Request against `main`.

---

## Code Style

### Python

We use [ruff](https://docs.astral.sh/ruff/) for linting and formatting:

```bash
# Check for lint issues
ruff check .

# Auto-fix lint issues
ruff check . --fix

# Format code
ruff format .
```

Configuration (from `pyproject.toml`):
- **Target**: Python 3.11
- **Line length**: 120 characters
- **Rules**: E, F, I, N, W, UP, S, B, A, C4, SIM
- **Ignored**: `S101` (assert in tests), `S603`/`S607` (subprocess — expected in testbed)

### Type Checking

We use mypy with gradual adoption:

```bash
mypy api/ src/
```

Untyped definitions are currently allowed (`disallow_untyped_defs = false`). New code should include type annotations where practical.

### XML (Wazuh Rules & Decoders)

- Use 2-space indentation
- Each `<rule>` element must include `id` and `level` attributes
- Include a `<description>` for every rule
- Add `<mitre>` mapping where applicable

### YAML (Sigma Rules)

- Follow the [Sigma specification](https://sigmahq.io/docs/basics/rules.html)
- Include `title`, `status`, `description`, `logsource`, `detection`, `level`, and `tags` fields
- Use MITRE ATT&CK tags in the format `attack.t1552.005`

---

## Adding Attack Scenarios

Attack scenarios are JSON files in the `scenarios/` directory, organised by category:

```
scenarios/
├── category-1-secrets/       # Credential Discovery
├── category-2-cloud/         # Cloud Credential Theft
├── category-3-cicd/          # CI/CD Pipeline Attacks
├── category-4-kubernetes/    # Kubernetes Security
└── category-5-ai-agents/     # AI Agent Exploitation
```

### Step-by-Step

1. **Choose a category** and assign the next scenario ID (e.g., `S2-06`).

2. **Create the scenario JSON** following this structure (see `scenarios/category-2-cloud/s2-01-imds-credential-theft.json` as a template):

   ```json
   {
     "id": "S2-06",
     "name": "Your Scenario Name",
     "category": "Cloud Service Accounts",
     "version": "1.0",
     "description": "Brief description of the attack",
     "difficulty": "Medium",
     "real_world_relevance": "Reference to real breach or CVE",
     "mitre_attack": {
       "tactics": ["Credential Access"],
       "techniques": [
         {"id": "T1552.005", "name": "Unsecured Credentials: Cloud Instance Metadata API"}
       ]
     },
     "prerequisites": {
       "containers": ["cloud-workload", "mock-imds"],
       "network": "cloud_net"
     },
     "phases": [
       {
         "name": "Phase Name",
         "description": "What this phase does",
         "actions": [
           {
             "type": "http_request",
             "target": "http://172.41.0.100:1338/...",
             "method": "GET",
             "expected_status": 200
           }
         ]
       }
     ],
     "expected_wazuh_alerts": [
       {"rule_id": "100650", "level": 8, "description": "Expected alert"}
     ],
     "demo_script": {
       "container": "cloud-workload",
       "command": "curl http://..."
     }
   }
   ```

3. **Write corresponding detection rules** — both Wazuh XML and Sigma YAML (see next section).

4. **Add E2E tests** in `tests/e2e/` under the appropriate category directory.

5. **Update the scenario catalog** in `docs/handbook/04-scenario-catalog.md`.

### Naming Convention

Files follow the pattern: `s{category}-{number}-{kebab-case-name}.json`

Examples: `s1-01-hardcoded-credentials.json`, `s5-03-tool-use-ssrf.json`

---

## Adding Detection Rules

Every new scenario should include detection rules in two formats.

### Wazuh Rules (XML)

Add rules to `wazuh/rules/nhi-detection-rules.xml` using the appropriate ID range:

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

Example rule:

```xml
<rule id="100650" level="8">
  <decoded_as>nhi-imds</decoded_as>
  <match>169.254.169.254</match>
  <description>NHI: AWS IMDS metadata access detected</description>
  <mitre>
    <id>T1552.005</id>
  </mitre>
  <group>nhi,imds,cloud,</group>
</rule>
```

### Sigma Rules (YAML)

Add rules to `sigma/rules/{category}/` following the naming pattern `nhi_{category}_{description}.yml`:

```yaml
title: NHI - AWS IMDS Access Detected
id: <generate-uuid>
status: experimental
description: Detects access to AWS Instance Metadata Service
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    CommandLine|contains: '169.254.169.254'
  condition: selection
level: high
tags:
  - attack.credential_access
  - attack.t1552.005
```

### Sigma Conversion

Convert Sigma rules to SIEM-native formats using the pySigma pipeline:

```bash
# Convert all rules to all formats
python scripts/sigma_convert.py --format all

# Convert a specific category to Splunk
python scripts/sigma_convert.py --format splunk --category cloud-imds

# List available categories
python scripts/sigma_convert.py --list-categories
```

### Decoders

If your scenario introduces a new log format, add a decoder to `wazuh/decoders/nhi-decoders.xml`. Decoders parse raw log lines into structured fields that rules can match against.

---

## Running Tests

### Test Tiers

| Tier | Marker | Docker Required | Command |
|------|--------|----------------|---------|
| Unit | `unit` | No | `pytest -m unit` |
| Rule Validation | `rules` | No | `pytest tests/rules/` |
| Smoke | `smoke` | Yes | `pytest -m smoke` |
| Integration | `integration` | Yes | `pytest -m integration` |
| E2E | `e2e` | Yes | `pytest -m e2e` |

### Running Tests

```bash
# Run all unit tests (no Docker needed)
pytest -m unit -v

# Run rule syntax validation
pytest tests/rules/ -v

# Run smoke tests (requires running testbed)
pytest -m smoke -v

# Run E2E tests for a specific category
pytest -m category_1 -v
pytest -m category_2 -v

# Run all tests with coverage
pytest --cov=api --cov=src --cov-report=html

# Run tests in parallel
pytest -n auto -m unit
```

### Test Structure

```
tests/
├── conftest.py              # Shared fixtures (Docker client, API clients, loaders)
├── smoke/                   # Service availability checks
├── unit/                    # No-Docker unit tests
├── integration/             # Cross-service tests
├── rules/                   # Rule syntax and decoder validation
├── e2e/                     # End-to-end scenario tests
│   ├── category_1_secrets/
│   ├── category_2_cloud/
│   ├── category_3_cicd/
│   ├── category_4_kubernetes/
│   └── category_5_ai_agents/
└── helpers/                 # Shared test utilities
```

### CI/CD

Tests run automatically via GitHub Actions (`.github/workflows/test.yml`):
- **Push to `main`/`develop`**: Unit tests + rule validation
- **Pull requests**: Unit tests + rule validation
- **Manual dispatch**: Full suite including integration and E2E (by category matrix)

---

## Project Architecture

### Docker Networks

| Network | CIDR | Purpose |
|---------|------|---------|
| `mgmt_net` | 172.40.0.0/24 | Wazuh manager, indexer, dashboard |
| `cloud_net` | 172.41.0.0/24 | Cloud simulation (apps, IMDS, Vault, AI agent) |
| `cicd_net` | 172.42.0.0/24 | CI/CD pipeline simulation |
| `k8s_net` | 172.43.0.0/24 | Kubernetes simulation |

### Key Services

| Service | Port | Description |
|---------|------|-------------|
| Wazuh Dashboard | 8443 | SIEM visualisation |
| Wazuh API | 55000 | Management API |
| Wazuh Indexer | 9200 | OpenSearch storage |
| NHI API | 8000 | FastAPI REST API |
| Mock IMDS | 1338 | AWS metadata simulation |
| HashiCorp Vault | 8200 | Secrets management |
| Mock CI/CD | 8080 | GitHub/GitLab simulation |
| Vulnerable App | 8888 | Intentionally vulnerable Flask app |

### Directory Map

| Directory | Contents |
|-----------|----------|
| `api/` | FastAPI REST API (routes, models, services) |
| `agents/` | Wazuh agent container configurations |
| `mock-services/` | Mock cloud/CI/CD services |
| `scenarios/` | Attack scenario JSON definitions |
| `sigma/` | Sigma rules and conversion output |
| `src/` | Sigma pipeline and scenario runner |
| `scripts/` | Lifecycle scripts and Sigma converter |
| `tests/` | Test suite (smoke, unit, integration, E2E) |
| `wazuh/` | Wazuh rules, decoders, and certificates |
| `docs/` | Handbook, architecture docs, conference materials |

---

## Pull Request Process

1. **Ensure all tests pass** — at minimum, unit tests and rule validation.
2. **Run linting**: `ruff check . && ruff format --check .`
3. **Update documentation** if your change affects scenarios, rules, or architecture.
4. **Fill out the PR description** with:
   - What changed and why
   - New scenarios or rules added (with IDs)
   - MITRE ATT&CK mappings for new detections
   - Test results
5. **One approval required** before merge.

### Checklist for New Scenarios

- [ ] Scenario JSON in `scenarios/{category}/`
- [ ] Wazuh rule(s) in `wazuh/rules/nhi-detection-rules.xml`
- [ ] Sigma rule(s) in `sigma/rules/{category}/`
- [ ] E2E test(s) in `tests/e2e/{category}/`
- [ ] Scenario catalog updated in `docs/handbook/04-scenario-catalog.md`
- [ ] MITRE ATT&CK technique mapped
- [ ] `ruff check .` passes
- [ ] `pytest -m unit` passes

---

## License

This project is released under a Non-Commercial Use License. Contributions are welcome for personal learning, academic research, security training, and conference demonstrations. See `LICENSE` for details.

By contributing, you agree that your contributions will be licensed under the same terms.
