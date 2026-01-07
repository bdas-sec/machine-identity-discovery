---
name: nhi-assistant
description: NHI (Non-Human Identity) Security Testbed assistant for the NDC Security 2026 demo. Use this skill when working with the machine-identity-discovery project, managing the Wazuh-based security testbed, running demo scenarios, troubleshooting container/agent issues, or executing attack simulations. Covers testbed lifecycle management, agent enrollment, Wazuh rules, and all 24 attack scenarios across 5 training levels.
---

# NHI Security Testbed Assistant

## Project Overview

The **Machine Identity Security Testbed** is a comprehensive environment for demonstrating and detecting Non-Human Identity (NHI) security threats. It uses Wazuh SIEM to monitor cloud workloads, CI/CD runners, and vulnerable applications for credential theft, privilege escalation, and identity abuse.

**Project Location:** `machine-identity-discovery/` (cloned repository)

### Key Components

| Component | Purpose | Port |
|-----------|---------|------|
| Wazuh Manager | SIEM core, agent management, alerts | 55000 (API), 1514-1515 |
| Wazuh Indexer | OpenSearch for alert storage | 9200 |
| Wazuh Dashboard | Web UI for monitoring | 8443 |
| Mock IMDS | Simulates AWS metadata service | 1338 |
| Vault | HashiCorp Vault for secrets | 8200 |
| Mock CI/CD | Simulates GitHub Actions/GitLab CI | 8080 |
| Cloud Workload | Simulated EC2 instance with Wazuh agent | - |
| Vulnerable App | Intentionally vulnerable Flask app | 8888 |
| CI/CD Runner | Simulated GitHub runner | - |

### Credentials

- **Dashboard:** admin / admin
- **Indexer:** admin / admin
- **API:** wazuh-wui / MyS3cr3tP@ssw0rd
- **Vault:** root-token-for-demo

## Testbed Management

### Starting the Testbed

```bash
cd machine-identity-discovery
./scripts/start.sh
```

The start script automatically handles:
1. Checks prerequisites (podman/docker, vm.max_map_count, memory)
2. Sets up environment from .env.example
3. Generates SSL certificates if needed
4. Fixes certificate permissions for rootless Podman
5. Initializes OpenSearch security configuration
6. Builds custom agent images
7. Starts all containers
8. Waits for services to be healthy (Manager, Dashboard, IMDS)
9. **Creates agent groups via API** (cloud, cicd, runner, ephemeral, vulnerable, demo, ubuntu, production)
10. **Restarts agent containers** so they re-enroll with groups
11. Waits for agents to connect (verifies all 3 agents are active)
12. Prints access summary with credentials

**Note**: The start script now handles agent group creation automatically, solving the "Invalid group" enrollment issue.

### Stopping the Testbed

```bash
./scripts/stop.sh          # Preserves data, backs up groups
./scripts/stop.sh --clean  # Removes all data and volumes
```

### Checking Health

```bash
# Container status
podman-compose ps

# Run smoke tests
.venv/bin/python -m pytest tests/smoke/ -v

# Check agents via API
curl -sk -u wazuh-wui:MyS3cr3tP@ssw0rd -X POST \
  "https://localhost:55000/security/user/authenticate?raw=true" > /tmp/token.txt
TOKEN=$(cat /tmp/token.txt)
curl -sk -H "Authorization: Bearer $TOKEN" "https://localhost:55000/agents"
```

## Agent Architecture

Three Wazuh agents monitor different workload types:

| Agent | Groups | Simulates |
|-------|--------|-----------|
| cloud-workload-001 | cloud, ubuntu, production | EC2 instance with IAM role |
| vulnerable-app-001 | cloud, vulnerable, demo | Web app with exposed secrets |
| cicd-runner-001 | cicd, runner, ephemeral | GitHub Actions runner |

### Required Agent Groups

Groups must exist before agents can enroll:
- cloud, cicd, runner, ephemeral, vulnerable, demo, ubuntu, production

Create groups via API:
```bash
for group in cloud cicd runner ephemeral vulnerable demo ubuntu production; do
  curl -sk -H "Authorization: Bearer $TOKEN" \
    -X POST "https://localhost:55000/groups" \
    -H "Content-Type: application/json" \
    -d "{\"group_id\": \"$group\"}"
done
```

## Troubleshooting

See [troubleshooting.md](references/troubleshooting.md) for detailed solutions.

### Quick Fixes

**Agents not enrolling ("Invalid group" error):**
```bash
# Create missing groups - see Agent Architecture section above
```

**ossec.conf permission error (line 0):**
- Agent entrypoint must set: `chown root:wazuh /var/ossec/etc/ossec.conf && chmod 640`
- Already fixed in current entrypoint scripts

**Dashboard connecting to localhost:9200:**
- Mount opensearch_dashboards.yml config with correct indexer hostname
- Already configured in docker-compose.yml

**Port 443 permission denied (rootless podman):**
- Use port 8443 instead of 443 for dashboard
- Already configured in docker-compose.yml

**Container name mismatches in tests:**
- Use hyphen format: `wazuh-manager` not `wazuh.manager`

## Demo Scenarios

See [scenarios.md](references/scenarios.md) for complete scenario catalog.

### Running Scenarios

**One-click full demo:**
```bash
python ~/.claude/skills/nhi-assistant/scripts/run_demo.py --all
```

**Run specific scenario:**
```bash
python ~/.claude/skills/nhi-assistant/scripts/run_demo.py --scenario s2-01
```

**Run by level:**
```bash
python ~/.claude/skills/nhi-assistant/scripts/run_demo.py --level 2
```

### Scenario Categories

| Level | Focus | Scenarios |
|-------|-------|-----------|
| 1 | Credential Discovery | S1-01 to S1-05 |
| 2 | Credential Theft | S2-01 to S2-05 |
| 3 | Privilege Escalation | S3-01 to S3-05 |
| 4 | Lateral Movement | S4-01 to S4-05 |
| 5 | Persistence | S5-01 to S5-04 |

## Custom Wazuh Rules

See [wazuh-rules.md](references/wazuh-rules.md) for detection rule reference.

The testbed includes custom rules for detecting:
- IMDS credential access (169.254.169.254)
- Environment variable harvesting
- JWT/API key exposure
- Service account token access
- Certificate and key file access

## Development Workflow

### Running Tests

```bash
# Activate virtual environment
source .venv/bin/activate

# Run all smoke tests
python -m pytest tests/smoke/ -v

# Run specific test file
python -m pytest tests/smoke/test_agent_enrollment.py -v
```

### Rebuilding Images

```bash
# Rebuild all images
./scripts/start.sh --build

# Or manually
podman-compose build --no-cache
```

### Viewing Logs

```bash
# All services
podman-compose logs -f

# Specific service
podman-compose logs -f wazuh-manager
podman-compose logs -f cloud-workload
```

## Files Reference

### Key Configuration Files

- `docker-compose.yml` - Container orchestration
- `wazuh/dashboard-config/opensearch_dashboards.yml` - Dashboard config
- `agents/*/entrypoint.sh` - Agent startup scripts
- `wazuh/rules/*.xml` - Custom detection rules
- `wazuh/decoders/*.xml` - Custom log decoders

### Test Files

- `tests/smoke/test_agent_enrollment.py` - Agent registration tests
- `tests/smoke/test_service_health.py` - Service health checks
- `tests/smoke/test_docker_infrastructure.py` - Container tests
- `tests/helpers/docker_utils.py` - Podman/Docker utilities

### Scripts

- `scripts/start.sh` - Start testbed with group restoration
- `scripts/stop.sh` - Stop testbed with group backup
