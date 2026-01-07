# Chapter 2: Installation Guide

## Prerequisites

### Hardware Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU | 4 cores | 8 cores |
| RAM | 6 GB | 8 GB |
| Disk | 20 GB | 40 GB |
| Network | Internet access for image pulls |

### Software Requirements

- **Operating System**: Linux (Ubuntu 20.04+, Debian 11+, RHEL 8+)
- **Container Runtime**: One of the following:
  - **Podman 4.0+** (recommended) with podman-compose
  - **Docker 24.0+** with Docker Compose V2
- **Git**: For cloning the repository

> **Note**: The testbed auto-detects Podman or Docker. Podman is preferred for rootless container operation. For rootless Podman, port 8443 is used instead of 443.

### System Configuration

```bash
# Required: Increase virtual memory map count for OpenSearch
sudo sysctl -w vm.max_map_count=262144

# Make persistent across reboots
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```

## Installation Steps

### Step 1: Clone the Repository

```bash
git clone https://github.com/RUDRA-Cybersecurity/machine-identity-discovery.git
cd machine-identity-discovery
```

### Step 2: Configure Environment

```bash
# Copy environment template
cp .env.example .env

# Edit configuration (optional - defaults work for demo)
nano .env
```

**Key Environment Variables**:

| Variable | Default | Description |
|----------|---------|-------------|
| `WAZUH_VERSION` | 4.9.2 | Wazuh stack version |
| `INDEXER_PASSWORD` | admin | OpenSearch admin password |
| `API_PASSWORD` | MyS3cr3tP@ssw0rd | Wazuh API password |
| `DASHBOARD_PASSWORD` | admin | Dashboard admin password |

### Step 3: Generate Certificates

```bash
# Certificates are generated automatically by start.sh
# Or manually run:
# For Podman:
podman-compose -f wazuh/certs/generate-certs.yml run --rm generator
# For Docker:
docker compose -f wazuh/certs/generate-certs.yml run --rm generator
```

### Step 4: Start the Testbed

```bash
# Start all core services
./scripts/start.sh

# Or start with optional services
./scripts/start.sh --all

# Start specific profiles
./scripts/start.sh --profile k8s --profile ai
```

### Step 5: Verify Installation

```bash
# Check container status
podman ps  # or: docker compose ps

# Expected output:
# NAME                 STATUS    PORTS
# wazuh-manager        running   0.0.0.0:55000->55000/tcp
# wazuh-indexer        running   0.0.0.0:9200->9200/tcp
# wazuh-dashboard      running   0.0.0.0:8443->8443/tcp
# cloud-workload       running
# vulnerable-app       running   0.0.0.0:8888->8888/tcp
# cicd-runner          running
# mock-imds            running   0.0.0.0:1338->1338/tcp
# vault                running   0.0.0.0:8200->8200/tcp
```

### Step 6: Access Wazuh Dashboard

1. Open browser: https://localhost:8443
2. Accept self-signed certificate warning
3. Login with:
   - **Username**: admin
   - **Password**: admin

## Service Health Checks

### Check Wazuh Manager

```bash
# API health check
curl -k -u wazuh-wui:MyS3cr3tP@ssw0rd https://localhost:55000/

# Check manager status
podman exec wazuh-manager /var/ossec/bin/wazuh-control status
```

### Check Agent Registration

```bash
# List registered agents
podman exec wazuh-manager /var/ossec/bin/agent_control -l

# Expected agents:
# - cloud-workload-001 (cloud, ubuntu, production groups)
# - vulnerable-app-001 (vulnerable, demo groups)
# - cicd-runner-001 (cicd, runner, ephemeral groups)

# Or use the health check script:
python .claude/skills/nhi-assistant/scripts/health_check.py
```

### Check Mock Services

```bash
# Mock IMDS
curl http://localhost:1338/latest/meta-data/

# Mock CI/CD
curl http://localhost:8080/

# Vault
curl http://localhost:8200/v1/sys/health
```

## Stopping the Testbed

```bash
# Stop all containers (preserve data)
./scripts/stop.sh

# Stop and remove all data
./scripts/stop.sh --clean

# Stop specific services (Podman)
podman stop vulnerable-app mock-imds
# Or (Docker)
docker compose stop vulnerable-app mock-imds
```

## Profiles and Optional Components

### Available Profiles

| Profile | Components | Use Case |
|---------|------------|----------|
| (default) | Wazuh stack, cloud-workload, vulnerable-app, mock-imds | Core demo |
| `k8s` | k8s-node simulation | Kubernetes scenarios |
| `ai` | ai-agent | AI agent scenarios |
| `all` | All components | Complete demo |

### Starting with Profiles

```bash
# Start with Kubernetes components
./scripts/start.sh --profile k8s

# Start with AI agent
./scripts/start.sh --profile ai

# Start everything
./scripts/start.sh --all
```

## Troubleshooting Installation

### Container Won't Start

```bash
# Check logs (Podman)
podman logs wazuh-indexer
podman logs wazuh-manager

# Or (Docker)
docker compose logs wazuh-indexer
docker compose logs wazuh-manager

# Common issue: vm.max_map_count
sudo sysctl vm.max_map_count
# If < 262144, run:
sudo sysctl -w vm.max_map_count=262144
```

### Certificate Errors

```bash
# Regenerate certificates
podman-compose -f wazuh/certs/generate-certs.yml run --rm generator
# Or:
docker compose -f wazuh/certs/generate-certs.yml run --rm generator

# Restart services
podman restart wazuh-manager wazuh-indexer wazuh-dashboard
```

### Agent Not Connecting

```bash
# Check agent logs
podman exec cloud-workload cat /var/ossec/logs/ossec.log

# Common issues:
# - Manager not reachable: Check network connectivity
# - Auth error: Verify WAZUH_MANAGER and WAZUH_REGISTRATION_PASSWORD
# - Invalid group: Agent groups must exist before enrollment (see below)
```

### Agent Group Issues

Agents require their groups to exist before enrollment. If you see "Invalid group" errors:

```bash
# Get API token
TOKEN=$(curl -sk -u wazuh-wui:MyS3cr3tP@ssw0rd -X POST \
  "https://localhost:55000/security/user/authenticate?raw=true")

# Create required groups
for group in cloud cicd runner ephemeral vulnerable demo ubuntu production; do
  curl -sk -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -X POST "https://localhost:55000/groups" \
    -d "{\"group_id\": \"$group\"}"
done

# Restart agent containers to re-enroll
podman restart cloud-workload vulnerable-app cicd-runner
```

### Port Conflicts

```bash
# Check what's using a port
sudo lsof -i :8443
sudo lsof -i :9200

# The testbed uses port 8443 by default for rootless Podman
# Modify ports in docker-compose.yml if needed
```

### Memory Issues

```bash
# Check container memory usage
podman stats  # or: docker stats

# Reduce memory for development
# Edit docker-compose.yml and set:
# mem_limit: 512m for agents
```

### ossec.conf Permission Errors

If Wazuh agents fail with permission errors on ossec.conf:

```bash
# Fix ownership inside container
podman exec cloud-workload chown root:wazuh /var/ossec/etc/ossec.conf
podman exec cloud-workload chmod 640 /var/ossec/etc/ossec.conf

# Restart agent
podman restart cloud-workload
```

## Upgrading

### Wazuh Version Upgrade

1. Update `WAZUH_VERSION` in `.env`
2. Pull new images: `podman-compose pull` (or `docker compose pull`)
3. Restart: `./scripts/stop.sh && ./scripts/start.sh`

### Testbed Updates

```bash
# Pull latest changes
git pull origin main

# Recreate containers
./scripts/stop.sh
./scripts/start.sh
```

## Uninstallation

```bash
# Stop all containers
./scripts/stop.sh --clean

# For complete cleanup (Podman)
podman system prune -af
podman volume prune -f

# Or (Docker)
docker compose down -v --rmi all
docker network prune -f
```

## Next Steps

After installation:
1. Review the Wazuh Dashboard at https://localhost:8443
2. Check that all agents are registered and active
3. Run health check: `python .claude/skills/nhi-assistant/scripts/health_check.py`
4. Run your first scenario: `python .claude/skills/nhi-assistant/scripts/run_demo.py --scenario s2-01`
5. See [Chapter 3: Wazuh Rules Reference](03-wazuh-rules-reference.md)
