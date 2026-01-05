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
- **Docker**: Version 24.0 or higher
- **Docker Compose**: V2 (bundled with Docker)
- **Git**: For cloning the repository

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
| `INDEXER_PASSWORD` | SecretPassword | OpenSearch admin password |
| `API_PASSWORD` | MyS3cr3tP@ssw0rd | Wazuh API password |
| `DASHBOARD_PASSWORD` | SecretPassword | Dashboard admin password |

### Step 3: Generate Certificates

```bash
# Certificates are generated automatically by start.sh
# Or manually run:
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
docker compose ps

# Expected output:
# NAME                 STATUS    PORTS
# wazuh-manager        running   0.0.0.0:55000->55000/tcp
# wazuh-indexer        running   0.0.0.0:9200->9200/tcp
# wazuh-dashboard      running   0.0.0.0:443->443/tcp
# cloud-workload       running
# vulnerable-app       running   0.0.0.0:8888->8888/tcp
# mock-imds            running   0.0.0.0:1338->1338/tcp
```

### Step 6: Access Wazuh Dashboard

1. Open browser: https://localhost:443
2. Accept self-signed certificate warning
3. Login with:
   - **Username**: admin
   - **Password**: SecretPassword

## Service Health Checks

### Check Wazuh Manager

```bash
# API health check
curl -k -u wazuh-wui:MyS3cr3tP@ssw0rd https://localhost:55000/

# Check manager status
docker exec wazuh-manager /var/ossec/bin/wazuh-control status
```

### Check Agent Registration

```bash
# List registered agents
docker exec wazuh-manager /var/ossec/bin/agent_control -l

# Expected output:
# ID: 001, Name: cloud-workload, IP: 172.41.0.10, Status: Active
# ID: 002, Name: vulnerable-app, IP: 172.41.0.20, Status: Active
# ID: 003, Name: cicd-runner, IP: 172.42.0.10, Status: Active
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

# Stop specific services
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
# Check logs
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
docker compose -f wazuh/certs/generate-certs.yml run --rm generator

# Restart services
docker compose restart
```

### Agent Not Connecting

```bash
# Check agent logs
docker exec cloud-workload cat /var/ossec/logs/ossec.log

# Common issues:
# - Manager not reachable: Check network connectivity
# - Auth error: Verify WAZUH_MANAGER and WAZUH_REGISTRATION_PASSWORD
```

### Port Conflicts

```bash
# Check what's using a port
sudo lsof -i :443
sudo lsof -i :9200

# Modify ports in .env if needed
DASHBOARD_PORT=8443
INDEXER_PORT=9201
```

### Memory Issues

```bash
# Check Docker memory usage
docker stats

# Reduce memory for development
# Edit docker-compose.yml and set:
# mem_limit: 512m for agents
```

## Upgrading

### Wazuh Version Upgrade

1. Update `WAZUH_VERSION` in `.env`
2. Pull new images: `docker compose pull`
3. Restart: `docker compose up -d`

### Testbed Updates

```bash
# Pull latest changes
git pull origin main

# Recreate containers
docker compose up -d --force-recreate
```

## Uninstallation

```bash
# Stop all containers
docker compose down

# Remove all data volumes
docker compose down -v

# Remove images
docker compose down --rmi all

# Clean up networks
docker network prune -f
```

## Next Steps

After installation:
1. Review the Wazuh Dashboard at https://localhost:443
2. Check that all agents are registered and active
3. Run your first scenario: `python src/scenario-runner/runner.py --run S2-01`
4. See [Chapter 3: Wazuh Rules Reference](03-wazuh-rules-reference.md)
