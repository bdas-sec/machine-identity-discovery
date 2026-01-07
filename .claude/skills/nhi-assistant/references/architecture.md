# NHI Testbed Architecture

## Overview

The Machine Identity Security Testbed simulates a cloud environment with multiple workload types, each monitored by Wazuh agents. The architecture is designed to demonstrate real-world NHI attack scenarios and detection capabilities.

## Network Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Host Machine (Podman)                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌─────────────────── wazuh-net (172.41.0.0/24) ───────────────────┐    │
│  │                                                                   │    │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │    │
│  │  │ wazuh.manager   │  │ wazuh.indexer   │  │ wazuh.dashboard │  │    │
│  │  │ 172.41.0.254    │  │ 172.41.0.253    │  │ 172.41.0.252    │  │    │
│  │  │ :55000 :1514-15 │  │ :9200           │  │ :5601→8443      │  │    │
│  │  └─────────────────┘  └─────────────────┘  └─────────────────┘  │    │
│  │                                                                   │    │
│  │  ┌─────────────────┐  ┌─────────────────┐                        │    │
│  │  │ cloud-workload  │  │ vulnerable-app  │                        │    │
│  │  │ 172.41.0.10     │  │ 172.41.0.20     │                        │    │
│  │  │ Wazuh Agent     │  │ :8080→8888      │                        │    │
│  │  └─────────────────┘  └─────────────────┘                        │    │
│  │                                                                   │    │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │    │
│  │  │ mock-imds       │  │ vault           │  │ mock-cicd       │  │    │
│  │  │ 172.41.0.100    │  │ 172.41.0.101    │  │ 172.41.0.102    │  │    │
│  │  │ :1338           │  │ :8200           │  │ :8080           │  │    │
│  │  └─────────────────┘  └─────────────────┘  └─────────────────┘  │    │
│  │                                                                   │    │
│  └───────────────────────────────────────────────────────────────────┘    │
│                                                                          │
│  ┌─────────────────── cicd-net (172.42.0.0/24) ────────────────────┐    │
│  │                                                                   │    │
│  │  ┌─────────────────┐                                             │    │
│  │  │ cicd-runner     │  ← Connected to both networks               │    │
│  │  │ 172.42.0.10     │                                             │    │
│  │  │ Wazuh Agent     │                                             │    │
│  │  └─────────────────┘                                             │    │
│  │                                                                   │    │
│  └───────────────────────────────────────────────────────────────────┘    │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘

Exposed Ports (localhost):
  - 8443  → Wazuh Dashboard
  - 55000 → Wazuh API
  - 9200  → Wazuh Indexer
  - 8200  → Vault UI
  - 1338  → Mock IMDS
  - 8080  → Mock CI/CD
  - 8888  → Vulnerable App
```

## Component Details

### Wazuh Stack

#### Wazuh Manager
- **Image:** wazuh/wazuh-manager:4.9.2
- **Purpose:** Central SIEM manager, receives logs from agents, processes rules
- **Key Directories:**
  - `/var/ossec/etc/` - Configuration
  - `/var/ossec/logs/` - Logs and alerts
  - `/var/ossec/ruleset/` - Detection rules
  - `/var/ossec/etc/decoders/` - Log decoders

#### Wazuh Indexer
- **Image:** wazuh/wazuh-indexer:4.9.2
- **Purpose:** OpenSearch-based storage for alerts and events
- **Credentials:** admin / admin (same as Dashboard)

#### Wazuh Dashboard
- **Image:** wazuh/wazuh-dashboard:4.9.2
- **Purpose:** Web UI for viewing alerts, managing agents
- **Credentials:** admin / admin
- **Config:** `/usr/share/wazuh-dashboard/config/opensearch_dashboards.yml`

### Agent Workloads

#### Cloud Workload Agent
- **Image:** nhi-testbed/cloud-workload:latest
- **Simulates:** EC2 instance with IAM role
- **Groups:** cloud, ubuntu, production
- **Environment:**
  - `INSTANCE_ID` - Simulated EC2 instance ID
  - `INSTANCE_TYPE` - EC2 instance type
  - `IAM_ROLE` - Attached IAM role name

#### Vulnerable App Agent
- **Image:** nhi-testbed/vulnerable-app:latest
- **Simulates:** Web application with exposed secrets
- **Groups:** cloud, vulnerable, demo
- **Endpoints:**
  - `/.env` - Exposed environment file
  - `/debug` - Environment variable dump
  - `/config` - Hardcoded secrets exposure

#### CI/CD Runner Agent
- **Image:** nhi-testbed/cicd-runner:latest
- **Simulates:** GitHub Actions self-hosted runner
- **Groups:** cicd, runner, ephemeral
- **Environment:**
  - `GITHUB_TOKEN` - Simulated PAT
  - `RUNNER_NAME` - Runner identifier

### Supporting Services

#### Mock IMDS
- **Purpose:** Simulates AWS Instance Metadata Service
- **Endpoint:** http://172.41.0.100:1338/latest/meta-data/
- **Features:**
  - Instance identity
  - IAM credentials (temporary)
  - User data

#### HashiCorp Vault
- **Purpose:** Secrets management demonstration
- **Token:** root-token-for-demo
- **Features:**
  - KV secrets engine
  - Token authentication

#### Mock CI/CD
- **Purpose:** Simulates CI/CD webhook and artifact server
- **Features:**
  - Build trigger simulation
  - Artifact download

## Data Flow

### Log Collection

```
Agent Workload                Wazuh Manager              Wazuh Indexer
     │                             │                          │
     │ 1. Generate logs            │                          │
     │ (ossec.log, syslog)         │                          │
     │                             │                          │
     │ 2. Agent forwards logs      │                          │
     │ ─────────────────────────► │                          │
     │         (TCP 1514)          │                          │
     │                             │ 3. Parse & decode        │
     │                             │ Apply rules              │
     │                             │                          │
     │                             │ 4. Index alerts          │
     │                             │ ────────────────────────►│
     │                             │      (TCP 9200)          │
     │                             │                          │
```

### Alert Generation

1. **Event occurs** on agent (e.g., curl to IMDS)
2. **Log generated** by auditd or application
3. **Agent collects** log via ossec.conf localfile
4. **Manager receives** log via remoted
5. **Decoder extracts** fields from log
6. **Rules evaluate** decoded fields
7. **Alert generated** if rule matches
8. **Alert indexed** in OpenSearch
9. **Dashboard displays** alert

## Volumes

| Volume | Purpose | Container |
|--------|---------|-----------|
| wazuh_api_configuration | API config | wazuh.manager |
| wazuh_etc | Manager config | wazuh.manager |
| wazuh_logs | Manager logs | wazuh.manager |
| wazuh_queue | Event queue | wazuh.manager |
| wazuh_var_multigroups | Group configs | wazuh.manager |
| wazuh_integrations | Integration scripts | wazuh.manager |
| wazuh_active_response | AR scripts | wazuh.manager |
| wazuh_agentless | Agentless config | wazuh.manager |
| wazuh_wodles | Wodle config | wazuh.manager |
| wazuh_filebeat_etc | Filebeat config | wazuh.manager |
| wazuh_filebeat_var | Filebeat data | wazuh.manager |
| indexer-data | OpenSearch data | wazuh.indexer |

## Security Considerations

### TLS/SSL
- All inter-component communication uses TLS
- Certificates generated via `wazuh/certs/generate-certs.yml`
- Root CA stored in `wazuh/certs/root-ca.pem`

### Agent Authentication
- Agents authenticate via registration (port 1515)
- Client keys stored in `/var/ossec/etc/client.keys`

### API Authentication
- JWT-based authentication
- Default user: wazuh-wui / MyS3cr3tP@ssw0rd
- Token expiry: 900 seconds

### Credentials Summary

| Service | Username | Password | Port |
|---------|----------|----------|------|
| Dashboard | admin | admin | 8443 |
| Indexer | admin | admin | 9200 |
| Wazuh API | wazuh-wui | MyS3cr3tP@ssw0rd | 55000 |
| Vault | root | root-token-for-demo | 8200 |
