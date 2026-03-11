# Falco Integration for NHI Security Testbed

Runtime security detection for Non-Human Identity threats in Kubernetes, with Wazuh cross-correlation.

## Overview

This integration deploys [Falco](https://falco.org/) with 11 custom detection rules targeting SPIFFE/SPIRE identity theft, cloud credential abuse, and container escape patterns. Falco alerts are forwarded to Wazuh via Falcosidekick for unified alerting and correlation with the existing NHI rule set (IDs 100600-100999).

## Installation

```bash
# Add the Falco Helm repository
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update

# Install Falco with NHI rules
helm install falco falcosecurity/falco \
  -n falco --create-namespace \
  -f k8s/falco/values.yaml

# Copy Wazuh ingestion rules to the manager
cp k8s/falco/wazuh-rules-falco.xml /var/ossec/etc/rules/
systemctl restart wazuh-manager
```

## Custom Rules

| # | Rule Name | Priority | MITRE ATT&CK | Description |
|---|-----------|----------|---------------|-------------|
| 1 | SPIRE Agent Socket Access by Unexpected Process | WARNING | T1552 | Non-SPIRE process opens the Workload API socket |
| 2 | SVID Private Key Read | CRITICAL | T1552.004 | Process reads an SVID `.key` or `.pem` file |
| 3 | SPIRE Server Admin Socket Access | CRITICAL | T1078.003 | Access to the SPIRE server registration API socket |
| 4 | Container Escape Attempt Near SPIRE | CRITICAL | T1611 | nsenter, unshare, or /proc/1/root access in a container |
| 5 | K8s SA Token Read from Non-Standard Process | WARNING | T1528 | Projected SA token read by unexpected binary |
| 6 | SPIRE Registration Entry Manipulation | WARNING | T1098 | SPIRE CLI entry create/update/delete |
| 7 | Trust Bundle Export | NOTICE | T1553 | SPIRE trust bundle exported via CLI |
| 8 | IMDS Access from Container | WARNING | T1552.005 | Container connects to 169.254.169.254 |
| 9 | Credential File Access in Container | WARNING | T1552.001 | Container reads .env, AWS creds, SSH keys, kubeconfig |
| 10 | Vault Token Discovery | WARNING | T1552 | Vault token file or VAULT_TOKEN env access |
| 11 | NHI Multi-Stage Attack Pattern | WARNING | T1078 | curl/wget to IMDS, Vault, or SPIRE from container |

## Wazuh Correlation Rules

Falco alerts forwarded via Falcosidekick are ingested by Wazuh rules in `wazuh-rules-falco.xml` (IDs 102000-102013):

| Rule ID | Level | Description |
|---------|-------|-------------|
| 102000 | 0 | Parent: Falco NHI event received |
| 102001 | 12 | SPIRE agent socket access by unexpected process |
| 102002 | 14 | SVID private key read |
| 102003 | 14 | SPIRE server admin socket accessed |
| 102004 | 15 | Container escape attempt near SPIRE |
| 102005 | 10 | K8s SA token read by non-standard process |
| 102006 | 12 | SPIRE registration entry manipulation |
| 102007 | 8 | Trust bundle exported |
| 102008 | 12 | IMDS access from container |
| 102009 | 10 | Credential file access in container |
| 102010 | 10 | Vault token discovery |
| 102011 | 12 | Multi-stage NHI attack pattern |
| 102012 | 14 | Correlation: 3+ Falco NHI alerts from same source in 2 min |
| 102013 | 15 | Correlation: SPIRE access + credential theft from same source |

## Architecture

```
+-------------------+     +--------------+     +----------------+
|  Falco (eBPF)     | --> | Falcosidekick| --> | Wazuh Manager  |
|  11 NHI rules     |     | webhook      |     | rules 102000+  |
+-------------------+     +--------------+     +----------------+
                                                       |
                                               +-------v--------+
                                               | Wazuh Indexer   |
                                               | (correlation    |
                                               |  with 100600+)  |
                                               +----------------+
```

## Files

| File | Purpose |
|------|---------|
| `values.yaml` | Falco Helm values with custom NHI rules and Falcosidekick config |
| `wazuh-rules-falco.xml` | Wazuh detection rules for ingested Falco events |
| `README.md` | This file |

## Testing

Trigger a test alert to verify the pipeline:

```bash
# From inside a container in the cluster:
cat /var/run/secrets/kubernetes.io/serviceaccount/token
# Expected: Falco fires "Kubernetes SA Token Read from Non-Standard Process"
#           Wazuh fires rule 102005

# IMDS probe:
curl -s http://169.254.169.254/latest/meta-data/
# Expected: Falco fires "IMDS Access from Container"
#           Wazuh fires rule 102008
```

## Requirements

- Kubernetes 1.24+
- Helm 3.x
- Falco 0.37+ (modern_ebpf driver)
- Wazuh 4.7+ manager with JSON decoder enabled
