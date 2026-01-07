# Wazuh NHI Detection Rules Reference

This document provides a quick reference for all custom NHI detection rules in the testbed.

## Rule ID Ranges

| Range | Category |
|-------|----------|
| 100600-100649 | Credential Discovery & Exposure |
| 100650-100699 | Cloud Metadata Service (IMDS) Abuse |
| 100700-100749 | Service Account Misuse |
| 100750-100799 | Kubernetes Security |
| 100800-100849 | CI/CD Pipeline Attacks |
| 100850-100899 | AI Agent Anomalies |
| 100900-100949 | Secret Pattern Detection |
| 100950-100999 | Correlation Rules |

---

## Credential Discovery & Exposure (100600-100649)

| Rule ID | Level | Description | MITRE |
|---------|-------|-------------|-------|
| 100600 | 10 | .env file access | T1552.001 |
| 100601 | 12 | AWS credentials file access | T1552.001 |
| 100602 | 10 | SSH private key access | T1552.004 |
| 100603 | 10 | Git credential file access | T1552.001, T1555 |
| 100604 | 10 | Docker config file access | T1552.001 |
| 100605 | 10 | Kubernetes config file access | T1552.001 |
| 100606 | 10 | Vault token file access | T1552.001 |
| 100607 | 10 | /proc/*/environ enumeration | T1082, T1552.007 |
| 100608 | 10 | NPM config (.npmrc) access | T1552.001 |
| 100609 | 14 | Multiple credential file accesses (5 in 60s) | T1552, T1083 |

---

## Cloud Metadata Service Abuse (100650-100699)

| Rule ID | Level | Description | MITRE |
|---------|-------|-------------|-------|
| 100650 | 8 | AWS IMDS access (169.254.169.254) | T1552.005 |
| 100651 | 12 | AWS IMDS IAM credential request | T1552.005, T1078.004 |
| 100652 | 5 | AWS IMDSv2 token request | T1552.005 |
| 100653 | 8 | GCP Metadata Service access | T1552.005 |
| 100654 | 12 | GCP service account token request | T1552.005, T1078.004 |
| 100655 | 8 | Azure IMDS managed identity access | T1552.005 |
| 100656 | 12 | Azure managed identity token request | T1552.005, T1078.004 |
| 100657 | 14 | Burst of IMDS requests (10 in 60s) | T1552.005, T1041 |
| 100658 | 12 | IMDS access from scripting tool | T1552.005 |

---

## Kubernetes Security (100750-100799)

| Rule ID | Level | Description | MITRE |
|---------|-------|-------------|-------|
| 100750 | 8 | ServiceAccount token access | T1552.007, T1078.001 |
| 100751 | 8 | Kubernetes secrets volume access | T1552.007 |
| 100752 | 8 | kubectl auth can-i (RBAC probing) | T1069.003, T1087.004 |
| 100753 | 10 | kubectl get secrets | T1552.007 |
| 100754 | 8 | Service account enumeration | T1087.004 |
| 100755 | 12 | Extensive RBAC enumeration (10 in 60s) | T1069.003 |
| 100756 | 14 | Direct etcd datastore access | T1552.007 |

---

## CI/CD Pipeline Attacks (100800-100849)

| Rule ID | Level | Description | MITRE |
|---------|-------|-------------|-------|
| 100800 | 10 | GITHUB_TOKEN in environment | T1552.007 |
| 100801 | 10 | GitLab CI_JOB_TOKEN detected | T1552.007 |
| 100802 | 10 | CI/CD runner credential file access | T1552.001 |
| 100803 | 12 | Pipeline configuration modified | T1195.002 |
| 100804 | 10 | NPM_TOKEN detected | T1552.007 |
| 100805 | 10 | ACTIONS_RUNTIME_TOKEN detected | T1552.007 |

---

## AI Agent Anomalies (100850-100899)

| Rule ID | Level | Description | MITRE |
|---------|-------|-------------|-------|
| 100850 | 10 | AI agent executing shell command | T1059 |
| 100851 | 12 | AI agent accessing credential file | T1552.001 |
| 100852 | 10 | Prompt injection attempt in web request | T1059 |
| 100853 | 12 | AI agent IMDS access (SSRF) | T1552.005 |
| 100854 | 10 | AI agent rapid file system operations | T1083 |

---

## Secret Pattern Detection (100900-100949)

| Rule ID | Level | Pattern | Description |
|---------|-------|---------|-------------|
| 100900 | 12 | `AKIA[0-9A-Z]{16}` | AWS Access Key ID |
| 100901 | 12 | `ghp_|gho_|ghs_[a-zA-Z0-9]{36}` | GitHub token |
| 100902 | 12 | `sk-[a-zA-Z0-9]{48}` | OpenAI API key |
| 100903 | 10 | `xox[baprs]-...` | Slack token |
| 100904 | 12 | `-----BEGIN.*PRIVATE KEY-----` | Private key |
| 100905 | 10 | `AIza[0-9A-Za-z\-_]{35}` | Google API key |

---

## Correlation Rules (100950-100999)

| Rule ID | Level | Trigger | Description |
|---------|-------|---------|-------------|
| 100950 | 14 | credential_harvest + imds | Multi-vector attack |
| 100951 | 14 | k8s_sa_token + k8s_secret_enum | Container attack chain |
| 100952 | 14 | cicd_github + git_cred | Supply chain attack |
| 100953 | 15 | ai_ssrf + ai_cred_access | AI agent compromise |
| 100954 | 15 | 5 nhi events in 600s from same IP | Complex attack |

---

## Rule Groups

Filter alerts by these groups:

| Group | Description |
|-------|-------------|
| `nhi` | All NHI rules |
| `nhi_env_access` | Environment file access |
| `nhi_cloud_cred` | Cloud credential access |
| `nhi_ssh_key` | SSH key access |
| `nhi_git_cred` | Git credential access |
| `nhi_docker_cred` | Docker config access |
| `nhi_k8s_cred` | Kubernetes config access |
| `nhi_vault_cred` | Vault token access |
| `nhi_env_enum` | Environment enumeration |
| `nhi_credential_harvest` | Multiple credential accesses |
| `nhi_imds` | IMDS access |
| `nhi_imds_cred` | IMDS credential theft |
| `nhi_k8s_sa_token` | K8s SA token access |
| `nhi_k8s_secrets` | K8s secrets access |
| `nhi_k8s_rbac_probe` | K8s RBAC probing |
| `nhi_cicd_github` | GitHub token activity |
| `nhi_cicd_gitlab` | GitLab token activity |
| `nhi_cicd_pipeline_tamper` | Pipeline modification |
| `nhi_ai_shell` | AI shell execution |
| `nhi_ai_cred_access` | AI credential access |
| `nhi_ai_ssrf` | AI SSRF attack |
| `nhi_secret_aws` | AWS secret pattern |
| `nhi_secret_github` | GitHub secret pattern |
| `nhi_multi_attack` | Multi-vector attack |
| `nhi_supply_chain` | Supply chain attack |

---

## Querying Alerts

### Via Wazuh API

```bash
# Get token
TOKEN=$(curl -sk -u wazuh-wui:MyS3cr3tP@ssw0rd -X POST \
  "https://localhost:55000/security/user/authenticate?raw=true")

# All NHI alerts
curl -sk -H "Authorization: Bearer $TOKEN" \
  "https://localhost:55000/security/events?q=rule.groups:nhi"

# Specific rule
curl -sk -H "Authorization: Bearer $TOKEN" \
  "https://localhost:55000/security/events?q=rule.id:100651"

# High severity only (level >= 12)
curl -sk -H "Authorization: Bearer $TOKEN" \
  "https://localhost:55000/security/events?q=rule.level>=12;rule.groups:nhi"
```

### Via Dashboard

1. Navigate to https://localhost:8443
2. Go to **Wazuh** → **Security Events**
3. Add filter: `rule.groups: nhi`
4. Or search: `rule.id: 100651`

---

## Adding Custom Rules

Rules are stored in: `wazuh/rules/`

After modifying rules:
```bash
# Restart manager to reload rules
podman restart wazuh-manager

# Or use API
curl -sk -H "Authorization: Bearer $TOKEN" \
  -X PUT "https://localhost:55000/manager/restart"
```

## Rule File Location

- **Custom rules:** `wazuh/rules/nhi-detection-rules.xml`
- **Custom decoders:** `wazuh/decoders/nhi-decoders.xml`
- **Mounted at:** `/var/ossec/etc/rules/` and `/var/ossec/etc/decoders/`
