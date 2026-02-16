# NHI Detection Coverage Matrix

## Summary

| Metric | Value |
|--------|-------|
| Total scenarios | 29 |
| Scenarios with E2E tests | 28 |
| Scenarios without tests | 1 |
| E2E coverage | **96.6%** |
| Total expected rules | 80 |
| Total Wazuh rules | 71 |
| OCSF-mapped rules | 52 |
| Sigma rules | 71 |
| Total test methods | 179 |
| Correlation rules tested | 5/6 |

## Scenario Coverage

| ID | Scenario | Category | Difficulty | Expected Rules | OCSF Classes | E2E Test | Methods |
|-----|----------|----------|------------|---------------|-------------|---------|---------|
| S1-01 | Hardcoded Credentials in Source Cod | API Keys & Secr | Easy | 100600, 100601, 100900 | 1001, 2001 | Y | 3 |
| S1-02 | Exposed .env File via Web Server | API Keys & Secr | Easy | 100603, 100604 | 1001 | Y | 3 |
| S1-03 | Git History Credential Leak | API Keys & Secr | Medium | 100605, 100606 | 1001 | Y | 3 |
| S1-04 | Environment Variable Exposure via / | API Keys & Secr | Medium | 100607, 100608, 100609 | 1001, 2001 | Y | 3 |
| S1-05 | Kubernetes Config Discovery | API Keys & Secr | Easy | 100605 | 1001 | **N** | 0 |
| S2-01 | IMDS Credential Theft | Cloud Service A | Medium | 100650, 100651 | 6003 | Y | 8 |
| S2-02 | Over-Permissioned IAM Role Exploita | Cloud Service A | Medium | 100700, 100701, 100702 | - | Y | 5 |
| S2-03 | Cross-Account Role Assumption Abuse | Cloud Service A | Hard | 100703, 100704, 100705 | - | Y | 7 |
| S2-04 | Service Account Key Exfiltration | Cloud Service A | Medium | 100706, 100707, 100708 | - | Y | 6 |
| S2-05 | HashiCorp Vault Token Theft | Cloud Service A | Medium | 100606 | 1001 | Y | 5 |
| S3-01 | Stolen GitHub Actions Runner Token | CI/CD Pipeline | Medium | 100800, 100801, 100802 | 1001, 2001 | Y | 8 |
| S3-02 | Pipeline Injection via Pull Request | CI/CD Pipeline | Medium | 100803, 100804, 100805 | 1001, 2001 | Y | 6 |
| S3-03 | OIDC Token Abuse for Cloud Access | CI/CD Pipeline | Hard | 100806, 100807, 100808 | - | Y | 7 |
| S3-04 | Vault Privilege Escalation | CI/CD & Supply  | Hard | 100606 | 1001 | Y | 5 |
| S3-05 | Multiple Credential Harvest | CI/CD & Supply  | Medium | 100601, 100602, 100603, 100606, 100600, 100609 | 1001, 2001 | Y | 5 |
| S4-01 | Privileged Pod Container Escape | Kubernetes | Hard | 100750, 100751, 100752 | 1001, 6003 | Y | 7 |
| S4-02 | Kubernetes Service Account Token Th | Kubernetes | Easy | 100753, 100754, 100755 | 2001, 6003 | Y | 7 |
| S4-03 | RBAC Misconfiguration Exploitation | Kubernetes | Medium | 100756, 100757, 100758 | 1001, 1007 | Y | 6 |
| S4-04 | Secrets Mounted in Pod | Kubernetes | Easy | 100759, 100760, 100761 | 1001, 1007 | Y | 7 |
| S4-05 | API Key Abuse via Environment Extra | Kubernetes & Co | Easy | 100900, 100901 | 2001 | Y | 6 |
| S5-01 | Prompt Injection Leading to Credent | AI Agents | Medium | 100850, 100851, 100852 | 1001, 1007, 6001 | Y | 6 |
| S5-02 | AI Agent with Excessive Permissions | AI Agents | Medium | 100853, 100854, 100855 | 2001, 4001, 6003 | Y | 7 |
| S5-03 | AI Agent Tool-Use SSRF Abuse | AI Agents | Medium | 100856, 100857, 100858 | 6001, 6003 | Y | 6 |
| S5-04 | AI Agent Memory/Context Poisoning | AI Agents | Hard | 100859, 100860, 100861 | 4001 | Y | 7 |
| S6-01 | OAuth App Consent Phishing | Infrastructure | Medium | 100907, 100853 | 6003 | Y | 9 |
| S6-02 | GitHub App Installation Token Theft | Infrastructure | Medium | 100800, 100901, 100952 | 2001 | Y | 9 |
| S6-03 | Workload Identity Federation Abuse | Infrastructure | Hard | 100653, 100654, 100907, 100950 | 6001, 6003 | Y | 10 |
| S6-04 | Terraform State File Credential Exp | Infrastructure | Medium | 100600, 100912, 100900 | 1001, 2001 | Y | 8 |
| S6-05 | Kubernetes etcd Direct Access - Clu | Infrastructure | Hard | 100756, 100764, 100955 | 1001, 6003 | Y | 10 |

## Correlation Rules

| Rule ID | Level | Description | OCSF | Tested | Methods |
|---------|-------|-------------|------|--------|---------|
| 100950 | 14 | NHI: Credential harvesting combined with IMDS acce | 6001 | Y | 3 |
| 100951 | 14 | NHI: K8s token theft followed by secrets enumerati | - | Y | 3 |
| 100952 | 14 | NHI: CI/CD token + git credential access - supply  | - | Y | 3 |
| 100953 | 15 | NHI: AI agent SSRF with credential access - agent  | - | Y | 3 |
| 100954 | 15 | NHI: Multiple machine identity security events fro | - | Y | 2 |
| 100955 | 15 | NHI: Multi-technique container escape chain - esca | - | **N** | 0 |

## OCSF Event Classes

| Class UID | Class Name | Scenarios | Rules |
|-----------|-----------|-----------|-------|
| 1001 | File Activity | 25 | 25 |
| 1007 | Process Activity | 5 | 5 |
| 2001 | Security Finding | 12 | 12 |
| 4001 | Network Activity | 2 | 2 |
| 6001 | Web Resources Activity | 3 | 3 |
| 6003 | API Activity | 12 | 12 |

## Untested Scenarios

- S1-05
