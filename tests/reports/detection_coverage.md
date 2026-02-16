# NHI Detection Coverage Matrix

## Summary

| Metric | Value |
|--------|-------|
| Total scenarios | 24 |
| Scenarios with E2E tests | 23 |
| Scenarios without tests | 1 |
| E2E coverage | **95.8%** |
| Total expected rules | 65 |
| Total test methods | 133 |
| Correlation rules tested | 5/5 |

## Scenario Coverage

| ID | Scenario | Category | Difficulty | Expected Rules | E2E Test | Test Methods |
|-----|----------|----------|------------|---------------|---------|-------------|
| S1-01 | Hardcoded Credentials in Source Code | API Keys & Secrets | Easy | 100600, 100601, 100900 | Y | 3 |
| S1-02 | Exposed .env File via Web Server | API Keys & Secrets | Easy | 100603, 100604 | Y | 3 |
| S1-03 | Git History Credential Leak | API Keys & Secrets | Medium | 100605, 100606 | Y | 3 |
| S1-04 | Environment Variable Exposure via /proc | API Keys & Secrets | Medium | 100607, 100608, 100609 | Y | 3 |
| S1-05 | Kubernetes Config Discovery | API Keys & Secrets | Easy | 100605 | **N** | 0 |
| S2-01 | IMDS Credential Theft | Cloud Service Accoun | Medium | 100650, 100651 | Y | 8 |
| S2-02 | Over-Permissioned IAM Role Exploitation | Cloud Service Accoun | Medium | 100700, 100701, 100702 | Y | 5 |
| S2-03 | Cross-Account Role Assumption Abuse | Cloud Service Accoun | Hard | 100703, 100704, 100705 | Y | 7 |
| S2-04 | Service Account Key Exfiltration | Cloud Service Accoun | Medium | 100706, 100707, 100708 | Y | 6 |
| S2-05 | HashiCorp Vault Token Theft | Cloud Service Accoun | Medium | 100606 | Y | 5 |
| S3-01 | Stolen GitHub Actions Runner Token | CI/CD Pipeline | Medium | 100800, 100801, 100802 | Y | 8 |
| S3-02 | Pipeline Injection via Pull Request | CI/CD Pipeline | Medium | 100803, 100804, 100805 | Y | 6 |
| S3-03 | OIDC Token Abuse for Cloud Access | CI/CD Pipeline | Hard | 100806, 100807, 100808 | Y | 7 |
| S3-04 | Vault Privilege Escalation | CI/CD & Supply Chain | Hard | 100606 | Y | 5 |
| S3-05 | Multiple Credential Harvest | CI/CD & Supply Chain | Medium | 100601, 100602, 100603, 100606, 100600, 100609 | Y | 5 |
| S4-01 | Privileged Pod Container Escape | Kubernetes | Hard | 100750, 100751, 100752 | Y | 7 |
| S4-02 | Kubernetes Service Account Token Theft | Kubernetes | Easy | 100753, 100754, 100755 | Y | 7 |
| S4-03 | RBAC Misconfiguration Exploitation | Kubernetes | Medium | 100756, 100757, 100758 | Y | 6 |
| S4-04 | Secrets Mounted in Pod | Kubernetes | Easy | 100759, 100760, 100761 | Y | 7 |
| S4-05 | API Key Abuse via Environment Extraction | Kubernetes & Contain | Easy | 100900, 100901 | Y | 6 |
| S5-01 | Prompt Injection Leading to Credential D | AI Agents | Medium | 100850, 100851, 100852 | Y | 6 |
| S5-02 | AI Agent with Excessive Permissions | AI Agents | Medium | 100853, 100854, 100855 | Y | 7 |
| S5-03 | AI Agent Tool-Use SSRF Abuse | AI Agents | Medium | 100856, 100857, 100858 | Y | 6 |
| S5-04 | AI Agent Memory/Context Poisoning | AI Agents | Hard | 100859, 100860, 100861 | Y | 7 |

## Correlation Rules

| Rule ID | Level | Description | Tested | Methods |
|---------|-------|-------------|--------|---------|
| 100950 | 14 | NHI: Credential harvesting combined with IMDS access - multi | Y | 3 |
| 100951 | 14 | NHI: K8s token theft followed by secrets enumeration - conta | Y | 3 |
| 100952 | 14 | NHI: CI/CD token + git credential access - supply chain atta | Y | 3 |
| 100953 | 15 | NHI: AI agent SSRF with credential access - agent compromise | Y | 3 |
| 100954 | 15 | NHI: Multiple machine identity security events from same sou | Y | 2 |

## Untested Scenarios

- S1-05
