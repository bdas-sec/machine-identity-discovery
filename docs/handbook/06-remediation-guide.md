# Chapter 6: Remediation Guide

## Overview

This chapter provides remediation guidance for each NHI vulnerability category. For each vulnerability type, we cover immediate actions and long-term fixes.

---

## Category 1: API Keys & Secrets

### Immediate Actions

```bash
# 1. Identify all exposed credentials
grep -rn "API_KEY\|SECRET\|PASSWORD\|TOKEN" /app/

# 2. Rotate all discovered credentials
# AWS
aws iam create-access-key --user-name service-user
aws iam delete-access-key --user-name service-user --access-key-id OLD_KEY

# GitHub
# Settings → Developer settings → Personal access tokens → Regenerate
```

### Long-Term Fixes

#### Use Secrets Management
```yaml
# HashiCorp Vault example
apiVersion: v1
kind: Pod
metadata:
  annotations:
    vault.hashicorp.com/agent-inject: "true"
    vault.hashicorp.com/agent-inject-secret-db: "database/creds/app"
spec:
  containers:
    - name: app
```

#### Implement Pre-commit Hooks
```bash
# Install gitleaks
brew install gitleaks

# Add pre-commit hook
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
gitleaks detect --source . --staged --verbose
EOF
chmod +x .git/hooks/pre-commit
```

#### Block .env in Web Server
```nginx
# nginx.conf
location ~ /\. {
    deny all;
    return 404;
}
```

---

## Category 2: Cloud Service Accounts

### IMDS Security

#### Enforce IMDSv2 (Recommended)
```bash
# For existing instances
aws ec2 modify-instance-metadata-options \
  --instance-id i-xxx \
  --http-tokens required \
  --http-endpoint enabled

# For new instances via launch template
aws ec2 create-launch-template \
  --launch-template-name secure-template \
  --launch-template-data '{
    "MetadataOptions": {
      "HttpTokens": "required",
      "HttpEndpoint": "enabled"
    }
  }'
```

#### Using IMDSv2 in Application
```python
import requests

# Get token first
token = requests.put(
    'http://169.254.169.254/latest/api/token',
    headers={'X-aws-ec2-metadata-token-ttl-seconds': '21600'}
).text

# Use token for metadata requests
credentials = requests.get(
    'http://169.254.169.254/latest/meta-data/iam/security-credentials/role',
    headers={'X-aws-ec2-metadata-token': token}
).json()
```

### IAM Least Privilege

#### Permission Boundary
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject"
      ],
      "Resource": "arn:aws:s3:::app-bucket/*"
    },
    {
      "Effect": "Deny",
      "Action": [
        "iam:*",
        "organizations:*"
      ],
      "Resource": "*"
    }
  ]
}
```

#### Cross-Account Trust with External ID
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::TRUSTED:root"},
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {"sts:ExternalId": "unique-secret-id"}
      }
    }
  ]
}
```

---

## Category 3: CI/CD Pipeline

### GitHub Actions Security

#### Minimal GITHUB_TOKEN Permissions
```yaml
# .github/workflows/ci.yml
permissions:
  contents: read
  packages: none
  actions: none
```

#### Secure pull_request_target
```yaml
on:
  pull_request_target:
    types: [opened, synchronize]

jobs:
  build:
    runs-on: ubuntu-latest
    environment: production  # Requires approval
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          persist-credentials: false
```

### OIDC Trust Policy (AWS)
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::ACCOUNT:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
          "token.actions.githubusercontent.com:sub": "repo:myorg/myrepo:ref:refs/heads/main"
        }
      }
    }
  ]
}
```

### Secret Scanning
```yaml
# Enable in GitHub repo settings
Settings → Code security and analysis → Secret scanning → Enable
Settings → Code security and analysis → Push protection → Enable
```

---

## Category 4: Kubernetes

### Pod Security Standards

#### Restricted Policy
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/warn: restricted
```

#### Secure Pod Spec
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secure-app
spec:
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 1000
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: app
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: ["ALL"]
```

### RBAC Best Practices

#### Minimal Role
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: app-role
  namespace: production
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get"]
    resourceNames: ["app-config"]
```

### External Secrets
```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: db-credentials
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend
    kind: ClusterSecretStore
  target:
    name: db-secret
  data:
    - secretKey: password
      remoteRef:
        key: database/credentials
        property: password
```

### Network Policy
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: block-metadata
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
              - 169.254.169.254/32
```

---

## Category 5: AI Agents

### Input Validation
```python
BLOCKED_PATTERNS = [
    r'ignore\s+previous',
    r'system\s+prompt',
    r'reveal\s+(your|all)',
    r'credentials',
    r'api[_\s]?key'
]

def validate_input(user_input: str) -> bool:
    for pattern in BLOCKED_PATTERNS:
        if re.search(pattern, user_input, re.IGNORECASE):
            return False
    return True
```

### Output Filtering
```python
SECRET_PATTERNS = [
    r'AKIA[0-9A-Z]{16}',           # AWS Access Key
    r'gh[prous]_[A-Za-z0-9_]{36}', # GitHub Token
    r'sk-[a-zA-Z0-9]{48}'          # OpenAI Key
]

def sanitize_output(output: str) -> str:
    for pattern in SECRET_PATTERNS:
        output = re.sub(pattern, '[REDACTED]', output)
    return output
```

### URL Allowlisting
```python
BLOCKED_HOSTS = [
    '169.254.169.254',
    'metadata.google.internal',
    'localhost',
    '127.0.0.1'
]

BLOCKED_CIDRS = [
    '10.0.0.0/8',
    '172.16.0.0/12',
    '192.168.0.0/16'
]

def is_url_allowed(url: str) -> bool:
    parsed = urlparse(url)
    # Check blocked hosts
    if parsed.hostname in BLOCKED_HOSTS:
        return False
    # Check private CIDRs
    try:
        ip = ipaddress.ip_address(parsed.hostname)
        for cidr in BLOCKED_CIDRS:
            if ip in ipaddress.ip_network(cidr):
                return False
    except ValueError:
        pass  # Hostname, not IP
    return True
```

### Agent Permission Boundaries
```python
class SecureAgent:
    def __init__(self):
        self.allowed_tools = ['search', 'read_public_data']
        self.denied_tools = ['execute_command', 'write_file', 'create_user']

    def execute_tool(self, tool_name: str, *args, **kwargs):
        if tool_name in self.denied_tools:
            raise PermissionError(f"Tool {tool_name} is not allowed")
        if tool_name not in self.allowed_tools:
            raise ValueError(f"Unknown tool: {tool_name}")
        return self.tools[tool_name](*args, **kwargs)
```

---

## Verification Checklist

After implementing remediations, verify:

### Secrets
- [ ] No hardcoded credentials in code
- [ ] .env files blocked from web access
- [ ] Pre-commit hooks active
- [ ] Secrets managed via vault/secrets manager

### Cloud
- [ ] IMDSv2 enforced
- [ ] IAM roles have least privilege
- [ ] Permission boundaries applied
- [ ] Cross-account roles use external IDs

### CI/CD
- [ ] GITHUB_TOKEN minimally scoped
- [ ] OIDC trust policies restricted
- [ ] Secret scanning enabled
- [ ] Workflow approvals required for forks

### Kubernetes
- [ ] Pod Security Standards enforced
- [ ] automountServiceAccountToken: false
- [ ] Network policies block metadata
- [ ] External secrets for sensitive data

### AI Agents
- [ ] Input validation implemented
- [ ] Output filtering active
- [ ] URL allowlisting enforced
- [ ] Tool permissions restricted
