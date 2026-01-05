# Chapter 3: Wazuh Rules Reference

## Rule Organization

Custom NHI detection rules use IDs in the range **100600-100999**.

| Range | Category | Description |
|-------|----------|-------------|
| 100600-100649 | Credential Discovery | File access, credential searches |
| 100650-100699 | Cloud Metadata (IMDS) | AWS/Azure/GCP metadata abuse |
| 100700-100749 | Service Account Misuse | IAM operations, role abuse |
| 100750-100799 | Kubernetes Security | SA tokens, RBAC, container escape |
| 100800-100849 | CI/CD Pipeline | Runner tokens, pipeline injection |
| 100850-100899 | AI Agent Anomalies | Prompt injection, tool abuse |
| 100900-100949 | Secret Pattern Detection | API key patterns in logs |
| 100950-100999 | Correlation Rules | Multi-stage attack chains |

## Rule Details

### Credential Discovery (100600-100649)

#### Rule 100600: Sensitive Configuration File Access
```xml
<rule id="100600" level="7">
  <if_sid>550</if_sid>
  <match>\.env|config\.py|settings\.py|credentials</match>
  <description>NHI: Sensitive configuration file access detected</description>
  <mitre>
    <id>T1552.001</id>
  </mitre>
  <group>nhi_credential_discovery,</group>
</rule>
```
- **Triggers**: File access to .env, config.py, settings.py, or files containing "credentials"
- **Level**: 7 (Low priority alert)
- **Response**: Review if access is expected for the process

#### Rule 100601: Credential Search Commands
```xml
<rule id="100601" level="10">
  <if_sid>5902</if_sid>
  <match>grep|find|locate</match>
  <match>password|secret|key|token|credential</match>
  <description>NHI: Credential discovery attempt via file search</description>
  <mitre>
    <id>T1552.001</id>
    <id>T1083</id>
  </mitre>
  <group>nhi_credential_discovery,</group>
</rule>
```
- **Triggers**: grep/find commands searching for credential-related terms
- **Level**: 10 (High priority alert)
- **Response**: Investigate user/process performing the search

### Cloud Metadata Rules (100650-100699)

#### Rule 100650: IMDS Access Detected
```xml
<rule id="100650" level="8">
  <if_group>web_log</if_group>
  <match>169.254.169.254|metadata.google.internal</match>
  <description>NHI: AWS/GCP Instance Metadata Service access detected</description>
  <mitre>
    <id>T1552.005</id>
  </mitre>
  <group>nhi_imds,</group>
</rule>
```
- **Triggers**: HTTP requests to cloud metadata endpoints
- **Level**: 8 (Medium-high priority)
- **Response**: Verify if application legitimately needs metadata access

#### Rule 100651: IMDS IAM Credential Request (CRITICAL)
```xml
<rule id="100651" level="12">
  <if_sid>100650</if_sid>
  <match>iam/security-credentials</match>
  <description>NHI: AWS IMDS IAM credential request - CREDENTIAL THEFT ATTEMPT</description>
  <mitre>
    <id>T1552.005</id>
    <id>T1078.004</id>
  </mitre>
  <group>nhi_imds_cred,</group>
</rule>
```
- **Triggers**: Request to IMDS IAM credential endpoint
- **Level**: 12 (Critical)
- **Response**: IMMEDIATE - Rotate credentials, investigate source

### Service Account Rules (100700-100749)

#### Rule 100700: IAM Permission Enumeration
```xml
<rule id="100700" level="8">
  <if_group>aws</if_group>
  <match>GetRolePolicy|ListRolePolicies|ListAttachedRolePolicies</match>
  <description>NHI: IAM permission enumeration from service account</description>
  <mitre>
    <id>T1087.004</id>
  </mitre>
  <group>nhi_iam,</group>
</rule>
```

#### Rule 100701: IAM User/Role Creation
```xml
<rule id="100701" level="12">
  <if_group>aws</if_group>
  <match>CreateUser|CreateRole</match>
  <srcip>^172\.</srcip>
  <description>NHI: IAM user/role creation from internal IP - PRIVILEGE ESCALATION</description>
  <mitre>
    <id>T1098</id>
  </mitre>
  <group>nhi_iam_priv_esc,</group>
</rule>
```

### Kubernetes Rules (100750-100799)

#### Rule 100750: Container Escape Attempt
```xml
<rule id="100750" level="14">
  <if_sid>5902</if_sid>
  <match>nsenter|chroot</match>
  <match>--target 1|/mnt/host</match>
  <description>NHI: Container escape attempt via nsenter/chroot</description>
  <mitre>
    <id>T1611</id>
  </mitre>
  <group>nhi_container_escape,</group>
</rule>
```
- **Level**: 14 (Critical)
- **Response**: IMMEDIATE - Terminate pod, cordon node

#### Rule 100753: Service Account Token Access
```xml
<rule id="100753" level="8">
  <if_sid>550</if_sid>
  <match>/var/run/secrets/kubernetes.io/serviceaccount/token</match>
  <description>NHI: Kubernetes service account token accessed</description>
  <mitre>
    <id>T1528</id>
  </mitre>
  <group>nhi_k8s_sa,</group>
</rule>
```

### CI/CD Rules (100800-100849)

#### Rule 100800: CI/CD Token Enumeration
```xml
<rule id="100800" level="8">
  <if_sid>5902</if_sid>
  <match>GITHUB_TOKEN|ACTIONS_RUNTIME_TOKEN|CI_JOB_TOKEN</match>
  <description>NHI: CI/CD token enumeration detected</description>
  <mitre>
    <id>T1528</id>
  </mitre>
  <group>nhi_cicd,</group>
</rule>
```

#### Rule 100802: CI/CD Secrets Access
```xml
<rule id="100802" level="12">
  <if_group>web_log</if_group>
  <match>actions/secrets|variables</match>
  <description>NHI: CI/CD secrets or logs access - POTENTIAL THEFT</description>
  <mitre>
    <id>T1552.001</id>
  </mitre>
  <group>nhi_cicd_secrets,</group>
</rule>
```

### AI Agent Rules (100850-100899)

#### Rule 100850: Prompt Injection Attempt
```xml
<rule id="100850" level="10">
  <if_group>ai_agent</if_group>
  <match>ignore previous|system prompt|reveal|disregard</match>
  <description>NHI: Prompt injection attempt detected</description>
  <mitre>
    <id>T1059</id>
  </mitre>
  <group>nhi_ai_injection,</group>
</rule>
```

#### Rule 100856: AI Agent SSRF to Metadata
```xml
<rule id="100856" level="14">
  <if_group>ai_agent</if_group>
  <match>169.254.169.254|metadata</match>
  <description>NHI: AI agent SSRF to cloud metadata - CREDENTIAL THEFT</description>
  <mitre>
    <id>T1552.005</id>
    <id>T1190</id>
  </mitre>
  <group>nhi_ai_ssrf,</group>
</rule>
```

### Secret Pattern Detection (100900-100949)

#### Rule 100900: AWS Access Key Pattern
```xml
<rule id="100900" level="12">
  <regex>AKIA[0-9A-Z]{16}</regex>
  <description>NHI: AWS Access Key pattern detected in logs</description>
  <mitre>
    <id>T1552.001</id>
  </mitre>
  <group>nhi_secret_pattern,</group>
</rule>
```

#### Rule 100901: GitHub Token Pattern
```xml
<rule id="100901" level="12">
  <regex>gh[prous]_[A-Za-z0-9_]{36}</regex>
  <description>NHI: GitHub token pattern detected in logs</description>
  <group>nhi_secret_pattern,</group>
</rule>
```

### Correlation Rules (100950-100999)

#### Rule 100950: Multi-Stage IMDS Attack
```xml
<rule id="100950" level="15" frequency="3" timeframe="60">
  <if_matched_sid>100650</if_matched_sid>
  <same_source_ip />
  <description>NHI: Multi-stage IMDS attack detected - ACTIVE ATTACK</description>
  <mitre>
    <id>T1552.005</id>
  </mitre>
  <group>nhi_correlation,</group>
</rule>
```
- **Triggers**: 3+ IMDS access events within 60 seconds from same source
- **Level**: 15 (Maximum severity)

## Rule Levels Reference

| Level | Severity | Description |
|-------|----------|-------------|
| 0-3 | Low | Informational, no alert |
| 4-7 | Low | Minor issues, logged |
| 8-11 | Medium | Significant events |
| 12-14 | High | Critical security events |
| 15 | Critical | Maximum severity, immediate action |

## MITRE ATT&CK Mapping

| Technique ID | Name | Rules |
|--------------|------|-------|
| T1552.001 | Credentials In Files | 100600, 100601 |
| T1552.005 | Cloud Instance Metadata | 100650, 100651 |
| T1078.004 | Cloud Accounts | 100651, 100701 |
| T1528 | Steal Application Token | 100753, 100800 |
| T1611 | Escape to Host | 100750 |
| T1098 | Account Manipulation | 100701, 100702 |

## Adding Custom Rules

### Location
Custom rules should be added to:
```
wazuh/rules/nhi-detection-rules.xml
```

### Rule Template
```xml
<rule id="100XXX" level="Y">
  <if_sid>parent_rule_id</if_sid>
  <match>pattern_to_match</match>
  <description>NHI: Description of the detection</description>
  <mitre>
    <id>TXXXX</id>
  </mitre>
  <group>nhi_category,</group>
</rule>
```

### Testing Rules
```bash
# Test rule syntax
docker exec wazuh-manager /var/ossec/bin/wazuh-logtest

# Paste log sample and verify rule triggers

# Reload rules
docker exec wazuh-manager /var/ossec/bin/wazuh-control reload
```

## Tuning Guidelines

### Reducing False Positives
1. Add specific exclusions for known good processes
2. Use `<srcip>` to limit to internal ranges
3. Add `<program_name>` to target specific applications

### Increasing Coverage
1. Add more log sources to ossec.conf
2. Create variations for different cloud providers
3. Add correlation rules for attack sequences

See [Chapter 7: Extending the Testbed](07-extending-testbed.md) for more details.
