# Chapter 5: Detection Playbook

## Alert Triage Workflow

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Alert     │────▶│  Initial    │────▶│   Full      │────▶│  Response   │
│  Received   │     │   Triage    │     │ Investigation│    │   Action    │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
                           │                   │                    │
                           ▼                   ▼                    ▼
                    ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
                    │ - Severity  │     │ - Context   │     │ - Contain   │
                    │ - Source    │     │ - Timeline  │     │ - Eradicate │
                    │ - Category  │     │ - Impact    │     │ - Recover   │
                    └─────────────┘     └─────────────┘     └─────────────┘
```

## Alert Categories and Response

### Critical Alerts (Level 12-15) - Immediate Response

#### IMDS Credential Theft (Rule 100651)
**Alert**: `NHI: AWS IMDS IAM credential request - CREDENTIAL THEFT ATTEMPT`

**Initial Triage** (2 minutes):
1. Identify the source process/container
2. Check if this is expected behavior (some apps legitimately query IMDS)
3. Verify the specific endpoint accessed (/iam/security-credentials/)

**Investigation** (10 minutes):
```bash
# Get auth token for Wazuh API
TOKEN=$(curl -sk -u wazuh-wui:MyS3cr3tP@ssw0rd -X POST \
  "https://localhost:55000/security/user/authenticate?raw=true")

# View detailed alert
curl -sk -H "Authorization: Bearer $TOKEN" "https://localhost:55000/alerts?rule_id=100651"

# Check source container logs
podman logs cloud-workload | grep -i "imds\|169.254"

# Review timeline of related events
curl -sk -H "Authorization: Bearer $TOKEN" "https://localhost:55000/alerts?agent_name=cloud-workload&limit=50"
```

**Response Actions**:
1. **Contain**: Isolate affected container/instance
2. **Rotate**: Immediately rotate IAM credentials
3. **Review**: Check CloudTrail for credential usage
4. **Block**: Implement IMDSv2 requirement

---

#### Container Escape (Rule 100750)
**Alert**: `NHI: Container escape attempt via nsenter/chroot`

**Initial Triage** (1 minute):
1. Identify the pod/container
2. Check if running as privileged
3. Verify legitimate admin activity

**Investigation**:
```bash
# Check container security context
docker inspect k8s-node | jq '.[0].HostConfig.Privileged'

# Review process history
docker exec k8s-node cat /var/ossec/logs/ossec.log | grep -i "nsenter\|chroot"
```

**Response Actions**:
1. **Terminate**: Kill the pod immediately
2. **Cordon**: Remove node from scheduling
3. **Rotate**: Kubelet credentials
4. **Review**: All pods on affected node

---

#### IAM Privilege Escalation (Rule 100701)
**Alert**: `NHI: IAM user/role creation from EC2 instance - PRIVILEGE ESCALATION`

**Initial Triage** (2 minutes):
1. Identify which IAM entity was created
2. Verify the source (should not be from EC2 instance)
3. Check attached permissions

**Investigation**:
```bash
# List recent IAM changes (simulated)
echo "Check CloudTrail for: CreateUser, CreateRole, AttachPolicy events"

# Identify created entities
echo "aws iam list-users --query 'Users[?CreateDate>=\`2024-01-01\`]'"
```

**Response Actions**:
1. **Delete**: Remove unauthorized IAM entities
2. **Revoke**: All sessions for source role
3. **Review**: Full CloudTrail audit
4. **Restrict**: Apply permission boundaries

---

### High Alerts (Level 8-11) - Investigate Within 1 Hour

#### Credential Discovery (Rule 100601)
**Alert**: `NHI: Credential discovery attempt via file search`

**Triage Questions**:
- Is this a developer troubleshooting?
- Is this from an automated scanning tool?
- What files were searched?

**Investigation Steps**:
1. Review the full command executed
2. Check user context (who ran the command)
3. Verify if any sensitive files were accessed

**Response Based on Findings**:
- **Legitimate**: Document and close
- **Suspicious**: Isolate, investigate user activity
- **Malicious**: Full incident response

---

#### Service Account Token Access (Rule 100753)
**Alert**: `NHI: Kubernetes service account token accessed`

**Triage Questions**:
- Is the application expected to use K8s API?
- Was the token used for API calls?
- What permissions does the SA have?

**Investigation**:
```bash
# Check SA permissions
kubectl auth can-i --list --as=system:serviceaccount:default:default

# Review API audit logs
kubectl logs -n kube-system -l component=kube-apiserver | grep "default:default"
```

---

### Medium Alerts (Level 4-7) - Review Daily

#### Configuration File Access (Rule 100600)
**Alert**: `NHI: Sensitive configuration file access detected`

**Triage**: Often legitimate, but worth reviewing patterns.

**Investigation**:
- Check if access aligns with deployment/update activity
- Verify the accessing process is expected
- Look for unusual access times

---

## Investigation Techniques

### Timeline Analysis

```bash
# Get auth token (if not already set)
TOKEN=$(curl -sk -u wazuh-wui:MyS3cr3tP@ssw0rd -X POST \
  "https://localhost:55000/security/user/authenticate?raw=true")

# Get all alerts for an agent in time order
curl -sk -H "Authorization: Bearer $TOKEN" \
  "https://localhost:55000/alerts?agent_name=cloud-workload&sort=-timestamp&limit=100" | \
  jq '.data.affected_items[] | {time: .timestamp, rule: .rule.id, desc: .rule.description}'
```

### Correlation Analysis

```bash
# Find related alerts by source IP
curl -sk -H "Authorization: Bearer $TOKEN" \
  "https://localhost:55000/alerts?srcip=172.41.0.10" | \
  jq '.data.affected_items'

# Find alerts by rule group
curl -sk -H "Authorization: Bearer $TOKEN" \
  "https://localhost:55000/alerts?group=nhi_imds" | \
  jq '.data.affected_items'
```

### Log Deep Dive

```bash
# Full logs from agent
docker exec wazuh-manager cat /var/ossec/logs/archives/archives.json | \
  jq 'select(.agent.name=="cloud-workload")'

# Search for specific patterns
docker exec wazuh-manager grep -r "169.254.169.254" /var/ossec/logs/
```

## Escalation Criteria

### Escalate to Security Team When:
- Any Level 12+ alert triggers
- Multiple related alerts from same source
- Evidence of data exfiltration
- Lateral movement detected
- Persistence mechanisms found

### Escalate to Management When:
- Confirmed credential compromise
- Evidence of data breach
- Regulatory implications
- Extended attacker presence (>24h)

## Response Checklists

### Credential Theft Response
- [ ] Identify all affected credentials
- [ ] Rotate credentials immediately
- [ ] Review access logs for usage
- [ ] Identify attacker entry point
- [ ] Block attacker access
- [ ] Document timeline
- [ ] Preserve evidence
- [ ] Update detection rules

### Container Compromise Response
- [ ] Terminate compromised container
- [ ] Preserve container filesystem
- [ ] Check for lateral movement
- [ ] Review node security
- [ ] Check other pods on node
- [ ] Update pod security policies
- [ ] Review RBAC permissions

### CI/CD Compromise Response
- [ ] Revoke all pipeline tokens
- [ ] Review recent builds
- [ ] Check for modified workflows
- [ ] Audit secret access
- [ ] Review artifact integrity
- [ ] Update pipeline security

## Metrics and Reporting

### Key Metrics to Track
- **MTTD** (Mean Time to Detect): Time from attack to alert
- **MTTR** (Mean Time to Respond): Time from alert to containment
- **Alert Volume**: By category and severity
- **False Positive Rate**: By rule

### Weekly Report Template
```markdown
## NHI Security Weekly Report

### Alert Summary
- Critical: X alerts
- High: X alerts
- Medium: X alerts

### Notable Incidents
1. [Incident description and resolution]

### Trends
- [Increase/decrease in specific categories]

### Recommendations
- [Rule tuning suggestions]
- [Process improvements]
```
