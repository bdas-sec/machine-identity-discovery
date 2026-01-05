# NDC Security Oslo 2026
## "Who Gave the Agent Admin Rights?! Securing Cloud & AI Machine Identities"

### Presentation Outline

---

## Session Details
- **Speaker**: Bodhisattva Das
- **Duration**: 45 minutes (40 min talk + 5 min Q&A)
- **Format**: Technical deep-dive with live demo

---

## Outline

### Part 1: The NHI Security Problem (8 minutes)

#### 1.1 Opening Hook (2 min)
- "Who here has given an AI agent access to production systems?"
- Show headline: Capital One breach - $80M fine, 100M records
- The attacker's favorite target: Non-Human Identities

#### 1.2 What Are NHIs? (3 min)
- API keys and secrets
- Service accounts (AWS IAM roles, GCP SAs, Azure SPs)
- CI/CD tokens (GitHub, GitLab, Azure DevOps)
- Kubernetes service accounts
- AI agent credentials

#### 1.3 Why NHIs Are The New Attack Surface (3 min)
- Statistics: 45x more NHIs than human identities
- They don't use MFA
- They often have excessive privileges
- They're everywhere and growing

---

### Part 2: Anatomy of NHI Attacks (10 minutes)

#### 2.1 Attack Category Overview (2 min)
- Show the 5 categories
- Real-world examples for each

#### 2.2 Deep Dive: IMDS Credential Theft (4 min)
- Explain 169.254.169.254
- Capital One attack flow
- Why it's so dangerous
- LIVE DEMO: IMDS attack

#### 2.3 Deep Dive: AI Agent Exploitation (4 min)
- Prompt injection basics
- Agent tools as attack surface
- SSRF through AI agents
- Why "agentic AI" is scary

---

### Part 3: Detection with Wazuh (12 minutes)

#### 3.1 Wazuh Introduction (2 min)
- Open-source SIEM
- Why it's great for NHI detection
- Our custom rules (100600-100999)

#### 3.2 LIVE DEMO: Attack & Detection (8 min)
- Show clean Wazuh dashboard
- Execute IMDS attack (S2-01)
- Watch alert appear in real-time
- Investigate the alert
- Show remediation

#### 3.3 Detection Rule Patterns (2 min)
- Pattern matching for secrets
- Correlation rules
- MITRE ATT&CK mapping

---

### Part 4: Securing Your NHIs (8 minutes)

#### 4.1 Immediate Actions (3 min)
- Audit your NHI inventory
- Find and rotate exposed secrets
- Enable IMDSv2
- Review CI/CD permissions

#### 4.2 Long-term Strategy (3 min)
- Secrets management (Vault, AWS SM)
- Least privilege everywhere
- OIDC for keyless auth
- AI agent guardrails

#### 4.3 Building Detection (2 min)
- Custom Wazuh rules
- CloudTrail monitoring
- GitHub secret scanning
- Correlation and alerting

---

### Part 5: Conclusion (2 minutes)

#### 5.1 Key Takeaways (1 min)
1. NHIs are your biggest blind spot
2. Assume breach - detect early
3. Least privilege is non-negotiable
4. AI agents need guardrails

#### 5.2 Resources & Call to Action (1 min)
- GitHub repo link
- Handbook link
- "Go run an NHI audit this week"

---

### Q&A (5 minutes)

---

## Timing Summary

| Section | Duration | Cumulative |
|---------|----------|------------|
| Part 1: Problem | 8 min | 8 min |
| Part 2: Attacks | 10 min | 18 min |
| Part 3: Detection | 12 min | 30 min |
| Part 4: Securing | 8 min | 38 min |
| Part 5: Conclusion | 2 min | 40 min |
| Q&A | 5 min | 45 min |

---

## Slide Count Estimate
- Title + Bio: 2 slides
- Part 1: 6 slides
- Part 2: 8 slides
- Part 3: 4 slides (rest is demo)
- Part 4: 6 slides
- Part 5: 2 slides
- **Total**: ~28 slides

---

## Demo Checkpoints

1. **Pre-demo** (before talk):
   - Testbed running
   - Dashboard open
   - Terminal ready
   - Backup video ready

2. **Demo 1** (Part 2): IMDS attack visualization
   - 3 minutes allocated
   - Backup: Screenshot sequence

3. **Demo 2** (Part 3): Full attack & detection
   - 8 minutes allocated
   - Backup: Pre-recorded video

---

## AV Requirements
- Screen sharing capability
- Two browser tabs:
  - Wazuh Dashboard
  - Terminal
- Backup: Video files
