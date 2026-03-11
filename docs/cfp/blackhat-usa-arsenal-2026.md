# Black Hat USA 2026 — Arsenal CFP Submission

**Submission platform**: [usa-arsenal-cfp.blackhat.com](https://usa-arsenal-cfp.blackhat.com/)
**Deadline**: March 13, 2026
**Event**: August 2026 — Las Vegas, NV
**Format**: Tool Demonstration (~1 hour 50 minutes)

---

## Tool Name

NHI Security Testbed

---

## Tool Description

The NHI Security Testbed is an open-source, containerised purple team framework for attacking and detecting non-human identity (NHI) threats across cloud, CI/CD, Kubernetes, AI agents, OAuth/OIDC, and SPIFFE/SPIRE environments. It is the only framework purpose-built for this category.

Non-human identities — service accounts, IAM roles, CI/CD tokens, OAuth apps, AI agent credentials, SPIFFE SVIDs — outnumber human users 50:1 in production cloud environments. They carry `AdministratorAccess` by default, never rotate, have no MFA, and generate telemetry that most SIEMs have zero rules for. The NHI Security Testbed provides a structured offensive kill chain for exploiting these identities, paired with real-time detection using 120+ validated detection rules across Wazuh and Sigma formats.

**By the numbers:**

- 120+ Wazuh detection rules and 120+ Sigma rules (cross-SIEM: Splunk, Sentinel, Elastic, Chronicle)
- 55+ attack scenarios across 10 categories and 6 progressive attack levels
- New offensive CLI tool: `nhi-recon` — Python-based NHI discovery, enumeration, attack chain execution, and detection evasion testing
- Real-time React attack dashboard: D3.js network topology, MITRE ATT&CK heat map, live alert feed
- 8-stage supply chain kill chain as the centerpiece demo
- 13 SPIFFE/SPIRE scenarios covering all 10 known attack vectors plus federation abuse
- AI agent expansion: MCP server credential relay, agent-to-agent credential flow, RAG poisoning
- Kubernetes-native deployment via Kind + Helm + NHIScenario CRD operator
- Falco integration with NHI-specific eBPF rules
- 5 mock services: AWS/Azure/GCP IMDS, CI/CD server (GitHub/GitLab), OAuth provider, SPIRE server, HashiCorp Vault
- FastAPI REST API for programmatic scenario execution, rule queries, and live alert retrieval
- Self-contained: Docker Compose, no cloud accounts needed, deploys in under 3 minutes

**The thesis:**

Every NHI attack in this framework uses zero malware. No exploit kits, no reverse shells, no custom payloads — only default permissions, standard HTTP requests, and the trust that cloud environments implicitly extend to machine identities. Endpoint detection sees nothing. Network IDS sees nothing. The attacker operates entirely within the cloud control plane, exactly as Capital One's attacker did in 2019, exactly as the SolarWinds attacker did in 2020.

The NHI Security Testbed is "Atomic Red Team for NHI": structured, reproducible, executable attack scenarios paired with corresponding detection rules — so security teams can close gaps they previously could not even see.

**MITRE ATT&CK techniques demonstrated:**

T1552.005 (Cloud Instance Metadata API), T1078.004 (Cloud Accounts), T1528 (Steal Application Access Token), T1195.002 (Compromise Software Supply Chain), T1611 (Escape to Host), T1550.001 (Application Access Token), T1134 (Access Token Manipulation), T1553.004 (Install Root Certificate), T1098 (Account Manipulation)

**Previous presentations:**

NDC Security 2026

---

## Code Repository

**GitHub**: [github.com/bdas-sec/machine-identity-discovery](https://github.com/bdas-sec/machine-identity-discovery)

**License**: Non-Commercial Use License (free for personal, educational, research, and security training purposes)

---

## Demo Plan

### Booth Setup

Single laptop running the full testbed via Docker Compose. External monitor displaying the real-time React attack dashboard — D3.js network topology in the left panel, MITRE ATT&CK heat map in the centre, live Wazuh alert feed on the right. Visitors interact with the `nhi-recon` CLI in the terminal and watch the dashboard light up in real time. The dashboard is the visual hook — it draws foot traffic from across the floor.

### Demo Flow (rotating ~20-minute cycles)

#### [0:00 - 4:00] The 60-Second Kill Chain via nhi-recon CLI

Live demonstration of SSRF-to-full-admin in under 60 seconds using the new `nhi-recon` offensive CLI:

```
nhi-recon discover --target localhost:8888
nhi-recon steal-creds --vector ssrf-imds --target localhost:8888
nhi-recon escalate --check-permissions
```

1. `discover`: Enumerates endpoints, identifies SSRF vector, locates `.env` file with hardcoded credentials
2. `steal-creds --vector ssrf-imds`: Three automated HTTP requests — SSRF to IMDS, retrieve IAM role name, exfiltrate `AccessKeyId`/`SecretAccessKey`/`SessionToken`
3. `escalate`: Reveals the role carries `AdministratorAccess`

Dashboard: Rule 100651 (IMDS credential theft) fires at Level 12. The MITRE ATT&CK heat map lights up at T1552.005. The network topology shows the attack path from the web tier to the cloud metadata service.

Total: unauthenticated web user to persistent cloud admin in under 60 seconds. Zero malware.

#### [4:00 - 10:00] 8-Stage Supply Chain Kill Chain

The centrepiece demo. A single compromised CI/CD token propagates through eight stages from initial access to persistent infrastructure control:

| Stage | Technique | Rule Fired |
|-------|-----------|------------|
| 1. Initial Access | SSRF to IMDS (Capital One vector) | 100651 — Level 12 |
| 2. Credential Harvest | IAM role key extraction | 100652 |
| 3. Privilege Escalation | Over-permissioned role → admin | 100700 |
| 4. CI/CD Pivot | Stolen cloud creds → GitHub Actions secrets | 100800-100805 |
| 5. Pipeline Persistence | Malicious workflow injection | 100807 |
| 6. Dependency Poisoning | Package registry manipulation | 100808 |
| 7. Artifact Signing | Supply chain attestation abuse | 100809 |
| 8. Downstream Compromise | Poisoned artifact deployed to production | 100810 |

Correlation Rule 100952 chains the full CI/CD attack at Level 14. The dashboard shows every stage transition in real time on the network topology graph.

#### [10:00 - 14:00] SPIFFE/SPIRE Attack Scenarios

Three live demonstrations of the new SPIFFE/SPIRE attack category — 13 scenarios total, covering all 10 known attack vectors:

- **SVID Harvesting** (Vector 3): Attacker on the same node accesses the SPIRE Workload API Unix socket and calls `FetchX509SVID`, harvesting cryptographic identity credentials for every workload on the node. Rule 101000 fires on socket access; Rule 101001 fires when a scripting tool touches the socket; Rule 101003 fires on the rapid SVID request burst.
- **Container Escape → SVID Theft** (Vector 6): `nsenter` to host, navigate to `/tmp/spire-agent/public/api.sock`, harvest all node SVIDs. Correlation Rule 101080 chains the escape indicators to socket access at Level 15.
- **Trust Bundle Poisoning** (Vector 8): Inject a rogue CA certificate into the SPIRE trust bundle via the server API. All services in the mesh now accept SVIDs signed by the attacker's CA. Rule 101041 fires on the `SetFederatedBundle` API call.

"SPIFFE replaces static credentials with short-lived cryptographic identities. That's a genuine security improvement. But the identity framework itself is an attack surface, and no SIEM has detection rules for it until now."

#### [14:00 - 18:00] AI Agent Attack Expansion

Four scenarios demonstrating the expanded AI agent attack surface:

- **MCP Server Credential Relay**: Agent's Model Context Protocol server relays cloud credentials to attacker-controlled tools
- **Agent-to-Agent Credential Flow**: Credential material propagates through an agent chain where no single agent has visibility into the full credential lifecycle
- **Tool-Use SSRF**: Agent's HTTP tool fetches IMDS credentials — "Capital One was 2019 with a misconfigured web app. In 2026, the SSRF is coming from inside the agent."
- **RAG Poisoning**: Malicious documents injected into the retrieval corpus instruct the agent to exfiltrate credentials

Correlation Rule 100953 chains agent SSRF to credential access at Level 15.

#### [18:00 - 20:00] Hands-On: Visitor Runs an Attack

Hand the terminal to the visitor. They run `nhi-recon` directly:

```
nhi-recon scenario --run s1-02 --watch
```

The `--watch` flag keeps the dashboard live as the attack executes. The visitor watches their own attack trigger detection alerts in real time. They leave understanding both the methodology and the gap.

---

## Technical Requirements

- Monitor with HDMI input (provided by Arsenal)
- Power outlet
- Wired internet connection (provided by Arsenal)
- Demo runs entirely offline — no cloud accounts or external dependencies required

---

## Supporting Documentation

- [Workshop Handbook](https://github.com/bdas-sec/machine-identity-discovery/tree/main/docs/handbook) — complete setup, architecture, and scenario guides
- [Scenario Catalog](https://github.com/bdas-sec/machine-identity-discovery/blob/main/docs/handbook/04-scenario-catalog.md) — all 55+ attack scenarios with step-by-step instructions
- [Sigma Rule Library](https://github.com/bdas-sec/machine-identity-discovery/tree/main/sigma/rules) — 120+ rules in Sigma YAML format with pySigma conversion pipeline
- [SPIFFE/SPIRE Attack Techniques Reference](https://github.com/bdas-sec/machine-identity-discovery/blob/main/docs/spiffe-spire-attack-techniques.md) — 10 attack vectors with detection guidance

---

## Why Arsenal

The NHI Security Testbed is a hands-on tool, not a slide deck. Arsenal's format — live tool demos with direct visitor interaction — is the right venue for a framework built around executable attack scenarios and real-time detection feedback.

The new `nhi-recon` CLI turns the Arsenal booth into an offensive experience: visitors run attacks themselves, not just watch a presenter run them. The real-time React dashboard gives the booth visual impact that draws people in from across the floor. Every visitor who runs a scenario leaves with the testbed URL, the `nhi-recon` CLI, and 120+ Sigma rules they can deploy into their own SIEM the same day.

No cloud accounts. No vendor dependencies. No marketing. Just 55+ attack scenarios, 120+ detection rules, an offensive CLI, and a visual dashboard — connected by the kill chain methodology that makes them coherent.

---

## Key Numbers at a Glance

| Metric | Value |
|--------|-------|
| Wazuh detection rules | 120+ |
| Sigma rules | 120+ |
| Attack scenarios | 55+ |
| Attack categories | 10 |
| SPIFFE/SPIRE scenarios | 13 |
| AI agent scenarios | 8+ |
| Supply chain kill chain stages | 8 |
| Supported SIEMs | 5 (Wazuh, Splunk, Sentinel, Elastic, Chronicle) |
| Mock services | 5 |
| MITRE ATT&CK techniques | 20+ |
| Deploys in | <3 minutes |
| Offensive CLI tool | nhi-recon |
| Real-time dashboard | React + D3.js + MITRE ATT&CK heat map |
| K8s deployment | Kind + Helm + NHIScenario CRD operator |

---

## Speaker Bio

**Bodhisattva Das** is a security practitioner specialising in cloud identity security and offensive techniques targeting non-human identities. He maintains the open-source NHI Security Testbed — a containerised purple team framework for attacking and detecting machine identity threats across cloud, CI/CD, Kubernetes, AI agent, and SPIFFE/SPIRE environments. He has presented this research at NDC Security 2026.

GitHub: [@bdas-sec](https://github.com/bdas-sec)
LinkedIn: [bdas1201](https://linkedin.com/in/bdas1201)
