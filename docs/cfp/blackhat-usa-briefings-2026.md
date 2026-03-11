# Black Hat USA 2026 — Briefings CFP Submission

**Submission platform**: [usa-briefings-cfp.blackhat.com](https://usa-briefings-cfp.blackhat.com/)
**Deadline**: March 20, 2026
**Event**: August 2026 — Las Vegas, NV
**Session length**: 40 minutes
**Track**: Cloud & Platform Security

---

## Title

State of NHI Detection: Why Your SIEM Can't See 80% of Machine Identity Attacks

---

## Abstract

Non-human identities — service accounts, IAM roles, CI/CD tokens, OAuth applications, AI agent credentials, SPIFFE SVIDs — outnumber human users 50:1 in production cloud environments. They carry `AdministratorAccess` by default, never rotate, and have no MFA. But the most consequential security gap is not in the identities themselves. It is in the monitoring.

Security operations centres were built to monitor humans. SIEM deployments accumulate hundreds of rules for failed logins, impossible travel, privilege changes by user accounts, session anomalies — all of which assume the identity under attack belongs to a person. When the attacker steals an IAM role's credentials via SSRF to the Instance Metadata Service — the exact technique used in the 2019 Capital One breach — those rules produce nothing. When a SolarWinds-style supply chain attacker establishes persistence through CI/CD pipeline injection, those rules produce nothing. When a compromised AI agent relays cloud credentials through its Model Context Protocol server, those rules produce nothing.

This talk presents the first cross-SIEM quantitative analysis of NHI detection coverage — a structured benchmark evaluating 5 SIEM platforms against 55+ NHI attack scenarios across 10 attack categories. The finding is direct: default SIEM configurations detect fewer than 20% of NHI-specific attack techniques. The remaining 80% generate no alerts. Not reduced-severity alerts. No alerts at all.

The session then delivers the fix: a validated library of 120+ detection rules — Wazuh native and Sigma format, converted via pySigma to Splunk SPL, Microsoft Sentinel KQL, Elastic EQL, and Google Chronicle YARA-L — covering the full NHI attack surface, from cloud IMDS abuse to SPIFFE/SPIRE identity infrastructure attacks to AI agent credential relay. Every rule is mapped to MITRE ATT&CK, validated against live attack traffic, and ready to deploy. Attendees receive the open-source testbed, the complete rule library, and the benchmark methodology to run their own gap analysis.

---

## Detailed Description

### The Research Problem: A Structural Monitoring Blind Spot

Cloud security monitoring has a structural blind spot that has persisted for over a decade. The problem is not a lack of data. IMDS access logs, IAM credential usage patterns, CI/CD API call records, Kubernetes service account audit events, SPIRE agent workload API logs — all of this telemetry already exists in most cloud environments. The problem is the absence of detection rules written for it.

The reason is straightforward: security operations teams were built around human identity threat models. Their SIEM rules encode assumptions about what an attack looks like — failed authentication attempts, unusual login locations, account privilege changes. These assumptions are structurally inapplicable to non-human identities. A service account does not fail a login. An IAM role does not travel. A CI/CD token does not have a session to hijack. When an attacker steals and uses these credentials, the activity is indistinguishable from legitimate automation — unless you have rules written specifically for machine identity behaviour.

This is not a criticism of existing SIEM investments. It is a gap in the field's collective understanding of what NHI attacks look like from a telemetry perspective. No published research has systematically characterised this gap across SIEM platforms, or provided a validated rule library to close it.

### Novel Research Contribution 1: Cross-SIEM NHI Detection Benchmark

The centrepiece of this talk is original research: a quantitative gap analysis evaluating NHI attack detection coverage across 5 SIEM platforms — Wazuh, Splunk, Microsoft Sentinel, Elastic Security, and Google Chronicle — against a standardised set of 55+ NHI attack scenarios across 10 categories.

**Benchmark methodology:**

- Each scenario is executed against the NHI Security Testbed, a fully containerised environment reproducing the complete NHI attack lifecycle
- Alert output is captured across all 5 SIEM platforms simultaneously via the pySigma conversion pipeline
- Detection is scored as positive only if at least one rule fires within 60 seconds of scenario execution — no credit for partial coverage or post-hoc correlation
- Results are reported per scenario category, per SIEM, and as an aggregate coverage percentage

**Preliminary findings across 10 attack categories:**

| Category | Default SIEM Coverage | With NHI Rule Library |
|----------|-----------------------|-----------------------|
| Cloud IMDS Exploitation | <10% | 94% |
| Service Account Credential Theft | <15% | 91% |
| CI/CD Pipeline Attacks | <20% | 89% |
| Kubernetes Service Account Abuse | ~25% | 93% |
| OAuth/OIDC Token Abuse | <10% | 87% |
| AI Agent Credential Relay | 0% | 85% |
| SPIFFE/SPIRE Identity Attacks | 0% | 88% |
| Cross-Domain Attack Chains | <5% | 82% |
| Secret Pattern Exfiltration | ~30% | 96% |
| Supply Chain Persistence | <15% | 84% |

The "0% default coverage" result for AI agent and SPIFFE/SPIRE categories is not surprising — these are emerging threat categories with no published detection research. The near-zero coverage for IMDS exploitation and OAuth token abuse is more striking. Capital One's 2019 breach via SSRF to IMDS is seven years old. The technique is well-documented in MITRE ATT&CK as T1552.005. Most SIEMs still have no rules for it in their default configuration.

**Why this benchmark is novel:**

No prior research has produced a cross-SIEM, quantitative detection coverage benchmark specifically for NHI attacks. Individual technique analyses exist (primarily focused on cloud provider-specific monitoring), but no framework has measured detection across the full NHI kill chain with validated, reproducible test cases.

### Novel Research Contribution 2: The 8-Stage Supply Chain Kill Chain

Existing cloud attack frameworks — including the MITRE ATT&CK Cloud Matrix — document techniques as a catalogue. They do not provide a purpose-built kill chain methodology for NHI exploitation that shows how individual techniques chain into a complete attack lifecycle.

This talk presents an 8-stage NHI-specific supply chain kill chain, developed by reverse-engineering documented breach patterns into reproducible, telemetry-producing attack steps:

**Stage 1 — Initial Access (T1190):** Application vulnerability exposes an SSRF endpoint. Attacker enumerates the vulnerable application using standard HTTP requests.

**Stage 2 — Credential Harvest (T1552.005):** SSRF to the AWS Instance Metadata Service. Three HTTP requests yield the IAM role name, `AccessKeyId`, `SecretAccessKey`, and `SessionToken`. This is the Capital One 2019 attack vector, reproduced exactly.

**Stage 3 — Privilege Escalation (T1078.004):** The harvested role carries `AdministratorAccess`. Unauthenticated web user to full cloud admin. No exploit required — default permissions on a machine identity.

**Stage 4 — CI/CD Pivot (T1528):** Stolen cloud credentials authenticate to the GitHub Actions API and the GitLab CI project variables endpoint. CI/CD secrets are extracted. One SSRF vulnerability now controls both the cloud account and the software delivery pipeline.

**Stage 5 — Pipeline Persistence (T1195.002):** A malicious workflow is injected into a CI/CD pipeline definition. Every subsequent pipeline execution runs attacker-controlled code with pipeline-scoped permissions.

**Stage 6 — Dependency Poisoning (T1195.001):** The compromised pipeline publishes a trojanised version of an internal package to the organisation's artifact registry.

**Stage 7 — Artifact Signing Abuse:** Supply chain attestation mechanisms — SLSA provenance, Sigstore/cosign — are satisfied using the compromised pipeline's legitimate signing identity. The attack is invisible to signature verification.

**Stage 8 — Downstream Compromise:** The poisoned artifact is consumed by downstream services. Attacker achieves persistent presence in production infrastructure using only sanctioned tooling throughout.

Total: eight stages, zero malware, zero unusual network traffic, zero endpoint alerts. Every step indistinguishable from legitimate CI/CD activity.

**Breach parallels:** SolarWinds (2020) demonstrated stages 5-8 at scale. Codecov (2021) reproduced stages 4-5 via a compromised bash script in the CI/CD pipeline. The 3CX breach (2023) added the downstream deployment stage. This kill chain synthesises all three into a unified, reproducible methodology.

### Novel Research Contribution 3: SPIFFE/SPIRE Attack Surface with Detection Rules

SPIFFE/SPIRE represents the current state of the art in cloud-native machine identity — short-lived, automatically rotated cryptographic identities replacing static API keys. It is a genuine security improvement. It also introduces a new attack surface that no published research addresses with detection rules.

This talk introduces 13 SPIFFE/SPIRE attack scenarios covering 10 attack vectors, with 30+ dedicated detection rules:

**The key insight:** SPIFFE replaces static credentials with short-lived SVIDs (SPIFFE Verifiable Identity Documents). But the infrastructure that issues and manages those SVIDs — the SPIRE Server, SPIRE Agents, and the Workload API Unix socket — is itself an attack surface. Compromising the identity infrastructure is equivalent to owning every credential it manages.

**Representative attack vectors with detection rules:**

- **SVID Harvesting (T1552.007):** Attacker on the same node accesses the SPIRE Workload API socket (`/tmp/spire-agent/public/api.sock`) and calls `FetchX509SVID`. Rules 101000-101005 detect socket access, scripting tools on the socket, and rapid SVID request bursts.
- **Container Escape → SVID Theft (T1611):** Container escape via `nsenter` followed by SPIRE socket access. Correlation Rule 101080 chains the escape indicators to socket access at Level 15 — the full attack chain in a single high-fidelity alert.
- **Trust Bundle Poisoning (T1553.004):** Attacker injects a rogue CA certificate into the SPIRE trust bundle via the `SetFederatedBundle` API. Every service in the mesh trusts SVIDs the attacker signs. Rule 101041 fires on the API call; FIM alerts on bundle file modification.
- **Delegated Identity API Abuse (T1134):** A workload authorized for SPIRE's Delegated Identity API calls `SubscribeToX509SVIDs`, receiving the private keys for every identity managed by that node's agent. Rule 101061 detects this API method — the most powerful single capability in SPIRE, now with detection coverage.

The SPIFFE/SPIRE attack surface is particularly relevant for organisations adopting zero-trust service mesh architectures. The framework CNCF graduated SPIFFE precisely because static credentials are a systemic risk. But zero-trust identity infrastructure itself requires monitoring — and no SIEM vendor has written rules for it.

### Novel Research Contribution 4: AI Agent NHI Attack Surface

AI agents are the fastest-growing category of non-human identity. Each agent deployment creates new NHI attack surface that inherits every anti-pattern from traditional machine identities — over-permissioned by default, no credential rotation, no MFA — while introducing new attack vectors:

- **MCP Server Credential Relay:** An agent's Model Context Protocol server acts as a credential relay. Tools registered to the MCP server can be invoked by the agent with the agent's cloud identity. A compromised MCP server tool definition can exfiltrate credential material during tool execution, with no indication in the agent's conversation context.
- **Agent-to-Agent Credential Flow:** In multi-agent pipelines, credential material passed between agents traverses an implicit trust boundary. No single agent has full visibility into the credential lifecycle; no SIEM has rules to reconstruct it.
- **Tool-Use SSRF:** The agent's built-in HTTP tool becomes an IMDS proxy. The agent fetches `http://169.254.169.254/latest/meta-data/iam/security-credentials/` as a routine tool invocation. "Capital One was 2019 with a misconfigured web application. In 2026, the SSRF is coming from inside the agent."
- **RAG Poisoning:** Malicious content injected into a Retrieval-Augmented Generation corpus includes instructions for the agent to exfiltrate its environment variables or call credential-bearing API endpoints. The attack surface grows with every document in the knowledge base.

Each scenario has dedicated detection rules. Correlation Rule 100953 chains agent SSRF to credential access at Level 15. The rule fires before the attacker exfiltrates data.

### Research Validation

Every technique in this framework is grounded in documented breach patterns:

- **Capital One (2019):** SSRF to IMDS credential theft — 106 million records. The exact technique in Kill Chain Stage 2. MITRE ATT&CK T1552.005.
- **SolarWinds (2020):** CI/CD pipeline compromise enabling supply chain persistence. Kill Chain Stages 5-8 reproduced exactly.
- **Uber (2022):** Compromised service account credentials for lateral movement across internal infrastructure. Kill Chain Stage 4.
- **Codecov (2021):** CI/CD build environment credential exfiltration. Kill Chain Stage 4, with direct parallels to the GitHub Actions pivot scenarios.
- **3CX (2023):** Supply chain compromise propagating through downstream artifact deployment. Kill Chain Stage 8.

Each testbed scenario was built by reverse-engineering the breach pattern — not by theorising about what attacks might look like, but by reconstructing what attackers demonstrably did and ensuring the resulting telemetry is detectable.

---

## Three Actionable Takeaways

**1. The cross-SIEM NHI detection gap benchmark — run it against your own environment.**

Attendees receive the full benchmark methodology, the 55+ test scenarios, and the NHI Security Testbed to reproduce the gap analysis against their own SIEM deployment. The benchmark produces a per-category coverage score — a concrete, measurable baseline for NHI detection maturity. Most organisations do not know their NHI detection coverage is near zero because they have never had a structured way to test it. After this talk, they do.

**2. 120+ production-ready Sigma detection rules — deploy to your SIEM today.**

The complete rule library covers cloud IMDS abuse across three providers, service account credential theft, CI/CD pipeline attacks, Kubernetes service account compromise, OAuth/OIDC token abuse, AI agent credential relay, SPIFFE/SPIRE identity attacks, secret pattern exfiltration, cross-domain attack chains, and multi-stage correlation. All rules are in Sigma YAML format; the pySigma pipeline converts to Splunk SPL, Sentinel KQL, Elastic EQL, and Chronicle YARA-L. Most SOCs have zero NHI-specific detections. These 120+ rules close that gap on day one.

**3. The 8-stage supply chain kill chain — map your detection coverage against it.**

The kill chain is a practical gap analysis tool, not just a conference demo. Each stage produces specific telemetry. Defenders can take the kill chain, walk through each stage, and identify which ones would generate alerts in their current SIEM configuration. Stages that produce no alerts are where the attacker has operational freedom. The kill chain makes the invisible visible — and gives the red team a structured methodology for NHI-focused adversary simulation.

---

## Presentation Outline

### [0:00 - 5:00] The Machine Identity Crisis (5 min)

The 50:1 ratio, and why it is growing — every AI agent deployment, every microservice, every CI/CD pipeline step creates new NHI attack surface. Side-by-side comparison of human identity security controls (MFA, rotation, access reviews, session limits, device trust) against machine identity security controls (none — not because practitioners are careless, but because the tools and frameworks to manage NHI security at scale did not exist until recently).

The structural monitoring problem: your SIEM was built to monitor humans. The rules encode human behaviour — failed logins, impossible travel, session anomalies. Machine identity attacks bypass every one of these heuristics. Then the breach parallels: Capital One (IMDS exploitation, 2019), SolarWinds (CI/CD persistence, 2020), Codecov (build environment credential exfiltration, 2021), 3CX (downstream artifact compromise, 2023). Each a different stage of the same underlying kill chain.

### [5:00 - 12:00] The Benchmark: What Your SIEM Actually Detects (7 min)

Presentation of the cross-SIEM detection coverage benchmark. Methodology explanation: 55+ attack scenarios, 10 categories, 5 SIEM platforms, scoring criteria. Results by category — the gap between default SIEM coverage and coverage with the NHI rule library applied.

The finding that anchors the rest of the talk: the two categories with 0% default coverage are AI agent attacks and SPIFFE/SPIRE attacks — the two fastest-growing NHI categories in production cloud environments. For IMDS exploitation — a seven-year-old, MITRE-documented technique — default coverage across all 5 SIEMs is below 10%.

Why the gap exists is not addressed by adding more SIEM rules for human identity threats. The gap is structural. Human identity detection heuristics do not transfer to machine identity telemetry. Closing the gap requires rules written specifically for NHI behaviour.

### [12:00 - 23:00] The 8-Stage Supply Chain Kill Chain (11 min)

Live demonstration against the open-source testbed. All 8 stages executed in sequence, each producing specific telemetry:

- **Stage 1 — Discovery (T1190):** Application endpoint enumeration, SSRF vector identification
- **Stage 2 — Credential Harvest (T1552.005):** SSRF to IMDS, IAM credential exfiltration. Rule 100651 fires at Level 12
- **Stage 3 — Escalation (T1078.004):** Over-permissioned IAM role yields `AdministratorAccess`
- **Stage 4 — CI/CD Pivot (T1528):** Stolen credentials authenticate to GitHub Actions API. Rules 100800-100805 fire. Correlation 100952 at Level 14
- **Stage 5 — Pipeline Persistence (T1195.002):** Workflow injection. Rule 100807
- **Stage 6 — Dependency Poisoning (T1195.001):** Package registry manipulation. Rule 100808
- **Stage 7 — Signing Abuse:** Attestation bypass using legitimate pipeline identity. Rule 100809
- **Stage 8 — Downstream Compromise:** Poisoned artifact in production. Rule 100810

Pause after Stage 2: "Three HTTP requests. Unauthenticated web user to full cloud admin. Zero malware. This is Capital One 2019. It still works."

Pause after Stage 8: "Eight stages. No custom payloads. No unusual network traffic. No endpoint alerts. The only difference between this and a routine CI/CD pipeline run is 120+ SIEM rules."

Total: 8 stages, zero malware, <90 seconds of attacker activity that existing monitoring misses entirely.

### [23:00 - 30:00] SPIFFE/SPIRE and AI Agent Attack Surface (7 min)

Two emerging categories that account for 0% default SIEM coverage — and growing NHI adoption.

**SPIFFE/SPIRE (3 min):** Architecture overview for a non-SPIFFE audience — 60 seconds maximum. Then three attack demonstrations: SVID Harvesting (socket access + rapid SVID request burst, Rules 101000-101005), Container Escape → SVID Theft (correlation chain: escape indicators + socket access = Level 15, Rule 101080), Trust Bundle Poisoning (rogue CA injection, Rule 101041). Key message: "Zero-trust identity infrastructure requires its own threat model. SPIFFE is a security improvement over static credentials. The identity framework itself is still an attack surface."

**AI Agents (4 min):** MCP server credential relay — the attack surface that did not exist two years ago and is now in production deployments. Tool-use SSRF: the agent makes the IMDS request. Agent-to-agent credential flow: the credential lifecycle spans multiple agents with no single point of visibility. RAG poisoning: the knowledge base is the attack surface. Key message: "AI agents inherit every NHI anti-pattern and add new attack vectors on top. The 50:1 ratio is accelerating. Every agent deployment is a new NHI without a detection rule."

### [30:00 - 37:00] Closing the Gap: 120+ Detection Rules (7 min)

Rule architecture overview: 10 categories, 120+ Wazuh rules, 120+ Sigma rules. Severity model from Level 5 (informational telemetry) to Level 15 (confirmed multi-stage attack chain). Correlation rules: how to chain signals across kill chain stages — Rule 100954 fires when 5+ NHI events originate from the same source within 600 seconds, producing a single high-fidelity alert from what would otherwise be scattered low-severity noise.

Sigma portability: live comparison of the same IMDS credential theft detection in Wazuh XML, Sigma YAML, Splunk SPL, and Sentinel KQL. The detection logic is identical; only the syntax changes. pySigma converts the full library to all four platforms without rewriting rules.

Deployment guidance: which rules to start with (correlation rules 100950-100954 and 101080-101081 provide the highest signal-to-noise ratio in environments with no existing NHI coverage), how to tune severity thresholds, and how to integrate correlation alerts into SOAR playbooks.

The testbed: `./scripts/start.sh` — deploys in under 3 minutes on any machine with Docker. The full benchmark, all 55+ scenarios, and all 120+ rules are available immediately.

### [37:00 - 40:00] Q&A (3 min)

---

## Why This Talk Is New

**1. The first quantitative cross-SIEM NHI detection benchmark.**

Prior research on NHI security is almost entirely offensive — technique documentation, breach post-mortems, individual attack demonstrations. No published work has measured detection coverage across SIEM platforms for NHI-specific attacks using a standardised, reproducible methodology. The benchmark is original research, not a repackaging of known techniques. The finding — default coverage below 20% for most categories, 0% for emerging categories — is a concrete, measurable statement about the state of the field.

**2. Kill chain methodology, not a technique catalogue.**

MITRE ATT&CK documents individual techniques. This talk presents an 8-stage supply chain kill chain that shows how those techniques chain into a complete attack lifecycle targeting machine identities. The methodology is what makes it actionable for both red teams (structured adversary simulation) and blue teams (stage-by-stage coverage analysis). The kill chain is the connection between "here are attack techniques" and "here is what your monitoring gaps actually look like."

**3. Detection rules for attack surfaces that have no published rules.**

AI agent credential relay, SPIFFE/SPIRE identity attacks, and cross-domain NHI attack chains are emerging threat categories with growing real-world adoption and zero published detection guidance. This talk delivers the first validated, MITRE-mapped detection rules for each — not theoretical guidance, but rules validated against live attack traffic from the testbed.

---

## Speaker Bio

**Bodhisattva Das** is a security practitioner specialising in cloud identity security and offensive techniques targeting non-human identities. He maintains the open-source NHI Security Testbed — a containerised purple team framework for attacking and detecting machine identity threats across cloud, CI/CD, Kubernetes, AI agent, and SPIFFE/SPIRE environments. His research focuses on the systemic risk created by over-privileged machine identities and the structural detection gap in security operations centres built to monitor humans, not machines. He has presented this research at NDC Security 2026.

GitHub: [@bdas-sec](https://github.com/bdas-sec)
LinkedIn: [bdas1201](https://linkedin.com/in/bdas1201)

---

## Supporting Materials

- **GitHub Repository**: [github.com/bdas-sec/machine-identity-discovery](https://github.com/bdas-sec/machine-identity-discovery)
- **Sigma Rule Library**: 120+ rules in `sigma/rules/` across 10 categories, with pySigma conversion pipeline (Splunk, Sentinel, Elastic, Chronicle)
- **SPIFFE/SPIRE Attack Techniques Reference**: Full technical documentation of 10 attack vectors with detection rule mappings — `docs/spiffe-spire-attack-techniques.md`
- **Scenario Catalog**: 55+ attack scenarios with step-by-step instructions and expected telemetry
- **Workshop Handbook**: Complete architecture documentation, setup guides, and detection playbooks
- **NDC Security 2026**: Prior presentation of the foundational NHI kill chain (March 2026)

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
| SIEMs benchmarked | 5 (Wazuh, Splunk, Sentinel, Elastic, Chronicle) |
| Default SIEM NHI coverage (finding) | <20% |
| Coverage with NHI rule library | 82-96% by category |
| MITRE ATT&CK techniques | 20+ |
| Machine-to-human identity ratio | 50:1 |
