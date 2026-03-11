# KubeCon + CloudNativeCon North America 2026 — CFP Submission

**Event**: KubeCon + CloudNativeCon North America 2026
**Submission type**: Session Presentation (35 minutes)
**Track recommendation**: Security + Compliance
**CNCF project alignment**: SPIFFE/SPIRE (graduated), Falco (incubating), Kubernetes (graduated)
**GitHub**: https://github.com/bdas-sec/machine-identity-discovery

---

## Title

**Attacking the Identity Plane: A Purple Team Framework for SPIFFE/SPIRE**

---

## Session Type

**Primary recommendation**: Session Presentation — 35 minutes

The material fits a 35-minute slot: 8 minutes framing the SPIFFE/SPIRE attack surface, 15 minutes of live attack demonstrations against a real SPIRE 1.11.2 deployment, and 12 minutes on the detection layer and takeaways. A 90-minute Tutorial option is noted at the end of this document for programme committees that want to offer the content as a hands-on workshop.

---

## Abstract (300 words)

SPIFFE and SPIRE promise to eliminate static credentials from cloud-native infrastructure. Short-lived X.509 SVIDs, automatic rotation, cryptographic workload identity — the security properties are genuinely excellent. The attack surface they introduce is not widely understood.

This talk presents the first open-source framework for attacking and detecting SPIFFE/SPIRE deployments. Running against a real SPIRE 1.11.2 deployment — not slides, not a mock server — 13 attack scenarios cover all 10 documented SPIFFE/SPIRE attack vectors: selector spoofing, SVID harvesting, registration entry manipulation, trust bundle poisoning, JWT-SVID replay, delegated identity API abuse, container escape to SVID theft, agent re-attestation abuse, overlapping entry exploitation, and kubelet verification bypass. Three additional scenarios cover SPIFFE federation abuse and cross-cloud Workload Identity Federation attacks that chain a compromised SVID into AWS, GCP, and Azure control planes.

Every scenario is backed by 21 purpose-built Sigma rules — the first SPIFFE-specific Sigma rules in existence, currently being submitted to the SigmaHQ community repository. These rules cover the full detection stack: socket access monitoring via auditd, SVID key extraction via file integrity monitoring, registration entry creation via SPIRE audit logs, trust bundle modification, delegated identity API calls, kubelet configuration tampering, and multi-stage correlation chains that escalate from individual Level 8 alerts to a Level 15 confirmed attack. The correlation rule for container escape followed by SPIRE socket access catches the canonical "Spooffe" attack pattern documented in CyberArk's nullcon 2026 research.

The framework also introduces spiffe-security-bench, a kube-bench-equivalent auditing tool that scans live SPIRE deployments for 23 security controls across server configuration, agent configuration, trust bundle management, and workload attestor hardening.

SPIFFE is a CNCF graduated project. The security community does not yet have structured offensive tooling for it. This talk changes that.

---

## Detailed Description

### The Problem

The CNCF community has done significant work on what SPIFFE/SPIRE provides: workload identity, zero-trust connectivity, elimination of long-lived credentials. The security literature on what SPIFFE/SPIRE introduces as an attack surface is sparse by comparison.

Consider what SPIRE controls in a mature cloud-native deployment:

- Every service-to-service authentication decision in the mesh
- Which workloads receive which identities (registration entries)
- The root CA certificates trusted across the entire deployment (trust bundles)
- The agent node on each Kubernetes worker that issues identity credentials to workloads

Compromise any of these components and the attacker does not get one service account. They get the identity plane. Every workload in the trust domain becomes impersonatable.

Three architectural facts make SPIRE a high-value target:

**1. The Workload API socket is the crown jewel.** The SPIRE Agent exposes a Unix domain socket — typically at `/run/spire/sockets/agent.sock` or `/tmp/spire-agent/public/api.sock` — that issues cryptographic identity documents on demand. Any process on the host that can connect to this socket and pass workload attestation receives an SVID. Container escape attacks that historically granted host filesystem access now grant something more: the ability to present as any workload registered on that node.

**2. Default SPIRE configurations are not production-ready for detection.** Audit logging is disabled by default (`audit_log_enabled = false`). The log messages required for PID-based workload tracking are only emitted at DEBUG level. Without these configurations in place, 14 of the 21 Sigma rules in this framework produce no alerts. The community needs to know this.

**3. SPIFFE federation multiplies the blast radius.** A federated SPIFFE deployment that connects your Kubernetes identity plane to AWS IAM via Workload Identity Federation means a compromised trust bundle is not a SPIRE problem — it is an AWS root access problem.

### What This Framework Provides

**Real SPIRE 1.11.2 deployment.** The testbed runs a production-representative SPIRE environment: a SPIRE Server with SQLite datastore, a SPIRE Agent on the workload node using the Kubernetes workload attestor, and three registered workloads with varying selector configurations — one using strong `k8s:pod-uid` selectors, one using weak `unix:uid:0` selectors, one using overlapping selectors that enable the multi-identity attack.

**13 attack scenarios across all documented attack vectors.** Each scenario is a structured JSON file with preconditions, step-by-step commands, expected log artifacts, and detection rule mappings. Scenarios execute against the live SPIRE deployment and produce real log output that fires real detection rules.

| Scenario | Attack Vector | MITRE Technique |
|----------|--------------|-----------------|
| S7-01 | Selector spoofing (weak unix selectors) | T1078 — Valid Accounts |
| S7-02 | SVID harvesting via socket access | T1552.007 — Container API |
| S7-03 | Registration entry manipulation | T1098 — Account Manipulation |
| S7-04 | SVID harvesting via scripting tool | T1552.004 — Private Keys |
| S7-05 | JWT-SVID replay from log leakage | T1528 — Steal Application Access Token |
| S7-06 | Delegated Identity API — full node compromise | T1134 — Access Token Manipulation |
| S7-07 | Container escape + SPIRE socket (Spooffe pattern) | T1611 — Escape to Host |
| S7-08 | Agent re-attestation abuse via stolen SAT | T1550 — Use Alternate Authentication Material |
| S7-09 | Overlapping entry exploitation | T1098 — Account Manipulation |
| S7-10 | Trust bundle poisoning via API | T1553.004 — Install Root Certificate |
| S7-11 | Kubelet verification bypass (MITM) | T1562.001 — Disable or Modify Tools |
| S7-12 | SPIFFE federation abuse — rogue trust domain | T1553.004 — Install Root Certificate |
| S7-13 | Cross-cloud WIF attack — SVID to AWS AssumeRoleWithWebIdentity | T1078.004 — Cloud Accounts |

**21 Sigma rules — the first SPIFFE-specific detection rules for any SIEM.** Covering socket access (auditd), SVID key extraction (FIM), burst SVID requests (frequency analysis), multi-identity PID detection (aggregation), registration entry creation and modification, trust bundle changes, delegated identity API calls, agent re-attestation events, configuration file tampering, weak selector detection, JWT-SVID log leakage, and three correlation rules that chain individual signals into confirmed attack scenarios. All 21 rules are being submitted to SigmaHQ for inclusion in the community repository — the first SPIFFE/SPIRE category in the project's history.

**spiffe-security-bench.** A command-line auditing tool modelled on kube-bench that runs 23 security checks against a live SPIRE deployment:

- Server: audit logging enabled, log format, datastore security, admin API access controls
- Agent: debug logging for PID tracking, kubelet verification not skipped, socket permissions
- Trust bundles: write access controls, FIM coverage, federation endpoint security
- Workload attestors: selector strength assessment, overlapping entry detection, admin flag usage

Output: pass/fail per control, severity rating, remediation command, and a JSON report compatible with CI/CD pipelines.

**15 Kubernetes Sigma rules** covering the container escape techniques that precede SPIRE socket access: nsenter host PID abuse, chroot to host filesystem, unshare namespace manipulation, cgroup escape, CAP_SYS_ADMIN mount abuse, hostPath sensitive file access, direct API access, RBAC enumeration, service account token access, and Kubernetes secrets enumeration — plus a correlation rule that chains container escape indicators with subsequent SPIRE socket access.

**Cross-domain attack chain demonstrations.** The most significant expansion of the original NHI kill chain for cloud-native environments:

```
Container escape (K8s Sigma rules)
    ↓
SPIRE Agent socket access (SPIFFE Sigma rules)
    ↓
SVID harvesting (T1552.007)
    ↓
SPIFFE federation abuse — rogue trust domain import
    ↓
Cross-cloud WIF: SVID as OIDC assertion to AWS STS
    ↓
AWS AdministratorAccess via AssumeRoleWithWebIdentity (T1078.004)
```

This chain requires zero static credentials. The attacker starts with container escape and ends with cloud admin access via the identity plane.

### Live Demo Plan (15 minutes within the 35-minute talk)

**Demo 1 — Socket access and SVID theft (4 min)**: From a container with a weak unix selector, connect to the SPIRE Workload API socket. Call `FetchX509SVID`. Receive an SVID for a target workload. Rule 101000 fires in Wazuh. The Sigma rule `nhi_spire_workload_api_socket_access.yml` is visible in the SIEM.

**Demo 2 — The Spooffe pattern: container escape to full node compromise (5 min)**: Privileged container with `hostPID: true`. Use `nsenter` to access the host PID namespace. Navigate to `/run/spire/sockets/agent.sock`. Run `grpcurl` to call the Workload API. Receive SVIDs for every workload on the node. Correlation rule `nhi_corr_spire_container_escape_svid` fires at Level 15. The entire chain from container to full node identity compromise takes 45 seconds.

**Demo 3 — Registration entry manipulation to identity theft (3 min)**: With SPIRE Server admin access, create a new registration entry mapping a high-value SPIFFE ID to the attacker's workload selectors. Rule 101020 fires on entry creation. Rule 101022 fires when the modified workload starts receiving the additional SVID. Correlation rule `nhi_corr_spire_registration_svid_chain` chains them at Level 14.

**Demo 4 — spiffe-security-bench live audit (3 min)**: Run `spiffe-security-bench` against the testbed SPIRE deployment. The tool identifies `skip_kubelet_verification = true` in the agent config, audit logging disabled on the server, and three registration entries using weak `unix:uid:0` selectors. Output in JSON and human-readable format.

### Detection Engineering Notes

SPIRE's default logging configuration makes detection difficult by design, not by intent. Two critical facts the community should know:

1. SPIRE Agent emits SVID fetch events — including the caller's PID — only at DEBUG log level. At the default INFO level, these messages are suppressed. PID-based detection rules (tracking which process ID is requesting which SVID) require `log_level = "DEBUG"` in the agent configuration.

2. The SPIRE Server does not enable audit logging by default (`audit_log_enabled = false`). Registration entry creation, modification, and deletion — the operations most critical for detecting entry manipulation attacks — are not logged unless this is explicitly set.

The framework includes hardened reference configurations for both the SPIRE Server and SPIRE Agent, plus Wazuh `ossec.conf` snippets for log ingestion and auditd rules for socket monitoring. These are the prerequisites that make the 21 Sigma rules actionable.

---

## Presentation Outline

### [0:00 - 3:00] The Identity Plane Problem (3 min)

SPIFFE/SPIRE delivers on its promise: workload identity without static credentials, automatic rotation, short-lived SVIDs. What changes when an attacker targets the system that issues those identities?

The 50:1 machine-to-human identity ratio grows with every microservice. SPIRE centralises all of those machine identities under a single control plane. That is the right architectural move. It also means the attack surface is now concentrated rather than distributed — and that concentration has a Unix domain socket you can connect to.

Brief architecture overview for attendees who are not SPIRE operators: Server, Agent, Workload API socket, SVIDs, trust bundles, registration entries. What each component holds and why attackers want it.

### [3:00 - 8:00] Attack Surface Map (5 min)

10 documented attack vectors, mapped to MITRE ATT&CK. Table overview — no deep dives yet, just the landscape. Three categories:

- **Identity issuance abuse** (Vectors 1-3): Selector spoofing, overlapping entries, direct socket harvesting — getting SVIDs you should not have
- **Identity infrastructure compromise** (Vectors 4-8): JWT replay, delegated identity API, container escape, re-attestation abuse, entry manipulation — attacking the systems that issue identity
- **Trust domain attacks** (Vectors 8-10): Trust bundle poisoning, federation abuse, kubelet bypass — undermining the root of trust itself

The key insight: vectors 1-3 get you one workload's identity. Vectors 4-8 get you all of them. Vectors 8-10 get you the ability to forge any identity in the trust domain.

### [8:00 - 23:00] Live Demonstrations (15 min)

Four live demos against the real SPIRE 1.11.2 deployment. See the detailed demo plan above. Each demo ends with the detection alert firing in the SIEM — attack and detection in the same screen.

### [23:00 - 28:00] The 21 Sigma Rules (5 min)

Rule architecture walkthrough:

- 8 rules for SVID issuance monitoring (socket access, scripting tools, burst requests, PID-based multi-identity detection, SVID key extraction)
- 7 rules for SPIRE Server operations (entry creation, modification, deletion, trust bundle changes, agent re-attestation, delegated identity API, configuration tampering)
- 3 correlation rules (container escape + socket access at Level 15; entry creation + SVID fetch at Level 14; PID multiple identity spoofing at Level 13)
- 3 miscellaneous rules (JWT-SVID log leakage, kubelet verification disabled, weak selector detection)

Critical prerequisite: what you need to change in SPIRE's default configuration before any of these rules fire. Audit logging and DEBUG-level agent logging are not defaults. Attendees leave knowing exactly what to enable.

SigmaHQ submission status: these 21 rules are the first SPIFFE/SPIRE detection content in the project's history. They will be submitted to the community repository before KubeCon.

### [28:00 - 31:00] spiffe-security-bench (3 min)

Live run of the auditing tool. 23 checks. Walk through the most commonly failed controls: audit logging disabled (fails by default), weak selectors in registration entries (common misconfigurations), and `skip_kubelet_verification = true` (frequently set to work around TLS issues in dev). CI/CD integration example: fail the pipeline if critical checks fail.

### [31:00 - 33:00] Hardening and Remediation (2 min)

The four most impactful configuration changes — ordered by effort-to-impact ratio:

1. Enable `audit_log_enabled = true` on the SPIRE Server (zero downtime, immediate detection coverage)
2. Set `log_level = "DEBUG"` on the SPIRE Agent with a dedicated log file (verbosity trade-off documented)
3. Replace `unix:uid:0` and `k8s:node-name` selectors with `k8s:pod-uid` and multi-selector AND logic
4. Deploy SPIRE via the CSI driver instead of hostPath socket mounts (eliminates the primary SVID harvesting surface)

### [33:00 - 35:00] Takeaways and Q&A Setup (2 min)

What attendees receive:

- Framework GitHub repository with all scenarios, Sigma rules, and reference configurations
- spiffe-security-bench binary and source
- Hardened SPIRE server.conf and agent.conf reference configurations
- Wazuh ossec.conf snippets and auditd rules for immediate deployment

---

## Benefits to the CNCF Community

**1. Fills a documented gap.** The SPIFFE specification acknowledges attack surfaces (JWT-SVID replay attacks, workload attestation weaknesses) but the community has no structured tooling for testing deployments against these attacks. Security teams deploying SPIFFE/SPIRE have no equivalent of kube-bench or Trivy for their identity infrastructure.

**2. First Sigma rules for a graduated CNCF project's attack surface.** The 21 rules being submitted to SigmaHQ represent the first SPIFFE-specific detection content in that community library. Every organisation running SPIRE that uses Splunk, Sentinel, Elastic, or Chronicle can deploy these rules immediately via the pySigma conversion pipeline — no custom development required.

**3. spiffe-security-bench addresses the configuration gap.** Default SPIRE configurations are not hardened for production security monitoring. The auditing tool gives operators a repeatable, automatable way to verify their SPIRE deployment against the security controls the detection rules depend on. Without the tool, teams discover these gaps when an alert fails to fire during an incident.

**4. Advances the "zero-trust is not zero-risk" narrative responsibly.** SPIFFE/SPIRE is the right answer for workload identity. Understanding its attack surface makes adoption stronger, not weaker. This framework is explicitly designed as a purple team tool — organisations use it to verify their defences, not to attack production systems.

**5. Cross-project value.** The container escape rules (15 Kubernetes Sigma rules) and the SPIRE socket access rules interact with Falco, providing a combined detection chain across two incubating/graduated CNCF projects. The framework includes a Falcosidekick-to-Wazuh integration pipeline for teams using Falco as their runtime security layer.

---

## What's New / Why Now

**The CyberArk "Spooffe" research (nullcon Goa 2026)** documented the container escape to SVID theft attack chain and demonstrated working proof-of-concept tooling. The security community now has evidence that SPIFFE/SPIRE deployments are being actively researched as attack targets. The NHI Security Testbed translates that research into a structured, repeatable framework with corresponding detection rules — the defensive response the community needs.

**SPIFFE/SPIRE graduated from CNCF incubation in 2022.** Deployments have scaled significantly. Large enterprises running service meshes at scale are now running SPIRE in environments where a trust bundle compromise means hundreds of services are affected simultaneously. The attack surface has grown; the detection tooling has not kept pace.

**The cross-cloud WIF attack chain is novel.** Existing research focuses on SPIRE-to-SPIRE attacks (within a single trust domain or across federated domains). The scenario where a compromised SVID is used as an OIDC assertion for `AssumeRoleWithWebIdentity` to obtain AWS IAM credentials — translating a Kubernetes identity compromise into a cloud account compromise — has not been publicly demonstrated with working code and detection rules.

**Nobody has built this before.** A search of GitHub, SigmaHQ, and the CNCF security landscape turns up zero open-source frameworks for SPIFFE/SPIRE attack simulation. Zero Sigma rules for SPIFFE/SPIRE. Zero kube-bench-equivalent tooling for SPIRE security. This talk introduces all three.

---

## Potential Tutorial Option (90 minutes)

If the programme committee is interested in a hands-on tutorial format, the following structure works for a 90-minute workshop:

- [0:00 - 15:00] Setup: attendees deploy the testbed on their own machines (pre-built container image available, deploys in under 3 minutes with `./scripts/start.sh`)
- [15:00 - 35:00] Attack track 1 — SVID harvesting: guided execution of S7-01 and S7-02 against the live SPIRE deployment, observing Wazuh alerts in real time
- [35:00 - 55:00] Attack track 2 — The Spooffe pattern: container escape to node compromise (S7-07), correlation alert at Level 15
- [55:00 - 70:00] Detection engineering: write a new Sigma rule for the delegated identity API attack (S7-06) from scratch, test it against live attack traffic
- [70:00 - 80:00] spiffe-security-bench: audit the testbed deployment, identify deliberate misconfigurations, apply remediations, verify rule coverage improves
- [80:00 - 90:00] Cross-cloud chain: S7-13 — SVID to AWS control plane via WIF

Prerequisites: Docker, git, 8 GB RAM. No cloud accounts. No vendor dependencies. SPIRE experience not required.

---

## Speaker Bio

**Bodhisattva Das** is a security practitioner specialising in cloud identity security and offensive techniques targeting non-human identities. He maintains the open-source NHI Security Testbed — a containerised purple team environment for attacking and detecting machine identity threats across cloud, Kubernetes, CI/CD, SPIFFE/SPIRE, and AI agent environments. His work on SPIFFE/SPIRE attack techniques produced the first open-source simulation framework for SPIFFE security testing and the first Sigma rules for SPIFFE/SPIRE detection, submitted to the SigmaHQ community repository in 2026. He has presented this research at security conferences in Europe and Scandinavia.

GitHub: [@bdas-sec](https://github.com/bdas-sec)
Repository: [github.com/bdas-sec/machine-identity-discovery](https://github.com/bdas-sec/machine-identity-discovery)

---

## Key Numbers Cheat Sheet

| Metric | Value | Source |
|--------|-------|--------|
| SPIFFE/SPIRE attack scenarios | 13 (all 10 documented vectors + 3 new) | `scenarios/category-7-spiffe-spire/` |
| SPIFFE/SPIRE Sigma rules | 21 (first ever for SPIFFE) | `sigma/rules/spiffe-spire/` |
| Kubernetes Sigma rules | 15 (container escape + RBAC + correlation) | `sigma/rules/kubernetes/` |
| Total Sigma rules in framework | 92 (8 categories) | `sigma/rules/` |
| spiffe-security-bench checks | 23 controls across 4 categories | `scripts/spiffe_identity_monitor.py` |
| SPIRE version | 1.11.2 (deployed, not mocked) | `spire/server/server.conf` |
| Attack vectors covered | 10 documented + federation + cross-cloud WIF | `docs/spiffe-spire-attack-techniques.md` |
| CNCF project alignment | SPIFFE/SPIRE (graduated), Falco (incubating), K8s (graduated) | — |
| Deployment time | Under 3 minutes | `./scripts/start.sh` |
| Cloud account required | No | Docker Compose only |
| SigmaHQ submission | In progress (first SPIFFE category) | — |

---

## Reviewer Notes

**Why this is a KubeCon talk, not a generic security talk.** The framework is built on real SPIRE infrastructure deployed via Docker Compose with the official SPIRE Helm chart available as a subchart for Kind cluster deployment. The attack scenarios execute against the actual SPIRE gRPC API. The detection rules monitor real SPIRE log formats and require real SPIRE configuration changes to activate. This is not a theoretical treatment of SPIFFE security — it is a working lab that Kubernetes operators can deploy in their own environments to test their SPIRE deployments before an attacker does.

**Why this matters to attendees who are not running SPIRE today.** KubeCon attendees are the people who will be running SPIRE tomorrow. The cloud-native identity roadmap consistently points toward SPIFFE for workload identity. The community needs offensive research to drive hardening — the same way kube-bench drove CIS Kubernetes Benchmark adoption. This framework is that research, structured for practical use.

**The "zero static credentials" attack chain.** The cross-cloud WIF scenario (S7-13) demonstrates a complete attack from container escape to AWS account compromise without ever handling a static credential. No access keys are stolen. No service account tokens are exfiltrated. The attack uses the identity infrastructure itself — SPIRE SVIDs — as the authentication material for cloud access. This is the attacker's native response to "just use SPIFFE for everything."
