# SPIFFE/SPIRE Attack Techniques Reference

## Overview

This document catalogs 10 attack vectors targeting SPIFFE (Secure Production Identity Framework For Everyone) and its reference implementation SPIRE (SPIFFE Runtime Environment). These techniques are based on the attack surface documented in Eviatar Gerzi's (CyberArk) nullcon Goa 2026 research "The Machine with Many Faces: Identity Impersonation in SPIFFE/SPIRE" and independent analysis of SPIRE's architecture.

SPIFFE is a CNCF graduated project that provides cryptographic identity to workloads in cloud-native environments. When SPIFFE is deployed via SPIRE, it replaces static credentials (API keys, service account tokens) with short-lived, automatically-rotated identity documents called SVIDs (SPIFFE Verifiable Identity Documents). While this is a significant security improvement, the identity framework itself introduces new attack surface.

**Purpose**: Provide sufficient technical detail to write SIEM detection rules for each attack vector, even without access to the Spooffe exploitation tool.

---

## SPIFFE/SPIRE Architecture (Attack Surface Context)

```
┌─────────────────────────────────────────────────────┐
│                   SPIRE Server                       │
│  - Issues SVIDs (X.509 and JWT)                     │
│  - Manages Registration Entries                      │
│  - Stores Trust Bundles                              │
│  - Authenticates Agents via Node Attestation         │
│  Port: 8081 (default)                                │
└──────────────────┬──────────────────────────────────┘
                   │ mTLS (Agent SVID as client cert)
                   │
┌──────────────────▼──────────────────────────────────┐
│                   SPIRE Agent                        │
│  - Runs on each node                                 │
│  - Performs Workload Attestation                     │
│  - Caches and serves SVIDs to workloads              │
│  - Exposes Workload API via Unix Domain Socket       │
│  Socket: /tmp/spire-agent/public/api.sock (default)  │
│     or:  /run/spire/sockets/agent.sock               │
└──────────────────┬──────────────────────────────────┘
                   │ Unix Domain Socket (gRPC)
                   │
┌──────────────────▼──────────────────────────────────┐
│                  Workloads                            │
│  - Request SVIDs via Workload API                    │
│  - Use SVIDs for mTLS, JWT auth                      │
│  - Identity = SPIFFE ID (e.g. spiffe://domain/svc)   │
└─────────────────────────────────────────────────────┘
```

### Key Components for Attackers

| Component | What It Holds | Why Attackers Want It |
|-----------|--------------|---------------------|
| **Workload API Socket** | Access point for SVID requests | Directly yields identity credentials |
| **Registration Entries** | SPIFFE ID ↔ selector mappings | Control which workloads get which identities |
| **Trust Bundles** | Root CA certificates per trust domain | Accepting rogue CAs enables identity forgery |
| **SPIRE Server Admin API** | Full control over entries, agents, bundles | Complete identity infrastructure compromise |
| **Agent Attestation Data** | Node identity proof (join tokens, AWS IID) | Replay to inject rogue agents |
| **SVID Private Keys** | Short-lived private keys for X.509 SVIDs | Direct workload impersonation |

---

## Attack Vector 1: Selector Spoofing

### MITRE ATT&CK: T1078 (Valid Accounts), T1098 (Account Manipulation)

### Technical Explanation

SPIRE uses **selectors** to determine which workloads receive which SPIFFE IDs. Selectors are attributes discovered during workload attestation — process UID, Kubernetes pod name, Docker labels, etc. Some selectors are inherently weak:

- **`k8s:node-name`**: The Kubernetes node name is relatively easy to spoof. If an Agent's SVID or attestation data is stolen, the node name restriction provides no meaningful defense.
- **`unix:uid:0`**: Matches any process running as root — overly broad in privileged containers.
- **`unix:gid:0`**: Same problem for the root group.
- **`docker:label`**: Container labels can be set by anyone who can create containers.

An attacker who can manipulate these attributes (e.g., by running as root in a privileged container, or by controlling container labels) can match selectors intended for other workloads and receive their SVIDs.

### Prerequisites

- Access to a container or process on a node running SPIRE Agent
- Ability to manipulate the selector attributes (run as root, set container labels, control pod metadata)

### Step-by-Step Attack Flow

1. **Enumerate existing registration entries**: Use `spire-server entry show` (if admin access) or observe workload API responses to understand which SPIFFE IDs are assigned to which selectors
2. **Identify weak selectors**: Look for entries using `k8s:node-name`, `unix:uid:0`, `docker:label` with generic values
3. **Match the selectors**: Create a process or container that matches the target workload's selectors (e.g., run as UID 0, set the matching Docker label)
4. **Request SVID from Workload API**: Connect to the SPIRE Agent's Unix domain socket and call `FetchX509SVID` or `FetchJWTSVID`
5. **Receive target's SVID**: The agent's workload attestor matches your process against the registration entry and issues the SVID
6. **Use the SVID**: Authenticate as the target workload to downstream services

### Logs/Artifacts Produced

- SPIRE Agent log: `"Fetched X.509 SVID"` with the spoofed SPIFFE ID and the attacker's PID
- SPIRE Agent log: Workload attestation selectors for the attacker's process
- Kubernetes audit log: Pod creation with specific labels or host PID access
- Process audit: New process created with UID 0 or specific attributes

### Detection Opportunities

| What to Detect | How | Rule Mapping |
|---------------|-----|-------------|
| Registration entries with weak selectors | Parse SPIRE server logs for entries using `k8s:node-name`, `unix:uid:0` | Rule 101021 |
| SVID issued to unexpected PID | Correlate SPIRE agent SVID issuance with expected workload PIDs | Rule 101000 |
| Multiple SVID requests from same PID | Same PID requesting SVIDs 5+ times in 120s — potential abuse | Rule 101005 |
| Same PID gets multiple different SPIFFE IDs | Smoking gun for selector spoofing — one process, multiple identities | Rule 101006 |
| Privileged container creation | K8s audit log for `hostPID: true` or `privileged: true` | Existing K8s rules |

### Hardening

- Use **strong selectors**: `k8s:pod-uid`, `k8s:container-name`, `k8s:ns` (namespace) instead of `k8s:node-name`
- Avoid `unix:uid:0` — use `unix:user` with specific service account names
- Combine multiple selectors (AND logic) to narrow matching
- Regularly audit registration entries for overly broad selectors
- Use SPIRE's Kubernetes Workload Registrar for automatic, precise registration

### References

- [SPIRE Workload Attestor (Unix)](https://github.com/spiffe/spire/blob/main/doc/plugin_agent_workloadattestor_unix.md)
- [SPIRE Workload Attestor (K8s)](https://github.com/spiffe/spire/blob/main/doc/plugin_agent_workloadattestor_k8s.md)
- [SPIRE GitHub Issue #1935 — k8s:host-ip selector request](https://github.com/spiffe/spire/issues/1935)

---

## Attack Vector 2: Overlapping Registration Entries

### MITRE ATT&CK: T1098 (Account Manipulation)

### Technical Explanation

SPIRE allows multiple registration entries with overlapping selectors. When a workload's attestation selectors match multiple entries, the agent issues SVIDs for **all** matching entries. This means:

- If Entry A maps `spiffe://domain/service-a` to selectors `[unix:uid:1000]`
- And Entry B maps `spiffe://domain/service-b` to selectors `[unix:uid:1000]`
- A workload running as UID 1000 receives SVIDs for **both** service-a and service-b

An attacker who can create ambiguous registration entries — or exploit existing ambiguities — can cause their workload to receive SVIDs for identities it shouldn't have.

### Prerequisites

- Admin access to SPIRE Server (for creating entries), OR
- Existing ambiguous entries in the deployment (misconfiguration)

### Step-by-Step Attack Flow

1. **Identify target SPIFFE ID**: Determine which identity you want to impersonate
2. **Analyze existing selectors**: Find selectors that your workload already matches, or that you can easily match
3. **Create overlapping entry**: Register a new entry mapping the target SPIFFE ID to selectors your workload satisfies
4. **Trigger attestation**: Restart your workload or wait for SVID rotation
5. **Receive additional SVID**: Your workload now has SVIDs for both its legitimate identity and the target identity

### Logs/Artifacts Produced

- SPIRE Server log: `"Entry created"` with the new SPIFFE ID and selectors
- SPIRE Server log: API call to `CreateEntry` or `BatchCreateEntry`
- SPIRE Agent log: Workload receiving multiple SVIDs where it previously received one

### Detection Opportunities

| What to Detect | How | Rule Mapping |
|---------------|-----|-------------|
| New registration entry creation | Monitor SPIRE server logs for `CreateEntry` | Rule 101020 |
| Entries with selectors that overlap existing entries | Compare new entry selectors against existing | Rule 101021 |
| Workload receiving unexpected SVID count | Agent log showing multiple SVIDs for single workload | Rule 101003 |
| Same PID obtains multiple distinct SPIFFE IDs | Direct indicator of overlapping entries — the "smoking gun" | Rule 101006 |

### Hardening

- Implement entry review/approval workflows before registration
- Use SPIRE's entry `admin` flag sparingly
- Audit for overlapping selectors periodically
- Consider using the `dns_names` field to add specificity
- Use `downstream` entry relationships to constrain SVID issuance

### References

- [SPIRE Registration Entries](https://spiffe.io/docs/latest/deploying/registering/)
- [SPIFFE Concepts](https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/)

---

## Attack Vector 3: SVID Harvesting

### MITRE ATT&CK: T1552.007 (Container API), T1552.004 (Private Keys)

### Technical Explanation

The SPIRE Agent exposes the Workload API via a Unix domain socket (typically at `/tmp/spire-agent/public/api.sock`). Any process on the node that can connect to this socket can request SVIDs. The agent performs workload attestation to verify the caller, but:

- In environments with weak selectors, attestation may pass for unauthorized workloads
- If the attacker has escaped a container to the host, they can directly access the socket
- The socket's file permissions may be overly permissive (world-readable)

Once connected, the attacker can call `FetchX509SVID` to obtain X.509 certificates and private keys, or `FetchJWTSVID` to obtain JWT bearer tokens.

### Prerequisites

- File system access to the SPIRE Agent socket path
- The agent must be running and connected to the SPIRE Server
- The calling process must match at least one registration entry's selectors (or selectors must be weak enough to match)

### Step-by-Step Attack Flow

1. **Locate the SPIRE Agent socket**:
   ```bash
   find / -name "api.sock" 2>/dev/null
   ls -la /tmp/spire-agent/public/api.sock
   ls -la /run/spire/sockets/agent.sock
   echo $SPIFFE_ENDPOINT_SOCKET
   ```

2. **Verify socket is accessible**:
   ```bash
   # Check permissions
   stat /tmp/spire-agent/public/api.sock
   ```

3. **Interact with the Workload API**:
   ```bash
   # Using grpcurl (if available)
   grpcurl -plaintext -unix /tmp/spire-agent/public/api.sock \
     SpiffeWorkloadAPI/FetchX509SVID

   # Using the go-spiffe library
   # Or using spiffe-helper tool
   ```

4. **Extract SVID materials**:
   - X.509 SVID: Certificate chain + private key (PEM format)
   - JWT-SVID: Signed JWT token

5. **Use harvested credentials**:
   - X.509: Configure as TLS client certificate for mTLS to target services
   - JWT: Include as Bearer token in HTTP Authorization header

### Logs/Artifacts Produced

- File access audit: Access to `api.sock` socket file
- SPIRE Agent log: `"FetchX509SVID"` or `"FetchJWTSVID"` with caller PID
- SPIRE Agent log: Workload attestation event with caller selectors
- Process audit: `grpcurl`, `curl`, `python`, or unusual process accessing the socket

### Detection Opportunities

| What to Detect | How | Rule Mapping |
|---------------|-----|-------------|
| Access to SPIRE socket paths | FIM on socket files or auditd | Rule 101000 |
| Scripting tools accessing socket | Process name matching (curl, python, grpcurl) | Rule 101001 |
| Rapid burst of SVID requests | Frequency-based: 10+ requests in 60s | Rule 101003 |
| Multiple SVID requests from same PID | PID-level tracking: 5+ fetches in 120s from one process | Rule 101005 |
| SVID key material on disk | FIM on SVID key storage paths | Rule 101002 |

### Hardening

- Restrict socket file permissions to only legitimate workload users
- Use the SPIRE Agent's `allowed_foreign_jwt_claims` to limit JWT scope
- Monitor the socket path with file integrity monitoring
- Deploy SPIRE CSI driver instead of hostPath mounts (eliminates socket exposure)
- Use network policies to isolate SPIRE Agent pods

### References

- [SPIFFE Workload Endpoint](https://spiffe.io/docs/latest/spiffe-specs/spiffe_workload_endpoint/)
- [SPIRE Agent Configuration](https://spiffe.io/docs/latest/deploying/spire_agent/)

---

## Attack Vector 4: JWT-SVID Replay

### MITRE ATT&CK: T1528 (Steal Application Access Token), T1550 (Use Alternate Authentication Material)

### Technical Explanation

JWT-SVIDs are bearer tokens — whoever possesses them can use them. Unlike X.509-SVIDs (which require the private key for the TLS handshake), JWT-SVIDs can be replayed simply by including them in HTTP requests. The SPIFFE specification itself acknowledges this risk:

> "Tokens are susceptible to replay attacks, where an attacker who obtains the token in transit can use it to impersonate a workload."

JWT-SVIDs have short TTLs (typically 5 minutes) but within that window, they can be:
- Intercepted from application logs that accidentally log Authorization headers
- Captured from network traffic if TLS is terminated before the application
- Extracted from process memory or environment variables
- Stolen from debug endpoints or tracing systems

### Prerequisites

- Access to JWT-SVID token (from logs, network capture, memory dump, or API response)
- The token must not be expired
- Knowledge of the target service endpoint

### Step-by-Step Attack Flow

1. **Obtain JWT-SVID**: Capture from one of these sources:
   ```bash
   # From application logs
   grep -r "eyJ" /var/log/app/ | grep spiffe

   # From environment variables
   cat /proc/*/environ 2>/dev/null | tr '\0' '\n' | grep -i svid

   # From debug/health endpoints
   curl http://app:8080/debug/vars | grep token
   ```

2. **Decode and verify**: Confirm it's a SPIFFE JWT-SVID:
   ```bash
   # Decode JWT header/payload (base64)
   echo "$TOKEN" | cut -d. -f2 | base64 -d
   # Look for: "sub": "spiffe://domain/workload"
   ```

3. **Replay the token**:
   ```bash
   curl -H "Authorization: Bearer $JWT_SVID" https://target-service/api/sensitive
   ```

4. **Act as the workload**: Within the TTL window, make requests authenticated as the target workload

### Logs/Artifacts Produced

- Application logs: JWT token strings (pattern: `eyJ...`)
- SPIRE Agent log: JWT-SVID fetch events
- Target service logs: Authenticated requests from unexpected source IP
- Network logs: Same JWT used from multiple source IPs

### Detection Opportunities

| What to Detect | How | Rule Mapping |
|---------------|-----|-------------|
| JWT-SVID appearing in log files | Pattern match for JWT + spiffe:// context | Rule 101060 |
| Same JWT used from multiple IPs | Network/access log correlation | Custom correlation |
| JWT-SVID in process environment | /proc/*/environ access + JWT pattern | Existing rule 100607 + 101060 |

### Hardening

- Never log JWT-SVIDs — sanitize Authorization headers in application logs
- Use X.509-SVIDs instead of JWT-SVIDs where possible (proof-of-possession)
- Implement audience (`aud`) validation in consuming services
- Consider DPoP (Demonstrating Proof-of-Possession) extensions to bind JWTs to keys
- Minimize JWT-SVID TTL (default 5 minutes is already short, but shorter is better)
- Encrypt traffic between all services (mTLS everywhere)

### References

- [SPIFFE JWT-SVID Specification](https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md)
- [SPIFFE Issue #260 — DPoP for JWT-SVID](https://github.com/spiffe/spiffe/issues/260)

---

## Attack Vector 5: Delegated Identity API Abuse

### MITRE ATT&CK: T1134 (Access Token Manipulation), T1078 (Valid Accounts)

### Technical Explanation

SPIRE's Delegated Identity API is a powerful feature that allows authorized workloads to request SVIDs **on behalf of other workloads**. A workload with access to this API can:

- Call `SubscribeToX509SVIDs` to receive ALL X.509 SVIDs managed by the agent
- Call `FetchJWTSVIDs` to obtain JWT-SVIDs for any identity
- Act as a transparent proxy for identity, impersonating any workload

This API exists for legitimate use cases (service mesh proxies, secret stores) but represents the single most powerful capability in SPIRE. Compromise of a workload authorized for the Delegated Identity API means compromise of **every identity on that node**.

### Prerequisites

- The workload must be explicitly authorized for the Delegated Identity API in the SPIRE Agent configuration
- The workload must be able to connect to the agent's admin API socket

### Step-by-Step Attack Flow

1. **Identify Delegated Identity API access**: Check SPIRE Agent configuration for `admin_socket_path` and which workloads are authorized
2. **Connect to admin socket**:
   ```bash
   # The admin socket is separate from the Workload API socket
   ls -la /tmp/spire-agent/private/admin.sock
   ```
3. **Subscribe to all SVIDs**:
   ```bash
   # Using gRPC client
   grpcurl -plaintext -unix /tmp/spire-agent/private/admin.sock \
     DelegatedIdentity/SubscribeToX509SVIDs
   ```
4. **Receive all workload SVIDs**: The API returns X.509 certificates and private keys for every identity the agent manages
5. **Impersonate any workload**: Use the harvested SVIDs to authenticate as any workload on the node

### Logs/Artifacts Produced

- SPIRE Agent log: `DelegatedIdentity` API method calls
- SPIRE Agent log: `SubscribeToX509SVIDs` or `FetchJWTSVIDs` with caller PID
- File access audit: Access to admin socket path
- Process audit: Unexpected process connecting to admin socket

### Detection Opportunities

| What to Detect | How | Rule Mapping |
|---------------|-----|-------------|
| Delegated Identity API calls | SPIRE agent log method matching | Rule 101061 |
| Admin socket access | FIM on admin socket path | Rule 101000 (extended) |
| Unexpected SVIDs fetched via delegation | SPIRE agent log with delegated caller | Rule 101061 |

### Hardening

- Minimize workloads authorized for Delegated Identity API
- Use a separate, restricted socket for the admin API
- Monitor admin socket access with file integrity monitoring
- Require additional attestation for Delegated Identity API consumers
- Consider network segmentation to isolate admin API access

### References

- [SPIRE Delegated Identity API](https://github.com/spiffe/spire/blob/main/proto/spire/api/agent/delegatedidentity/v1/delegatedidentity.proto)

---

## Attack Vector 6: Container Escape to SVID Theft

### MITRE ATT&CK: T1611 (Escape to Host), T1552.007 (Container API)

### Technical Explanation

This is the canonical "Spooffe" attack pattern. SPIRE Agents run on the host (or as a DaemonSet with host access). Their Workload API socket is typically accessible from the host filesystem. An attacker who escapes a container to the host gains access to the SPIRE Agent socket and can harvest SVIDs for any workload running on that node.

The attack chain:
1. **Container escape**: Via nsenter, chroot, cgroup abuse, or privileged container capabilities
2. **Socket access**: Navigate to the SPIRE Agent socket on the host filesystem
3. **SVID harvesting**: Request SVIDs from the Workload API

This is particularly dangerous because the attacker's escaped process may match different selectors than their original container, potentially granting access to more identities.

### Prerequisites

- Running in a container with escape potential:
  - Privileged container (`--privileged`)
  - `hostPID: true` (shares PID namespace with host)
  - CAP_SYS_ADMIN capability
  - Host path volume mounts
- SPIRE Agent running on the same host

### Step-by-Step Attack Flow

1. **Escape the container** (multiple techniques):
   ```bash
   # Via nsenter (requires hostPID)
   nsenter --target 1 --mount --uts --ipc --net --pid -- bash

   # Via chroot with host filesystem mount
   chroot /host /bin/bash

   # Via cgroup escape
   mkdir /tmp/escape && mount -t cgroup -o rdma cgroup /tmp/escape
   echo 1 > /tmp/escape/notify_on_release
   ```

2. **Locate SPIRE Agent socket on host**:
   ```bash
   find / -name "api.sock" -path "*spire*" 2>/dev/null
   ls -la /tmp/spire-agent/public/api.sock
   ls -la /run/spire/sockets/agent.sock
   ```

3. **Verify connectivity**:
   ```bash
   # Check if the socket is accessible and the agent is responding
   grpcurl -plaintext -unix /tmp/spire-agent/public/api.sock list
   ```

4. **Harvest SVIDs**:
   ```bash
   # Fetch X.509 SVIDs
   grpcurl -plaintext -unix /tmp/spire-agent/public/api.sock \
     SpiffeWorkloadAPI/FetchX509SVID

   # Fetch JWT SVIDs (for specific audience)
   grpcurl -plaintext -unix /tmp/spire-agent/public/api.sock \
     -d '{"audience": ["target-service"]}' \
     SpiffeWorkloadAPI/FetchJWTSVID
   ```

5. **Use SVIDs for lateral movement**: Authenticate to other services in the mesh

### Logs/Artifacts Produced

- Container escape indicators (see existing K8s rules 100757-100764):
  - `nsenter` execution
  - `chroot` to host filesystem
  - `unshare` namespace manipulation
  - cgroup mount operations
  - CAP_SYS_ADMIN mount abuse
- File access: SPIRE socket paths accessed post-escape
- SPIRE Agent log: SVID fetch from unexpected PID (host PID namespace)
- Network: New connections from host to SPIRE Server

### Detection Opportunities

| What to Detect | How | Rule Mapping |
|---------------|-----|-------------|
| Container escape + SPIRE socket access | Correlation: escape indicators followed by socket access | Rule 101080 (correlation) |
| Socket access from host namespace PID | SPIRE agent log with unexpected PID | Rule 101000, 101001 |
| Post-escape lateral movement | Network connections using harvested SVIDs | Network monitoring |

### Hardening

- Never deploy containers with `privileged: true` or `hostPID: true`
- Use Pod Security Standards/Admission to enforce non-privileged containers
- Deploy SPIRE via CSI driver (avoids hostPath socket exposure)
- Implement network policies blocking container-to-SPIRE-agent traffic
- Use Kubernetes RuntimeClass with gVisor or Kata Containers for workload isolation
- Monitor for container escape indicators (existing rules 100757-100764)

### References

- [Container Escape Techniques — MITRE T1611](https://attack.mitre.org/techniques/T1611/)
- [SPIRE CSI Driver](https://github.com/spiffe/spiffe-csi)

---

## Attack Vector 7: Registration Entry Manipulation

### MITRE ATT&CK: T1098 (Account Manipulation), T1136 (Create Account)

### Technical Explanation

SPIRE Server registration entries define the mapping between SPIFFE IDs and workload selectors. An attacker with admin access to the SPIRE Server can:

- **Create rogue entries**: Map arbitrary SPIFFE IDs to selectors matching attacker-controlled workloads
- **Modify existing entries**: Change selectors to include attacker workloads
- **Delete entries**: Deny legitimate workloads their identities (DoS)

SPIRE Server admin access is obtained via:
- The SPIRE Server CLI (`spire-server` command) running on the server node
- The Server Admin API (gRPC on port 8081 by default)
- Kubernetes RBAC if SPIRE is deployed via the Kubernetes registrar

### Prerequisites

- Admin access to the SPIRE Server (CLI, API, or K8s RBAC)
- Knowledge of the target trust domain and workload naming conventions

### Step-by-Step Attack Flow

1. **Gain SPIRE Server admin access**:
   ```bash
   # Direct CLI access
   spire-server entry show

   # Via kubectl if registrar is deployed
   kubectl -n spire get spiffeids
   ```

2. **Enumerate existing entries**:
   ```bash
   spire-server entry show -output json
   ```

3. **Create a rogue entry** mapping a high-value SPIFFE ID to your workload's selectors:
   ```bash
   spire-server entry create \
     -spiffeID spiffe://domain/payments-service \
     -parentID spiffe://domain/node1 \
     -selector unix:uid:1000 \
     -selector k8s:ns:default
   ```

4. **Trigger your workload's attestation**: Restart your workload or wait for SVID rotation

5. **Receive the target SVID**: Your workload now authenticates as `payments-service`

### Logs/Artifacts Produced

- SPIRE Server log: `"Entry created"` with entry details
- SPIRE Server log: API method `entry.v1.Entry/CreateEntry` or `BatchCreateEntry`
- SPIRE Server audit: `caller_id` and `caller_addr` for the admin session
- K8s audit log: Changes to SpiffeID custom resources (if using K8s registrar)

### Detection Opportunities

| What to Detect | How | Rule Mapping |
|---------------|-----|-------------|
| Registration entry creation | SPIRE server log matching CreateEntry | Rule 101020 |
| Entry with weak selectors | Content analysis of selector values | Rule 101021 |
| Entry modification or deletion | SPIRE server log matching Update/DeleteEntry | Rule 101022 |
| Entry creation followed by SVID fetch | Correlation: entry create + socket access | Rule 101081 |

### Hardening

- Restrict SPIRE Server admin access to a minimal set of operators
- Use Kubernetes RBAC to control who can create/modify SpiffeID resources
- Implement change management for registration entries
- Audit all registration entry changes
- Use `admin` flag on entries only when necessary
- Consider using upstream CA plugin to limit trust scope

### References

- [SPIRE Registration](https://spiffe.io/docs/latest/deploying/registering/)
- [SPIRE Server CLI Reference](https://spiffe.io/docs/latest/deploying/spire_server/)

---

## Attack Vector 8: Trust Bundle Poisoning

### MITRE ATT&CK: T1553.004 (Install Root Certificate), T1556 (Modify Authentication Process)

### Technical Explanation

SPIRE trust bundles contain the root CA certificates for one or more trust domains. In federated SPIFFE deployments, trust bundles from external trust domains are imported to enable cross-domain authentication. An attacker who can modify trust bundles can:

- **Inject a rogue CA certificate**: Services will trust SVIDs signed by the attacker's CA
- **Remove legitimate CAs**: Denial of service — existing SVIDs become unverifiable
- **Replace the bundle**: Complete takeover of the trust domain's identity verification

Trust bundles are stored in the SPIRE Server datastore and distributed to agents. They can be manipulated via:
- SPIRE Server API (`SetFederatedBundle`, `AppendBundle`, `BatchSetFederatedBundle`)
- Direct modification of the bundle file (`/opt/spire/data/server/bundle.json`)
- Tampering with the bundle endpoint (for SPIFFE bundle endpoint discovery)

### Prerequisites

- Admin access to SPIRE Server, OR
- Write access to the trust bundle file on disk, OR
- Network position to intercept bundle distribution (MITM)

### Step-by-Step Attack Flow

1. **Generate a rogue CA**:
   ```bash
   openssl req -x509 -newkey rsa:4096 -keyout rogue-ca.key -out rogue-ca.crt \
     -days 365 -nodes -subj "/CN=RogueCA"
   ```

2. **Inject into trust bundle** via SPIRE Server API:
   ```bash
   spire-server bundle set -id spiffe://target-domain \
     -path rogue-ca.crt
   ```

   Or directly modify the bundle file:
   ```bash
   # Append rogue CA to bundle.json
   cat rogue-ca.crt >> /opt/spire/data/server/bundle.json
   ```

3. **Issue rogue SVIDs**: Sign X.509 certificates with the rogue CA that have SPIFFE ID URIs in the SAN field

4. **Present rogue SVIDs to services**: Target services verify against the poisoned trust bundle and accept the rogue SVIDs as valid

### Logs/Artifacts Produced

- SPIRE Server log: API calls to `SetFederatedBundle`, `AppendBundle`, `BatchSetFederatedBundle`
- File integrity: Changes to bundle.json or trust bundle files
- SPIRE Server log: Trust domain federation events
- X.509 certificate transparency: New CA certificates appearing in the trust chain

### Detection Opportunities

| What to Detect | How | Rule Mapping |
|---------------|-----|-------------|
| Trust bundle modification API calls | SPIRE server log method matching | Rule 101041 |
| Bundle file changes on disk | FIM on bundle.json and trust bundle paths | Rule 101041 |
| New trust domain added to federation | SPIRE server log federation events | Rule 101041 |

### Hardening

- Protect the SPIRE Server datastore with strict access controls
- Use FIM to monitor trust bundle files
- Implement bundle verification via the SPIFFE Trust Bundle endpoint (RFC)
- In federated deployments, verify bundles out-of-band before importing
- Use hardware-backed key storage (HSM/KMS) for the signing CA
- Rotate CAs regularly and monitor for unexpected CA additions

### References

- [SPIFFE Trust Domain and Bundle](https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/#trust-domain)
- [SPIRE Federation](https://spiffe.io/docs/latest/architecture/federation/)

---

## Attack Vector 9: Agent Re-attestation Abuse

### MITRE ATT&CK: T1078 (Valid Accounts), T1550 (Use Alternate Authentication Material)

### Technical Explanation

SPIRE Agents authenticate to the SPIRE Server through **node attestation** — a process where the agent proves the identity of the node it runs on. Attestation methods include:

- **Join tokens**: Pre-shared secrets (expire after single use)
- **AWS IID**: Instance Identity Document from the EC2 metadata service
- **Azure MSI**: Managed Service Identity token
- **GCP IIT**: Instance Identity Token
- **Kubernetes SAT**: Kubernetes Service Account Token

An attacker who obtains attestation data (e.g., by stealing an AWS IID from IMDS, or a K8s SAT from a mounted token) can potentially:

1. **Register a rogue agent**: Present the stolen attestation data to the SPIRE Server as if it were a legitimate node
2. **Replay attestation**: Use captured attestation data to re-attest a malicious agent

If successful, the rogue agent receives a node SVID and can request workload SVIDs for any registration entries whose `parentID` matches the compromised node identity.

### Prerequisites

- Access to node attestation credentials (stolen IID, SAT, join token)
- Network access to the SPIRE Server's agent attestation endpoint (port 8081)
- The attestation method must not have replay protections (join tokens are safe — single use)

### Step-by-Step Attack Flow

1. **Steal node attestation data**:
   ```bash
   # AWS Instance Identity Document (from IMDS)
   curl http://169.254.169.254/latest/dynamic/instance-identity/document

   # Kubernetes Service Account Token
   cat /var/run/secrets/kubernetes.io/serviceaccount/token
   ```

2. **Configure a rogue SPIRE Agent** with the stolen attestation data

3. **Attempt node attestation**: The rogue agent presents the stolen credentials to the SPIRE Server

4. **If successful**: The rogue agent receives a node SVID and becomes a trusted member of the SPIRE infrastructure

5. **Request workload SVIDs**: The rogue agent can now issue SVIDs for any workload registered under the compromised node's parentID

### Logs/Artifacts Produced

- SPIRE Server log: `AttestAgent` API call with node attestation details
- SPIRE Server log: New agent registration or re-attestation event
- SPIRE Server log: Agent connection from unexpected IP address
- IMDS access log: Instance identity document request (if AWS-based)
- K8s audit log: Service account token access

### Detection Opportunities

| What to Detect | How | Rule Mapping |
|---------------|-----|-------------|
| Agent attestation events | SPIRE server log matching AttestAgent | Rule 101040 |
| Attestation from unexpected IP | SPIRE server log caller_addr analysis | Rule 101040 |
| Multiple attestation attempts | Frequency-based: repeated attestation failures | Custom |
| Credential theft feeding attestation | Correlation: IMDS theft (100651) + agent attestation (101040) | Custom correlation |

### Hardening

- Use attestation methods with replay protection (e.g., join tokens expire after use)
- For AWS: Use IMDSv2 to prevent casual IMDS access (requires PUT token)
- For K8s: Use projected service account tokens (bound, short-lived)
- Implement node attestor plugins that verify unique, non-replayable node attributes
- Monitor for unexpected agent attestation events
- Restrict network access to SPIRE Server port 8081

### References

- [SPIRE Node Attestation](https://spiffe.io/docs/latest/spire-about/spire-concepts/#node-attestation)
- [SPIRE Agent Configuration](https://spiffe.io/docs/latest/deploying/spire_agent/)

---

## Attack Vector 10: Kubelet Verification Bypass

### MITRE ATT&CK: T1562.001 (Disable or Modify Tools)

### Technical Explanation

The SPIRE Agent's Kubernetes workload attestor communicates with the kubelet to discover pod metadata for workload attestation. By default, SPIRE verifies the kubelet's TLS certificate to prevent MITM attacks. However, the configuration option `skip_kubelet_verification` can disable this verification:

```hcl
WorkloadAttestor "k8s" {
    plugin_data {
        skip_kubelet_verification = true
    }
}
```

When verification is skipped:
- An attacker who can intercept kubelet traffic can provide forged pod metadata
- The SPIRE Agent trusts the forged metadata and assigns incorrect SPIFFE IDs
- This enables selector spoofing at the infrastructure level

Additionally, the kubelet has a **read-only port** (10255) that serves pod metadata without authentication. If the SPIRE Agent is configured to use this port, any network-adjacent attacker can respond with forged data.

### Prerequisites

- SPIRE Agent deployed with `skip_kubelet_verification = true`, OR
- SPIRE Agent using the kubelet read-only port (10255)
- Network position to intercept or redirect kubelet traffic

### Step-by-Step Attack Flow

1. **Discover SPIRE Agent configuration**:
   ```bash
   cat /opt/spire/conf/agent.conf | grep -i kubelet
   # Look for skip_kubelet_verification = true
   # Look for kubelet_read_only_port
   ```

2. **Position for MITM**: If kubelet verification is skipped:
   ```bash
   # ARP spoofing or DNS hijacking to intercept kubelet traffic
   # Respond with forged pod metadata
   ```

3. **Forge pod metadata**: Craft kubelet responses that match registration entries for target SPIFFE IDs

4. **Agent attestation uses forged data**: SPIRE Agent assigns SVIDs based on the attacker-controlled metadata

### Logs/Artifacts Produced

- SPIRE Agent configuration: `skip_kubelet_verification = true`
- SPIRE Agent configuration: `kubelet_read_only_port` usage
- Network logs: Unusual traffic patterns to/from kubelet port
- Configuration change events: Modification of SPIRE Agent config files

### Detection Opportunities

| What to Detect | How | Rule Mapping |
|---------------|-----|-------------|
| Config with skip_kubelet_verification | Content match in SPIRE config files | Rule 101043 |
| SPIRE config file changes | FIM on SPIRE configuration directories | Rule 101042 |
| Kubelet read-only port usage | Network monitoring for port 10255 traffic | Custom |

### Hardening

- Never set `skip_kubelet_verification = true` in production
- Disable the kubelet read-only port (set `--read-only-port=0`)
- Use the secure kubelet port (10250) with proper TLS verification
- Monitor SPIRE Agent configuration files with FIM
- Use admission webhooks to prevent SPIRE configuration changes in K8s

### References

- [SPIRE K8s Workload Attestor Configuration](https://github.com/spiffe/spire/blob/main/doc/plugin_agent_workloadattestor_k8s.md)
- [Kubernetes Kubelet Authentication/Authorization](https://kubernetes.io/docs/reference/access-authn-authz/kubelet-authn-authz/)

---

## Attack Chaining: The "Spooffe" Pattern

The most devastating attacks combine multiple vectors. The canonical chain demonstrated in Gerzi's research:

```
Container Escape (Vector 6)
    ↓
SPIRE Agent Socket Access (Vector 3)
    ↓
SVID Harvesting (Vector 3)
    ↓
Lateral Movement via stolen SVIDs
    ↓
Registration Entry Manipulation (Vector 7) — if server access obtained
    ↓
Full trust domain compromise
```

### Detection Rule Chain

```
Rule 100757 (nsenter container escape) — Level 10
    ↓
Rule 101000 (SPIRE socket access) — Level 8
    ↓
Rule 101001 (scripting tool on socket) — Level 12
    ↓
Rule 101080 (CORRELATION: escape + socket access) — Level 15
    ↓
Rule 100954 (5+ NHI events from same source) — Level 15
```

This chain escalates from individual Level 8-12 alerts to a Level 15 confirmed multi-stage attack within minutes.

---

## Summary: Detection Coverage Matrix

| Attack Vector | Primary Rule(s) | Correlation Rule | Coverage |
|--------------|-----------------|-----------------|----------|
| 1. Selector Spoofing | 101021, 101005, 101006 | 101081 | Registration + PID-based SVID tracking |
| 2. Overlapping Entries | 101020, 101021, 101006 | 101081 | Entry creation + multi-identity PID |
| 3. SVID Harvesting | 101000, 101001, 101002, 101003, 101004, 101005 | 101080 | Socket + key + PID burst |
| 4. JWT-SVID Replay | 101060 | — | Log leakage detection |
| 5. Delegated Identity | 101061 | — | API access detection |
| 6. Container Escape → SVID | 100757-100764 + 101000 | 101080 | Full chain correlation |
| 7. Entry Manipulation | 101020, 101021, 101022 | 101081 | Create/modify/delete |
| 8. Trust Bundle Poisoning | 101041 | — | API + FIM detection |
| 9. Agent Re-attestation | 101040 | — | Attestation monitoring |
| 10. Kubelet Bypass | 101042, 101043 | — | Config monitoring |

---

## Appendix: SPIFFE/SPIRE Log Sources Configuration

> **CRITICAL PREREQUISITES FOR DETECTION RULES TO WORK:**
>
> SPIRE default configuration is NOT sufficient for detection. The following
> changes are REQUIRED (verified against SPIRE source code and spiffe.io docs):
>
> | Setting | SPIRE Default | Required Value | Rules Affected |
> |---------|--------------|----------------|----------------|
> | Server `audit_log_enabled` | `false` | `true` | 101020-101022, 101040 |
> | Agent `log_level` | `"INFO"` | `"DEBUG"` | 101004-101006 |
> | Agent `log_format` | `"text"` | `"json"` (recommended) | All agent rules |
> | Server `log_format` | `"text"` | `"json"` (recommended) | All server rules |
> | Socket monitoring | None | auditd rules | 101000-101003 |
>
> **Why DEBUG logging is needed for PID-based detection:** SPIRE Agent logs
> "Fetched X.509 SVID" and "Fetched JWT SVID" at DEBUG level only (confirmed
> in handler.go). PID is injected by the addWatcherPID middleware via
> `peertracker.WatcherFromContext(ctx).PID()` — so it appears on ALL workload
> API log lines at DEBUG level, but these messages are suppressed at INFO level.
>
> **Why JSON format is recommended:** The decoders support BOTH JSON and TEXT
> Logrus formats, but JSON provides more reliable field extraction. TEXT format
> uses `key=value` pairs (e.g., `pid=1234 spiffe_id=spiffe://...`) while JSON
> uses `"key":"value"` (e.g., `"pid":1234,"spiffe_id":"spiffe://..."`).
>
> **Known limitation (Fetched JWT SVID):** The "Fetched JWT SVID" log message
> includes `pid` (via middleware) but does NOT include `spiffe_id` — only `ttl`
> is explicitly added (handler.go line 300). This means rule 101006 cannot
> distinguish different SPIFFE IDs for JWT SVID fetches. X.509 SVID fetches
> DO include both `pid` and `spiffe_id` (handler.go line 390).
>
> **Known limitation (Rule 101006):** Wazuh lacks `<different_field>` support.
> Rule 101006 fires on 2+ SVID events from the same PID within 5 minutes,
> regardless of whether the SPIFFE IDs differ. Normal SVID rotation will
> trigger this rule. Analyst must verify that SPIFFE IDs differ in the alerts.
> The Sigma equivalent (nhi_spire_pid_multiple_identities.yml) uses proper
> `count(distinct spiffe_id) by pid > 1` aggregation.

### SPIRE Server Configuration (server.conf)

```hcl
server {
    # REQUIRED for detection rules 101020-101022, 101040, 101041
    audit_log_enabled = true

    log_level = "INFO"
    log_format = "json"
    log_file = "/var/log/spire/server.log"
}
```

### SPIRE Agent Configuration (agent.conf)

```hcl
agent {
    # REQUIRED for PID-based detection (rules 101004-101006)
    # WARNING: DEBUG logging is verbose — consider dedicated log file
    log_level = "DEBUG"
    log_format = "json"
    log_file = "/var/log/spire/agent.log"
}
```

### SPIRE Server Log Forwarding (Wazuh Agent ossec.conf)

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/spire/server.log</location>
  <label key="log_type">spire-server</label>
</localfile>
```

### SPIRE Agent Log Forwarding (Wazuh Agent ossec.conf)

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/spire/agent.log</location>
  <label key="log_type">spire-agent</label>
</localfile>
```

### Auditd Rules for SPIRE Socket Monitoring

```bash
# REQUIRED for rule 101000 to detect socket connections (FIM alone is insufficient)
# Socket connections don't trigger file modification events — auditd watches syscalls
-w /tmp/spire-agent/public/api.sock -p rwa -k spire_socket
-w /run/spire/sockets/agent.sock -p rwa -k spire_socket
```

### File Integrity Monitoring for SPIRE Paths

```xml
<!-- FIM detects file creation/modification/deletion (NOT socket connections) -->
<!-- Useful for: config tampering (101042-101043), key extraction (101002),
     trust bundle changes (101041) -->
<syscheck>
  <directories check_all="yes">/tmp/spire-agent/public</directories>
  <directories check_all="yes">/run/spire/sockets</directories>
  <directories check_all="yes">/opt/spire/data</directories>
  <directories check_all="yes">/opt/spire/conf</directories>
  <directories check_all="yes" realtime="yes">/opt/spire/data/server/bundle.json</directories>
</syscheck>
```

### Kubernetes Audit Policy for SPIRE Events

```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  - level: RequestResponse
    resources:
      - group: "spiffe.io"
        resources: ["spiffeids"]
    verbs: ["create", "update", "patch", "delete"]
  - level: Metadata
    resources:
      - group: ""
        resources: ["configmaps", "secrets"]
    namespaces: ["spire"]
```
