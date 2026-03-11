# spiffe-security-bench

Security benchmark for SPIFFE/SPIRE deployments. Analogous to [kube-bench](https://github.com/aquasecurity/kube-bench) for Kubernetes, this tool audits a SPIRE deployment against 10 known attack vectors and produces a PASS/FAIL/WARN report with remediation guidance.

## Checks

| ID     | Check                            | Attack Vector                        | Severity |
|--------|----------------------------------|--------------------------------------|----------|
| SSB-01 | Weak Workload Selectors          | Selector Spoofing                    | Critical |
| SSB-02 | SVID Private Key Protection      | SVID Harvesting                      | Critical |
| SSB-03 | Registration Entry Integrity     | Registration Tampering               | High     |
| SSB-04 | Overlapping Selector Detection   | Ambiguous Identity Assignment        | High     |
| SSB-05 | JWT-SVID Validation              | JWT-SVID Replay                      | High     |
| SSB-06 | Delegated Identity API Access    | Admin Socket Abuse                   | Critical |
| SSB-07 | Container Escape to SPIRE Socket | Container Escape -> SPIRE            | Critical |
| SSB-08 | Trust Bundle Integrity           | Trust Bundle Poisoning               | Critical |
| SSB-09 | Agent Attestation Security       | Rogue Agent Re-attestation           | High     |
| SSB-10 | Kubelet Verification             | skip_kubelet_verification Bypass     | High     |

Each check maps to a MITRE ATT&CK technique and includes evidence collection and remediation advice.

## Installation

```bash
pip install -e tools/spiffe-security-bench/
```

Or from the tool directory:

```bash
cd tools/spiffe-security-bench
pip install -e .
```

## Usage

Run all checks against a local SPIRE deployment:

```bash
spiffe-security-bench
```

Target a specific SPIRE server:

```bash
spiffe-security-bench --spire-server spire-server.example.com:8081
```

Run specific checks:

```bash
spiffe-security-bench --check SSB-01 --check SSB-04
```

JSON output for CI pipelines:

```bash
spiffe-security-bench -o json
```

YAML output:

```bash
spiffe-security-bench -o yaml
```

Custom socket paths:

```bash
spiffe-security-bench \
  --server-socket /run/spire/server/private/api.sock \
  --spire-agent-socket /run/spire/agent/public/api.sock
```

## Example Output

```
SPIFFE Security Bench v0.1.0
Target: localhost:8081

           SPIFFE Security Bench Results
  4 PASS  2 FAIL  3 WARN  1 SKIP

 ID      Status Severity   Check                              Attack Vector              Details
 SSB-01  FAIL   CRITICAL   Weak Workload Selectors            Selector Spoofing          Found 3 entries with weak selectors
 SSB-02  PASS   CRITICAL   SVID Private Key Protection        SVID Harvesting            Checked 12 key files -- none are grou...
 SSB-03  WARN   HIGH       Registration Entry Integrity       Registration Tampering     Found 1 potentially suspicious entries
 SSB-04  PASS   HIGH       Overlapping Selector Detection     Ambiguous Identity Assign  No overlapping selectors found across...
 SSB-05  WARN   HIGH       JWT-SVID Validation                JWT-SVID Replay            default_jwt_svid_ttl not explicitly set
 SSB-06  FAIL   CRITICAL   Delegated Identity API Access      Admin Socket Abuse         Admin socket has excessive permissions
 SSB-07  PASS   CRITICAL   Container Escape to SPIRE Socket   Container Escape -> SPIRE  SPIRE socket permissions appear restr...
 SSB-08  WARN   CRITICAL   Trust Bundle Integrity             Trust Bundle Poisoning     spire-server CLI not found
 SSB-09  PASS   HIGH       Agent Attestation Security         Rogue Agent Re-attestation Agent attestation configuration appea...
 SSB-10  SKIP   HIGH       Kubelet Verification               skip_kubelet_verification  Could not find SPIRE server config

Remediation Recommendations:
  x SSB-01: Use composite selectors (unix:uid + unix:path + sha256) instead of single weak selectors
  x SSB-06: Restrict admin socket access to authorized processes only, disable delegated identity API unless required
  ! SSB-03: Audit registration entries regularly, implement approval workflows for entry creation
  ! SSB-05: Set short JWT-SVID TTL (5m or less), always validate audience claims
  ! SSB-08: Verify trust bundles come from trusted sources, monitor for unexpected CA changes

Security Score: 44% (4/9 checks passed)
```

## How It Works

The tool inspects a SPIRE deployment through three channels:

1. **SPIRE Server CLI** -- queries registration entries, trust bundles, and agent state via `spire-server` commands against the admin socket
2. **File system inspection** -- checks SVID key permissions, config files, and socket permissions on the local host
3. **Container environment** -- detects privileged containers, shared namespaces, and other escape vectors

Checks gracefully degrade to WARN status when SPIRE components are not reachable, making it safe to run in any environment.

## Integration with NHI Testbed

This tool is part of the [Machine Identity Security Testbed](../../README.md). The attack vectors tested here correspond to SPIFFE/SPIRE scenarios in `scenarios/category-7-spiffe-spire/` and detection rules in `sigma/rules/spiffe-spire/`.
