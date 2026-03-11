"""Security benchmark checks for SPIFFE/SPIRE deployments.

Each check targets a specific attack vector against SPIFFE/SPIRE infrastructure.
Checks are designed to run against a live SPIRE deployment and produce
PASS/FAIL/WARN/SKIP results with evidence and remediation guidance.
"""

import json
import os
import stat
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class CheckResult:
    """Result of a single security benchmark check."""

    id: str
    title: str
    attack_vector: str
    status: str  # PASS, FAIL, WARN, INFO, SKIP
    severity: str  # critical, high, medium, low
    details: str = ""
    remediation: str = ""
    cve_ref: str = ""
    mitre_ref: str = ""
    evidence: list[str] = field(default_factory=list)


CHECKS = [
    {
        "id": "SSB-01",
        "title": "Weak Workload Selectors",
        "attack_vector": "Selector Spoofing",
        "severity": "critical",
        "description": (
            "Check for registration entries using easily spoofable selectors "
            "(unix:uid, unix:gid alone)"
        ),
        "mitre_ref": "T1078, T1098",
    },
    {
        "id": "SSB-02",
        "title": "SVID Private Key Protection",
        "attack_vector": "SVID Harvesting",
        "severity": "critical",
        "description": "Check if SVID private keys are stored with proper file permissions",
        "mitre_ref": "T1552.004",
    },
    {
        "id": "SSB-03",
        "title": "Registration Entry Integrity",
        "attack_vector": "Registration Tampering",
        "severity": "high",
        "description": "Check for unauthorized or suspicious registration entries",
        "mitre_ref": "T1098, T1556",
    },
    {
        "id": "SSB-04",
        "title": "Overlapping Selector Detection",
        "attack_vector": "Ambiguous Identity Assignment",
        "severity": "high",
        "description": (
            "Check for entries with identical selectors mapping to different SPIFFE IDs"
        ),
        "mitre_ref": "T1078",
    },
    {
        "id": "SSB-05",
        "title": "JWT-SVID Validation",
        "attack_vector": "JWT-SVID Replay",
        "severity": "high",
        "description": "Check JWT-SVID TTL, audience validation, and replay protections",
        "mitre_ref": "T1550.001",
    },
    {
        "id": "SSB-06",
        "title": "Delegated Identity API Access",
        "attack_vector": "Admin Socket Abuse",
        "severity": "critical",
        "description": (
            "Check SPIRE Agent admin socket permissions and delegated identity API access"
        ),
        "mitre_ref": "T1078.003",
    },
    {
        "id": "SSB-07",
        "title": "Container Escape to SPIRE Socket",
        "attack_vector": "Container Escape -> SPIRE",
        "severity": "critical",
        "description": "Check if SPIRE sockets are accessible from container breakout paths",
        "mitre_ref": "T1611",
    },
    {
        "id": "SSB-08",
        "title": "Trust Bundle Integrity",
        "attack_vector": "Trust Bundle Poisoning",
        "severity": "critical",
        "description": "Check trust bundle source, rotation, and integrity verification",
        "mitre_ref": "T1553",
    },
    {
        "id": "SSB-09",
        "title": "Agent Attestation Security",
        "attack_vector": "Rogue Agent Re-attestation",
        "severity": "high",
        "description": (
            "Check agent attestation method, join token security, and re-attestation controls"
        ),
        "mitre_ref": "T1078",
    },
    {
        "id": "SSB-10",
        "title": "Kubelet Verification",
        "attack_vector": "skip_kubelet_verification Bypass",
        "severity": "high",
        "description": "Check if skip_kubelet_verification is enabled (allows pod spoofing)",
        "mitre_ref": "T1078.004",
    },
]

# Well-known paths where SPIRE stores key material
_KEY_SEARCH_PATHS = [
    "/opt/spire/data/agent/",
    "/opt/spire/sockets/",
    "/tmp/spire-agent/",
    "/var/lib/spire/",
    "/run/spire/",
]

# Well-known SPIRE server config locations
_SERVER_CONFIG_PATHS = [
    "/opt/spire/conf/server/server.conf",
    "/etc/spire/server/server.conf",
    "spire/server/server.conf",
]

# Well-known SPIRE agent config locations
_AGENT_CONFIG_PATHS = [
    "/opt/spire/conf/agent/agent.conf",
    "/etc/spire/agent/agent.conf",
    "spire/agent/agent.conf",
]

# Well-known admin socket locations
_ADMIN_SOCKET_PATHS = [
    "/opt/spire/sockets/admin.sock",
    "/tmp/spire-agent/private/admin.sock",
    "/run/spire/admin.sock",
]

# Weak selector types that are trivially spoofable when used alone
_WEAK_SELECTOR_PREFIXES = ("unix:uid", "unix:gid")

# Suspicious keywords in SPIFFE IDs that warrant investigation
_SUSPICIOUS_ID_KEYWORDS = ("admin", "root", "evil", "test", "hack", "debug", "tmp")


def _run_spire_cli(args: list[str], timeout: int = 10) -> subprocess.CompletedProcess:
    """Run a spire-server CLI command and return the result."""
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)


def _query_entries(server_socket: str) -> Optional[list[dict]]:
    """Query SPIRE server for registration entries. Returns None on failure."""
    try:
        proc = _run_spire_cli([
            "spire-server", "entry", "show",
            "-socketPath", server_socket,
            "-output", "json",
        ])
        if proc.returncode == 0:
            data = json.loads(proc.stdout)
            return data.get("entries", [])
    except FileNotFoundError:
        return None
    except (json.JSONDecodeError, subprocess.TimeoutExpired):
        return None
    return None


def _find_config(candidates: list[str]) -> Optional[tuple[str, str]]:
    """Find and read the first existing config file. Returns (path, content) or None."""
    for config_path in candidates:
        if os.path.exists(config_path):
            with open(config_path) as f:
                return config_path, f.read()
    return None


def run_all_checks(
    spire_server: str,
    agent_socket: str,
    server_socket: str,
    selected: Optional[list[str]] = None,
    verbose: bool = False,
) -> list[CheckResult]:
    """Run all security benchmark checks against the target SPIRE deployment."""
    results = []

    for check_def in CHECKS:
        if selected and check_def["id"] not in selected:
            continue

        check_fn = CHECK_FUNCTIONS.get(check_def["id"])
        if check_fn:
            result = check_fn(
                check_def, spire_server, agent_socket, server_socket, verbose
            )
        else:
            result = CheckResult(
                id=check_def["id"],
                title=check_def["title"],
                attack_vector=check_def["attack_vector"],
                status="SKIP",
                severity=check_def["severity"],
                details="Check not yet implemented",
                mitre_ref=check_def.get("mitre_ref", ""),
            )
        results.append(result)

    return results


# ---------------------------------------------------------------------------
# Individual check implementations
# ---------------------------------------------------------------------------


def check_weak_selectors(check_def, server, agent_socket, server_socket, verbose):
    """SSB-01: Check for weak/spoofable selectors in registration entries.

    Single unix:uid or unix:gid selectors are trivially spoofable by any process
    running as that UID/GID. Production entries should use composite selectors
    combining multiple attestation signals (e.g., unix:uid + unix:path + sha256).
    """
    result = CheckResult(
        id=check_def["id"],
        title=check_def["title"],
        attack_vector=check_def["attack_vector"],
        status="PASS",
        severity=check_def["severity"],
        mitre_ref=check_def.get("mitre_ref", ""),
        remediation=(
            "Use composite selectors (unix:uid + unix:path + sha256) "
            "instead of single weak selectors"
        ),
    )

    entries = _query_entries(server_socket)
    if entries is None:
        result.status = "WARN"
        result.details = (
            "Could not query SPIRE server -- spire-server CLI not found or not reachable"
        )
        return result

    weak_entries = []
    for entry in entries:
        selectors = entry.get("selectors", [])
        if len(selectors) == 1:
            sel = selectors[0]
            sel_str = f"{sel.get('type', '')}:{sel.get('value', '')}"
            if any(sel_str.startswith(p) for p in _WEAK_SELECTOR_PREFIXES):
                weak_entries.append({
                    "spiffe_id": entry.get("spiffe_id", ""),
                    "selector": sel_str,
                })

    if weak_entries:
        result.status = "FAIL"
        result.details = f"Found {len(weak_entries)} entries with weak selectors"
        result.evidence = [json.dumps(e) for e in weak_entries[:5]]
    else:
        result.details = f"All {len(entries)} entries use composite selectors"

    return result


def check_svid_key_protection(check_def, server, agent_socket, server_socket, verbose):
    """SSB-02: Check SVID private key file permissions.

    SVID private keys must be restricted to mode 0600 or 0400 and owned by the
    workload user. Group-readable or world-readable keys allow any local process
    to harvest SVIDs and impersonate the workload identity.
    """
    result = CheckResult(
        id=check_def["id"],
        title=check_def["title"],
        attack_vector=check_def["attack_vector"],
        status="PASS",
        severity=check_def["severity"],
        mitre_ref=check_def.get("mitre_ref", ""),
        remediation=(
            "Ensure SVID key files are mode 0600 or 0400, owned by the workload user"
        ),
    )

    excessive_perms = []
    checked_paths = 0

    for base_path in _KEY_SEARCH_PATHS:
        path = Path(base_path)
        if not path.exists():
            continue
        for pattern in ("*.key", "*.pem", "svid.*"):
            for f in path.rglob(pattern):
                checked_paths += 1
                try:
                    st = f.stat()
                except OSError:
                    continue
                mode = stat.S_IMODE(st.st_mode)
                if mode & (stat.S_IRGRP | stat.S_IROTH):
                    excessive_perms.append({"path": str(f), "mode": oct(mode)})

    if excessive_perms:
        result.status = "FAIL"
        result.details = (
            f"Found {len(excessive_perms)} key files with excessive permissions"
        )
        result.evidence = [json.dumps(e) for e in excessive_perms[:5]]
    elif checked_paths == 0:
        result.status = "WARN"
        result.details = "No SPIRE key directories found on this host"
    else:
        result.details = f"Checked {checked_paths} key files -- none are group/world readable"

    return result


def check_registration_integrity(check_def, server, agent_socket, server_socket, verbose):
    """SSB-03: Check for suspicious registration entries.

    Looks for SPIFFE IDs containing suspicious keywords (admin, root, evil, test)
    and entries with root selectors (uid:0, gid:0) that may indicate unauthorized
    registration or persistence by an attacker.
    """
    result = CheckResult(
        id=check_def["id"],
        title=check_def["title"],
        attack_vector=check_def["attack_vector"],
        status="PASS",
        severity=check_def["severity"],
        mitre_ref=check_def.get("mitre_ref", ""),
        remediation=(
            "Audit registration entries regularly, implement approval workflows "
            "for entry creation"
        ),
    )

    entries = _query_entries(server_socket)
    if entries is None:
        result.status = "WARN"
        result.details = "Could not query SPIRE server"
        return result

    suspicious = []
    for entry in entries:
        spiffe_id = entry.get("spiffe_id", "")
        id_lower = spiffe_id.lower()

        # Flag suspicious name patterns
        for kw in _SUSPICIOUS_ID_KEYWORDS:
            if kw in id_lower:
                suspicious.append({
                    "spiffe_id": spiffe_id,
                    "reason": f"suspicious keyword '{kw}' in SPIFFE ID",
                })
                break

        # Flag root selectors
        selectors = entry.get("selectors", [])
        for s in selectors:
            val = s.get("value", "")
            if val in ("uid:0", "gid:0", "0"):
                sel_type = s.get("type", "")
                if sel_type in ("unix", ""):
                    suspicious.append({
                        "spiffe_id": spiffe_id,
                        "reason": f"root selector {sel_type}:{val}",
                    })

    if suspicious:
        result.status = "WARN"
        result.details = f"Found {len(suspicious)} potentially suspicious entries"
        result.evidence = [json.dumps(s) for s in suspicious[:5]]
    else:
        result.details = f"All {len(entries)} entries appear legitimate"

    return result


def check_overlapping_selectors(check_def, server, agent_socket, server_socket, verbose):
    """SSB-04: Check for overlapping selectors across registration entries.

    When multiple SPIFFE IDs share identical selectors, workloads may receive
    ambiguous identities. An attacker who matches the shared selector can
    obtain SVIDs for any of the overlapping identities.
    """
    result = CheckResult(
        id=check_def["id"],
        title=check_def["title"],
        attack_vector=check_def["attack_vector"],
        status="PASS",
        severity=check_def["severity"],
        mitre_ref=check_def.get("mitre_ref", ""),
        remediation="Ensure each workload has unique composite selectors",
    )

    entries = _query_entries(server_socket)
    if entries is None:
        result.status = "WARN"
        result.details = "Could not query SPIRE server"
        return result

    selector_map: dict[str, list[str]] = {}
    for entry in entries:
        selectors = entry.get("selectors", [])
        key = "|".join(
            sorted(
                f"{s.get('type', '')}:{s.get('value', '')}" for s in selectors
            )
        )
        spiffe_id = entry.get("spiffe_id", "")
        selector_map.setdefault(key, []).append(spiffe_id)

    overlaps = {k: v for k, v in selector_map.items() if len(v) > 1}
    if overlaps:
        result.status = "FAIL"
        result.details = (
            f"Found {len(overlaps)} selector sets mapping to multiple SPIFFE IDs"
        )
        result.evidence = [
            json.dumps({"selectors": k, "spiffe_ids": v})
            for k, v in list(overlaps.items())[:5]
        ]
    else:
        result.details = (
            f"No overlapping selectors found across {len(entries)} entries"
        )

    return result


def check_jwt_svid_validation(check_def, server, agent_socket, server_socket, verbose):
    """SSB-05: Check JWT-SVID configuration for secure defaults.

    JWT-SVIDs with long TTLs expand the replay window. The recommended maximum
    TTL is 5 minutes. This check also verifies that audience validation is
    not explicitly disabled.
    """
    result = CheckResult(
        id=check_def["id"],
        title=check_def["title"],
        attack_vector=check_def["attack_vector"],
        status="PASS",
        severity=check_def["severity"],
        mitre_ref=check_def.get("mitre_ref", ""),
        remediation=(
            "Set short JWT-SVID TTL (5m or less), always validate audience claims"
        ),
    )

    config = _find_config(_SERVER_CONFIG_PATHS)
    if config is None:
        result.status = "WARN"
        result.details = "Could not find SPIRE server config file"
        return result

    config_path, content = config
    issues = []

    # Check default_jwt_svid_ttl
    if "default_jwt_svid_ttl" not in content:
        issues.append(
            "default_jwt_svid_ttl not explicitly set (uses server default)"
        )
    else:
        # Flag TTLs of 1 hour or greater
        for long_ttl in ("1h", "2h", "4h", "8h", "24h", "3600", "7200"):
            if long_ttl in content:
                issues.append(
                    f"JWT-SVID TTL appears to be {long_ttl} or more "
                    "(recommended: 5 minutes or less)"
                )
                break

    # Check for disabled audience validation
    if "allow_missing_audience" in content or "skip_audience" in content:
        issues.append("Audience validation may be disabled in config")

    if issues:
        result.status = "WARN"
        result.details = "; ".join(issues)
        result.evidence = [f"Config: {config_path}"]
    else:
        result.details = "JWT-SVID configuration appears secure"
        result.evidence = [f"Config: {config_path}"]

    return result


def check_delegated_identity(check_def, server, agent_socket, server_socket, verbose):
    """SSB-06: Check delegated identity API and admin socket access controls.

    The SPIRE Agent admin socket grants full delegated identity API access.
    If the socket has excessive permissions, any local process can request
    SVIDs for arbitrary workloads. Also checks for insecure bootstrap mode.
    """
    result = CheckResult(
        id=check_def["id"],
        title=check_def["title"],
        attack_vector=check_def["attack_vector"],
        status="PASS",
        severity=check_def["severity"],
        mitre_ref=check_def.get("mitre_ref", ""),
        remediation=(
            "Restrict admin socket access to authorized processes only, "
            "disable delegated identity API unless required"
        ),
    )

    issues = []
    excessive_found = False

    # Check admin socket permissions
    for sock_path in _ADMIN_SOCKET_PATHS:
        if os.path.exists(sock_path):
            try:
                st = os.stat(sock_path)
                mode = stat.S_IMODE(st.st_mode)
                group_or_other = (
                    stat.S_IRGRP | stat.S_IROTH | stat.S_IWGRP | stat.S_IWOTH
                )
                if mode & group_or_other:
                    issues.append(
                        f"Admin socket {sock_path} has excessive permissions: {oct(mode)}"
                    )
                    excessive_found = True
            except OSError:
                pass

    # Check agent config for admin socket and insecure bootstrap
    config = _find_config(_AGENT_CONFIG_PATHS)
    if config is not None:
        config_path, content = config
        if "admin_socket_path" in content:
            issues.append(f"Admin socket enabled in {config_path}")
        if "insecure_bootstrap" in content.lower():
            issues.append(f"Insecure bootstrap enabled in {config_path}")

    if issues:
        result.status = "FAIL" if excessive_found else "WARN"
        result.details = "; ".join(issues)
        result.evidence = issues
    else:
        result.details = "No admin socket exposure detected"

    return result


def check_container_escape(check_def, server, agent_socket, server_socket, verbose):
    """SSB-07: Check container escape paths to SPIRE sockets.

    If SPIRE sockets are world-writable or the container runs in privileged mode,
    a container escape gives direct access to the SPIRE Workload API or admin API,
    allowing the attacker to mint arbitrary SVIDs.
    """
    result = CheckResult(
        id=check_def["id"],
        title=check_def["title"],
        attack_vector=check_def["attack_vector"],
        status="PASS",
        severity=check_def["severity"],
        mitre_ref=check_def.get("mitre_ref", ""),
        remediation=(
            "Mount SPIRE sockets as read-only, use hostPath restrictions, "
            "enable PodSecurity standards"
        ),
    )

    socket_paths = list({
        agent_socket,
        server_socket,
        "/tmp/spire-agent/public/api.sock",
        "/opt/spire/sockets/workload_api.sock",
        "/run/spire/agent.sock",
    })

    issues = []

    for sock_path in socket_paths:
        if os.path.exists(sock_path):
            try:
                st = os.stat(sock_path)
                mode = stat.S_IMODE(st.st_mode)
                if mode & stat.S_IWOTH:
                    issues.append(
                        f"Socket {sock_path} is world-writable: {oct(mode)}"
                    )
            except OSError:
                pass

    # Detect privileged container via full capability bitmask
    proc_status = "/proc/1/status"
    if os.path.exists(proc_status):
        try:
            with open(proc_status) as f:
                status = f.read()
            # Full 64-bit capability set indicates privileged mode
            if "CapEff:\t0000003fffffffff" in status:
                issues.append(
                    "Running in privileged container -- "
                    "full access to host SPIRE sockets possible"
                )
        except OSError:
            pass

    # Check for hostPID / hostNetwork indicators
    if os.path.exists("/proc/1/ns/pid"):
        try:
            host_ns = os.readlink("/proc/1/ns/pid")
            self_ns = os.readlink("/proc/self/ns/pid")
            if host_ns == self_ns:
                issues.append(
                    "Process shares host PID namespace -- "
                    "can access host SPIRE agent process"
                )
        except OSError:
            pass

    if issues:
        result.status = "FAIL"
        result.details = "; ".join(issues)
        result.evidence = issues
    else:
        result.details = "SPIRE socket permissions appear restrictive"

    return result


def check_trust_bundle(check_def, server, agent_socket, server_socket, verbose):
    """SSB-08: Check trust bundle integrity and federation configuration.

    A poisoned trust bundle (injecting a rogue CA) allows an attacker to mint
    valid SVIDs for any SPIFFE ID in the trust domain. This check verifies the
    bundle is present and audits federated trust bundles.
    """
    result = CheckResult(
        id=check_def["id"],
        title=check_def["title"],
        attack_vector=check_def["attack_vector"],
        status="PASS",
        severity=check_def["severity"],
        mitre_ref=check_def.get("mitre_ref", ""),
        remediation=(
            "Verify trust bundles come from trusted sources, "
            "monitor for unexpected CA changes"
        ),
    )

    try:
        proc = _run_spire_cli([
            "spire-server", "bundle", "show",
            "-socketPath", server_socket,
            "-output", "json",
        ])
        if proc.returncode != 0:
            result.status = "WARN"
            result.details = "Could not query trust bundle"
            return result

        # Bundle exists -- now check federation
        try:
            fed_proc = _run_spire_cli([
                "spire-server", "bundle", "list",
                "-socketPath", server_socket,
                "-output", "json",
            ])
            if fed_proc.returncode == 0:
                fed_data = json.loads(fed_proc.stdout)
                bundles = fed_data.get("bundles", [])
                if bundles:
                    result.status = "WARN"
                    domains = [
                        b.get("trust_domain", "unknown") for b in bundles
                    ]
                    result.details = (
                        f"Found {len(bundles)} federated trust bundles -- "
                        "verify each is authorized"
                    )
                    result.evidence = domains
                else:
                    result.details = "No federated bundles present"
            else:
                result.details = (
                    "Trust bundle present, could not enumerate federation"
                )
        except (json.JSONDecodeError, subprocess.TimeoutExpired):
            result.details = "Trust bundle present, could not check federation"

    except FileNotFoundError:
        result.status = "WARN"
        result.details = "spire-server CLI not found"
    except subprocess.TimeoutExpired:
        result.status = "WARN"
        result.details = "Timed out querying SPIRE server"

    return result


def check_agent_attestation(check_def, server, agent_socket, server_socket, verbose):
    """SSB-09: Check agent attestation security.

    join_token is the weakest attestation method -- tokens can be reused if not
    rotated. Insecure bootstrap (TOFU) skips server verification on first contact.
    Production deployments should use strong attestation (k8s_psat, aws_iid, etc.).
    """
    result = CheckResult(
        id=check_def["id"],
        title=check_def["title"],
        attack_vector=check_def["attack_vector"],
        status="PASS",
        severity=check_def["severity"],
        mitre_ref=check_def.get("mitre_ref", ""),
        remediation=(
            "Use strong attestation (k8s_psat, aws_iid) instead of join_token, "
            "rotate tokens regularly"
        ),
    )

    config = _find_config(_AGENT_CONFIG_PATHS)
    if config is None:
        result.status = "WARN"
        result.details = "Could not find agent config"
        return result

    config_path, content = config
    result.evidence.append(f"Config: {config_path}")

    issues = []
    if "join_token" in content:
        issues.append(
            "Using join_token attestation (weakest method, tokens can be reused)"
        )
    if "insecure_bootstrap" in content.lower():
        issues.append("Insecure bootstrap enabled -- TOFU without verification")

    if issues:
        result.status = "FAIL" if "join_token" in str(issues) else "WARN"
        result.details = "; ".join(issues)
    else:
        result.details = "Agent attestation configuration appears secure"

    return result


def check_kubelet_verification(check_def, server, agent_socket, server_socket, verbose):
    """SSB-10: Check if skip_kubelet_verification is enabled.

    When skip_kubelet_verification is true, SPIRE does not verify pod identity
    through the kubelet. An attacker with API server access can create fake pods
    to obtain SVIDs for any registered workload.
    """
    result = CheckResult(
        id=check_def["id"],
        title=check_def["title"],
        attack_vector=check_def["attack_vector"],
        status="PASS",
        severity=check_def["severity"],
        mitre_ref=check_def.get("mitre_ref", ""),
        remediation=(
            "Disable skip_kubelet_verification in production, "
            "use verified kubelet connections"
        ),
    )

    config = _find_config(_SERVER_CONFIG_PATHS)
    if config is None:
        result.status = "WARN"
        result.details = "Could not find SPIRE server config"
        return result

    config_path, content = config
    result.evidence = [f"Config: {config_path}"]

    # Look for the setting and its value
    content_lower = content.lower()
    if "skip_kubelet_verification" in content_lower:
        # Find the line with the setting
        for line in content_lower.splitlines():
            stripped = line.strip()
            if "skip_kubelet_verification" in stripped:
                if "true" in stripped:
                    result.status = "FAIL"
                    result.details = (
                        "skip_kubelet_verification is enabled -- pods can be spoofed"
                    )
                    return result
        result.details = "skip_kubelet_verification is present but set to false"
    else:
        result.details = "skip_kubelet_verification not set (defaults to disabled)"

    return result


# Map check IDs to their implementation functions
CHECK_FUNCTIONS = {
    "SSB-01": check_weak_selectors,
    "SSB-02": check_svid_key_protection,
    "SSB-03": check_registration_integrity,
    "SSB-04": check_overlapping_selectors,
    "SSB-05": check_jwt_svid_validation,
    "SSB-06": check_delegated_identity,
    "SSB-07": check_container_escape,
    "SSB-08": check_trust_bundle,
    "SSB-09": check_agent_attestation,
    "SSB-10": check_kubelet_verification,
}
