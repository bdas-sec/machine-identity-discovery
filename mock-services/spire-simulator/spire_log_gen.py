#!/usr/bin/env python3
"""Mock SPIRE Log Generator — replays realistic SPIRE Agent + Server log patterns.

Based on real SPIRE 1.11.2 JSON log output captured from testbed deployment.
Generates both normal operations and attack scenarios for detection testing.

Log destinations:
  /var/log/spire/agent.log   — SPIRE Agent logs (DEBUG, JSON)
  /var/log/spire-server/server.log — SPIRE Server audit logs (INFO, JSON)

Author: Bodhisattva Das
Machine Identity Detection Testbed
"""

import json
import os
import random
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

# Configuration
AGENT_LOG = os.environ.get("SPIRE_AGENT_LOG", "/var/log/spire/agent.log")
SERVER_LOG = os.environ.get("SPIRE_SERVER_LOG", "/var/log/spire-server/server.log")
TRUST_DOMAIN = os.environ.get("SPIRE_TRUST_DOMAIN", "example.org")
AGENT_IP = os.environ.get("SPIRE_AGENT_IP", "172.43.0.31")
SERVER_IP = os.environ.get("SPIRE_SERVER_IP", "172.43.0.30")

# Timing (seconds)
NORMAL_FETCH_INTERVAL = int(os.environ.get("NORMAL_FETCH_INTERVAL", "30"))
ATTACK_INTERVAL = int(os.environ.get("ATTACK_INTERVAL", "120"))
ROTATION_INTERVAL = int(os.environ.get("ROTATION_INTERVAL", "300"))

# Scenario toggles
ENABLE_SPOOFING = os.environ.get("ENABLE_SPOOFING", "true").lower() == "true"
ENABLE_BURST = os.environ.get("ENABLE_BURST", "true").lower() == "true"
ENABLE_ROGUE_ENTRY = os.environ.get("ENABLE_ROGUE_ENTRY", "true").lower() == "true"
ENABLE_OVERLAPPING = os.environ.get("ENABLE_OVERLAPPING", "false").lower() == "true"
ENABLE_JWT_REPLAY = os.environ.get("ENABLE_JWT_REPLAY", "false").lower() == "true"
ENABLE_DELEGATED_IDENTITY = os.environ.get("ENABLE_DELEGATED_IDENTITY", "false").lower() == "true"
ENABLE_CONTAINER_ESCAPE = os.environ.get("ENABLE_CONTAINER_ESCAPE", "false").lower() == "true"
ENABLE_TRUST_BUNDLE_POISON = os.environ.get("ENABLE_TRUST_BUNDLE_POISON", "false").lower() == "true"
ENABLE_REATTESTATION = os.environ.get("ENABLE_REATTESTATION", "false").lower() == "true"
ENABLE_KUBELET_BYPASS = os.environ.get("ENABLE_KUBELET_BYPASS", "false").lower() == "true"

# Workload definitions
LEGITIMATE_WORKLOADS = [
    {"spiffe_id": f"spiffe://{TRUST_DOMAIN}/web-frontend", "uid": 1000, "pid_base": 100},
    {"spiffe_id": f"spiffe://{TRUST_DOMAIN}/api-server", "uid": 1001, "pid_base": 200},
    {"spiffe_id": f"spiffe://{TRUST_DOMAIN}/db-proxy", "uid": 1002, "pid_base": 300},
]

ROGUE_WORKLOAD = {
    "spiffe_id": f"spiffe://{TRUST_DOMAIN}/workload-evil",
    "uid": 1000,  # Same UID as web-frontend — selector overlap!
}

JOIN_TOKEN = str(uuid.uuid4())
AGENT_SPIFFE_ID = f"spiffe://{TRUST_DOMAIN}/spire/agent/join_token/{JOIN_TOKEN}"


def now_iso():
    """Return current UTC time in SPIRE's format (no fractional seconds)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_log(path, entry):
    """Append a JSON log line to the specified file."""
    line = json.dumps(entry, separators=(",", ":"))
    with open(path, "a") as f:
        f.write(line + "\n")
    # Also write to stdout for Docker log capture
    print(line, flush=True)


def gen_entry_id():
    return str(uuid.uuid4())


def gen_request_id():
    return str(uuid.uuid4())


# ============================================================
# SPIRE Agent Log Generators (based on real 1.11.2 output)
# ============================================================

def agent_startup():
    """Emit agent startup sequence."""
    ts = now_iso()
    logs = [
        {"level": "warning", "msg": "Current umask 0022 is too permissive; setting umask 0027", "time": ts},
        {"data_dir": "/opt/spire/data/agent", "level": "info", "msg": "Starting agent", "time": ts, "version": "1.11.2"},
        {"external": False, "level": "info", "msg": "Plugin loaded", "plugin_name": "join_token", "plugin_type": "NodeAttestor", "subsystem_name": "catalog", "time": ts},
        {"external": False, "level": "info", "msg": "Plugin loaded", "plugin_name": "memory", "plugin_type": "KeyManager", "subsystem_name": "catalog", "time": ts},
        {"external": False, "level": "info", "msg": "Configured plugin", "plugin_name": "unix", "plugin_type": "WorkloadAttestor", "reconfigurable": False, "subsystem_name": "catalog", "time": ts},
        {"level": "info", "msg": "Bundle loaded", "subsystem_name": "attestor", "time": ts, "trust_domain_id": f"spiffe://{TRUST_DOMAIN}"},
        {"level": "info", "msg": "Node attestation was successful", "reattestable": False, "spiffe_id": AGENT_SPIFFE_ID, "subsystem_name": "attestor", "time": ts, "trust_domain_id": f"spiffe://{TRUST_DOMAIN}"},
        {"address": {"Name": "/opt/spire/sockets/workload_api.sock", "Net": "unix"}, "level": "info", "msg": "Starting Workload and SDS APIs", "network": "unix", "subsystem_name": "endpoints", "time": ts},
    ]
    for entry in logs:
        write_log(AGENT_LOG, entry)


def agent_entry_created(spiffe_id):
    """Emit agent-side entry cache creation event."""
    ts = now_iso()
    entry_id = gen_entry_id()
    write_log(AGENT_LOG, {
        "entry": entry_id,
        "level": "debug",
        "msg": "Entry created",
        "selectors_added": 1,
        "spiffe_id": spiffe_id,
        "subsystem_name": "cache_manager",
        "time": ts,
    })
    return entry_id


def agent_svid_created(spiffe_id, entry_id):
    """Emit SVID creation event."""
    ts = now_iso()
    write_log(AGENT_LOG, {
        "entry_id": entry_id,
        "level": "info",
        "msg": "Creating X509-SVID",
        "spiffe_id": spiffe_id,
        "subsystem_name": "manager",
        "time": ts,
    })
    write_log(AGENT_LOG, {
        "entry": entry_id,
        "level": "debug",
        "msg": "SVID updated",
        "spiffe_id": spiffe_id,
        "subsystem_name": "cache_manager",
        "time": ts,
    })


def agent_pid_attested(pid, uid, extra_selectors=None):
    """Emit PID attestation event with selectors."""
    ts = now_iso()
    selectors = [
        {"type": "unix", "value": f"uid:{uid}"},
        {"type": "unix", "value": "gid:0"},
        {"type": "unix", "value": "supplementary_gid:0"},
        {"type": "unix", "value": "path:/usr/bin/workload"},
        {"type": "unix", "value": f"sha256:{uuid.uuid4().hex}"},
    ]
    if extra_selectors:
        selectors.extend(extra_selectors)
    write_log(AGENT_LOG, {
        "level": "debug",
        "msg": "PID attested to have selectors",
        "pid": pid,
        "selectors": selectors,
        "subsystem_name": "workload_attestor",
        "time": ts,
    })


def agent_svid_fetched(pid, spiffe_id, count=1):
    """Emit SVID fetch event — the key detection event."""
    ts = now_iso()
    write_log(AGENT_LOG, {
        "count": count,
        "level": "debug",
        "method": "FetchX509SVID",
        "msg": "Fetched X.509 SVID",
        "pid": pid,
        "registered": True,
        "service": "WorkloadAPI",
        "spiffe_id": spiffe_id,
        "subsystem_name": "endpoints",
        "time": ts,
        "ttl": random.uniform(2000, 3600),
    })


def agent_no_identity(pid):
    """Emit 'No identity issued' for unregistered PID."""
    ts = now_iso()
    write_log(AGENT_LOG, {
        "level": "debug",
        "method": "FetchX509SVID",
        "msg": "No identity issued",
        "pid": pid,
        "registered": False,
        "service": "WorkloadAPI",
        "subsystem_name": "endpoints",
        "time": ts,
    })


# ============================================================
# SPIRE Server Log Generators (based on real audit output)
# ============================================================

def server_startup():
    """Emit server startup sequence."""
    ts = now_iso()
    logs = [
        {"level": "warning", "msg": "Current umask 0022 is too permissive; setting umask 0027", "time": ts},
        {"admin_ids": None, "data_dir": "/opt/spire/data/server", "launch_log_level": "debug", "level": "info", "msg": "Configured", "time": ts, "version": "1.11.2"},
        {"level": "info", "msg": "Building in-memory entry cache", "subsystem_name": "endpoints", "time": ts},
        {"level": "info", "msg": "Completed building in-memory entry cache", "subsystem_name": "endpoints", "time": ts},
    ]
    for entry in logs:
        write_log(SERVER_LOG, entry)


def server_audit_entry_create(spiffe_id, selectors_str, caller_uid=0):
    """Emit server-side entry creation audit event."""
    ts = now_iso()
    write_log(SERVER_LOG, {
        "authorized_as": "local",
        "authorized_via": "transport",
        "caller_gid": 0,
        "caller_path": "/opt/spire/bin/spire-server",
        "caller_uid": caller_uid,
        "entry_id": gen_entry_id(),
        "level": "info",
        "method": "BatchCreateEntry",
        "msg": "API accessed",
        "parent_id": AGENT_SPIFFE_ID,
        "request_id": gen_request_id(),
        "selectors": selectors_str,
        "service": "entry.v1.Entry",
        "spiffe_id": spiffe_id,
        "status": "success",
        "subsystem_name": "api",
        "time": ts,
        "type": "audit",
    })


def server_audit_attest_agent():
    """Emit server-side agent attestation audit event."""
    ts = now_iso()
    port = random.randint(40000, 60000)
    write_log(SERVER_LOG, {
        "agent_id": AGENT_SPIFFE_ID,
        "authorized_as": "nobody",
        "authorized_via": "",
        "caller_addr": f"{AGENT_IP}:{port}",
        "level": "info",
        "method": "AttestAgent",
        "msg": "API accessed",
        "node_attestor_type": "join_token",
        "request_id": gen_request_id(),
        "service": "agent.v1.Agent",
        "status": "success",
        "subsystem_name": "api",
        "time": ts,
        "type": "audit",
    })


def server_audit_get_entries():
    """Emit routine GetAuthorizedEntries audit event."""
    ts = now_iso()
    port = random.randint(40000, 60000)
    write_log(SERVER_LOG, {
        "authorized_as": "agent",
        "authorized_via": "datastore",
        "caller_addr": f"{AGENT_IP}:{port}",
        "caller_id": AGENT_SPIFFE_ID,
        "level": "info",
        "method": "GetAuthorizedEntries",
        "msg": "API accessed",
        "request_id": gen_request_id(),
        "service": "entry.v1.Entry",
        "status": "success",
        "subsystem_name": "api",
        "time": ts,
        "type": "audit",
    })


def server_audit_create_join_token():
    """Emit join token creation audit event."""
    ts = now_iso()
    write_log(SERVER_LOG, {
        "authorized_as": "local",
        "authorized_via": "transport",
        "caller_gid": 0,
        "caller_path": "/opt/spire/bin/spire-server",
        "caller_uid": 0,
        "level": "info",
        "method": "CreateJoinToken",
        "msg": "API accessed",
        "request_id": gen_request_id(),
        "service": "agent.v1.Agent",
        "spiffe_id": f"spiffe://{TRUST_DOMAIN}/spire-agent",
        "status": "success",
        "subsystem_name": "api",
        "time": ts,
        "ttl": 600,
        "type": "audit",
    })


# ============================================================
# Scenario Generators
# ============================================================

def scenario_normal_operations(pid_counter):
    """Generate normal workload SVID fetch — single identity per PID."""
    workload = random.choice(LEGITIMATE_WORKLOADS)
    pid = workload["pid_base"] + random.randint(1, 50)
    agent_pid_attested(pid, workload["uid"])
    agent_svid_fetched(pid, workload["spiffe_id"], count=1)
    # Server-side routine polling
    server_audit_get_entries()
    return pid_counter + 1


def scenario_selector_spoofing(pid_counter):
    """Simulate selector spoofing — TWO distinct SPIFFE IDs for same PID.
    This is the 'Spooffe' attack by Eviatar Gerzi."""
    legitimate = LEGITIMATE_WORKLOADS[0]  # web-frontend (uid:1000)
    pid = legitimate["pid_base"] + random.randint(51, 99)

    # First: rogue entry creation on server
    server_audit_entry_create(
        ROGUE_WORKLOAD["spiffe_id"],
        f"unix:uid:{ROGUE_WORKLOAD['uid']}",
    )

    # Then: agent caches the new entry
    entry_id = agent_entry_created(ROGUE_WORKLOAD["spiffe_id"])
    agent_svid_created(ROGUE_WORKLOAD["spiffe_id"], entry_id)

    # PID attestation
    agent_pid_attested(pid, legitimate["uid"])

    # SVID fetch returns BOTH identities (count=2)
    agent_svid_fetched(pid, legitimate["spiffe_id"], count=2)
    agent_svid_fetched(pid, ROGUE_WORKLOAD["spiffe_id"], count=2)

    return pid_counter + 1


def scenario_svid_burst(pid_counter):
    """Simulate SVID harvesting — rapid burst of fetch requests from one PID."""
    workload = random.choice(LEGITIMATE_WORKLOADS)
    pid = workload["pid_base"] + random.randint(100, 150)

    agent_pid_attested(pid, workload["uid"])

    # Burst: 12-15 rapid fetches
    burst_count = random.randint(12, 15)
    for _ in range(burst_count):
        agent_svid_fetched(pid, workload["spiffe_id"], count=1)
        time.sleep(0.1)  # Rapid but not instant

    return pid_counter + 1


def scenario_svid_rotation():
    """Normal SVID rotation — 'SVID updated' events."""
    for workload in LEGITIMATE_WORKLOADS:
        entry_id = gen_entry_id()
        ts = now_iso()
        write_log(AGENT_LOG, {
            "cache_type": "workload",
            "count": len(LEGITIMATE_WORKLOADS),
            "level": "debug",
            "limit": 500,
            "msg": "Renewing stale entries",
            "subsystem_name": "manager",
            "time": ts,
        })
        agent_svid_created(workload["spiffe_id"], entry_id)


def scenario_overlapping_entries(pid_counter):
    """Simulate overlapping registration entries — two entries with the same
    unix:uid:1000 selector but different SPIFFE IDs.  The agent then delivers
    multiple SVIDs to a workload that only expects one."""
    shared_uid = 1000
    first_id = f"spiffe://{TRUST_DOMAIN}/web-frontend"
    second_id = f"spiffe://{TRUST_DOMAIN}/payment-processor"

    # Server: two entries created with identical selector
    server_audit_entry_create(first_id, f"unix:uid:{shared_uid}")
    server_audit_entry_create(second_id, f"unix:uid:{shared_uid}")

    # Agent: caches both entries
    entry_id_a = agent_entry_created(first_id)
    agent_svid_created(first_id, entry_id_a)
    entry_id_b = agent_entry_created(second_id)
    agent_svid_created(second_id, entry_id_b)

    # Workload receives multiple SVIDs unexpectedly
    pid = 500 + random.randint(1, 50)
    agent_pid_attested(pid, shared_uid)
    agent_svid_fetched(pid, first_id, count=2)
    agent_svid_fetched(pid, second_id, count=2)

    return pid_counter + 1


def scenario_jwt_replay(pid_counter):
    """Simulate JWT-SVID replay — one PID fetches a JWT-SVID, then a
    completely different PID accesses the same token (stolen or shared)."""
    workload = LEGITIMATE_WORKLOADS[0]
    legitimate_pid = workload["pid_base"] + random.randint(1, 50)
    rogue_pid = 9000 + random.randint(1, 100)
    audience = ["test-service"]

    # Legitimate fetch
    ts = now_iso()
    write_log(AGENT_LOG, {
        "level": "info",
        "msg": "Fetched JWT SVID",
        "spiffe_id": workload["spiffe_id"],
        "audience": audience,
        "pid": legitimate_pid,
        "method": "FetchJWTSVID",
        "service": "WorkloadAPI",
        "subsystem_name": "endpoints",
        "time": ts,
    })

    time.sleep(0.5)

    # Replay: different PID uses the same JWT
    ts = now_iso()
    write_log(AGENT_LOG, {
        "level": "info",
        "msg": "Fetched JWT SVID",
        "spiffe_id": workload["spiffe_id"],
        "audience": audience,
        "pid": rogue_pid,
        "method": "FetchJWTSVID",
        "service": "WorkloadAPI",
        "subsystem_name": "endpoints",
        "time": ts,
    })

    # Warning: PID mismatch for same SPIFFE ID and audience
    ts = now_iso()
    write_log(AGENT_LOG, {
        "level": "warning",
        "msg": "JWT SVID requested by unexpected PID",
        "spiffe_id": workload["spiffe_id"],
        "audience": audience,
        "original_pid": legitimate_pid,
        "requesting_pid": rogue_pid,
        "subsystem_name": "endpoints",
        "time": ts,
    })

    return pid_counter + 1


def scenario_delegated_identity(pid_counter):
    """Simulate Delegated Identity API abuse — a process connects to the
    admin socket and calls SubscribeToX509SVIDs to impersonate workloads."""
    caller_pid = 7000 + random.randint(1, 100)
    admin_socket = "/opt/spire/sockets/admin.sock"

    ts = now_iso()
    write_log(AGENT_LOG, {
        "level": "warning",
        "msg": "Delegated Identity API accessed",
        "method": "SubscribeToX509SVIDs",
        "caller_pid": caller_pid,
        "caller_addr": admin_socket,
        "subsystem_name": "delegated_identity",
        "time": ts,
    })

    # The caller receives SVIDs for all registered workloads
    for workload in LEGITIMATE_WORKLOADS:
        ts = now_iso()
        write_log(AGENT_LOG, {
            "level": "info",
            "msg": "Delegated SVID delivered",
            "method": "SubscribeToX509SVIDs",
            "spiffe_id": workload["spiffe_id"],
            "caller_pid": caller_pid,
            "caller_addr": admin_socket,
            "subsystem_name": "delegated_identity",
            "time": ts,
        })

    return pid_counter + 1


def scenario_container_escape(pid_counter):
    """Simulate container escape to SPIRE agent socket — nsenter execution
    followed by SPIRE socket access from an unexpected PID on the host."""
    escape_pid = 4000 + random.randint(1, 50)
    target_pid = 1  # PID 1 on host (init/systemd)
    host_pid = 4100 + random.randint(1, 50)

    # Audit log: nsenter execution (container escape attempt)
    ts = now_iso()
    write_log(AGENT_LOG, {
        "level": "warning",
        "msg": "Suspicious process execution detected",
        "exe": "/usr/bin/nsenter",
        "args": f"--target {target_pid} --mount --uts --ipc --net --pid",
        "pid": escape_pid,
        "uid": 0,
        "subsystem_name": "audit",
        "time": ts,
    })

    time.sleep(0.3)

    # SPIRE agent log: socket access from unexpected PID after escape
    ts = now_iso()
    write_log(AGENT_LOG, {
        "level": "warning",
        "msg": "Workload API accessed from unexpected PID",
        "pid": host_pid,
        "registered": False,
        "method": "FetchX509SVID",
        "service": "WorkloadAPI",
        "socket": "/opt/spire/sockets/workload_api.sock",
        "subsystem_name": "endpoints",
        "time": ts,
    })

    # The escaped process attempts attestation
    agent_pid_attested(host_pid, 0, extra_selectors=[
        {"type": "unix", "value": "path:/usr/bin/nsenter"},
    ])
    agent_no_identity(host_pid)

    return pid_counter + 1


def scenario_trust_bundle_poison():
    """Simulate trust bundle poisoning — an attacker uses the admin API to
    inject or replace the trust bundle for the trust domain."""
    ts = now_iso()

    # Initial bundle set (looks like normal bootstrap)
    write_log(SERVER_LOG, {
        "level": "info",
        "msg": "Bundle set",
        "trust_domain": f"spiffe://{TRUST_DOMAIN}",
        "source": "admin_api",
        "caller": "admin",
        "method": "BatchSetFederatedBundle",
        "service": "bundle.v1.Bundle",
        "request_id": gen_request_id(),
        "subsystem_name": "api",
        "time": ts,
        "type": "audit",
    })

    time.sleep(0.5)

    # Suspicious: bundle update from unexpected foreign trust domain
    ts = now_iso()
    write_log(SERVER_LOG, {
        "level": "info",
        "msg": "Bundle set",
        "trust_domain": "spiffe://attacker-domain.evil",
        "source": "admin_api",
        "caller": "admin",
        "method": "BatchSetFederatedBundle",
        "service": "bundle.v1.Bundle",
        "request_id": gen_request_id(),
        "subsystem_name": "api",
        "time": ts,
        "type": "audit",
    })

    # Second update: overwriting the legitimate bundle
    ts = now_iso()
    write_log(SERVER_LOG, {
        "level": "warning",
        "msg": "Bundle updated",
        "trust_domain": f"spiffe://{TRUST_DOMAIN}",
        "source": "admin_api",
        "caller": "admin",
        "method": "BatchUpdateEntry",
        "service": "bundle.v1.Bundle",
        "request_id": gen_request_id(),
        "num_authorities": 2,
        "subsystem_name": "api",
        "time": ts,
        "type": "audit",
    })


def scenario_agent_reattestation(pid_counter):
    """Simulate unexpected agent re-attestation — a new agent attests from
    an IP address not in the expected range, potentially a rogue agent."""
    rogue_token = str(uuid.uuid4())
    rogue_agent_id = f"spiffe://{TRUST_DOMAIN}/spire/agent/join_token/{rogue_token}"
    rogue_ip = f"172.43.0.{random.randint(90, 110)}"
    rogue_port = random.randint(40000, 60000)

    ts = now_iso()
    write_log(SERVER_LOG, {
        "level": "info",
        "msg": "Agent attestation request",
        "method": "join_token",
        "agent_id": rogue_agent_id,
        "remote_addr": f"{rogue_ip}:{rogue_port}",
        "service": "agent.v1.Agent",
        "request_id": gen_request_id(),
        "subsystem_name": "api",
        "time": ts,
        "type": "audit",
    })

    # Server processes the attestation
    ts = now_iso()
    write_log(SERVER_LOG, {
        "agent_id": rogue_agent_id,
        "authorized_as": "nobody",
        "authorized_via": "",
        "caller_addr": f"{rogue_ip}:{rogue_port}",
        "level": "info",
        "method": "AttestAgent",
        "msg": "API accessed",
        "node_attestor_type": "join_token",
        "request_id": gen_request_id(),
        "service": "agent.v1.Agent",
        "status": "success",
        "subsystem_name": "api",
        "time": ts,
        "type": "audit",
    })

    # Warning: new agent from unexpected network
    ts = now_iso()
    write_log(SERVER_LOG, {
        "level": "warning",
        "msg": "Agent attested from unexpected address",
        "agent_id": rogue_agent_id,
        "remote_addr": rogue_ip,
        "expected_subnet": "172.43.0.0/24",
        "subsystem_name": "api",
        "time": ts,
    })

    return pid_counter + 1


def scenario_kubelet_bypass(pid_counter):
    """Simulate kubelet verification bypass — the k8s workload attestor is
    configured to skip kubelet verification, weakening pod identity checks."""
    ts = now_iso()
    write_log(AGENT_LOG, {
        "level": "warning",
        "msg": "Kubelet verification skipped",
        "attestor": "k8s",
        "reason": "skip_kubelet_verification=true",
        "subsystem_name": "workload_attestor",
        "time": ts,
    })

    # An unverified pod gets attested without kubelet confirmation
    rogue_pid = 8000 + random.randint(1, 100)
    ts = now_iso()
    write_log(AGENT_LOG, {
        "level": "info",
        "msg": "Workload attested without kubelet verification",
        "attestor": "k8s",
        "pid": rogue_pid,
        "namespace": "default",
        "service_account": "compromised-sa",
        "pod": f"rogue-pod-{uuid.uuid4().hex[:8]}",
        "subsystem_name": "workload_attestor",
        "time": ts,
    })

    # The unverified workload fetches an SVID
    agent_pid_attested(rogue_pid, 0, extra_selectors=[
        {"type": "k8s", "value": "ns:default"},
        {"type": "k8s", "value": "sa:compromised-sa"},
    ])
    agent_svid_fetched(rogue_pid, f"spiffe://{TRUST_DOMAIN}/ns/default/sa/compromised-sa", count=1)

    return pid_counter + 1


# ============================================================
# Main Loop
# ============================================================

def main():
    # Ensure log directories exist
    for log_path in [AGENT_LOG, SERVER_LOG]:
        Path(log_path).parent.mkdir(parents=True, exist_ok=True)

    print(f"[*] SPIRE Log Generator starting", file=sys.stderr)
    print(f"    Agent log:  {AGENT_LOG}", file=sys.stderr)
    print(f"    Server log: {SERVER_LOG}", file=sys.stderr)
    print(f"    Spoofing:          {ENABLE_SPOOFING}", file=sys.stderr)
    print(f"    Burst:             {ENABLE_BURST}", file=sys.stderr)
    print(f"    Rogue:             {ENABLE_ROGUE_ENTRY}", file=sys.stderr)
    print(f"    Overlapping:       {ENABLE_OVERLAPPING}", file=sys.stderr)
    print(f"    JWT Replay:        {ENABLE_JWT_REPLAY}", file=sys.stderr)
    print(f"    Delegated ID:      {ENABLE_DELEGATED_IDENTITY}", file=sys.stderr)
    print(f"    Container Escape:  {ENABLE_CONTAINER_ESCAPE}", file=sys.stderr)
    print(f"    Trust Bundle:      {ENABLE_TRUST_BUNDLE_POISON}", file=sys.stderr)
    print(f"    Reattestation:     {ENABLE_REATTESTATION}", file=sys.stderr)
    print(f"    Kubelet Bypass:    {ENABLE_KUBELET_BYPASS}", file=sys.stderr)

    # Startup sequence
    server_startup()
    server_audit_create_join_token()
    server_audit_attest_agent()
    agent_startup()

    # Register legitimate workloads
    for workload in LEGITIMATE_WORKLOADS:
        server_audit_entry_create(workload["spiffe_id"], f"unix:uid:{workload['uid']}")
        entry_id = agent_entry_created(workload["spiffe_id"])
        agent_svid_created(workload["spiffe_id"], entry_id)

    pid_counter = 0
    cycle = 0

    while True:
        cycle += 1

        # Normal operations every cycle
        pid_counter = scenario_normal_operations(pid_counter)

        # SVID rotation periodically
        if cycle % (ROTATION_INTERVAL // NORMAL_FETCH_INTERVAL) == 0:
            scenario_svid_rotation()

        # Attack scenarios (staggered)
        if ENABLE_SPOOFING and cycle % (ATTACK_INTERVAL // NORMAL_FETCH_INTERVAL) == 0:
            print(f"[!] Injecting selector spoofing scenario", file=sys.stderr)
            pid_counter = scenario_selector_spoofing(pid_counter)

        if ENABLE_BURST and cycle % ((ATTACK_INTERVAL + 60) // NORMAL_FETCH_INTERVAL) == 0:
            print(f"[!] Injecting SVID burst scenario", file=sys.stderr)
            pid_counter = scenario_svid_burst(pid_counter)

        if ENABLE_ROGUE_ENTRY and cycle % ((ATTACK_INTERVAL + 30) // NORMAL_FETCH_INTERVAL) == 0:
            print(f"[!] Injecting rogue entry creation", file=sys.stderr)
            server_audit_entry_create(
                ROGUE_WORKLOAD["spiffe_id"],
                f"unix:uid:{ROGUE_WORKLOAD['uid']}",
            )

        if ENABLE_OVERLAPPING and cycle % ((ATTACK_INTERVAL + 90) // NORMAL_FETCH_INTERVAL) == 0:
            print(f"[!] Injecting overlapping entries scenario", file=sys.stderr)
            pid_counter = scenario_overlapping_entries(pid_counter)

        if ENABLE_JWT_REPLAY and cycle % ((ATTACK_INTERVAL + 45) // NORMAL_FETCH_INTERVAL) == 0:
            print(f"[!] Injecting JWT-SVID replay scenario", file=sys.stderr)
            pid_counter = scenario_jwt_replay(pid_counter)

        if ENABLE_DELEGATED_IDENTITY and cycle % ((ATTACK_INTERVAL + 75) // NORMAL_FETCH_INTERVAL) == 0:
            print(f"[!] Injecting delegated identity API abuse scenario", file=sys.stderr)
            pid_counter = scenario_delegated_identity(pid_counter)

        if ENABLE_CONTAINER_ESCAPE and cycle % ((ATTACK_INTERVAL + 105) // NORMAL_FETCH_INTERVAL) == 0:
            print(f"[!] Injecting container escape scenario", file=sys.stderr)
            pid_counter = scenario_container_escape(pid_counter)

        if ENABLE_TRUST_BUNDLE_POISON and cycle % ((ATTACK_INTERVAL + 120) // NORMAL_FETCH_INTERVAL) == 0:
            print(f"[!] Injecting trust bundle poisoning scenario", file=sys.stderr)
            scenario_trust_bundle_poison()

        if ENABLE_REATTESTATION and cycle % ((ATTACK_INTERVAL + 135) // NORMAL_FETCH_INTERVAL) == 0:
            print(f"[!] Injecting agent re-attestation scenario", file=sys.stderr)
            pid_counter = scenario_agent_reattestation(pid_counter)

        if ENABLE_KUBELET_BYPASS and cycle % ((ATTACK_INTERVAL + 150) // NORMAL_FETCH_INTERVAL) == 0:
            print(f"[!] Injecting kubelet bypass scenario", file=sys.stderr)
            pid_counter = scenario_kubelet_bypass(pid_counter)

        time.sleep(NORMAL_FETCH_INTERVAL)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[*] SPIRE Log Generator stopped", file=sys.stderr)
