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
    print(f"    Spoofing:   {ENABLE_SPOOFING}", file=sys.stderr)
    print(f"    Burst:      {ENABLE_BURST}", file=sys.stderr)
    print(f"    Rogue:      {ENABLE_ROGUE_ENTRY}", file=sys.stderr)

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

        time.sleep(NORMAL_FETCH_INTERVAL)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[*] SPIRE Log Generator stopped", file=sys.stderr)
