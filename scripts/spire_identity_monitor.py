#!/usr/bin/env python3
"""SPIRE Identity Monitor — PID-based SVID anomaly detection.

Implements detection logic that Wazuh rules cannot express natively:
  - count(distinct spiffe_id) by pid > 1  → selector spoofing (CRITICAL)
  - count(requests) by pid > N in window  → SVID harvesting (HIGH)

Runs every 60 seconds via Wazuh <localfile> full_command monitoring.
Output format: NHI_SPIRE_DETECT: key=value pairs (decoded by Wazuh).

State is persisted to /tmp/spire_monitor_state.json so each run only
processes new log lines since the last invocation.

Author: Bodhisattva Das
Machine Identity Detection Testbed
"""

import json
import sys
import time
from collections import defaultdict
from pathlib import Path

# Configuration
AGENT_LOG = "/var/log/spire/agent.log"
STATE_FILE = "/tmp/spire_monitor_state.json"
WINDOW_SECONDS = 300      # 5-minute sliding window
BURST_THRESHOLD = 10      # requests per PID per window
MULTI_ID_THRESHOLD = 2    # distinct SPIFFE IDs per PID


def load_state():
    """Load last processed position from state file."""
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_state(state):
    """Persist state to disk for next invocation."""
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(state, f)
    except OSError:
        pass  # Non-fatal: worst case we re-process some lines


def parse_timestamp(ts_str):
    """Parse ISO 8601 timestamp from SPIRE JSON logs.

    SPIRE uses Go's time.RFC3339Nano format, but real logs may or may not
    include fractional seconds:
      2026-02-28T14:30:00Z              (no fractional seconds)
      2026-02-28T14:30:00.123456789Z    (nanosecond precision)
    """
    if not ts_str:
        return None
    try:
        from datetime import datetime, timezone
        # Strip trailing Z
        clean = ts_str.rstrip("Z")
        # Handle fractional seconds if present
        if "." in clean:
            parts = clean.split(".")
            # Truncate to 6 decimal places (microseconds)
            frac = parts[1][:6].ljust(6, "0")
            clean = f"{parts[0]}.{frac}"
            dt = datetime.strptime(clean, "%Y-%m-%dT%H:%M:%S.%f")
        else:
            dt = datetime.strptime(clean, "%Y-%m-%dT%H:%M:%S")
        return dt.replace(tzinfo=timezone.utc).timestamp()
    except (ValueError, IndexError):
        return None


def main():
    log_path = Path(AGENT_LOG)
    if not log_path.exists():
        # No SPIRE agent log — nothing to monitor
        return

    # Load state (last processed position)
    state = load_state()
    last_pos = state.get("last_pos", 0)

    # Check if log was rotated (file smaller than last position)
    try:
        file_size = log_path.stat().st_size
        if file_size < last_pos:
            last_pos = 0  # Log rotated, start from beginning
    except OSError:
        return

    now = time.time()
    cutoff = now - WINDOW_SECONDS

    # Per-PID tracking: {pid: {"spiffe_ids": set(), "count": int, "first_seen": float}}
    pid_data = defaultdict(lambda: {"spiffe_ids": set(), "count": 0, "first_seen": now})

    try:
        with open(log_path) as f:
            f.seek(last_pos)
            for line in f:
                line = line.strip()
                if not line:
                    continue

                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                # Filter to SVID fetch/issuance events only
                msg = entry.get("msg", "")
                if not any(k in msg for k in [
                    "Fetched X.509 SVID",
                    "Fetched JWT SVID",
                    "SVID updated",
                    "No identity issued",
                ]):
                    continue

                # Parse timestamp and apply sliding window
                ts = parse_timestamp(entry.get("time", ""))
                if ts and ts < cutoff:
                    continue

                # Extract PID (injected by addWatcherPID middleware)
                pid = entry.get("pid")
                if pid is None:
                    continue

                pid_str = str(pid)
                pid_data[pid_str]["count"] += 1
                if ts and ts < pid_data[pid_str]["first_seen"]:
                    pid_data[pid_str]["first_seen"] = ts

                # Extract SPIFFE ID (present in X.509 SVID fetch, absent in JWT)
                spiffe_id = entry.get("spiffe_id", "")
                if spiffe_id:
                    pid_data[pid_str]["spiffe_ids"].add(spiffe_id)

            new_pos = f.tell()
    except OSError:
        return

    # Evaluate detections and output results
    for pid, data in pid_data.items():
        distinct = len(data["spiffe_ids"])
        count = data["count"]

        # Detection 1: Multi-identity — CONFIRMED selector spoofing
        # A legitimate workload should have exactly ONE SPIFFE identity.
        # Multiple distinct IDs for the same PID = overlapping registration entries.
        if distinct >= MULTI_ID_THRESHOLD:
            ids_str = ",".join(sorted(data["spiffe_ids"]))
            print(
                f'NHI_SPIRE_DETECT: type=multi_identity pid={pid} '
                f'distinct_count={distinct} request_count={count} '
                f'spiffe_ids="{ids_str}" window={WINDOW_SECONDS}s '
                f'severity=critical'
            )

        # Detection 2: SVID burst — credential harvesting
        # Normal workloads fetch once at startup + rotation (hours).
        # 10+ requests in 5 minutes = harvesting or API fuzzing.
        elif count >= BURST_THRESHOLD:
            ids_str = (
                ",".join(sorted(data["spiffe_ids"]))
                if data["spiffe_ids"]
                else "unknown"
            )
            print(
                f'NHI_SPIRE_DETECT: type=svid_burst pid={pid} '
                f'distinct_count={distinct} request_count={count} '
                f'spiffe_ids="{ids_str}" window={WINDOW_SECONDS}s '
                f'severity=high'
            )

    # Save state for next run
    save_state({"last_pos": new_pos, "last_run": now})


if __name__ == "__main__":
    main()
