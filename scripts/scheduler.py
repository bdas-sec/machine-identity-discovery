#!/usr/bin/env python3
"""
NHI Scenario Scheduler — Automated scenario execution with cron-like scheduling.

Runs attack scenarios on a configurable schedule, validates detection alerts,
and reports results to the metrics exporter and/or stdout.

Usage:
    python scripts/scheduler.py                          # Run all scenarios once
    python scripts/scheduler.py --cron "*/30 * * * *"    # Every 30 minutes
    python scripts/scheduler.py --interval 300           # Every 5 minutes
    python scripts/scheduler.py --level 1 --level 2      # Only levels 1 and 2
    python scripts/scheduler.py --scenario s2-01         # Single scenario
    python scripts/scheduler.py --validate               # Verify Wazuh alerts
    python scripts/scheduler.py --report json            # JSON output
    python scripts/scheduler.py --daemon                 # Run as background daemon
"""

import argparse
import datetime
import json
import logging
import os
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CONTAINER_RUNTIME = os.environ.get("CONTAINER_RUNTIME", "docker")
WAZUH_API_URL = os.environ.get("WAZUH_API_URL", "https://localhost:55000")
WAZUH_API_USER = os.environ.get("WAZUH_API_USER", "wazuh-wui")
WAZUH_API_PASSWORD = os.environ.get("WAZUH_API_PASSWORD", "MyS3cr3tP@ssw0rd")
METRICS_URL = os.environ.get("NHI_METRICS_URL", "http://localhost:9091")
VALIDATION_POLL_INTERVAL = int(os.environ.get("VALIDATION_POLL_INTERVAL", "3"))
VALIDATION_MAX_WAIT = int(os.environ.get("VALIDATION_MAX_WAIT", "30"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("nhi-scheduler")


# ---------------------------------------------------------------------------
# Scenario Definitions
# ---------------------------------------------------------------------------

@dataclass
class ScenarioDef:
    """Lightweight scenario definition for the scheduler."""
    id: str
    name: str
    level: int
    target: str
    commands: list[str]
    detection_rules: list[str] = field(default_factory=list)


# Mirrors the scenarios from api/routes/scenarios.py and run_demo.py
SCENARIOS: dict[str, ScenarioDef] = {
    "s1-01": ScenarioDef("s1-01", "Environment File Enumeration", 1, "cloud-workload",
                         ["find /app -name '*.env*' 2>/dev/null || true",
                          "cat /app/.env 2>/dev/null || echo 'No .env found'"],
                         ["100600"]),
    "s1-02": ScenarioDef("s1-02", "AWS Credentials Discovery", 1, "cloud-workload",
                         ["ls -la ~/.aws/ 2>/dev/null || echo 'No AWS config'",
                          "cat ~/.aws/credentials 2>/dev/null || echo 'No credentials file'"],
                         ["100601"]),
    "s1-03": ScenarioDef("s1-03", "SSH Key Discovery", 1, "cloud-workload",
                         ["find /root/.ssh -type f 2>/dev/null || echo 'No SSH dir'"],
                         ["100602"]),
    "s1-04": ScenarioDef("s1-04", "Git Credentials Discovery", 1, "cicd-runner",
                         ["cat ~/.git-credentials 2>/dev/null || echo 'No git credentials'"],
                         ["100603"]),
    "s1-05": ScenarioDef("s1-05", "Kubernetes Config Discovery", 1, "cloud-workload",
                         ["cat ~/.kube/config 2>/dev/null || echo 'No kubeconfig'"],
                         ["100605"]),
    "s2-01": ScenarioDef("s2-01", "IMDS Credential Theft (AWS)", 2, "cloud-workload",
                         ["curl -s http://mock-imds:1338/latest/meta-data/",
                          "curl -s http://mock-imds:1338/latest/meta-data/iam/security-credentials/",
                          "ROLE=$(curl -s http://mock-imds:1338/latest/meta-data/iam/security-credentials/); "
                          "curl -s http://mock-imds:1338/latest/meta-data/iam/security-credentials/$ROLE"],
                         ["100650", "100651", "100658"]),
    "s2-02": ScenarioDef("s2-02", "Process Environment Harvesting", 2, "cloud-workload",
                         ["env | grep -iE 'key|token|secret|password' || true"],
                         ["100607"]),
    "s2-03": ScenarioDef("s2-03", "K8s ServiceAccount Token Theft", 2, "cloud-workload",
                         ["cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null || echo 'No SA token'"],
                         ["100750", "100751"]),
    "s2-04": ScenarioDef("s2-04", "CI/CD Token Extraction", 2, "cicd-runner",
                         ["env | grep -i github || true", "env | grep -i token || true"],
                         ["100800", "100802"]),
    "s2-05": ScenarioDef("s2-05", "Vault Token Theft", 2, "cloud-workload",
                         ["cat ~/.vault-token 2>/dev/null || echo 'No vault token'",
                          "env | grep VAULT || true"],
                         ["100606"]),
    "s3-01": ScenarioDef("s3-01", "IMDS Role Assumption", 3, "cloud-workload",
                         ["CREDS=$(curl -s http://mock-imds:1338/latest/meta-data/iam/security-credentials/demo-ec2-role); "
                          "echo $CREDS | head -c 200"],
                         ["100651", "100657"]),
    "s3-02": ScenarioDef("s3-02", "Kubernetes RBAC Probing", 3, "cloud-workload",
                         ["kubectl auth can-i --list 2>/dev/null || echo 'kubectl not available'"],
                         ["100752", "100755"]),
    "s3-03": ScenarioDef("s3-03", "Kubernetes Secrets Enumeration", 3, "cloud-workload",
                         ["kubectl get secrets -A 2>/dev/null || echo 'Cannot list secrets'"],
                         ["100753"]),
    "s3-04": ScenarioDef("s3-04", "Vault Privilege Escalation", 3, "cloud-workload",
                         ["TOKEN=$(cat ~/.vault-token 2>/dev/null); "
                          "curl -s -H \"X-Vault-Token: $TOKEN\" http://vault:8200/v1/secret/data/production 2>/dev/null || echo 'Vault access failed'"],
                         ["100606"]),
    "s3-05": ScenarioDef("s3-05", "Multiple Credential Harvest", 3, "cloud-workload",
                         ["cat ~/.aws/credentials 2>/dev/null || true; "
                          "cat ~/.ssh/id_rsa 2>/dev/null | head -5 || true; "
                          "cat ~/.git-credentials 2>/dev/null || true; "
                          "cat ~/.vault-token 2>/dev/null || true; "
                          "cat /app/.env 2>/dev/null || true"],
                         ["100609"]),
    "s4-01": ScenarioDef("s4-01", "Cross-Network Movement", 4, "cicd-runner",
                         ["curl -s http://cloud-workload:8080/ 2>/dev/null || echo 'Cannot reach cloud workload'"],
                         []),
    "s4-02": ScenarioDef("s4-02", "Stolen SSH Key Usage", 4, "cloud-workload",
                         ["cat ~/.ssh/id_rsa 2>/dev/null | head -3 || echo 'No SSH key'"],
                         ["100602"]),
    "s4-03": ScenarioDef("s4-03", "Git Credential Abuse", 4, "cicd-runner",
                         ["cat ~/.git-credentials 2>/dev/null || echo 'No credentials'"],
                         ["100603"]),
    "s4-04": ScenarioDef("s4-04", "Docker Registry Authentication", 4, "cicd-runner",
                         ["cat ~/.docker/config.json 2>/dev/null || echo 'No docker config'"],
                         ["100604"]),
    "s4-05": ScenarioDef("s4-05", "API Key Abuse", 4, "vulnerable-app",
                         ["env | grep -iE 'api|key|token' || true"],
                         []),
    "s5-01": ScenarioDef("s5-01", "Pipeline Poisoning", 5, "cicd-runner",
                         ["find /runner -name '*.yml' 2>/dev/null | head -5 || true"],
                         ["100803"]),
    "s5-02": ScenarioDef("s5-02", "Credential Rotation Backdoor", 5, "cloud-workload",
                         ["cat ~/.aws/credentials 2>/dev/null || echo 'No AWS creds'"],
                         ["100601"]),
    "s5-03": ScenarioDef("s5-03", "Service Account Token Persistence", 5, "cloud-workload",
                         ["cp /var/run/secrets/kubernetes.io/serviceaccount/token /tmp/sa_token 2>/dev/null || echo 'No SA token'"],
                         ["100750"]),
    "s5-04": ScenarioDef("s5-04", "Environment Variable Injection", 5, "vulnerable-app",
                         ["env | wc -l"],
                         []),
}


# ---------------------------------------------------------------------------
# Execution Engine
# ---------------------------------------------------------------------------

@dataclass
class ScenarioRunResult:
    """Result of executing a single scenario."""
    scenario_id: str
    scenario_name: str
    level: int
    status: str  # "success", "partial", "error"
    commands_executed: int
    commands_succeeded: int
    detection_rules_expected: list[str]
    detection_rules_fired: list[str] = field(default_factory=list)
    detection_rules_missed: list[str] = field(default_factory=list)
    validated: bool = False
    duration_seconds: float = 0.0
    timestamp: str = ""
    error: str = ""


def detect_runtime() -> str:
    """Detect container runtime (podman or docker)."""
    for rt in ["podman", "docker"]:
        try:
            result = subprocess.run(
                [rt, "ps"], capture_output=True, timeout=5,
            )
            if result.returncode == 0:
                return rt
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return CONTAINER_RUNTIME


def execute_scenario(scenario: ScenarioDef, runtime: str) -> ScenarioRunResult:
    """Execute a scenario's commands against the target container."""
    start = time.monotonic()
    result = ScenarioRunResult(
        scenario_id=scenario.id,
        scenario_name=scenario.name,
        level=scenario.level,
        status="error",
        commands_executed=len(scenario.commands),
        commands_succeeded=0,
        detection_rules_expected=scenario.detection_rules,
        timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    )

    for cmd in scenario.commands:
        try:
            proc = subprocess.run(
                [runtime, "exec", scenario.target, "bash", "-c", cmd],
                capture_output=True, text=True, timeout=30,
            )
            if proc.returncode == 0:
                result.commands_succeeded += 1
        except subprocess.TimeoutExpired:
            log.warning("  Command timed out: %s", cmd[:60])
        except Exception as e:
            result.error = str(e)
            log.error("  Command failed: %s", e)

    if result.commands_succeeded == result.commands_executed:
        result.status = "success"
    elif result.commands_succeeded > 0:
        result.status = "partial"

    result.duration_seconds = round(time.monotonic() - start, 2)
    return result


# ---------------------------------------------------------------------------
# Alert Validation
# ---------------------------------------------------------------------------

def _get_wazuh_token() -> str | None:
    """Authenticate to Wazuh API and get JWT token."""
    import base64
    import ssl

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        credentials = base64.b64encode(
            f"{WAZUH_API_USER}:{WAZUH_API_PASSWORD}".encode()
        ).decode("ascii")

        url = f"{WAZUH_API_URL}/security/user/authenticate?raw=true"
        req = urllib.request.Request(url, method="POST")
        req.add_header("Authorization", f"Basic {credentials}")

        with urllib.request.urlopen(req, context=ctx, timeout=10) as response:
            return response.read().decode().strip()
    except Exception as e:
        log.error("Wazuh auth failed: %s", e)
        return None


def validate_alerts(result: ScenarioRunResult) -> ScenarioRunResult:
    """Poll Wazuh API for expected alerts after scenario execution."""
    if not result.detection_rules_expected:
        result.validated = True
        return result

    token = _get_wazuh_token()
    if not token:
        log.warning("  Cannot validate — Wazuh auth failed")
        return result

    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    expected = set(result.detection_rules_expected)
    detected = set()
    deadline = time.monotonic() + VALIDATION_MAX_WAIT

    while time.monotonic() < deadline:
        try:
            # Query recent alerts
            url = f"{WAZUH_API_URL}/alerts?limit=100&sort=-timestamp"
            req = urllib.request.Request(url)
            req.add_header("Authorization", f"Bearer {token}")

            with urllib.request.urlopen(req, context=ctx, timeout=10) as response:
                data = json.loads(response.read())

            alerts = data.get("data", {}).get("affected_items", [])
            for alert in alerts:
                rule_id = str(alert.get("rule", {}).get("id", ""))
                if rule_id in expected:
                    detected.add(rule_id)

            if detected >= expected:
                break

        except Exception as e:
            log.debug("  Alert poll error: %s", e)

        time.sleep(VALIDATION_POLL_INTERVAL)

    result.detection_rules_fired = sorted(detected)
    result.detection_rules_missed = sorted(expected - detected)
    result.validated = True
    return result


# ---------------------------------------------------------------------------
# Metrics Reporting
# ---------------------------------------------------------------------------

def report_to_metrics(result: ScenarioRunResult) -> None:
    """POST scenario result to the NHI metrics exporter."""
    try:
        payload = json.dumps({
            "scenario_id": result.scenario_id,
            "status": result.status,
            "rules_expected": len(result.detection_rules_expected),
            "rules_fired": len(result.detection_rules_fired),
            "duration": result.duration_seconds,
        }).encode()

        req = urllib.request.Request(
            f"{METRICS_URL}/record/scenario",
            data=payload,
            method="POST",
        )
        req.add_header("Content-Type", "application/json")

        with urllib.request.urlopen(req, timeout=5):
            pass
    except Exception:
        pass  # Metrics reporting is best-effort


# ---------------------------------------------------------------------------
# Cron Parser (minimal)
# ---------------------------------------------------------------------------

def _match_cron_field(field_str: str, current: int, max_val: int) -> bool:
    """Check if a single cron field matches the current value."""
    if field_str == "*":
        return True

    # Handle */N (step)
    if field_str.startswith("*/"):
        step = int(field_str[2:])
        return current % step == 0

    # Handle comma-separated values
    values = [int(v) for v in field_str.split(",")]
    return current in values


def cron_matches_now(cron_expr: str) -> bool:
    """Check if a cron expression matches the current time (minute-level precision).

    Supports: *, */N, comma-separated values.
    Format: minute hour day_of_month month day_of_week
    """
    parts = cron_expr.strip().split()
    if len(parts) != 5:
        return False

    now = datetime.datetime.now()
    checks = [
        (parts[0], now.minute, 59),
        (parts[1], now.hour, 23),
        (parts[2], now.day, 31),
        (parts[3], now.month, 12),
        (parts[4], now.weekday(), 6),  # 0=Monday in Python
    ]

    return all(_match_cron_field(f, c, m) for f, c, m in checks)


# ---------------------------------------------------------------------------
# Run Session
# ---------------------------------------------------------------------------

@dataclass
class SchedulerSession:
    """Results from a complete scheduler run."""
    start_time: str
    end_time: str = ""
    scenarios_run: int = 0
    scenarios_passed: int = 0
    scenarios_failed: int = 0
    detection_rate: float = 0.0
    results: list[ScenarioRunResult] = field(default_factory=list)

    def finalize(self):
        self.end_time = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.scenarios_run = len(self.results)
        self.scenarios_passed = sum(1 for r in self.results if r.status == "success")
        self.scenarios_failed = self.scenarios_run - self.scenarios_passed

        total_expected = sum(len(r.detection_rules_expected) for r in self.results if r.validated)
        total_fired = sum(len(r.detection_rules_fired) for r in self.results if r.validated)
        self.detection_rate = round(total_fired / total_expected, 3) if total_expected > 0 else 0.0


def run_scenarios(
    scenario_ids: list[str],
    runtime: str,
    validate: bool = False,
    report_metrics: bool = True,
) -> SchedulerSession:
    """Execute a batch of scenarios and return results."""
    session = SchedulerSession(
        start_time=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    )

    for sid in scenario_ids:
        scenario = SCENARIOS.get(sid)
        if not scenario:
            log.warning("Unknown scenario: %s", sid)
            continue

        log.info("[%s] %s (Level %d, target: %s)",
                 scenario.id, scenario.name, scenario.level, scenario.target)

        result = execute_scenario(scenario, runtime)

        if validate:
            log.info("  Validating alerts (waiting up to %ds)...", VALIDATION_MAX_WAIT)
            result = validate_alerts(result)
            fired = len(result.detection_rules_fired)
            expected = len(result.detection_rules_expected)
            if expected > 0:
                log.info("  Detection: %d/%d rules fired %s",
                         fired, expected,
                         "OK" if fired == expected else "MISS")

        if report_metrics:
            report_to_metrics(result)

        log.info("  Status: %s (%.1fs)", result.status, result.duration_seconds)
        session.results.append(result)

    session.finalize()
    return session


def format_session_report(session: SchedulerSession, fmt: str) -> str:
    """Format a session report as text or JSON."""
    if fmt == "json":
        return json.dumps({
            "start_time": session.start_time,
            "end_time": session.end_time,
            "scenarios_run": session.scenarios_run,
            "scenarios_passed": session.scenarios_passed,
            "scenarios_failed": session.scenarios_failed,
            "detection_rate": session.detection_rate,
            "results": [asdict(r) for r in session.results],
        }, indent=2)

    lines = [
        "",
        "=" * 60,
        "NHI SCENARIO SCHEDULER REPORT",
        "=" * 60,
        f"  Started:    {session.start_time}",
        f"  Finished:   {session.end_time}",
        f"  Scenarios:  {session.scenarios_run} run, "
        f"{session.scenarios_passed} passed, {session.scenarios_failed} failed",
    ]

    if any(r.validated for r in session.results):
        lines.append(f"  Detection:  {session.detection_rate:.0%}")

    lines.append("")
    lines.append(f"  {'ID':<8} {'Name':<35} {'Status':<10} {'Detection':<15} {'Time':<8}")
    lines.append(f"  {'-'*8} {'-'*35} {'-'*10} {'-'*15} {'-'*8}")

    for r in session.results:
        if r.validated and r.detection_rules_expected:
            det = f"{len(r.detection_rules_fired)}/{len(r.detection_rules_expected)}"
        else:
            det = "n/a"
        lines.append(f"  {r.scenario_id:<8} {r.scenario_name:<35} {r.status:<10} {det:<15} {r.duration_seconds:.1f}s")

    lines.append("=" * 60)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Daemon Mode
# ---------------------------------------------------------------------------

_shutdown = threading.Event()


def _signal_handler(signum, frame):
    log.info("Received signal %d, shutting down...", signum)
    _shutdown.set()


def run_daemon(
    scenario_ids: list[str],
    runtime: str,
    validate: bool,
    report_fmt: str,
    cron_expr: str | None = None,
    interval: int | None = None,
):
    """Run the scheduler as a daemon with cron or interval scheduling."""
    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)

    log.info("Scheduler daemon started")
    if cron_expr:
        log.info("  Schedule: cron '%s'", cron_expr)
    elif interval:
        log.info("  Schedule: every %d seconds", interval)

    log.info("  Scenarios: %d", len(scenario_ids))
    log.info("  Validation: %s", "enabled" if validate else "disabled")

    last_cron_run_minute = -1

    while not _shutdown.is_set():
        should_run = False

        if interval:
            should_run = True
        elif cron_expr:
            now = datetime.datetime.now()
            current_minute = now.hour * 60 + now.minute
            if cron_matches_now(cron_expr) and current_minute != last_cron_run_minute:
                should_run = True
                last_cron_run_minute = current_minute

        if should_run:
            log.info("--- Starting scheduled run ---")
            session = run_scenarios(scenario_ids, runtime, validate)
            report = format_session_report(session, report_fmt)
            if report_fmt == "json":
                log.info("Run complete — %d scenarios", session.scenarios_run)
            else:
                print(report)

        # Sleep in small increments so we can respond to signals
        wait_time = interval if interval else 30
        for _ in range(wait_time):
            if _shutdown.is_set():
                break
            time.sleep(1)

    log.info("Scheduler daemon stopped")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="NHI Scenario Scheduler — automated attack scenario execution",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Scenario selection
    parser.add_argument(
        "--scenario", "-s", action="append", default=None,
        help="Run specific scenario(s) by ID (e.g., -s s2-01 -s s2-02)",
    )
    parser.add_argument(
        "--level", "-l", type=int, action="append", default=None,
        help="Run all scenarios at given level(s) (e.g., -l 1 -l 2)",
    )

    # Scheduling
    parser.add_argument(
        "--cron", default=None,
        help="Cron expression for scheduling (e.g., '*/30 * * * *')",
    )
    parser.add_argument(
        "--interval", type=int, default=None,
        help="Run every N seconds (simpler alternative to --cron)",
    )
    parser.add_argument(
        "--daemon", action="store_true",
        help="Run as a background daemon (requires --cron or --interval)",
    )

    # Validation and reporting
    parser.add_argument(
        "--validate", "-v", action="store_true",
        help="Validate Wazuh alerts after scenario execution",
    )
    parser.add_argument(
        "--report", choices=["text", "json"], default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--no-metrics", action="store_true",
        help="Disable reporting to NHI metrics exporter",
    )

    # Runtime
    parser.add_argument(
        "--runtime", default=None,
        help="Container runtime (auto-detected if not specified)",
    )

    # List scenarios
    parser.add_argument(
        "--list", action="store_true",
        help="List available scenarios and exit",
    )

    args = parser.parse_args()

    # List mode
    if args.list:
        print(f"\n{'ID':<8} {'Level':<8} {'Target':<18} {'Name'}")
        print(f"{'-'*8} {'-'*8} {'-'*18} {'-'*40}")
        for s in SCENARIOS.values():
            print(f"{s.id:<8} {s.level:<8} {s.target:<18} {s.name}")
        print(f"\n{len(SCENARIOS)} scenarios available")
        return 0

    # Detect runtime
    runtime = args.runtime or detect_runtime()
    log.info("Container runtime: %s", runtime)

    # Build scenario list
    scenario_ids: list[str] = []

    if args.scenario:
        scenario_ids = args.scenario
    elif args.level:
        scenario_ids = [s.id for s in SCENARIOS.values() if s.level in args.level]
    else:
        scenario_ids = list(SCENARIOS.keys())

    if not scenario_ids:
        log.error("No scenarios selected")
        return 1

    log.info("Selected %d scenarios", len(scenario_ids))

    # Daemon mode
    if args.daemon:
        if not args.cron and not args.interval:
            log.error("Daemon mode requires --cron or --interval")
            return 1
        run_daemon(
            scenario_ids=scenario_ids,
            runtime=runtime,
            validate=args.validate,
            report_fmt=args.report,
            cron_expr=args.cron,
            interval=args.interval,
        )
        return 0

    # Single run
    session = run_scenarios(
        scenario_ids=scenario_ids,
        runtime=runtime,
        validate=args.validate,
        report_metrics=not args.no_metrics,
    )

    report = format_session_report(session, args.report)
    print(report)

    return 0 if session.scenarios_failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
