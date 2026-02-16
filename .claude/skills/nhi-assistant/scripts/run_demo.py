#!/usr/bin/env python3
"""
NHI Security Testbed Demo Runner

Run attack scenarios to demonstrate NHI security detection capabilities.

Usage:
    python run_demo.py --all              # Run all scenarios
    python run_demo.py --level 2          # Run all Level 2 scenarios
    python run_demo.py --scenario s2-01   # Run specific scenario
    python run_demo.py --list             # List all scenarios
    python run_demo.py --all --validate   # Run all + verify Wazuh alerts
"""

import argparse
import json
import subprocess
import sys
import time
import urllib3
from dataclasses import dataclass, field
from typing import Optional

# Suppress InsecureRequestWarning for self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import requests
except ImportError:
    requests = None  # type: ignore[assignment]

# Wazuh API defaults
WAZUH_API_URL = "https://localhost:55000"
WAZUH_API_USER = "wazuh-wui"
WAZUH_API_PASS = "MyS3cr3tP@ssw0rd"

# Alert validation settings
VALIDATION_POLL_INTERVAL = 3  # seconds between polls
VALIDATION_MAX_WAIT = 30  # max seconds to wait for alerts


@dataclass
class ValidationResult:
    scenario_id: str
    expected_rules: list[str]
    detected_rules: list[str] = field(default_factory=list)
    missed_rules: list[str] = field(default_factory=list)
    extra_rules: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return len(self.missed_rules) == 0 and len(self.expected_rules) > 0

    @property
    def skipped(self) -> bool:
        return len(self.expected_rules) == 0


@dataclass
class Scenario:
    id: str
    name: str
    level: int
    target: str
    commands: list[str]
    description: str
    detection_rules: list[str]


# Define all scenarios
SCENARIOS = {
    # Level 1: Credential Discovery
    "s1-01": Scenario(
        id="s1-01",
        name="Environment File Enumeration",
        level=1,
        target="cloud-workload",
        commands=[
            "find /app -name '*.env*' 2>/dev/null || true",
            "cat /app/.env 2>/dev/null || echo 'No .env found'",
        ],
        description="Scan for .env files containing credentials",
        detection_rules=["100600"],
    ),
    "s1-02": Scenario(
        id="s1-02",
        name="AWS Credentials Discovery",
        level=1,
        target="cloud-workload",
        commands=[
            "ls -la ~/.aws/ 2>/dev/null || echo 'No AWS config'",
            "cat ~/.aws/credentials 2>/dev/null || echo 'No credentials file'",
        ],
        description="Search for AWS credential files",
        detection_rules=["100601"],
    ),
    "s1-03": Scenario(
        id="s1-03",
        name="SSH Key Discovery",
        level=1,
        target="cloud-workload",
        commands=[
            "find /root/.ssh -type f 2>/dev/null || echo 'No SSH dir'",
            "ls -la /root/.ssh/ 2>/dev/null || true",
        ],
        description="Enumerate SSH private keys",
        detection_rules=["100602"],
    ),
    "s1-04": Scenario(
        id="s1-04",
        name="Git Credentials Discovery",
        level=1,
        target="cicd-runner",
        commands=[
            "cat ~/.git-credentials 2>/dev/null || echo 'No git credentials'",
            "cat ~/.gitconfig 2>/dev/null || echo 'No gitconfig'",
        ],
        description="Search for git credential helpers",
        detection_rules=["100603"],
    ),
    "s1-05": Scenario(
        id="s1-05",
        name="Kubernetes Config Discovery",
        level=1,
        target="cloud-workload",
        commands=[
            "cat ~/.kube/config 2>/dev/null || echo 'No kubeconfig'",
            "find / -name 'kubeconfig*' 2>/dev/null | head -5 || true",
        ],
        description="Find kubeconfig files",
        detection_rules=["100605"],
    ),

    # Level 2: Credential Theft
    "s2-01": Scenario(
        id="s2-01",
        name="IMDS Credential Theft (AWS)",
        level=2,
        target="cloud-workload",
        commands=[
            "curl -s http://mock-imds:1338/latest/meta-data/",
            "curl -s http://mock-imds:1338/latest/meta-data/iam/security-credentials/",
            "ROLE=$(curl -s http://mock-imds:1338/latest/meta-data/iam/security-credentials/); curl -s http://mock-imds:1338/latest/meta-data/iam/security-credentials/$ROLE",
        ],
        description="Extract IAM credentials from AWS IMDS",
        detection_rules=["100650", "100651", "100658"],
    ),
    "s2-02": Scenario(
        id="s2-02",
        name="Process Environment Harvesting",
        level=2,
        target="cloud-workload",
        commands=[
            "env | grep -iE 'key|token|secret|password' || true",
            "cat /proc/1/environ 2>/dev/null | tr '\\0' '\\n' | head -20 || echo 'Cannot read environ'",
        ],
        description="Extract secrets from process environment",
        detection_rules=["100607"],
    ),
    "s2-03": Scenario(
        id="s2-03",
        name="Kubernetes ServiceAccount Token Theft",
        level=2,
        target="cloud-workload",
        commands=[
            "cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null || echo 'No SA token'",
            "ls -la /var/run/secrets/kubernetes.io/serviceaccount/ 2>/dev/null || true",
        ],
        description="Extract K8s service account token",
        detection_rules=["100750", "100751"],
    ),
    "s2-04": Scenario(
        id="s2-04",
        name="CI/CD Token Extraction",
        level=2,
        target="cicd-runner",
        commands=[
            "env | grep -i github || true",
            "env | grep -i token || true",
            "cat /runner/.credentials 2>/dev/null || echo 'No credentials file'",
        ],
        description="Extract GitHub/GitLab tokens",
        detection_rules=["100800", "100802"],
    ),
    "s2-05": Scenario(
        id="s2-05",
        name="Vault Token Theft",
        level=2,
        target="cloud-workload",
        commands=[
            "cat ~/.vault-token 2>/dev/null || echo 'No vault token'",
            "env | grep VAULT || true",
        ],
        description="Steal HashiCorp Vault tokens",
        detection_rules=["100606"],
    ),

    # Level 3: Privilege Escalation
    "s3-01": Scenario(
        id="s3-01",
        name="IMDS Role Assumption",
        level=3,
        target="cloud-workload",
        commands=[
            "CREDS=$(curl -s http://mock-imds:1338/latest/meta-data/iam/security-credentials/demo-ec2-role); echo $CREDS | head -c 200",
        ],
        description="Use stolen IMDS credentials",
        detection_rules=["100651", "100657"],
    ),
    "s3-02": Scenario(
        id="s3-02",
        name="Kubernetes RBAC Probing",
        level=3,
        target="cloud-workload",
        commands=[
            "kubectl auth can-i --list 2>/dev/null || echo 'kubectl not available'",
            "kubectl auth can-i create pods 2>/dev/null || true",
            "kubectl auth can-i get secrets 2>/dev/null || true",
        ],
        description="Enumerate K8s permissions",
        detection_rules=["100752", "100755"],
    ),
    "s3-03": Scenario(
        id="s3-03",
        name="Kubernetes Secrets Enumeration",
        level=3,
        target="cloud-workload",
        commands=[
            "kubectl get secrets -A 2>/dev/null || echo 'Cannot list secrets'",
        ],
        description="List and extract K8s secrets",
        detection_rules=["100753"],
    ),
    "s3-04": Scenario(
        id="s3-04",
        name="Vault Privilege Escalation",
        level=3,
        target="cloud-workload",
        commands=[
            "TOKEN=$(cat ~/.vault-token 2>/dev/null); curl -s -H \"X-Vault-Token: $TOKEN\" http://vault:8200/v1/secret/data/production 2>/dev/null || echo 'Vault access failed'",
        ],
        description="Use stolen vault token",
        detection_rules=["100606"],
    ),
    "s3-05": Scenario(
        id="s3-05",
        name="Multiple Credential Harvest",
        level=3,
        target="cloud-workload",
        commands=[
            "cat ~/.aws/credentials 2>/dev/null || true; cat ~/.ssh/id_rsa 2>/dev/null | head -5 || true; cat ~/.git-credentials 2>/dev/null || true; cat ~/.vault-token 2>/dev/null || true; cat /app/.env 2>/dev/null || true",
        ],
        description="Rapid enumeration of credentials",
        detection_rules=["100609"],
    ),

    # Level 4: Lateral Movement
    "s4-01": Scenario(
        id="s4-01",
        name="Cross-Network Movement",
        level=4,
        target="cicd-runner",
        commands=[
            "curl -s http://cloud-workload:8080/ 2>/dev/null || curl -s http://172.41.0.10:8080/ 2>/dev/null || echo 'Cannot reach cloud workload'",
        ],
        description="Access cloud workload from CI/CD",
        detection_rules=[],
    ),
    "s4-02": Scenario(
        id="s4-02",
        name="Stolen SSH Key Usage",
        level=4,
        target="cloud-workload",
        commands=[
            "cat ~/.ssh/id_rsa 2>/dev/null | head -3 || echo 'No SSH key'",
            "ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 localhost 2>&1 || true",
        ],
        description="Use discovered SSH keys",
        detection_rules=["100602"],
    ),
    "s4-03": Scenario(
        id="s4-03",
        name="Git Credential Abuse",
        level=4,
        target="cicd-runner",
        commands=[
            "git config --global credential.helper 2>/dev/null || true",
            "cat ~/.git-credentials 2>/dev/null || echo 'No credentials'",
        ],
        description="Use stolen git credentials",
        detection_rules=["100603"],
    ),
    "s4-04": Scenario(
        id="s4-04",
        name="Docker Registry Authentication",
        level=4,
        target="cicd-runner",
        commands=[
            "cat ~/.docker/config.json 2>/dev/null || echo 'No docker config'",
        ],
        description="Use stolen Docker config",
        detection_rules=["100604"],
    ),
    "s4-05": Scenario(
        id="s4-05",
        name="API Key Abuse",
        level=4,
        target="vulnerable-app",
        commands=[
            "env | grep -iE 'api|key|token' || true",
        ],
        description="Extract and identify API keys",
        detection_rules=[],
    ),

    # Level 5: Persistence
    "s5-01": Scenario(
        id="s5-01",
        name="Pipeline Poisoning",
        level=5,
        target="cicd-runner",
        commands=[
            "find /runner -name '*.yml' 2>/dev/null | head -5 || true",
            "ls -la /runner/_work/.github/workflows/ 2>/dev/null || echo 'No workflows'",
        ],
        description="Identify pipeline configs for modification",
        detection_rules=["100803"],
    ),
    "s5-02": Scenario(
        id="s5-02",
        name="Credential Rotation Backdoor",
        level=5,
        target="cloud-workload",
        commands=[
            "cat ~/.aws/credentials 2>/dev/null || echo 'No AWS creds'",
            "echo '# Backdoor check' >> /tmp/test 2>/dev/null || true",
        ],
        description="Identify credential persistence locations",
        detection_rules=["100601"],
    ),
    "s5-03": Scenario(
        id="s5-03",
        name="Service Account Token Persistence",
        level=5,
        target="cloud-workload",
        commands=[
            "cp /var/run/secrets/kubernetes.io/serviceaccount/token /tmp/sa_token 2>/dev/null || echo 'No SA token'",
            "ls -la /tmp/sa_token 2>/dev/null || true",
        ],
        description="Copy SA tokens for persistence",
        detection_rules=["100750"],
    ),
    "s5-04": Scenario(
        id="s5-04",
        name="Environment Variable Injection",
        level=5,
        target="vulnerable-app",
        commands=[
            "env | wc -l",
            "export TEST_BACKDOOR=true 2>/dev/null || true",
        ],
        description="Identify env var injection points",
        detection_rules=[],
    ),
}


def get_container_runtime() -> str:
    """Detect container runtime."""
    try:
        subprocess.run(["podman", "--version"], capture_output=True, check=True)
        return "podman"
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "docker"


def get_wazuh_token(api_url: str, user: str, password: str) -> Optional[str]:
    """Authenticate with Wazuh API and return JWT token."""
    if requests is None:
        print("  [!] 'requests' library not installed — cannot validate alerts")
        return None
    try:
        resp = requests.post(
            f"{api_url}/security/user/authenticate",
            auth=(user, password),
            verify=False,
            timeout=10,
        )
        if resp.status_code == 200:
            return resp.json().get("data", {}).get("token")
        print(f"  [!] Wazuh auth failed (HTTP {resp.status_code}): {resp.text[:200]}")
    except requests.ConnectionError:
        print(f"  [!] Cannot connect to Wazuh API at {api_url}")
    except Exception as e:
        print(f"  [!] Wazuh auth error: {e}")
    return None


def query_wazuh_alerts(
    api_url: str, token: str, rule_ids: list[str],
) -> dict[str, list[dict]]:
    """Query Wazuh API for recent alerts matching given rule IDs.

    Returns a dict mapping rule_id -> list of matching alert summaries.
    """
    found: dict[str, list[dict]] = {rid: [] for rid in rule_ids}
    if requests is None:
        return found

    headers = {"Authorization": f"Bearer {token}"}
    # Search for NHI alerts in the lookback window
    try:
        resp = requests.get(
            f"{api_url}/alerts",
            headers=headers,
            params={
                "limit": 100,
                "sort": "-timestamp",
            },
            verify=False,
            timeout=15,
        )
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            items = data.get("affected_items", [])
            for alert in items:
                rid = str(alert.get("rule", {}).get("id", ""))
                if rid in found:
                    found[rid].append(alert)
        elif resp.status_code == 401:
            # Token may have expired
            pass
    except Exception:
        pass
    return found


def validate_scenario_alerts(
    scenario: Scenario,
    api_url: str,
    token: str,
    max_wait: int = VALIDATION_MAX_WAIT,
    poll_interval: int = VALIDATION_POLL_INTERVAL,
) -> ValidationResult:
    """Poll Wazuh API to verify expected detection rules fired for a scenario."""
    result = ValidationResult(
        scenario_id=scenario.id,
        expected_rules=list(scenario.detection_rules),
    )

    if not scenario.detection_rules:
        print("  [~] No detection rules expected — skipping validation")
        return result

    print(f"  [*] Validating alerts for rules: {', '.join(scenario.detection_rules)}")
    remaining = set(scenario.detection_rules)
    elapsed = 0

    while remaining and elapsed < max_wait:
        time.sleep(poll_interval)
        elapsed += poll_interval

        alerts = query_wazuh_alerts(api_url, token, list(remaining))
        for rule_id, items in alerts.items():
            if items:
                remaining.discard(rule_id)
                result.detected_rules.append(rule_id)
                print(f"    [+] Rule {rule_id} detected ({len(items)} alert(s))")

        if remaining:
            print(f"    [...] Waiting for {len(remaining)} rule(s) — {elapsed}s/{max_wait}s")

    # Final accounting
    result.missed_rules = list(remaining)

    if result.passed:
        print(f"  [OK] All {len(result.detected_rules)} expected rules detected")
    elif result.missed_rules:
        print(f"  [FAIL] Missing rules: {', '.join(result.missed_rules)}")

    return result


def run_command_in_container(runtime: str, container: str, command: str) -> tuple[int, str, str]:
    """Execute command in container."""
    cmd = [runtime, "exec", container, "bash", "-c", command]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode, result.stdout, result.stderr


def run_scenario(scenario: Scenario, runtime: str, verbose: bool = False) -> bool:
    """Run a single scenario."""
    print(f"\n{'='*60}")
    print(f"Scenario: {scenario.id} - {scenario.name}")
    print(f"Level: {scenario.level} | Target: {scenario.target}")
    print(f"Description: {scenario.description}")
    print(f"Detection Rules: {', '.join(scenario.detection_rules) or 'N/A'}")
    print(f"{'='*60}")

    success = True
    for i, cmd in enumerate(scenario.commands, 1):
        print(f"\n[{i}/{len(scenario.commands)}] Executing: {cmd[:80]}...")

        returncode, stdout, stderr = run_command_in_container(
            runtime, scenario.target, cmd
        )

        if verbose or returncode != 0:
            if stdout:
                print(f"  Output: {stdout[:500]}")
            if stderr and returncode != 0:
                print(f"  Error: {stderr[:200]}")

        if returncode != 0 and "not found" not in stderr.lower():
            # Some commands are expected to fail (e.g., no file exists)
            pass

        time.sleep(0.5)  # Small delay between commands

    print(f"\n[+] Scenario {scenario.id} completed")
    return success


def list_scenarios():
    """List all available scenarios."""
    print("\nAvailable Scenarios:")
    print("="*70)

    current_level = 0
    for sid, scenario in sorted(SCENARIOS.items()):
        if scenario.level != current_level:
            current_level = scenario.level
            level_names = {
                1: "Credential Discovery",
                2: "Credential Theft",
                3: "Privilege Escalation",
                4: "Lateral Movement",
                5: "Persistence",
            }
            print(f"\n--- Level {current_level}: {level_names.get(current_level, 'Unknown')} ---")

        print(f"  {sid}: {scenario.name} ({scenario.target})")

    print("\n" + "="*70)


def print_validation_summary(results: list[ValidationResult]):
    """Print a summary table of all validation results."""
    print(f"\n{'='*70}")
    print("ALERT VALIDATION SUMMARY")
    print(f"{'='*70}")

    passed = [r for r in results if r.passed]
    failed = [r for r in results if not r.passed and not r.skipped]
    skipped = [r for r in results if r.skipped]

    for r in results:
        if r.skipped:
            status = "SKIP"
        elif r.passed:
            status = " OK "
        else:
            status = "FAIL"
        detected = len(r.detected_rules)
        expected = len(r.expected_rules)
        missed_str = f" (missed: {', '.join(r.missed_rules)})" if r.missed_rules else ""
        print(f"  [{status}] {r.scenario_id}: {detected}/{expected} rules{missed_str}")

    print(f"\n  Passed: {len(passed)} | Failed: {len(failed)} | Skipped: {len(skipped)}")

    if failed:
        print("\n  Failed scenarios:")
        for r in failed:
            print(f"    - {r.scenario_id}: missing rules {', '.join(r.missed_rules)}")

    print(f"{'='*70}")


def main():
    parser = argparse.ArgumentParser(
        description="NHI Security Testbed Demo Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--all", action="store_true", help="Run all scenarios")
    parser.add_argument("--level", type=int, choices=[1, 2, 3, 4, 5], help="Run scenarios for specific level")
    parser.add_argument("--scenario", type=str, help="Run specific scenario (e.g., s2-01)")
    parser.add_argument("--list", action="store_true", help="List all scenarios")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show command output")
    parser.add_argument("--delay", type=float, default=2.0, help="Delay between scenarios (seconds)")
    parser.add_argument(
        "--validate", action="store_true",
        help="Validate that expected Wazuh alerts fire after each scenario",
    )
    parser.add_argument("--wazuh-url", default=WAZUH_API_URL, help="Wazuh API URL (default: %(default)s)")
    parser.add_argument("--wazuh-user", default=WAZUH_API_USER, help="Wazuh API user (default: %(default)s)")
    parser.add_argument("--wazuh-pass", default=WAZUH_API_PASS, help="Wazuh API password")
    parser.add_argument(
        "--validation-timeout", type=int, default=VALIDATION_MAX_WAIT,
        help="Max seconds to wait for alerts per scenario (default: %(default)s)",
    )

    args = parser.parse_args()

    if args.list:
        list_scenarios()
        return 0

    if not (args.all or args.level or args.scenario):
        parser.print_help()
        return 1

    runtime = get_container_runtime()
    print(f"Using container runtime: {runtime}")

    # Initialize Wazuh API token if validating
    wazuh_token = None
    if args.validate:
        if requests is None:
            print("[!] Alert validation requires 'requests' library: pip install requests")
            print("[!] Continuing without validation...")
            args.validate = False
        else:
            print(f"[*] Authenticating with Wazuh API at {args.wazuh_url}...")
            wazuh_token = get_wazuh_token(args.wazuh_url, args.wazuh_user, args.wazuh_pass)
            if wazuh_token:
                print("[+] Wazuh API authentication successful")
            else:
                print("[!] Wazuh API authentication failed — continuing without validation")
                args.validate = False

    # Collect scenarios to run
    scenarios_to_run = []

    if args.all:
        scenarios_to_run = list(SCENARIOS.values())
    elif args.level:
        scenarios_to_run = [s for s in SCENARIOS.values() if s.level == args.level]
    elif args.scenario:
        if args.scenario.lower() in SCENARIOS:
            scenarios_to_run = [SCENARIOS[args.scenario.lower()]]
        else:
            print(f"Error: Unknown scenario '{args.scenario}'")
            list_scenarios()
            return 1

    if not scenarios_to_run:
        print("No scenarios to run")
        return 1

    print(f"\nRunning {len(scenarios_to_run)} scenario(s)...")
    print("Watch Wazuh Dashboard at https://localhost:8443 for alerts")
    if args.validate:
        print("Alert validation: ENABLED")

    success_count = 0
    validation_results: list[ValidationResult] = []

    for scenario in scenarios_to_run:
        try:
            if run_scenario(scenario, runtime, args.verbose):
                success_count += 1

            # Validate alerts if enabled
            if args.validate and wazuh_token:
                result = validate_scenario_alerts(
                    scenario,
                    args.wazuh_url,
                    wazuh_token,
                    max_wait=args.validation_timeout,
                )
                validation_results.append(result)

            time.sleep(args.delay)
        except Exception as e:
            print(f"Error running {scenario.id}: {e}")

    print(f"\n{'='*60}")
    print(f"Demo Complete: {success_count}/{len(scenarios_to_run)} scenarios executed")
    print(f"{'='*60}")

    # Print validation summary
    if args.validate and validation_results:
        print_validation_summary(validation_results)

    print("\nCheck Wazuh Dashboard for generated alerts:")
    print("  URL: https://localhost:8443")
    print("  Filter: rule.groups: nhi")

    return 0


if __name__ == "__main__":
    sys.exit(main())
