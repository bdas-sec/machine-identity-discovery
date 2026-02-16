#!/usr/bin/env python3
"""
NHI Security Testbed Health Check

Verify all testbed components are healthy and ready for demos.

Usage:
    python health_check.py           # Run all checks
    python health_check.py --quick   # Quick connectivity check only
    python health_check.py --fix     # Attempt to fix common issues
"""

import argparse
import json
import shutil
import subprocess
import sys
import urllib.request
import ssl


class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    END = "\033[0m"


def ok(msg: str) -> None:
    print(f"  {Colors.GREEN}[OK]{Colors.END} {msg}")


def fail(msg: str) -> None:
    print(f"  {Colors.RED}[FAIL]{Colors.END} {msg}")


def warn(msg: str) -> None:
    print(f"  {Colors.YELLOW}[WARN]{Colors.END} {msg}")


def info(msg: str) -> None:
    print(f"  {Colors.BLUE}[INFO]{Colors.END} {msg}")


def get_container_runtime() -> str:
    """Detect container runtime."""
    if shutil.which("podman"):
        return "podman"
    return "docker"


def run_command(cmd: list[str], timeout: int = 30) -> tuple[int, str, str]:
    """Run command and return result."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except Exception as e:
        return -1, "", str(e)


def check_containers(runtime: str) -> tuple[bool, list[str]]:
    """Check if required containers are running."""
    print("\n[Checking Containers]")

    required = [
        "wazuh-manager",
        "wazuh-indexer",
        "wazuh-dashboard",
        "cloud-workload",
        "vulnerable-app",
        "cicd-runner",
        "mock-imds",
        "vault",
    ]

    running = []
    missing = []

    # Get running containers
    if runtime == "podman":
        cmd = ["podman", "ps", "--format", "{{.Names}}"]
    else:
        cmd = ["docker", "ps", "--format", "{{.Names}}"]

    returncode, stdout, stderr = run_command(cmd)

    if returncode != 0:
        fail(f"Cannot list containers: {stderr}")
        return False, required

    container_names = stdout.strip().split("\n")

    for container in required:
        if container in container_names:
            ok(container)
            running.append(container)
        else:
            fail(f"{container} not running")
            missing.append(container)

    return len(missing) == 0, missing


def check_wazuh_indexer() -> bool:
    """Check Wazuh Indexer health."""
    print("\n[Checking Wazuh Indexer]")

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        # Create request with basic auth
        url = "https://localhost:9200/_cluster/health"
        req = urllib.request.Request(url)

        # Add basic auth header
        import base64
        credentials = base64.b64encode(b"admin:admin").decode("ascii")
        req.add_header("Authorization", f"Basic {credentials}")

        with urllib.request.urlopen(req, context=ctx, timeout=10) as response:
            data = json.loads(response.read())
            status = data.get("status", "unknown")

            if status in ("green", "yellow"):
                ok(f"Cluster status: {status}")
                return True
            else:
                fail(f"Cluster status: {status}")
                return False

    except Exception as e:
        fail(f"Cannot connect: {e}")
        return False


def check_wazuh_manager() -> bool:
    """Check Wazuh Manager API."""
    print("\n[Checking Wazuh Manager API]")

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        url = "https://localhost:55000/"
        req = urllib.request.Request(url)

        with urllib.request.urlopen(req, context=ctx, timeout=10) as response:
            data = response.read().decode()

            if "Wazuh" in data or "Unauthorized" in data:
                ok("API responding")
                return True
            else:
                fail("Unexpected response")
                return False

    except Exception as e:
        fail(f"Cannot connect: {e}")
        return False


def check_wazuh_agents() -> tuple[bool, int]:
    """Check Wazuh agent enrollment."""
    print("\n[Checking Wazuh Agents]")

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        # Get auth token
        import base64
        credentials = base64.b64encode(b"wazuh-wui:MyS3cr3tP@ssw0rd").decode("ascii")

        url = "https://localhost:55000/security/user/authenticate?raw=true"
        req = urllib.request.Request(url, method="POST")
        req.add_header("Authorization", f"Basic {credentials}")

        with urllib.request.urlopen(req, context=ctx, timeout=10) as response:
            token = response.read().decode().strip()

        # Get agents
        url = "https://localhost:55000/agents"
        req = urllib.request.Request(url)
        req.add_header("Authorization", f"Bearer {token}")

        with urllib.request.urlopen(req, context=ctx, timeout=10) as response:
            data = json.loads(response.read())

        agents = data.get("data", {}).get("affected_items", [])
        active_agents = [a for a in agents if a.get("status") == "active" and a.get("id") != "000"]

        expected = ["cloud-workload-001", "vulnerable-app-001", "cicd-runner-001"]
        found = {a.get("name") for a in active_agents}

        for agent_name in expected:
            if agent_name in found:
                ok(agent_name)
            else:
                fail(f"{agent_name} not enrolled or inactive")

        return len(found & set(expected)) == len(expected), len(active_agents)

    except Exception as e:
        fail(f"Cannot check agents: {e}")
        return False, 0


def check_dashboard() -> bool:
    """Check Wazuh Dashboard."""
    print("\n[Checking Wazuh Dashboard]")

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        url = "https://localhost:8443/status"
        req = urllib.request.Request(url)

        with urllib.request.urlopen(req, context=ctx, timeout=15) as response:
            ok("Dashboard responding")
            return True

    except urllib.error.HTTPError as e:
        if e.code == 401:
            ok("Dashboard responding (auth required)")
            return True
        fail(f"HTTP error: {e.code}")
        return False
    except Exception as e:
        fail(f"Cannot connect: {e}")
        return False


def check_mock_services() -> bool:
    """Check mock services."""
    print("\n[Checking Mock Services]")

    all_ok = True

    # Mock IMDS
    try:
        url = "http://localhost:1338/health"
        with urllib.request.urlopen(url, timeout=5) as response:
            if "healthy" in response.read().decode():
                ok("Mock IMDS")
            else:
                fail("Mock IMDS unhealthy")
                all_ok = False
    except Exception as e:
        fail(f"Mock IMDS: {e}")
        all_ok = False

    # Vault
    try:
        url = "http://localhost:8200/v1/sys/health"
        with urllib.request.urlopen(url, timeout=5) as response:
            ok("Vault")
    except Exception as e:
        fail(f"Vault: {e}")
        all_ok = False

    # Mock CI/CD
    try:
        url = "http://localhost:8080/"
        with urllib.request.urlopen(url, timeout=5) as response:
            ok("Mock CI/CD")
    except Exception as e:
        fail(f"Mock CI/CD: {e}")
        all_ok = False

    # Mock OAuth Provider
    try:
        url = "http://localhost:8090/health"
        with urllib.request.urlopen(url, timeout=5) as response:
            if "healthy" in response.read().decode():
                ok("Mock OAuth Provider")
            else:
                fail("Mock OAuth Provider unhealthy")
                all_ok = False
    except Exception as e:
        fail(f"Mock OAuth Provider: {e}")
        all_ok = False

    # Mock GCP Metadata
    try:
        url = "http://localhost:1339/health"
        req = urllib.request.Request(url)
        req.add_header("Metadata-Flavor", "Google")
        with urllib.request.urlopen(req, timeout=5) as response:
            if "healthy" in response.read().decode():
                ok("Mock GCP Metadata")
            else:
                fail("Mock GCP Metadata unhealthy")
                all_ok = False
    except Exception as e:
        fail(f"Mock GCP Metadata: {e}")
        all_ok = False

    # Vulnerable App
    try:
        url = "http://localhost:8888/"
        with urllib.request.urlopen(url, timeout=5) as response:
            ok("Vulnerable App")
    except Exception as e:
        fail(f"Vulnerable App: {e}")
        all_ok = False

    return all_ok


def check_agent_groups() -> bool:
    """Check if required agent groups exist."""
    print("\n[Checking Agent Groups]")

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    required_groups = {"cloud", "cicd", "runner", "ephemeral", "vulnerable", "demo", "ubuntu", "production"}

    try:
        import base64
        credentials = base64.b64encode(b"wazuh-wui:MyS3cr3tP@ssw0rd").decode("ascii")

        # Get token
        url = "https://localhost:55000/security/user/authenticate?raw=true"
        req = urllib.request.Request(url, method="POST")
        req.add_header("Authorization", f"Basic {credentials}")

        with urllib.request.urlopen(req, context=ctx, timeout=10) as response:
            token = response.read().decode().strip()

        # Get groups
        url = "https://localhost:55000/groups"
        req = urllib.request.Request(url)
        req.add_header("Authorization", f"Bearer {token}")

        with urllib.request.urlopen(req, context=ctx, timeout=10) as response:
            data = json.loads(response.read())

        existing = {g.get("name") for g in data.get("data", {}).get("affected_items", [])}
        missing = required_groups - existing

        if missing:
            fail(f"Missing groups: {', '.join(missing)}")
            return False
        else:
            ok(f"All {len(required_groups)} groups exist")
            return True

    except Exception as e:
        fail(f"Cannot check groups: {e}")
        return False


def fix_common_issues(runtime: str) -> None:
    """Attempt to fix common issues."""
    print("\n[Attempting Fixes]")

    # Create missing groups
    info("Creating agent groups...")

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        import base64
        credentials = base64.b64encode(b"wazuh-wui:MyS3cr3tP@ssw0rd").decode("ascii")

        url = "https://localhost:55000/security/user/authenticate?raw=true"
        req = urllib.request.Request(url, method="POST")
        req.add_header("Authorization", f"Basic {credentials}")

        with urllib.request.urlopen(req, context=ctx, timeout=10) as response:
            token = response.read().decode().strip()

        groups = ["cloud", "cicd", "runner", "ephemeral", "vulnerable", "demo", "ubuntu", "production"]
        created = 0

        for group in groups:
            try:
                url = "https://localhost:55000/groups"
                data = json.dumps({"group_id": group}).encode()
                req = urllib.request.Request(url, data=data, method="POST")
                req.add_header("Authorization", f"Bearer {token}")
                req.add_header("Content-Type", "application/json")

                with urllib.request.urlopen(req, context=ctx, timeout=10) as response:
                    result = json.loads(response.read())
                    if "created" in str(result):
                        created += 1
            except urllib.error.HTTPError:
                pass  # Group may already exist

        if created > 0:
            ok(f"Created {created} groups")
        else:
            info("All groups already exist")

    except Exception as e:
        fail(f"Cannot create groups: {e}")

    # Restart agents
    info("Restarting agent containers...")
    agents = ["cloud-workload", "vulnerable-app", "cicd-runner"]

    for agent in agents:
        returncode, _, stderr = run_command([runtime, "restart", agent], timeout=60)
        if returncode == 0:
            ok(f"Restarted {agent}")
        else:
            fail(f"Cannot restart {agent}: {stderr}")


def main():
    parser = argparse.ArgumentParser(description="NHI Testbed Health Check")
    parser.add_argument("--quick", action="store_true", help="Quick check only")
    parser.add_argument("--fix", action="store_true", help="Attempt to fix issues")

    args = parser.parse_args()

    print(f"{Colors.BLUE}")
    print("=" * 50)
    print("  NHI Security Testbed Health Check")
    print("=" * 50)
    print(f"{Colors.END}")

    runtime = get_container_runtime()
    info(f"Container runtime: {runtime}")

    all_ok = True

    # Container check
    containers_ok, missing = check_containers(runtime)
    if not containers_ok:
        all_ok = False
        if missing:
            warn(f"Missing containers: {', '.join(missing)}")
            warn("Run: ./scripts/start.sh")

    if args.quick:
        # Quick check - just containers
        pass
    else:
        # Full check
        if not check_wazuh_indexer():
            all_ok = False

        if not check_wazuh_manager():
            all_ok = False

        agents_ok, agent_count = check_wazuh_agents()
        if not agents_ok:
            all_ok = False

        if not check_dashboard():
            all_ok = False

        if not check_mock_services():
            all_ok = False

        if not check_agent_groups():
            all_ok = False

    # Summary
    print(f"\n{'='*50}")
    if all_ok:
        print(f"{Colors.GREEN}All checks passed! Testbed is ready.{Colors.END}")
    else:
        print(f"{Colors.RED}Some checks failed.{Colors.END}")

        if args.fix:
            fix_common_issues(runtime)
            print("\nRe-run health check to verify fixes.")

    print(f"{'='*50}\n")

    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
