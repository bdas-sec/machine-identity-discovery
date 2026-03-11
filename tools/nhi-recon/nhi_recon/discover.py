"""Discovery module -- scan for NHI credentials and identity endpoints."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

import click
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from nhi_recon.utils import (
    add_finding,
    console,
    detect_credential_type,
    format_table,
    make_request,
    post_to_dashboard,
)

# ---------------------------------------------------------------------------
# Patterns for environment variable names that commonly hold NHI secrets
# ---------------------------------------------------------------------------
_ENV_VAR_PATTERNS: list[tuple[str, str]] = [
    ("AWS_ACCESS_KEY_ID", "AWS"),
    ("AWS_SECRET_ACCESS_KEY", "AWS"),
    ("AWS_SESSION_TOKEN", "AWS"),
    ("AWS_SECURITY_TOKEN", "AWS"),
    ("GITHUB_TOKEN", "GitHub"),
    ("GITHUB_APP_PRIVATE_KEY", "GitHub"),
    ("GH_TOKEN", "GitHub"),
    ("GITLAB_TOKEN", "GitLab"),
    ("CI_JOB_TOKEN", "GitLab CI"),
    ("OPENAI_API_KEY", "OpenAI"),
    ("ANTHROPIC_API_KEY", "Anthropic"),
    ("AZURE_CLIENT_SECRET", "Azure"),
    ("AZURE_TENANT_ID", "Azure"),
    ("GOOGLE_APPLICATION_CREDENTIALS", "GCP"),
    ("VAULT_TOKEN", "Vault"),
    ("DOCKER_AUTH_CONFIG", "Docker"),
    ("NPM_TOKEN", "NPM"),
    ("PYPI_TOKEN", "PyPI"),
    ("DATABASE_URL", "Database"),
    ("ACTIONS_RUNTIME_TOKEN", "GitHub Actions"),
    ("ACTIONS_ID_TOKEN_REQUEST_URL", "GitHub Actions OIDC"),
    ("RUNNER_TOKEN", "CI/CD Runner"),
]

_CREDENTIAL_FILE_PATHS: list[tuple[str, str]] = [
    ("~/.aws/credentials", "AWS CLI credentials"),
    ("~/.aws/config", "AWS CLI config"),
    ("~/.kube/config", "Kubernetes kubeconfig"),
    ("~/.docker/config.json", "Docker registry credentials"),
    ("~/.ssh/id_rsa", "SSH private key (RSA)"),
    ("~/.ssh/id_ed25519", "SSH private key (Ed25519)"),
    ("~/.ssh/id_ecdsa", "SSH private key (ECDSA)"),
    ("~/.npmrc", "NPM auth token"),
    ("~/.pypirc", "PyPI auth token"),
    (".env", "Environment file"),
    (".env.local", "Local environment file"),
    (".env.production", "Production environment file"),
    ("terraform.tfstate", "Terraform state (may contain secrets)"),
    ("terraform.tfvars", "Terraform variables"),
]

_K8S_SA_PATHS: list[tuple[str, str]] = [
    ("/var/run/secrets/kubernetes.io/serviceaccount/token", "K8s SA token"),
    ("/var/run/secrets/kubernetes.io/serviceaccount/namespace", "K8s namespace"),
    ("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt", "K8s CA certificate"),
]

_DOCKER_SECRET_DIR = "/run/secrets"
_PROC_ENVIRON_PATTERN = re.compile(rb"([A-Z_]+)=(.*?)(?:\x00|$)")

# IMDS endpoints to probe
_IMDS_ENDPOINTS: list[dict[str, Any]] = [
    {
        "name": "AWS IMDSv1",
        "url": "http://{target}/latest/meta-data/",
        "headers": {},
        "provider": "AWS",
    },
    {
        "name": "AWS IMDSv2 Token",
        "url": "http://{target}/latest/api/token",
        "headers": {"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
        "method": "PUT",
        "provider": "AWS",
    },
    {
        "name": "GCP Metadata",
        "url": "http://{target}/computeMetadata/v1/",
        "headers": {"Metadata-Flavor": "Google"},
        "provider": "GCP",
    },
    {
        "name": "Azure IMDS",
        "url": "http://{target}/metadata/instance?api-version=2021-02-01",
        "headers": {"Metadata": "true"},
        "provider": "Azure",
    },
]


# ===================================================================
# Click group
# ===================================================================

@click.group()
def discover() -> None:
    """Discover non-human identities in the target environment."""


# -------------------------------------------------------------------
# credentials
# -------------------------------------------------------------------

@discover.command()
@click.option("--target", "-t", required=True, help="Target host or container")
@click.option("--deep", is_flag=True, help="Deep scan including /proc environ")
@click.pass_context
def credentials(ctx: click.Context, target: str, deep: bool) -> None:
    """Scan for credential files, environment variables, and secrets."""
    dashboard_url = ctx.obj.get("dashboard_url") if ctx.obj else None
    console.rule("[bold]NHI Credential Discovery[/bold]")
    console.print(f"Target: [cyan]{target}[/cyan]  Deep: {deep}\n")

    # 1. Environment variables -------------------------------------------
    console.print("[bold]Phase 1:[/bold] Checking environment variables ...")
    env_rows: list[list[str]] = []
    for var_name, provider in _ENV_VAR_PATTERNS:
        val = os.environ.get(var_name)
        if val:
            masked = val[:8] + "..." if len(val) > 8 else val
            cred_type = detect_credential_type(val)
            env_rows.append([var_name, provider, cred_type, masked])
            add_finding(
                title=f"Environment variable: {var_name}",
                severity="high",
                details=f"Provider: {provider} | Type: {cred_type}",
                evidence=f"{var_name}={masked}",
                remediation="Use a secrets manager instead of environment variables.",
            )
    if env_rows:
        console.print(
            format_table(
                "Discovered Environment Variables",
                ["Variable", "Provider", "Cred Type", "Value (masked)"],
                env_rows,
            )
        )
    else:
        console.print("  [dim]No sensitive environment variables found.[/dim]")

    # 2. Credential files ------------------------------------------------
    console.print("\n[bold]Phase 2:[/bold] Checking credential files ...")
    file_rows: list[list[str]] = []
    for path_str, description in _CREDENTIAL_FILE_PATHS:
        p = Path(path_str).expanduser()
        if p.exists():
            size = p.stat().st_size
            file_rows.append([str(p), description, f"{size} bytes"])
            add_finding(
                title=f"Credential file: {p}",
                severity="medium" if "ssh" not in str(p).lower() else "high",
                details=description,
                evidence=f"Size: {size} bytes",
                remediation="Restrict file permissions; consider secrets manager.",
            )
    if file_rows:
        console.print(
            format_table(
                "Discovered Credential Files",
                ["Path", "Description", "Size"],
                file_rows,
            )
        )
    else:
        console.print("  [dim]No credential files found.[/dim]")

    # 3. SSH keys --------------------------------------------------------
    console.print("\n[bold]Phase 3:[/bold] Checking SSH keys ...")
    ssh_dir = Path.home() / ".ssh"
    ssh_rows: list[list[str]] = []
    if ssh_dir.is_dir():
        for f in ssh_dir.iterdir():
            if f.is_file() and f.suffix not in {".pub", ".known_hosts", ".config"}:
                try:
                    header = f.read_text(errors="replace")[:80]
                except OSError:
                    header = "(unreadable)"
                if "PRIVATE KEY" in header or f.name.startswith("id_"):
                    ssh_rows.append([str(f), f.name, header.split("\n")[0][:60]])
    if ssh_rows:
        console.print(
            format_table(
                "SSH Private Keys",
                ["Path", "Name", "Header"],
                ssh_rows,
            )
        )
    else:
        console.print("  [dim]No SSH private keys found.[/dim]")

    # 4. Kubernetes service account tokens --------------------------------
    console.print("\n[bold]Phase 4:[/bold] Checking Kubernetes service account ...")
    k8s_rows: list[list[str]] = []
    for path_str, desc in _K8S_SA_PATHS:
        p = Path(path_str)
        if p.exists():
            try:
                content = p.read_text(errors="replace")[:120]
            except OSError:
                content = "(unreadable)"
            k8s_rows.append([str(p), desc, content[:60] + "..."])
            add_finding(
                title=f"K8s SA artifact: {p}",
                severity="high",
                details=desc,
                evidence=content[:60],
                remediation="Use bound service account tokens with short TTL.",
            )
    if k8s_rows:
        console.print(
            format_table(
                "Kubernetes Service Account Artifacts",
                ["Path", "Description", "Content Preview"],
                k8s_rows,
            )
        )
    else:
        console.print("  [dim]No Kubernetes SA tokens found.[/dim]")

    # 5. /proc/*/environ (deep) ------------------------------------------
    if deep:
        console.print("\n[bold]Phase 5:[/bold] Scanning /proc/*/environ ...")
        proc_rows: list[list[str]] = []
        proc_dir = Path("/proc")
        if proc_dir.is_dir():
            sensitive_names = {name for name, _ in _ENV_VAR_PATTERNS}
            for pid_dir in sorted(proc_dir.iterdir()):
                if not pid_dir.name.isdigit():
                    continue
                environ_path = pid_dir / "environ"
                try:
                    raw = environ_path.read_bytes()
                except OSError:
                    continue
                for m in _PROC_ENVIRON_PATTERN.finditer(raw):
                    key = m.group(1).decode(errors="replace")
                    val = m.group(2).decode(errors="replace")
                    if key in sensitive_names:
                        masked = val[:8] + "..." if len(val) > 8 else val
                        proc_rows.append([pid_dir.name, key, masked])
            if proc_rows:
                console.print(
                    format_table(
                        "Secrets in /proc/*/environ",
                        ["PID", "Variable", "Value (masked)"],
                        proc_rows,
                    )
                )
                add_finding(
                    title="Secrets exposed via /proc/*/environ",
                    severity="high",
                    details=f"Found {len(proc_rows)} secret(s) in process environments",
                    evidence=f"PIDs: {', '.join(r[0] for r in proc_rows[:5])}",
                    remediation="Avoid passing secrets via environment variables to long-lived processes.",
                )
        else:
            console.print("  [dim]/proc not available on this platform.[/dim]")

    # 6. Docker secrets --------------------------------------------------
    console.print("\n[bold]Phase 6:[/bold] Checking Docker secrets ...")
    secrets_dir = Path(_DOCKER_SECRET_DIR)
    docker_rows: list[list[str]] = []
    if secrets_dir.is_dir():
        for f in secrets_dir.iterdir():
            if f.is_file():
                try:
                    content = f.read_text(errors="replace").strip()
                    masked = content[:8] + "..." if len(content) > 8 else content
                except OSError:
                    masked = "(unreadable)"
                docker_rows.append([f.name, masked])
                add_finding(
                    title=f"Docker secret: {f.name}",
                    severity="medium",
                    details=f"Docker secret mounted at {f}",
                    evidence=masked,
                    remediation="Rotate secrets regularly; restrict container access.",
                )
    if docker_rows:
        console.print(
            format_table("Docker Secrets", ["Name", "Value (masked)"], docker_rows)
        )
    else:
        console.print("  [dim]No Docker secrets directory found.[/dim]")

    post_to_dashboard(dashboard_url, "discover.credentials", {"target": target})
    console.rule("[bold green]Credential Discovery Complete[/bold green]")


# -------------------------------------------------------------------
# imds
# -------------------------------------------------------------------

@discover.command()
@click.option("--target", "-t", required=True, help="IMDS target (host:port)")
@click.pass_context
def imds(ctx: click.Context, target: str) -> None:
    """Probe for cloud metadata services (IMDS)."""
    dashboard_url = ctx.obj.get("dashboard_url") if ctx.obj else None
    console.rule("[bold]IMDS / Cloud Metadata Discovery[/bold]")
    console.print(f"Target: [cyan]{target}[/cyan]\n")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        for ep in _IMDS_ENDPOINTS:
            url = ep["url"].format(target=target)
            method = ep.get("method", "GET")
            task = progress.add_task(f"Probing {ep['name']} ...", total=None)

            resp = make_request(url, method, headers=ep["headers"])
            progress.update(task, completed=True)

            if resp is not None and resp.status_code == 200:
                body = resp.text[:500]
                add_finding(
                    title=f"{ep['name']} endpoint reachable",
                    severity="high",
                    details=f"Provider: {ep['provider']} | URL: {url}",
                    evidence=body[:200],
                    remediation=f"Restrict access to {ep['provider']} metadata endpoint.",
                )

                # Follow-up: try to get credentials if AWS
                if ep["provider"] == "AWS" and method == "GET":
                    _enumerate_aws_imds(target, ep["headers"], dashboard_url)
                elif ep["provider"] == "GCP":
                    _enumerate_gcp_metadata(target, dashboard_url)
            else:
                status = resp.status_code if resp else "N/A"
                console.print(f"  [dim]{ep['name']}: not reachable (status {status})[/dim]")

    post_to_dashboard(dashboard_url, "discover.imds", {"target": target})
    console.rule("[bold green]IMDS Discovery Complete[/bold green]")


def _enumerate_aws_imds(
    target: str, headers: dict[str, str], dashboard_url: str | None
) -> None:
    """Follow-up enumeration for AWS IMDS."""
    # List IAM roles
    roles_url = f"http://{target}/latest/meta-data/iam/security-credentials/"
    resp = make_request(roles_url, headers=headers)
    if resp and resp.status_code == 200:
        roles = [r.strip() for r in resp.text.strip().split("\n") if r.strip()]
        console.print(f"  [yellow]Discovered IAM roles: {roles}[/yellow]")
        for role in roles:
            cred_url = f"http://{target}/latest/meta-data/iam/security-credentials/{role}"
            cred_resp = make_request(cred_url, headers=headers)
            if cred_resp and cred_resp.status_code == 200:
                try:
                    creds = cred_resp.json()
                except Exception:
                    creds = {"raw": cred_resp.text[:300]}
                add_finding(
                    title=f"AWS IAM Role Credentials Stolen: {role}",
                    severity="critical",
                    details=f"Retrieved temporary credentials for role '{role}'",
                    evidence=json.dumps(
                        {
                            k: v[:20] + "..." if isinstance(v, str) and len(v) > 20 else v
                            for k, v in creds.items()
                        },
                        indent=2,
                    ),
                    remediation="Enforce IMDSv2 (--http-tokens required); limit IAM role permissions.",
                )
                post_to_dashboard(
                    dashboard_url,
                    "discover.imds.credential_theft",
                    {"role": role, "provider": "AWS"},
                )


def _enumerate_gcp_metadata(target: str, dashboard_url: str | None) -> None:
    """Follow-up enumeration for GCP metadata service."""
    gcp_headers = {"Metadata-Flavor": "Google"}

    # Service accounts
    sa_url = f"http://{target}/computeMetadata/v1/instance/service-accounts/"
    resp = make_request(sa_url, headers=gcp_headers)
    if resp and resp.status_code == 200:
        accounts = [a.strip().rstrip("/") for a in resp.text.strip().split("\n") if a.strip()]
        console.print(f"  [yellow]GCP service accounts: {accounts}[/yellow]")

        for acct in accounts:
            token_url = (
                f"http://{target}/computeMetadata/v1/instance/service-accounts/{acct}/token"
            )
            token_resp = make_request(token_url, headers=gcp_headers)
            if token_resp and token_resp.status_code == 200:
                try:
                    token_data = token_resp.json()
                except Exception:
                    token_data = {"raw": token_resp.text[:200]}
                add_finding(
                    title=f"GCP Access Token Stolen: {acct}",
                    severity="critical",
                    details=f"Retrieved access token for service account '{acct}'",
                    evidence=json.dumps(
                        {
                            k: (str(v)[:20] + "...") if isinstance(v, str) and len(str(v)) > 20 else v
                            for k, v in token_data.items()
                        },
                        indent=2,
                    ),
                    remediation="Restrict metadata server access; use Workload Identity.",
                )
                post_to_dashboard(
                    dashboard_url,
                    "discover.imds.credential_theft",
                    {"account": acct, "provider": "GCP"},
                )


# -------------------------------------------------------------------
# spiffe
# -------------------------------------------------------------------

@discover.command()
@click.option("--target", "-t", required=True, help="Target host or container")
@click.pass_context
def spiffe(ctx: click.Context, target: str) -> None:
    """Discover SPIFFE/SPIRE workload identities."""
    dashboard_url = ctx.obj.get("dashboard_url") if ctx.obj else None
    console.rule("[bold]SPIFFE / SPIRE Discovery[/bold]")
    console.print(f"Target: [cyan]{target}[/cyan]\n")

    # Check for SPIRE agent socket
    socket_paths = [
        "/tmp/spire-agent/public/api.sock",
        "/run/spire/sockets/agent.sock",
        "/opt/spire/sockets/agent.sock",
    ]

    for sock_path in socket_paths:
        p = Path(sock_path)
        if p.exists():
            add_finding(
                title=f"SPIRE agent socket found: {sock_path}",
                severity="high",
                details="SPIRE Workload API socket is accessible. "
                        "An attacker can request SVIDs and enumerate trust domains.",
                evidence=f"Socket at {sock_path}",
                remediation="Restrict socket permissions; use Unix group policies.",
            )

    # Try SPIRE health/bundle endpoints over HTTP if target looks like host:port
    if ":" in target or target.replace(".", "").isdigit():
        base = f"http://{target}"

        # Health
        resp = make_request(f"{base}/health")
        if resp and resp.status_code == 200:
            console.print(f"  [green]SPIRE server health OK[/green]")

        # Trust bundle
        bundle_resp = make_request(f"{base}/trust-bundle")
        if bundle_resp and bundle_resp.status_code == 200:
            add_finding(
                title="SPIRE trust bundle exposed",
                severity="medium",
                details="Trust bundle is publicly accessible.",
                evidence=bundle_resp.text[:200],
                remediation="Restrict bundle endpoint to authenticated agents.",
            )

        # Registration entries
        entries_resp = make_request(f"{base}/entries")
        if entries_resp and entries_resp.status_code == 200:
            try:
                entries = entries_resp.json()
            except Exception:
                entries = []
            if isinstance(entries, list):
                console.print(f"  [yellow]Found {len(entries)} registration entries[/yellow]")
                weak_selectors = []
                for entry in entries:
                    selectors = entry.get("selectors", [])
                    spiffe_id = entry.get("spiffe_id", "unknown")
                    # Check for weak selectors (e.g., only uid:0)
                    selector_types = [s.get("type", "") for s in selectors]
                    if len(selectors) == 1 and any("uid" in t for t in selector_types):
                        weak_selectors.append(spiffe_id)
                if weak_selectors:
                    add_finding(
                        title="Weak SPIRE selectors detected",
                        severity="high",
                        details=f"Entries with single UID selector: {weak_selectors}",
                        evidence=f"{len(weak_selectors)} entries with weak selectors",
                        remediation="Use compound selectors (e.g., uid + sha256 hash).",
                    )

        # Federation endpoints
        fed_resp = make_request(f"{base}/federation/bundles")
        if fed_resp and fed_resp.status_code == 200:
            add_finding(
                title="SPIRE federation bundles exposed",
                severity="medium",
                details="Federation trust bundles are accessible.",
                evidence=fed_resp.text[:200],
                remediation="Restrict federation bundle endpoint.",
            )

    post_to_dashboard(dashboard_url, "discover.spiffe", {"target": target})
    console.rule("[bold green]SPIFFE Discovery Complete[/bold green]")


# -------------------------------------------------------------------
# kubernetes
# -------------------------------------------------------------------

@discover.command()
@click.option("--target", "-t", required=True, help="Target host or Kubernetes API")
@click.pass_context
def kubernetes(ctx: click.Context, target: str) -> None:
    """Discover Kubernetes service accounts and RBAC."""
    dashboard_url = ctx.obj.get("dashboard_url") if ctx.obj else None
    console.rule("[bold]Kubernetes Identity Discovery[/bold]")
    console.print(f"Target: [cyan]{target}[/cyan]\n")

    # Check local SA token
    sa_token_path = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")
    sa_ns_path = Path("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
    token = None
    namespace = None

    if sa_token_path.exists():
        try:
            token = sa_token_path.read_text().strip()
        except OSError:
            pass
        add_finding(
            title="Kubernetes SA token found",
            severity="high",
            details="Service account token is mounted in this container.",
            evidence=f"Token prefix: {token[:30]}..." if token else "(unreadable)",
            remediation="Disable automountServiceAccountToken if not needed.",
        )

    if sa_ns_path.exists():
        try:
            namespace = sa_ns_path.read_text().strip()
        except OSError:
            pass
        console.print(f"  Namespace: [cyan]{namespace}[/cyan]")

    # If we have a token, try to query the K8s API
    api_base = f"https://{target}"
    auth_headers = {}
    if token:
        auth_headers["Authorization"] = f"Bearer {token}"

    # Version endpoint (usually unauthenticated)
    console.print("\n[bold]Probing Kubernetes API ...[/bold]")
    version_resp = make_request(f"{api_base}/version", headers=auth_headers)
    if version_resp and version_resp.status_code == 200:
        try:
            ver = version_resp.json()
            console.print(
                f"  K8s version: [green]{ver.get('gitVersion', 'unknown')}[/green]"
            )
        except Exception:
            pass

    # Self-subject access review (check our own permissions)
    if token:
        console.print("\n[bold]Checking permissions via SelfSubjectAccessReview ...[/bold]")
        _check_k8s_permissions(api_base, auth_headers, namespace or "default")

    # Check for mounted secrets in common paths
    console.print("\n[bold]Checking for mounted secrets ...[/bold]")
    secret_paths = [
        "/var/run/secrets",
        "/etc/kubernetes",
        "/root/.kube",
    ]
    for sp in secret_paths:
        p = Path(sp)
        if p.is_dir():
            files = list(p.rglob("*"))
            if files:
                add_finding(
                    title=f"Secrets directory: {sp}",
                    severity="medium",
                    details=f"Found {len(files)} files under {sp}",
                    evidence=", ".join(str(f.name) for f in files[:10]),
                    remediation="Restrict volume mounts; use projected volumes.",
                )

    post_to_dashboard(dashboard_url, "discover.kubernetes", {"target": target})
    console.rule("[bold green]Kubernetes Discovery Complete[/bold green]")


def _check_k8s_permissions(
    api_base: str, headers: dict[str, str], namespace: str
) -> None:
    """Attempt SelfSubjectAccessReview for common dangerous permissions."""
    dangerous_perms = [
        ("*", "*", "*"),
        ("", "secrets", "list"),
        ("", "secrets", "get"),
        ("", "pods", "create"),
        ("", "pods/exec", "create"),
        ("", "serviceaccounts", "create"),
        ("rbac.authorization.k8s.io", "clusterroles", "bind"),
        ("rbac.authorization.k8s.io", "clusterrolebindings", "create"),
    ]

    allowed_rows: list[list[str]] = []
    for group, resource, verb in dangerous_perms:
        review = {
            "apiVersion": "authorization.k8s.io/v1",
            "kind": "SelfSubjectAccessReview",
            "spec": {
                "resourceAttributes": {
                    "namespace": namespace,
                    "verb": verb,
                    "group": group,
                    "resource": resource,
                }
            },
        }
        resp = make_request(
            f"{api_base}/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
            method="POST",
            headers={**headers, "Content-Type": "application/json"},
            json_body=review,
        )
        if resp and resp.status_code in (200, 201):
            try:
                result = resp.json()
                allowed = result.get("status", {}).get("allowed", False)
            except Exception:
                allowed = False
            if allowed:
                allowed_rows.append([group or "(core)", resource, verb])

    if allowed_rows:
        console.print(
            format_table(
                "Allowed Dangerous Permissions",
                ["API Group", "Resource", "Verb"],
                allowed_rows,
            )
        )
        add_finding(
            title="Dangerous Kubernetes permissions detected",
            severity="critical",
            details=f"Service account has {len(allowed_rows)} dangerous permission(s)",
            evidence="; ".join(f"{r[1]}/{r[2]}" for r in allowed_rows),
            remediation="Apply least-privilege RBAC; avoid cluster-admin.",
        )
    else:
        console.print("  [dim]No dangerous permissions detected (or API unreachable).[/dim]")
