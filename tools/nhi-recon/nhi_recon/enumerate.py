"""Enumeration module -- map permissions and accessible services for discovered NHIs."""

from __future__ import annotations

import json
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

# Common NHI-related service ports
_SERVICE_PROBES: list[dict[str, Any]] = [
    {
        "name": "AWS IMDS",
        "port": 1338,
        "path": "/latest/meta-data/",
        "headers": {},
        "expect_contains": "iam",
    },
    {
        "name": "GCP Metadata",
        "port": 1339,
        "path": "/computeMetadata/v1/",
        "headers": {"Metadata-Flavor": "Google"},
        "expect_status": 200,
    },
    {
        "name": "HashiCorp Vault",
        "port": 8200,
        "path": "/v1/sys/health",
        "headers": {},
        "expect_status": 200,
    },
    {
        "name": "SPIRE Server",
        "port": 8081,
        "path": "/health",
        "headers": {},
        "expect_status": 200,
    },
    {
        "name": "Kubernetes API",
        "port": 6443,
        "path": "/version",
        "headers": {},
        "expect_status": 200,
        "scheme": "https",
    },
    {
        "name": "Kubernetes API (alt)",
        "port": 443,
        "path": "/version",
        "headers": {},
        "expect_status": 200,
        "scheme": "https",
    },
    {
        "name": "OAuth Provider",
        "port": 1340,
        "path": "/.well-known/openid-configuration",
        "headers": {},
        "expect_status": 200,
    },
    {
        "name": "CI/CD Server",
        "port": 1341,
        "path": "/health",
        "headers": {},
        "expect_status": 200,
    },
    {
        "name": "Docker Socket (HTTP)",
        "port": 2375,
        "path": "/version",
        "headers": {},
        "expect_status": 200,
    },
]


# ===================================================================
# Click group
# ===================================================================

@click.group("enumerate")
def enumerate_group() -> None:
    """Enumerate permissions and access of discovered NHIs."""


# -------------------------------------------------------------------
# permissions
# -------------------------------------------------------------------

@enumerate_group.command()
@click.option(
    "--credential",
    "-c",
    required=True,
    help="Credential value to enumerate (type auto-detected).",
)
@click.option(
    "--target",
    "-t",
    default=None,
    help="Target host for API calls (defaults to localhost).",
)
@click.pass_context
def permissions(ctx: click.Context, credential: str, target: str | None) -> None:
    """Map permissions of a discovered credential."""
    dashboard_url = ctx.obj.get("dashboard_url") if ctx.obj else None
    target = target or ctx.obj.get("target") or "localhost"
    console.rule("[bold]NHI Permission Enumeration[/bold]")

    cred_type = detect_credential_type(credential)
    console.print(f"Credential type: [cyan]{cred_type}[/cyan]")
    console.print(f"Target: [cyan]{target}[/cyan]\n")

    if "AWS" in cred_type:
        _enumerate_aws_permissions(credential, target, dashboard_url)
    elif "GitHub" in cred_type:
        _enumerate_github_permissions(credential, target, dashboard_url)
    elif "Vault" in cred_type:
        _enumerate_vault_permissions(credential, target, dashboard_url)
    elif "K8s" in cred_type or "JWT" in cred_type:
        _enumerate_k8s_permissions(credential, target, dashboard_url)
    elif "GCP" in cred_type:
        _enumerate_gcp_permissions(credential, target, dashboard_url)
    else:
        console.print(
            f"[yellow]Unknown credential type '{cred_type}'. "
            f"Attempting generic enumeration.[/yellow]"
        )
        _enumerate_generic(credential, target, dashboard_url)

    post_to_dashboard(
        dashboard_url,
        "enumerate.permissions",
        {"cred_type": cred_type, "target": target},
    )
    console.rule("[bold green]Permission Enumeration Complete[/bold green]")


def _enumerate_aws_permissions(
    credential: str, target: str, dashboard_url: str | None
) -> None:
    """Enumerate AWS credential permissions via mock IMDS/STS."""
    console.print("[bold]AWS Credential Enumeration[/bold]\n")
    rows: list[list[str]] = []

    # Try STS GetCallerIdentity equivalent
    sts_url = f"http://{target}:1338/latest/meta-data/iam/info"
    resp = make_request(sts_url)
    if resp and resp.status_code == 200:
        try:
            info = resp.json()
            rows.append(["Identity", "IAM Info", json.dumps(info)[:80]])
        except Exception:
            pass

    # Try listing roles
    roles_url = f"http://{target}:1338/latest/meta-data/iam/security-credentials/"
    resp = make_request(roles_url)
    if resp and resp.status_code == 200:
        roles = [r.strip() for r in resp.text.split("\n") if r.strip()]
        for role in roles:
            rows.append(["IAM Role", role, "Credential retrieval possible"])

    # Common high-risk actions to check
    risk_actions = [
        ("iam:PassRole", "critical", "Can escalate by passing roles to services"),
        ("sts:AssumeRole", "high", "Can assume other roles"),
        ("s3:GetObject", "medium", "Can read S3 objects"),
        ("ec2:RunInstances", "high", "Can launch EC2 instances"),
        ("lambda:InvokeFunction", "medium", "Can invoke Lambda functions"),
        ("secretsmanager:GetSecretValue", "critical", "Can read secrets"),
    ]
    for action, severity, desc in risk_actions:
        rows.append([action, severity.upper(), desc])

    if rows:
        console.print(
            format_table(
                "AWS Permission Assessment",
                ["Permission/Resource", "Severity/Role", "Details"],
                rows,
            )
        )
        add_finding(
            title="AWS credential permission matrix",
            severity="high",
            details=f"Enumerated {len(rows)} permission/resource entries",
            evidence=f"Credential prefix: {credential[:12]}...",
            remediation="Apply least-privilege IAM policies; rotate credentials.",
        )


def _enumerate_github_permissions(
    credential: str, target: str, dashboard_url: str | None
) -> None:
    """Enumerate GitHub token permissions via mock CI/CD."""
    console.print("[bold]GitHub Token Enumeration[/bold]\n")

    # Try the mock CI/CD server
    cicd_base = f"http://{target}:1341"
    headers = {"Authorization": f"token {credential}"}

    endpoints = [
        ("/github/repos/demo-org/demo-repo/actions/secrets", "Repository Secrets", "critical"),
        ("/github/actions/runner/token", "Runner Registration", "high"),
        ("/github/actions/oidc/token", "OIDC Token Exchange", "high"),
        ("/github/app", "GitHub App Info", "medium"),
    ]

    rows: list[list[str]] = []
    for path, name, severity in endpoints:
        resp = make_request(f"{cicd_base}{path}", headers=headers)
        status = resp.status_code if resp else "N/A"
        accessible = "YES" if resp and resp.status_code == 200 else "NO"
        rows.append([name, path, str(status), accessible, severity.upper()])
        if resp and resp.status_code == 200:
            add_finding(
                title=f"GitHub endpoint accessible: {name}",
                severity=severity,
                details=f"Token grants access to {path}",
                evidence=f"HTTP {status}",
                remediation="Restrict token scopes; use fine-grained PATs.",
            )

    console.print(
        format_table(
            "GitHub Token Access Matrix",
            ["Endpoint", "Path", "Status", "Accessible", "Risk"],
            rows,
        )
    )


def _enumerate_vault_permissions(
    credential: str, target: str, dashboard_url: str | None
) -> None:
    """Enumerate Vault token permissions."""
    console.print("[bold]Vault Token Enumeration[/bold]\n")
    vault_base = f"http://{target}:8200"
    headers = {"X-Vault-Token": credential}

    # Token self lookup
    resp = make_request(f"{vault_base}/v1/auth/token/lookup-self", headers=headers)
    if resp and resp.status_code == 200:
        try:
            data = resp.json().get("data", {})
            policies = data.get("policies", [])
            console.print(f"  Policies: [yellow]{policies}[/yellow]")
            console.print(f"  Display name: {data.get('display_name', 'N/A')}")
            if "root" in policies:
                add_finding(
                    title="Vault ROOT token discovered",
                    severity="critical",
                    details="Token has root policy -- full Vault access",
                    evidence=f"Policies: {policies}",
                    remediation="Never use root tokens in production; create scoped tokens.",
                )
        except Exception:
            pass

    # Try common secret paths
    secret_paths = [
        "v1/secret/data/cloud/aws",
        "v1/secret/data/cloud/gcp",
        "v1/secret/data/ci/github",
        "v1/secret/data/app/database",
        "v1/secret/metadata",
    ]
    rows: list[list[str]] = []
    for sp in secret_paths:
        resp = make_request(f"{vault_base}/{sp}", headers=headers)
        accessible = resp is not None and resp.status_code == 200
        rows.append([sp, "YES" if accessible else "NO"])
        if accessible:
            add_finding(
                title=f"Vault secret path accessible: {sp}",
                severity="high",
                details=f"Token can read {sp}",
                evidence=f"HTTP {resp.status_code}",
                remediation="Restrict Vault policies to minimum required paths.",
            )

    console.print(
        format_table("Vault Secret Path Access", ["Path", "Accessible"], rows)
    )


def _enumerate_k8s_permissions(
    credential: str, target: str, dashboard_url: str | None
) -> None:
    """Enumerate Kubernetes service account permissions."""
    console.print("[bold]Kubernetes SA Token Enumeration[/bold]\n")
    console.print(
        "[dim]Use 'nhi-recon discover kubernetes' for full K8s enumeration.[/dim]"
    )
    console.print(f"  Token prefix: {credential[:30]}...")
    cred_type = detect_credential_type(credential)
    add_finding(
        title="Kubernetes service account token",
        severity="high",
        details=f"Detected type: {cred_type}",
        evidence=f"Token prefix: {credential[:30]}...",
        remediation="Use bound SA tokens with projected volumes.",
    )


def _enumerate_gcp_permissions(
    credential: str, target: str, dashboard_url: str | None
) -> None:
    """Enumerate GCP access token permissions."""
    console.print("[bold]GCP Access Token Enumeration[/bold]\n")

    gcp_base = f"http://{target}:1339"
    gcp_headers = {"Metadata-Flavor": "Google"}

    # Project info
    resp = make_request(
        f"{gcp_base}/computeMetadata/v1/project/project-id", headers=gcp_headers
    )
    if resp and resp.status_code == 200:
        console.print(f"  Project: [cyan]{resp.text}[/cyan]")

    # Service accounts
    resp = make_request(
        f"{gcp_base}/computeMetadata/v1/instance/service-accounts/",
        headers=gcp_headers,
    )
    if resp and resp.status_code == 200:
        accounts = [a.strip().rstrip("/") for a in resp.text.split("\n") if a.strip()]
        console.print(f"  Service accounts: [yellow]{accounts}[/yellow]")

        for acct in accounts:
            # Scopes
            scopes_resp = make_request(
                f"{gcp_base}/computeMetadata/v1/instance/service-accounts/{acct}/scopes",
                headers=gcp_headers,
            )
            if scopes_resp and scopes_resp.status_code == 200:
                scopes = [s.strip() for s in scopes_resp.text.split("\n") if s.strip()]
                dangerous = [s for s in scopes if "cloud-platform" in s or "admin" in s]
                if dangerous:
                    add_finding(
                        title=f"Overpermissioned GCP SA: {acct}",
                        severity="critical",
                        details=f"SA has broad scopes: {dangerous}",
                        evidence=f"All scopes: {scopes}",
                        remediation="Use minimum required OAuth scopes.",
                    )

    add_finding(
        title="GCP access token enumerated",
        severity="high",
        details=f"Token prefix: {credential[:16]}...",
        evidence="GCP metadata service reachable",
        remediation="Restrict metadata service access; use Workload Identity.",
    )


def _enumerate_generic(
    credential: str, target: str, dashboard_url: str | None
) -> None:
    """Generic enumeration for unknown credential types."""
    console.print("[bold]Generic Credential Enumeration[/bold]\n")
    console.print(f"  Value: {credential[:20]}...")
    add_finding(
        title="Unknown credential type",
        severity="medium",
        details="Could not auto-detect credential type. Manual analysis required.",
        evidence=f"Prefix: {credential[:20]}...",
        remediation="Identify the credential owner and rotate immediately.",
    )


# -------------------------------------------------------------------
# services
# -------------------------------------------------------------------

@enumerate_group.command()
@click.option("--target", "-t", required=True, help="Target host to scan")
@click.pass_context
def services(ctx: click.Context, target: str) -> None:
    """Enumerate accessible NHI-related services from current identity."""
    dashboard_url = ctx.obj.get("dashboard_url") if ctx.obj else None
    console.rule("[bold]NHI Service Enumeration[/bold]")
    console.print(f"Target: [cyan]{target}[/cyan]\n")

    rows: list[list[str]] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        for probe in _SERVICE_PROBES:
            name = probe["name"]
            port = probe["port"]
            scheme = probe.get("scheme", "http")
            path = probe["path"]
            headers = probe.get("headers", {})

            task = progress.add_task(f"Probing {name} ({port}) ...", total=None)
            url = f"{scheme}://{target}:{port}{path}"
            resp = make_request(url, headers=headers, timeout=5.0)
            progress.update(task, completed=True)

            if resp is not None:
                status = resp.status_code
                reachable = status < 500
                body_preview = resp.text[:80].replace("\n", " ") if reachable else ""
                rows.append([
                    name,
                    str(port),
                    str(status),
                    "[green]YES[/green]" if reachable else "[red]NO[/red]",
                    body_preview,
                ])
                if reachable:
                    add_finding(
                        title=f"Service reachable: {name}",
                        severity="medium",
                        details=f"{name} on port {port} is accessible",
                        evidence=f"HTTP {status}: {body_preview[:60]}",
                        remediation=f"Restrict network access to {name}.",
                    )
            else:
                rows.append([name, str(port), "N/A", "[dim]TIMEOUT[/dim]", ""])

    console.print(
        format_table(
            "NHI Service Scan Results",
            ["Service", "Port", "Status", "Reachable", "Response Preview"],
            rows,
        )
    )

    post_to_dashboard(
        dashboard_url,
        "enumerate.services",
        {"target": target, "services_found": sum(1 for r in rows if "YES" in r[3])},
    )
    console.rule("[bold green]Service Enumeration Complete[/bold green]")
