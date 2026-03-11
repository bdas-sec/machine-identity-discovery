"""CLI entry point for spiffe-security-bench."""

import click
from rich.console import Console

from .checks import run_all_checks
from .report import generate_report

console = Console()


@click.command()
@click.option(
    "--spire-server",
    default="localhost:8081",
    help="SPIRE Server API address",
)
@click.option(
    "--spire-agent-socket",
    default="/tmp/spire-agent/public/api.sock",
    help="SPIRE Agent socket path",
)
@click.option(
    "--server-socket",
    default="/tmp/spire-server/private/api.sock",
    help="SPIRE Server admin socket path",
)
@click.option(
    "--output",
    "-o",
    type=click.Choice(["text", "json", "yaml"]),
    default="text",
    help="Output format",
)
@click.option(
    "--check",
    "-c",
    multiple=True,
    help="Run specific check(s) by ID (e.g. SSB-01). Can be repeated.",
)
@click.option("--verbose", "-v", is_flag=True, help="Show verbose output")
def cli(spire_server, spire_agent_socket, server_socket, output, check, verbose):
    """Security benchmark for SPIFFE/SPIRE deployments.

    Audits a SPIRE deployment against 10 known attack vectors
    and produces a PASS/FAIL/WARN report. Analogous to kube-bench
    for Kubernetes, but focused on SPIFFE/SPIRE identity infrastructure.

    \b
    Checks cover:
      SSB-01  Weak Workload Selectors
      SSB-02  SVID Private Key Protection
      SSB-03  Registration Entry Integrity
      SSB-04  Overlapping Selector Detection
      SSB-05  JWT-SVID Validation
      SSB-06  Delegated Identity API Access
      SSB-07  Container Escape to SPIRE Socket
      SSB-08  Trust Bundle Integrity
      SSB-09  Agent Attestation Security
      SSB-10  Kubelet Verification
    """
    console.print("[bold purple]SPIFFE Security Bench v0.1.0[/bold purple]")
    console.print(f"Target: {spire_server}")
    console.print()

    results = run_all_checks(
        spire_server=spire_server,
        agent_socket=spire_agent_socket,
        server_socket=server_socket,
        selected=list(check) if check else None,
        verbose=verbose,
    )

    generate_report(results, output_format=output, console=console)
