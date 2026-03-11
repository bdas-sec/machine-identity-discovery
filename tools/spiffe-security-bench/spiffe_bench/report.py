"""Report generation for spiffe-security-bench.

Supports three output formats:
  - text: Rich-formatted table with color-coded status, severity, and remediation
  - json: Machine-readable JSON to stdout
  - yaml: Machine-readable YAML to stdout
"""

import json
from typing import Optional

import yaml
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .checks import CheckResult


def generate_report(
    results: list[CheckResult],
    output_format: str = "text",
    console: Optional[Console] = None,
):
    """Generate benchmark report in the specified format."""
    if output_format == "json":
        _json_report(results)
    elif output_format == "yaml":
        _yaml_report(results)
    else:
        _text_report(results, console or Console())


def _text_report(results: list[CheckResult], console: Console):
    """Rich text report with table, remediation, and score."""
    passed = sum(1 for r in results if r.status == "PASS")
    failed = sum(1 for r in results if r.status == "FAIL")
    warned = sum(1 for r in results if r.status == "WARN")
    skipped = sum(1 for r in results if r.status == "SKIP")

    console.print()
    console.print(
        Panel(
            f"[green]{passed} PASS[/green]  [red]{failed} FAIL[/red]  "
            f"[yellow]{warned} WARN[/yellow]  [dim]{skipped} SKIP[/dim]",
            title="[bold]SPIFFE Security Bench Results[/bold]",
            border_style="purple",
        )
    )
    console.print()

    # Results table
    table = Table(show_header=True, header_style="bold")
    table.add_column("ID", width=8)
    table.add_column("Status", width=6)
    table.add_column("Severity", width=10)
    table.add_column("Check", width=35)
    table.add_column("Attack Vector", width=25)
    table.add_column("Details", width=50)

    status_colors = {
        "PASS": "green",
        "FAIL": "red",
        "WARN": "yellow",
        "INFO": "blue",
        "SKIP": "dim",
    }
    severity_colors = {
        "critical": "red",
        "high": "orange3",
        "medium": "yellow",
        "low": "blue",
    }

    for r in results:
        sc = status_colors.get(r.status, "white")
        sev_c = severity_colors.get(r.severity, "white")
        table.add_row(
            r.id,
            f"[{sc}]{r.status}[/{sc}]",
            f"[{sev_c}]{r.severity.upper()}[/{sev_c}]",
            r.title,
            r.attack_vector,
            r.details[:50] if r.details else "",
        )

    console.print(table)

    # Remediation recommendations for failures and warnings
    failures = [r for r in results if r.status in ("FAIL", "WARN")]
    if failures:
        console.print()
        console.print("[bold]Remediation Recommendations:[/bold]")
        for r in failures:
            if r.status == "FAIL":
                icon = "[red]x[/red]"
            else:
                icon = "[yellow]![/yellow]"
            console.print(f"  {icon} {r.id}: {r.remediation}")
            if r.evidence:
                for e in r.evidence[:3]:
                    console.print(f"    [dim]Evidence: {e}[/dim]")

    # Security score
    total = len([r for r in results if r.status != "SKIP"])
    score = (passed / total * 100) if total > 0 else 0
    if score >= 80:
        color = "green"
    elif score >= 60:
        color = "yellow"
    else:
        color = "red"

    console.print()
    console.print(
        f"[bold]Security Score: [{color}]{score:.0f}%[/{color}][/bold] "
        f"({passed}/{total} checks passed)"
    )


def _json_report(results: list[CheckResult]):
    """JSON report to stdout."""
    data = {
        "tool": "spiffe-security-bench",
        "version": "0.1.0",
        "summary": {
            "total": len(results),
            "passed": sum(1 for r in results if r.status == "PASS"),
            "failed": sum(1 for r in results if r.status == "FAIL"),
            "warned": sum(1 for r in results if r.status == "WARN"),
            "skipped": sum(1 for r in results if r.status == "SKIP"),
        },
        "checks": [
            {
                "id": r.id,
                "title": r.title,
                "attack_vector": r.attack_vector,
                "status": r.status,
                "severity": r.severity,
                "details": r.details,
                "remediation": r.remediation,
                "mitre_ref": r.mitre_ref,
                "evidence": r.evidence,
            }
            for r in results
        ],
    }
    print(json.dumps(data, indent=2))


def _yaml_report(results: list[CheckResult]):
    """YAML report to stdout."""
    data = {
        "tool": "spiffe-security-bench",
        "version": "0.1.0",
        "summary": {
            "total": len(results),
            "passed": sum(1 for r in results if r.status == "PASS"),
            "failed": sum(1 for r in results if r.status == "FAIL"),
            "warned": sum(1 for r in results if r.status == "WARN"),
            "skipped": sum(1 for r in results if r.status == "SKIP"),
        },
        "checks": [
            {
                "id": r.id,
                "title": r.title,
                "attack_vector": r.attack_vector,
                "status": r.status,
                "severity": r.severity,
                "details": r.details,
                "remediation": r.remediation,
                "mitre_ref": r.mitre_ref,
            }
            for r in results
        ],
    }
    print(yaml.dump(data, default_flow_style=False, sort_keys=False))
