"""Report generation module -- produce assessment reports in multiple formats."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import click
from jinja2 import Environment, FileSystemLoader
from rich.panel import Panel

from nhi_recon.utils import (
    Finding,
    console,
    findings as global_findings,
)

_TEMPLATE_DIR = Path(__file__).parent / "templates"


# ===================================================================
# Click group
# ===================================================================

@click.group()
def report() -> None:
    """Generate assessment reports."""


# -------------------------------------------------------------------
# generate
# -------------------------------------------------------------------

@report.command()
@click.option(
    "--format",
    "-f",
    "fmt",
    type=click.Choice(["html", "json", "sarif"]),
    default="json",
    help="Output format.",
)
@click.option("--output", "-o", "output_path", default="nhi-report", help="Output file base name.")
@click.pass_context
def generate(ctx: click.Context, fmt: str, output_path: str) -> None:
    """Generate NHI security assessment report from collected findings."""
    console.rule("[bold]Report Generation[/bold]")

    if not global_findings:
        console.print(
            "[yellow]No findings collected yet. Run discover/enumerate/chain "
            "commands first, then generate a report.[/yellow]"
        )
        return

    findings_data = [f.to_dict() for f in global_findings]
    report_meta = _build_metadata(findings_data)

    if fmt == "json":
        _generate_json(findings_data, report_meta, output_path)
    elif fmt == "html":
        _generate_html(findings_data, report_meta, output_path)
    elif fmt == "sarif":
        _generate_sarif(findings_data, report_meta, output_path)

    console.rule("[bold green]Report Generation Complete[/bold green]")


# -------------------------------------------------------------------
# Internal helpers
# -------------------------------------------------------------------

def _build_metadata(findings_data: list[dict[str, Any]]) -> dict[str, Any]:
    """Build report metadata / executive summary."""
    severity_counts = {}
    for f in findings_data:
        sev = f.get("severity", "info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    total = len(findings_data)
    critical = severity_counts.get("critical", 0)
    high = severity_counts.get("high", 0)

    # Simple risk score: critical=10, high=5, medium=3, low=1
    weights = {"critical": 10, "high": 5, "medium": 3, "low": 1, "info": 0}
    risk_score = sum(weights.get(f.get("severity", "info"), 0) for f in findings_data)
    max_score = total * 10 if total else 1
    risk_pct = min(100, int((risk_score / max_score) * 100))

    if risk_pct >= 75:
        risk_label = "CRITICAL"
    elif risk_pct >= 50:
        risk_label = "HIGH"
    elif risk_pct >= 25:
        risk_label = "MEDIUM"
    else:
        risk_label = "LOW"

    return {
        "title": "NHI Security Assessment Report",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tool": "nhi-recon",
        "tool_version": "0.1.0",
        "total_findings": total,
        "severity_counts": severity_counts,
        "risk_score": risk_score,
        "risk_percentage": risk_pct,
        "risk_label": risk_label,
    }


def _generate_json(
    findings_data: list[dict[str, Any]],
    meta: dict[str, Any],
    output_path: str,
) -> None:
    """Write JSON report."""
    filepath = f"{output_path}.json"
    payload = {
        "metadata": meta,
        "findings": findings_data,
    }
    Path(filepath).write_text(json.dumps(payload, indent=2))
    console.print(f"  JSON report written to: [cyan]{filepath}[/cyan]")
    console.print(
        Panel(
            f"Total findings: {meta['total_findings']}\n"
            f"Risk: [bold]{meta['risk_label']}[/bold] ({meta['risk_percentage']}%)",
            title="Summary",
        )
    )


def _generate_html(
    findings_data: list[dict[str, Any]],
    meta: dict[str, Any],
    output_path: str,
) -> None:
    """Render HTML report via Jinja2 template."""
    filepath = f"{output_path}.html"
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=True,
    )
    template = env.get_template("report.html.j2")
    html = template.render(meta=meta, findings=findings_data)
    Path(filepath).write_text(html)
    console.print(f"  HTML report written to: [cyan]{filepath}[/cyan]")


def _generate_sarif(
    findings_data: list[dict[str, Any]],
    meta: dict[str, Any],
    output_path: str,
) -> None:
    """Generate SARIF (Static Analysis Results Interchange Format) report.

    SARIF is consumed by GitHub Code Scanning, Azure DevOps, and other CI/CD
    platforms for inline security findings.
    """
    filepath = f"{output_path}.sarif"

    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []

    severity_to_sarif = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }

    seen_rule_ids: set[str] = set()
    for idx, f in enumerate(findings_data):
        rule_id = f"NHI{idx + 1:04d}"
        title = f.get("title", "Unknown")

        if rule_id not in seen_rule_ids:
            seen_rule_ids.add(rule_id)
            rules.append({
                "id": rule_id,
                "name": title.replace(" ", ""),
                "shortDescription": {"text": title},
                "fullDescription": {"text": f.get("details", "")},
                "help": {
                    "text": f.get("remediation", "No remediation provided."),
                    "markdown": f"**Remediation:** {f.get('remediation', 'N/A')}",
                },
                "defaultConfiguration": {
                    "level": severity_to_sarif.get(f.get("severity", "info"), "note")
                },
            })

        results.append({
            "ruleId": rule_id,
            "level": severity_to_sarif.get(f.get("severity", "info"), "note"),
            "message": {
                "text": f"{f.get('details', '')} | Evidence: {f.get('evidence', 'N/A')}",
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "nhi-recon-scan"},
                        "region": {"startLine": 1},
                    }
                }
            ],
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "nhi-recon",
                        "version": meta.get("tool_version", "0.1.0"),
                        "informationUri": "https://github.com/yourorg/nhi-security-testbed",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }

    Path(filepath).write_text(json.dumps(sarif, indent=2))
    console.print(f"  SARIF report written to: [cyan]{filepath}[/cyan]")
    console.print(
        f"  [dim]Compatible with GitHub Code Scanning, Azure DevOps, SARIF Viewer.[/dim]"
    )
