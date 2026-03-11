"""Shared utilities for nhi-recon."""

from __future__ import annotations

import re
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any

import httpx
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# ---------------------------------------------------------------------------
# Global Rich console
# ---------------------------------------------------------------------------
console = Console()

# ---------------------------------------------------------------------------
# Finding model
# ---------------------------------------------------------------------------
SEVERITY_COLOURS = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}


@dataclass
class Finding:
    """A single reconnaissance finding."""

    title: str
    severity: str  # critical | high | medium | low | info
    details: str
    evidence: str = ""
    remediation: str = ""
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# Global store for findings accumulated during a session.
findings: list[Finding] = []


def add_finding(
    title: str,
    severity: str,
    details: str,
    evidence: str = "",
    remediation: str = "",
) -> Finding:
    """Create a finding, store it, and print a summary panel."""
    f = Finding(
        title=title,
        severity=severity.lower(),
        details=details,
        evidence=evidence,
        remediation=remediation,
    )
    findings.append(f)
    colour = SEVERITY_COLOURS.get(f.severity, "white")
    console.print(
        Panel(
            f"[bold]{f.title}[/bold]\n"
            f"Severity: [{colour}]{f.severity.upper()}[/{colour}]\n\n"
            f"{f.details}\n"
            + (f"\n[dim]Evidence:[/dim] {f.evidence}" if f.evidence else ""),
            border_style=colour,
            title="Finding",
            title_align="left",
        )
    )
    return f


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def make_request(
    url: str,
    method: str = "GET",
    *,
    headers: dict[str, str] | None = None,
    json_body: Any | None = None,
    timeout: float = 10.0,
    raise_on_error: bool = False,
) -> httpx.Response | None:
    """Make an HTTP request and return the response, or None on error."""
    try:
        with httpx.Client(timeout=timeout, verify=False) as client:  # noqa: S501
            resp = client.request(
                method, url, headers=headers, json=json_body
            )
            if raise_on_error:
                resp.raise_for_status()
            return resp
    except httpx.HTTPStatusError:
        raise
    except Exception as exc:
        console.print(f"[dim]Request to {url} failed: {exc}[/dim]")
        return None


def post_to_dashboard(
    dashboard_url: str | None,
    event_type: str,
    data: dict[str, Any],
) -> None:
    """POST an event to the dashboard API for live visualization."""
    if not dashboard_url:
        return
    payload = {
        "event_type": event_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": data,
    }
    try:
        make_request(
            f"{dashboard_url.rstrip('/')}/api/events",
            method="POST",
            json_body=payload,
            timeout=5.0,
        )
    except Exception:
        pass  # best-effort; do not crash if dashboard is down


# ---------------------------------------------------------------------------
# Credential type detection
# ---------------------------------------------------------------------------

_CREDENTIAL_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS Access Key", re.compile(r"^(AKIA|ASIA)[A-Z0-9]{16}$")),
    ("AWS Secret Key", re.compile(r"^[A-Za-z0-9/+=]{40}$")),
    ("GitHub Token (classic)", re.compile(r"^ghp_[A-Za-z0-9]{36}$")),
    ("GitHub Token (fine-grained)", re.compile(r"^github_pat_[A-Za-z0-9_]{22,}")),
    ("GitHub Actions Token", re.compile(r"^ghs_[A-Za-z0-9]{36}$")),
    ("GitLab Token", re.compile(r"^gl[a-z]{2,4}-[A-Za-z0-9_-]{20,}")),
    ("OpenAI API Key", re.compile(r"^sk-[A-Za-z0-9]{20,}")),
    ("Vault Token", re.compile(r"^hvs\.[A-Za-z0-9]{20,}")),
    ("K8s Service Account Token", re.compile(r"^eyJhbGciOi")),
    ("SPIFFE ID", re.compile(r"^spiffe://")),
    ("GCP Access Token", re.compile(r"^ya29\.[A-Za-z0-9_-]+")),
    ("Azure DevOps PAT", re.compile(r"^[a-z0-9]{52}$")),
    ("Generic JWT", re.compile(r"^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+")),
]


def detect_credential_type(value: str) -> str:
    """Auto-detect credential type from its value pattern."""
    value = value.strip()
    for name, pattern in _CREDENTIAL_PATTERNS:
        if pattern.match(value):
            return name
    return "Unknown"


def format_table(title: str, columns: list[str], rows: list[list[str]]) -> Table:
    """Build a Rich table quickly."""
    table = Table(title=title, show_lines=True)
    for col in columns:
        table.add_column(col)
    for row in rows:
        table.add_row(*row)
    return table
