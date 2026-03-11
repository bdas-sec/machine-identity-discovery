"""Dashboard REST endpoints."""

import logging
from typing import Any

from fastapi import APIRouter

from api.services.scenario_loader import scenario_loader
from api.services.wazuh_client import wazuh_client

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/dashboard", tags=["dashboard"])

# In-memory dashboard state (reset on restart)
_state: dict[str, Any] = {
    "scenarios_run": 0,
    "alerts_generated": 0,
    "detection_rate": 0.0,
    "active_scenario": None,
    "current_phase": 0,
    "total_phases": 0,
}


@router.get("/state")
async def get_dashboard_state() -> dict[str, Any]:
    """Get current dashboard state."""
    return _state


@router.post("/state/reset")
async def reset_dashboard_state():
    """Reset dashboard counters."""
    _state.update({
        "scenarios_run": 0,
        "alerts_generated": 0,
        "detection_rate": 0.0,
        "active_scenario": None,
        "current_phase": 0,
        "total_phases": 0,
    })
    return {"status": "reset"}


@router.get("/mitre-coverage")
async def get_mitre_coverage() -> dict[str, Any]:
    """Get MITRE ATT&CK technique coverage from loaded scenarios."""
    scenarios = scenario_loader.list_all()
    coverage: dict[str, dict] = {}

    for scenario in scenarios:
        mitre = scenario.get("mitre_attack", {})
        tactics = mitre.get("tactics", [])
        techniques = mitre.get("techniques", [])

        for tech in techniques:
            tech_id = tech.get("id", "")
            if tech_id not in coverage:
                coverage[tech_id] = {
                    "technique_id": tech_id,
                    "technique_name": tech.get("name", ""),
                    "tactics": list(set(tactics)),
                    "count": 0,
                    "scenarios": [],
                }
            coverage[tech_id]["count"] += 1
            coverage[tech_id]["scenarios"].append(scenario.get("id", ""))
            # Merge tactics
            for t in tactics:
                if t not in coverage[tech_id]["tactics"]:
                    coverage[tech_id]["tactics"].append(t)

    return {
        "total_techniques": len(coverage),
        "techniques": list(coverage.values()),
    }


@router.get("/topology")
async def get_topology() -> dict[str, Any]:
    """Get network topology for visualization."""
    nodes = [
        {"id": "vulnerable-app", "label": "Vulnerable App", "zone": "cloud", "type": "service"},
        {"id": "cloud-workload", "label": "Cloud Workload", "zone": "cloud", "type": "agent"},
        {"id": "mock-imds", "label": "Mock IMDS", "zone": "cloud", "type": "service"},
        {"id": "vault", "label": "HashiCorp Vault", "zone": "cloud", "type": "service"},
        {"id": "ai-agent", "label": "AI Agent", "zone": "cloud", "type": "agent"},
        {"id": "cicd-runner", "label": "CI/CD Runner", "zone": "cicd", "type": "agent"},
        {"id": "mock-cicd", "label": "Mock CI/CD Server", "zone": "cicd", "type": "service"},
        {"id": "k8s-node-1", "label": "K8s Node 1", "zone": "k8s", "type": "agent"},
        {"id": "spire-server", "label": "SPIRE Server", "zone": "k8s", "type": "service"},
        {"id": "spire-agent", "label": "SPIRE Agent", "zone": "k8s", "type": "service"},
        {"id": "wazuh-manager", "label": "Wazuh Manager", "zone": "mgmt", "type": "service"},
        {"id": "wazuh-indexer", "label": "Wazuh Indexer", "zone": "mgmt", "type": "service"},
        {"id": "wazuh-dashboard", "label": "Wazuh Dashboard", "zone": "mgmt", "type": "service"},
    ]
    links = [
        {"source": "vulnerable-app", "target": "mock-imds", "label": "SSRF"},
        {"source": "cloud-workload", "target": "mock-imds", "label": "IMDS"},
        {"source": "cloud-workload", "target": "vault", "label": "Secrets"},
        {"source": "ai-agent", "target": "vault", "label": "Creds"},
        {"source": "cicd-runner", "target": "mock-cicd", "label": "Pipeline"},
        {"source": "cicd-runner", "target": "cloud-workload", "label": "Pivot"},
        {"source": "k8s-node-1", "target": "spire-server", "label": "SPIFFE"},
        {"source": "spire-agent", "target": "spire-server", "label": "Attestation"},
        {"source": "cloud-workload", "target": "wazuh-manager", "label": "Logs"},
        {"source": "cicd-runner", "target": "wazuh-manager", "label": "Logs"},
        {"source": "k8s-node-1", "target": "wazuh-manager", "label": "Logs"},
        {"source": "wazuh-manager", "target": "wazuh-indexer", "label": "Index"},
    ]
    return {"nodes": nodes, "links": links}


def update_state(
    scenario_id: str | None = None,
    phase: int = 0,
    total: int = 0,
    alerts: int = 0,
    detection_rate: float = 0.0,
):
    """Update dashboard state (called by scenario execution)."""
    if scenario_id:
        _state["active_scenario"] = scenario_id
        _state["current_phase"] = phase
        _state["total_phases"] = total
    if alerts:
        _state["alerts_generated"] += alerts
    if detection_rate:
        _state["detection_rate"] = detection_rate
    if phase == total and total > 0:
        _state["scenarios_run"] += 1
        _state["active_scenario"] = None
