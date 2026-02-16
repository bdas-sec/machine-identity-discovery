"""Health check endpoints."""

import subprocess
from fastapi import APIRouter
from pydantic import BaseModel

from api.config import settings

router = APIRouter(tags=["health"])


class ServiceStatus(BaseModel):
    name: str
    status: str  # "healthy", "unhealthy", "unknown"
    detail: str | None = None


class HealthResponse(BaseModel):
    status: str  # "healthy", "degraded", "unhealthy"
    version: str
    services: list[ServiceStatus]


EXPECTED_CONTAINERS = [
    "wazuh-manager",
    "wazuh-indexer",
    "wazuh-dashboard",
    "cloud-workload",
    "vulnerable-app",
    "cicd-runner",
    "mock-imds",
    "vault",
]


def check_container(runtime: str, name: str) -> ServiceStatus:
    """Check if a container is running and healthy."""
    try:
        result = subprocess.run(
            [runtime, "inspect", "--format", "{{.State.Status}}", name],
            capture_output=True, text=True, timeout=5,
        )
        status = result.stdout.strip()
        if status == "running":
            return ServiceStatus(name=name, status="healthy")
        return ServiceStatus(name=name, status="unhealthy", detail=f"state: {status}")
    except Exception as e:
        return ServiceStatus(name=name, status="unknown", detail=str(e))


@router.get("/health", response_model=HealthResponse)
async def health_check():
    """Check testbed health: container status for all services."""
    runtime = settings.container_runtime
    services = [check_container(runtime, name) for name in EXPECTED_CONTAINERS]

    healthy_count = sum(1 for s in services if s.status == "healthy")
    total = len(services)

    if healthy_count == total:
        overall = "healthy"
    elif healthy_count > 0:
        overall = "degraded"
    else:
        overall = "unhealthy"

    return HealthResponse(
        status=overall,
        version=settings.version,
        services=services,
    )
