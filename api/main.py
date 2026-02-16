"""NHI Security Testbed API — FastAPI application."""

from contextlib import asynccontextmanager

from fastapi import FastAPI

from api.config import settings
from api.routes import alerts, health, rules, scenarios
from api.services.scenario_loader import scenario_loader
from api.services.wazuh_client import wazuh_client


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle."""
    scenario_loader.load_all()
    yield
    await wazuh_client.close()


app = FastAPI(
    title=settings.app_name,
    description=(
        "REST API for the NHI Machine Identity Security Testbed. "
        "Execute attack scenarios, query detection rules, and monitor Wazuh alerts."
    ),
    version=settings.version,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# Routes already define their own prefix and tags
app.include_router(health.router)
app.include_router(scenarios.router)
app.include_router(rules.router)
app.include_router(alerts.router)


@app.get("/", tags=["root"])
async def root():
    """API root — basic info and endpoint directory."""
    return {
        "name": settings.app_name,
        "version": settings.version,
        "docs": "/docs",
        "endpoints": {
            "health": "/health",
            "scenarios": "/scenarios",
            "rules": "/rules",
            "alerts": "/alerts",
        },
    }
