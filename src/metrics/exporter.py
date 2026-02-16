#!/usr/bin/env python3
"""
NHI Security Testbed - Prometheus Metrics Exporter
NDC Security 2026 - "Who Gave the Agent Admin Rights?!"

Exposes Prometheus-format metrics at /metrics for detection coverage,
scenario execution, alert latency, and service health monitoring.

Endpoints:
- /metrics   - Prometheus text format metrics
- /health    - Health check for Docker/Compose

Periodically polls the Wazuh Manager API to collect live data on
alerts, rules, and connected agents.
"""

import os
import json
import time
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path

import httpx
from flask import Flask, Response, jsonify
from prometheus_client import (
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
    CONTENT_TYPE_LATEST,
)

app = Flask(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("nhi-metrics")

# ============================================================
# Configuration from environment
# ============================================================
METRICS_PORT = int(os.environ.get("METRICS_PORT", "9091"))
WAZUH_API_URL = os.environ.get("WAZUH_API_URL", "https://wazuh.manager:55000")
WAZUH_API_USER = os.environ.get("WAZUH_API_USER", "wazuh-wui")
WAZUH_API_PASSWORD = os.environ.get("WAZUH_API_PASSWORD", "MyS3cr3tP@ssw0rd")
NHI_API_URL = os.environ.get("NHI_API_URL", "http://nhi-api:8000")
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL_SECONDS", "30"))
SCENARIOS_DIR = os.environ.get("SCENARIOS_DIR", "/app/scenarios")

# ============================================================
# Prometheus metrics registry
# ============================================================
registry = CollectorRegistry()

# Service health gauges (1 = up, 0 = down)
service_up = Gauge(
    "nhi_service_up",
    "Whether a testbed service is reachable (1=up, 0=down)",
    ["service"],
    registry=registry,
)

# Scenario run counters
scenario_runs_total = Counter(
    "nhi_scenario_runs_total",
    "Total scenario executions",
    ["scenario_id", "status"],
    registry=registry,
)

# Rule fire counts (populated from Wazuh alerts)
rule_fires_total = Counter(
    "nhi_rule_fires_total",
    "Total alert fires per Wazuh rule",
    ["rule_id", "description", "level"],
    registry=registry,
)

# Alert latency histogram (seconds between event generation and alert)
alert_latency = Histogram(
    "nhi_alert_latency_seconds",
    "Latency from event to Wazuh alert in seconds",
    buckets=[0.5, 1, 2, 5, 10, 20, 30, 60, 120],
    registry=registry,
)

# Detection coverage ratio
detection_coverage = Gauge(
    "nhi_detection_coverage_ratio",
    "Fraction of scenarios with at least one triggered rule",
    registry=registry,
)

# Active Wazuh agents
agents_active = Gauge(
    "nhi_wazuh_agents_active",
    "Number of Wazuh agents in Active state",
    registry=registry,
)

# Total registered agents
agents_total = Gauge(
    "nhi_wazuh_agents_total",
    "Total registered Wazuh agents",
    registry=registry,
)

# Total alerts observed since exporter start
alerts_total = Gauge(
    "nhi_alerts_total",
    "Total number of alerts observed in Wazuh",
    registry=registry,
)

# Rule counts by group
rule_fires_by_group = Gauge(
    "nhi_rule_fires_by_group",
    "Alert counts aggregated by rule group",
    ["group"],
    registry=registry,
)

# Exporter metadata
exporter_scrape_duration = Histogram(
    "nhi_exporter_scrape_duration_seconds",
    "Time taken to scrape data from Wazuh API",
    buckets=[0.1, 0.5, 1, 2, 5, 10, 30],
    registry=registry,
)

exporter_scrape_errors = Counter(
    "nhi_exporter_scrape_errors_total",
    "Number of failed scrapes from Wazuh API",
    registry=registry,
)

exporter_info = Gauge(
    "nhi_exporter_info",
    "Exporter build information",
    ["version"],
    registry=registry,
)
exporter_info.labels(version="0.1.0").set(1)


# ============================================================
# Wazuh API client (synchronous, using httpx)
# ============================================================
class WazuhMetricsClient:
    """Synchronous Wazuh API client for the metrics collector."""

    def __init__(self, base_url: str, username: str, password: str):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self._token: str | None = None
        self._token_ts: float = 0

    def _get_client(self) -> httpx.Client:
        return httpx.Client(verify=False, timeout=15)

    def authenticate(self) -> bool:
        """Obtain a JWT token from the Wazuh API."""
        try:
            with self._get_client() as client:
                resp = client.post(
                    f"{self.base_url}/security/user/authenticate",
                    auth=(self.username, self.password),
                )
                if resp.status_code == 200:
                    self._token = resp.json().get("data", {}).get("token")
                    self._token_ts = time.time()
                    return bool(self._token)
        except Exception as exc:
            logger.warning("Wazuh auth failed: %s", exc)
        return False

    def _headers(self) -> dict[str, str]:
        if not self._token or (time.time() - self._token_ts > 780):
            self.authenticate()
        return {"Authorization": f"Bearer {self._token}"}

    def get(self, path: str, params: dict | None = None) -> dict | None:
        """Perform an authenticated GET. Returns parsed JSON or None."""
        try:
            with self._get_client() as client:
                resp = client.get(
                    f"{self.base_url}{path}",
                    headers=self._headers(),
                    params=params,
                )
                if resp.status_code == 401:
                    self.authenticate()
                    resp = client.get(
                        f"{self.base_url}{path}",
                        headers=self._headers(),
                        params=params,
                    )
                resp.raise_for_status()
                return resp.json()
        except Exception as exc:
            logger.debug("Wazuh GET %s failed: %s", path, exc)
            return None

    def is_reachable(self) -> bool:
        """Quick connectivity check."""
        try:
            with self._get_client() as client:
                resp = client.get(f"{self.base_url}/", verify=False, timeout=5)
                return resp.status_code in (200, 401)
        except Exception:
            return False


wazuh = WazuhMetricsClient(WAZUH_API_URL, WAZUH_API_USER, WAZUH_API_PASSWORD)

# ============================================================
# Scenario loading (reads scenario JSON files for coverage calc)
# ============================================================
_scenario_cache: list[dict] | None = None


def load_scenarios() -> list[dict]:
    """Load all scenario definitions from disk (cached)."""
    global _scenario_cache
    if _scenario_cache is not None:
        return _scenario_cache

    scenarios = []
    base = Path(SCENARIOS_DIR)
    if not base.exists():
        logger.warning("Scenarios directory not found: %s", SCENARIOS_DIR)
        return scenarios

    for fpath in sorted(base.rglob("*.json")):
        try:
            with open(fpath) as f:
                scenarios.append(json.load(f))
        except Exception as exc:
            logger.warning("Failed to load scenario %s: %s", fpath, exc)

    _scenario_cache = scenarios
    logger.info("Loaded %d scenario definitions", len(scenarios))
    return scenarios


# ============================================================
# Metrics collection logic
# ============================================================

# Internal state for incremental counter tracking
_last_rule_fire_counts: dict[str, float] = {}


def collect_service_health():
    """Probe testbed services and set health gauges."""
    checks = {
        "wazuh-manager": (WAZUH_API_URL.replace("https://", "").replace("http://", "").split(":")[0], True),
        "nhi-api": (NHI_API_URL, False),
    }

    # Wazuh Manager
    service_up.labels(service="wazuh-manager").set(1 if wazuh.is_reachable() else 0)

    # NHI API
    try:
        with httpx.Client(timeout=5) as client:
            resp = client.get(f"{NHI_API_URL}/health")
            service_up.labels(service="nhi-api").set(1 if resp.status_code == 200 else 0)
    except Exception:
        service_up.labels(service="nhi-api").set(0)


def collect_agent_metrics():
    """Fetch agent list and update gauges."""
    data = wazuh.get("/agents", {"limit": 100})
    if not data:
        return

    items = data.get("data", {}).get("affected_items", [])
    active = sum(1 for a in items if a.get("status") == "active")
    agents_active.set(active)
    agents_total.set(len(items))


def collect_alert_metrics():
    """Fetch recent alerts and update rule fire counters and latency."""
    data = wazuh.get("/alerts", {"limit": 500, "sort": "-timestamp"})
    if not data:
        return

    total = data.get("data", {}).get("total_affected_items", 0)
    alerts_total.set(total)

    items = data.get("data", {}).get("affected_items", [])

    # Aggregate rule fires
    rule_counts: dict[tuple[str, str, str], int] = {}
    group_counts: dict[str, int] = {}

    for alert in items:
        rule = alert.get("rule", {})
        rid = str(rule.get("id", ""))
        desc = rule.get("description", "")
        level = str(rule.get("level", ""))
        groups = rule.get("groups", [])

        key = (rid, desc, level)
        rule_counts[key] = rule_counts.get(key, 0) + 1

        for g in groups:
            group_counts[g] = group_counts.get(g, 0) + 1

        # Attempt to compute alert latency from timestamp
        ts_str = alert.get("timestamp")
        if ts_str:
            try:
                alert_time = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                latency = (datetime.now(timezone.utc) - alert_time).total_seconds()
                if 0 < latency < 3600:
                    alert_latency.observe(latency)
            except Exception:
                pass

    # Update rule fire counters (increment by new fires since last scrape)
    for (rid, desc, level), count in rule_counts.items():
        cache_key = f"{rid}:{desc}"
        prev = _last_rule_fire_counts.get(cache_key, 0)
        delta = max(0, count - prev)
        if delta > 0:
            rule_fires_total.labels(rule_id=rid, description=desc, level=level).inc(delta)
        _last_rule_fire_counts[cache_key] = count

    # Update group gauges
    for group, count in group_counts.items():
        rule_fires_by_group.labels(group=group).set(count)


def collect_detection_coverage():
    """Compute detection coverage ratio: scenarios with triggered rules / total."""
    scenarios = load_scenarios()
    if not scenarios:
        detection_coverage.set(0)
        return

    data = wazuh.get("/alerts", {"limit": 500, "sort": "-timestamp"})
    if not data:
        detection_coverage.set(0)
        return

    items = data.get("data", {}).get("affected_items", [])
    fired_rule_ids = {str(a.get("rule", {}).get("id", "")) for a in items}

    covered = 0
    for scenario in scenarios:
        expected = scenario.get("expected_wazuh_alerts", [])
        if not expected:
            continue
        expected_ids = {str(e.get("rule_id", "")) for e in expected}
        if fired_rule_ids & expected_ids:
            covered += 1

    total_with_rules = sum(
        1 for s in scenarios if s.get("expected_wazuh_alerts")
    )
    if total_with_rules > 0:
        detection_coverage.set(covered / total_with_rules)
    else:
        detection_coverage.set(0)


def run_collection():
    """Execute one full collection cycle."""
    start = time.time()
    try:
        collect_service_health()
        collect_agent_metrics()
        collect_alert_metrics()
        collect_detection_coverage()
        elapsed = time.time() - start
        exporter_scrape_duration.observe(elapsed)
        logger.info("Collection cycle completed in %.2fs", elapsed)
    except Exception as exc:
        exporter_scrape_errors.inc()
        logger.error("Collection cycle failed: %s", exc)


# ============================================================
# Background collector thread
# ============================================================
def _collector_loop():
    """Runs in a daemon thread, collecting metrics at fixed intervals."""
    logger.info("Background collector started (interval=%ds)", POLL_INTERVAL)
    while True:
        run_collection()
        time.sleep(POLL_INTERVAL)


# ============================================================
# Flask routes
# ============================================================
@app.route("/metrics")
def metrics():
    """Prometheus metrics endpoint."""
    return Response(
        generate_latest(registry),
        mimetype=CONTENT_TYPE_LATEST,
    )


@app.route("/health")
def health():
    """Health check endpoint."""
    return jsonify({
        "status": "healthy",
        "service": "nhi-metrics-exporter",
        "wazuh_reachable": wazuh.is_reachable(),
    })


@app.route("/")
def root():
    """Root endpoint with service information."""
    return jsonify({
        "service": "NHI Security Testbed Metrics Exporter",
        "version": "0.1.0",
        "endpoints": {
            "/metrics": "Prometheus text format metrics",
            "/health": "Health check",
        },
    })


# ============================================================
# Record scenario run (called by the NHI API or demo runner)
# ============================================================
@app.route("/record/scenario", methods=["POST"])
def record_scenario_run():
    """
    Record a scenario execution result.

    Expected JSON body:
        {"scenario_id": "s2-01", "status": "success"|"failure"|"error"}
    """
    from flask import request

    data = request.get_json(silent=True) or {}
    sid = data.get("scenario_id", "unknown")
    status = data.get("status", "unknown")
    scenario_runs_total.labels(scenario_id=sid, status=status).inc()
    return jsonify({"recorded": True, "scenario_id": sid, "status": status})


# ============================================================
# Entry point
# ============================================================
if __name__ == "__main__":
    print("=" * 60)
    print("NHI Security Testbed - Prometheus Metrics Exporter")
    print("NDC Security 2026")
    print("=" * 60)
    print()
    print(f"Wazuh API:       {WAZUH_API_URL}")
    print(f"NHI API:         {NHI_API_URL}")
    print(f"Metrics port:    {METRICS_PORT}")
    print(f"Poll interval:   {POLL_INTERVAL}s")
    print(f"Scenarios dir:   {SCENARIOS_DIR}")
    print()
    print("Endpoints:")
    print(f"  http://localhost:{METRICS_PORT}/metrics")
    print(f"  http://localhost:{METRICS_PORT}/health")
    print("=" * 60)

    # Start background collector
    collector_thread = threading.Thread(target=_collector_loop, daemon=True)
    collector_thread.start()

    app.run(host="0.0.0.0", port=METRICS_PORT, debug=False)
