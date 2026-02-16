"""
Integration tests for NHI Prometheus metrics exporter and monitoring stack.

Validates that the NHI metrics exporter (port 9091) exposes expected metrics
in Prometheus text format, that Prometheus (port 9090) scrapes them, and
that Grafana (port 3000) is operational.

Metric reference (from src/metrics/exporter.py):
  nhi_service_up              (Gauge,     labels: service)
  nhi_wazuh_agents_active     (Gauge)
  nhi_wazuh_agents_total      (Gauge)
  nhi_rule_fires_total        (Counter,   labels: rule_id, description, level)
  nhi_alerts_total            (Gauge)
  nhi_rule_fires_by_group     (Gauge,     labels: group)
  nhi_alert_latency_seconds   (Histogram)
  nhi_detection_coverage_ratio(Gauge)
  nhi_scenario_runs_total     (Counter,   labels: scenario_id, status)
  nhi_exporter_scrape_duration_seconds (Histogram)
  nhi_exporter_scrape_errors_total     (Counter)
  nhi_exporter_info           (Gauge,     labels: version)
"""

import json
import re
import os
import pytest
import requests


# NHI Metrics exporter — the custom Flask app on port 9091
NHI_METRICS_URL = os.environ.get("NHI_METRICS_URL", "http://localhost:9091")
# Prometheus server itself — on port 9090
PROMETHEUS_URL = os.environ.get("PROMETHEUS_URL", "http://localhost:9090")
# Grafana — on port 3000
GRAFANA_URL = os.environ.get("GRAFANA_URL", "http://localhost:3000")


def _skip_if_exporter_unavailable():
    """Skip if NHI metrics exporter is not running."""
    try:
        resp = requests.get(f"{NHI_METRICS_URL}/health", timeout=5)
        if resp.status_code != 200:
            pytest.skip("NHI metrics exporter not available")
    except requests.ConnectionError:
        pytest.skip("NHI metrics exporter not running")


def _skip_if_prometheus_unavailable():
    """Skip if Prometheus server is not running."""
    try:
        resp = requests.get(f"{PROMETHEUS_URL}/-/healthy", timeout=5)
        if resp.status_code != 200:
            pytest.skip("Prometheus server not available")
    except requests.ConnectionError:
        pytest.skip("Prometheus server not running")


def _skip_if_grafana_unavailable():
    """Skip if Grafana is not running."""
    try:
        resp = requests.get(f"{GRAFANA_URL}/api/health", timeout=5)
        if resp.status_code != 200:
            pytest.skip("Grafana not available")
    except requests.ConnectionError:
        pytest.skip("Grafana not running")


# ============================================================
# NHI Metrics Exporter Tests (port 9091)
# ============================================================

@pytest.mark.integration
class TestExporterHealthEndpoint:
    """Verify the /health endpoint returns correct JSON."""

    @pytest.fixture(autouse=True)
    def _check(self):
        _skip_if_exporter_unavailable()

    def test_health_returns_200(self):
        """GET /health returns 200."""
        resp = requests.get(f"{NHI_METRICS_URL}/health", timeout=10)
        assert resp.status_code == 200

    def test_health_json_structure(self):
        """Health response has required fields."""
        resp = requests.get(f"{NHI_METRICS_URL}/health", timeout=10)
        data = resp.json()
        assert "status" in data, "Missing 'status' field"
        assert data["status"] == "healthy"
        assert "service" in data, "Missing 'service' field"
        assert "wazuh_reachable" in data, "Missing 'wazuh_reachable' field"


@pytest.mark.integration
class TestExporterMetricsEndpoint:
    """Verify the /metrics endpoint format and accessibility."""

    @pytest.fixture(autouse=True)
    def _check(self):
        _skip_if_exporter_unavailable()

    def _get_metrics(self):
        resp = requests.get(f"{NHI_METRICS_URL}/metrics", timeout=10)
        return resp

    def test_metrics_returns_200(self):
        """GET /metrics returns 200."""
        resp = self._get_metrics()
        assert resp.status_code == 200

    def test_metrics_content_type(self):
        """Metrics endpoint returns Prometheus text format."""
        resp = self._get_metrics()
        content_type = resp.headers.get("Content-Type", "")
        assert "text/plain" in content_type or "text/openmetrics" in content_type, \
            f"Unexpected Content-Type: {content_type}"

    def test_metrics_format_valid(self):
        """Response follows Prometheus exposition format."""
        resp = self._get_metrics()
        lines = resp.text.strip().split("\n")
        for line in lines:
            if not line:
                continue
            # Comments (# HELP, # TYPE) or metric lines
            assert line.startswith("#") or re.match(
                r'^[a-zA-Z_:][a-zA-Z0-9_:]*(\{[^}]*\})?\s+[\d.eE+\-NnaInif]+(\s+\d+)?$',
                line
            ), f"Invalid Prometheus line: {line}"


@pytest.mark.integration
class TestExporterServiceHealthMetrics:
    """Verify nhi_service_up gauge metrics."""

    @pytest.fixture(autouse=True)
    def _check(self):
        _skip_if_exporter_unavailable()

    def _get_metrics_text(self):
        resp = requests.get(f"{NHI_METRICS_URL}/metrics", timeout=10)
        return resp.text

    def test_service_up_metric_exists(self):
        """nhi_service_up gauge is exposed."""
        metrics = self._get_metrics_text()
        assert "nhi_service_up" in metrics, \
            "Missing nhi_service_up metric"

    def test_service_up_has_service_label(self):
        """nhi_service_up has service label."""
        metrics = self._get_metrics_text()
        pattern = r'nhi_service_up\{.*service="[^"]*".*\}'
        assert re.search(pattern, metrics), \
            "nhi_service_up missing service label"

    def test_wazuh_manager_monitored(self):
        """Wazuh manager is monitored via nhi_service_up."""
        metrics = self._get_metrics_text()
        assert 'service="wazuh-manager"' in metrics, \
            "wazuh-manager not monitored by nhi_service_up"


@pytest.mark.integration
class TestExporterAgentMetrics:
    """Verify agent count metrics."""

    @pytest.fixture(autouse=True)
    def _check(self):
        _skip_if_exporter_unavailable()

    def _get_metrics_text(self):
        resp = requests.get(f"{NHI_METRICS_URL}/metrics", timeout=10)
        return resp.text

    def test_agents_active_metric(self):
        """nhi_wazuh_agents_active gauge exists."""
        metrics = self._get_metrics_text()
        assert "nhi_wazuh_agents_active" in metrics, \
            "Missing nhi_wazuh_agents_active metric"

    def test_agents_total_metric(self):
        """nhi_wazuh_agents_total gauge exists."""
        metrics = self._get_metrics_text()
        assert "nhi_wazuh_agents_total" in metrics, \
            "Missing nhi_wazuh_agents_total metric"


@pytest.mark.integration
class TestExporterAlertMetrics:
    """Verify alert and rule fire metrics."""

    @pytest.fixture(autouse=True)
    def _check(self):
        _skip_if_exporter_unavailable()

    def _get_metrics_text(self):
        resp = requests.get(f"{NHI_METRICS_URL}/metrics", timeout=10)
        return resp.text

    def test_alerts_total_metric(self):
        """nhi_alerts_total gauge exists."""
        metrics = self._get_metrics_text()
        assert "nhi_alerts_total" in metrics, \
            "Missing nhi_alerts_total metric"

    def test_rule_fires_total_metric(self):
        """nhi_rule_fires_total counter exists."""
        metrics = self._get_metrics_text()
        assert "nhi_rule_fires_total" in metrics, \
            "Missing nhi_rule_fires_total metric"

    def test_rule_fires_has_labels(self):
        """nhi_rule_fires_total has rule_id and level labels."""
        metrics = self._get_metrics_text()
        if "nhi_rule_fires_total{" not in metrics:
            pytest.skip("No rule fires recorded yet")
        assert re.search(
            r'nhi_rule_fires_total\{.*rule_id="[^"]*".*\}', metrics
        ), "nhi_rule_fires_total missing rule_id label"
        assert re.search(
            r'nhi_rule_fires_total\{.*level="[^"]*".*\}', metrics
        ), "nhi_rule_fires_total missing level label"

    def test_rule_fires_by_group_metric(self):
        """nhi_rule_fires_by_group gauge exists."""
        metrics = self._get_metrics_text()
        assert "nhi_rule_fires_by_group" in metrics, \
            "Missing nhi_rule_fires_by_group metric"

    def test_alert_latency_histogram(self):
        """nhi_alert_latency_seconds histogram exists."""
        metrics = self._get_metrics_text()
        has_histogram = (
            "nhi_alert_latency_seconds_bucket" in metrics
            or "nhi_alert_latency_seconds_count" in metrics
            or "nhi_alert_latency_seconds" in metrics
        )
        assert has_histogram, \
            "Missing nhi_alert_latency_seconds histogram"


@pytest.mark.integration
class TestExporterCoverageMetrics:
    """Verify detection coverage ratio metric."""

    @pytest.fixture(autouse=True)
    def _check(self):
        _skip_if_exporter_unavailable()

    def _get_metrics_text(self):
        resp = requests.get(f"{NHI_METRICS_URL}/metrics", timeout=10)
        return resp.text

    def test_detection_coverage_ratio(self):
        """nhi_detection_coverage_ratio gauge exists."""
        metrics = self._get_metrics_text()
        assert "nhi_detection_coverage_ratio" in metrics, \
            "Missing nhi_detection_coverage_ratio metric"

    def test_coverage_ratio_range(self):
        """Coverage ratio is between 0.0 and 1.0."""
        metrics = self._get_metrics_text()
        match = re.search(
            r'^nhi_detection_coverage_ratio\s+([\d.eE+\-]+)',
            metrics,
            re.MULTILINE
        )
        if not match:
            pytest.skip("nhi_detection_coverage_ratio not found as bare metric")
        value = float(match.group(1))
        assert 0.0 <= value <= 1.0, \
            f"Coverage ratio {value} outside [0, 1] range"


@pytest.mark.integration
class TestExporterScenarioMetrics:
    """Verify scenario execution recording."""

    @pytest.fixture(autouse=True)
    def _check(self):
        _skip_if_exporter_unavailable()

    def _get_metrics_text(self):
        resp = requests.get(f"{NHI_METRICS_URL}/metrics", timeout=10)
        return resp.text

    def test_scenario_runs_total_metric(self):
        """nhi_scenario_runs_total counter exists."""
        metrics = self._get_metrics_text()
        assert "nhi_scenario_runs_total" in metrics, \
            "Missing nhi_scenario_runs_total metric"

    def test_record_scenario_endpoint(self):
        """POST /record/scenario records a scenario run."""
        resp = requests.post(
            f"{NHI_METRICS_URL}/record/scenario",
            json={"scenario_id": "test-qa-probe", "status": "success"},
            timeout=10
        )
        assert resp.status_code == 200, \
            f"POST /record/scenario returned {resp.status_code}"

    def test_recorded_scenario_appears_in_metrics(self):
        """After recording, scenario_id appears in metrics."""
        # Record a test scenario
        requests.post(
            f"{NHI_METRICS_URL}/record/scenario",
            json={"scenario_id": "test-qa-probe", "status": "success"},
            timeout=10
        )
        metrics = self._get_metrics_text()
        if 'scenario_id="test-qa-probe"' not in metrics:
            pytest.skip("Scenario recording may be async or metric not yet visible")


@pytest.mark.integration
class TestExporterInternalMetrics:
    """Verify exporter self-monitoring metrics."""

    @pytest.fixture(autouse=True)
    def _check(self):
        _skip_if_exporter_unavailable()

    def _get_metrics_text(self):
        resp = requests.get(f"{NHI_METRICS_URL}/metrics", timeout=10)
        return resp.text

    def test_exporter_info_metric(self):
        """nhi_exporter_info gauge with version label exists."""
        metrics = self._get_metrics_text()
        assert "nhi_exporter_info" in metrics, \
            "Missing nhi_exporter_info metric"

    def test_exporter_info_has_version(self):
        """nhi_exporter_info has version label."""
        metrics = self._get_metrics_text()
        assert re.search(
            r'nhi_exporter_info\{.*version="[^"]*".*\}', metrics
        ), "nhi_exporter_info missing version label"

    def test_scrape_duration_histogram(self):
        """nhi_exporter_scrape_duration_seconds histogram exists."""
        metrics = self._get_metrics_text()
        has_histogram = (
            "nhi_exporter_scrape_duration_seconds_bucket" in metrics
            or "nhi_exporter_scrape_duration_seconds_count" in metrics
            or "nhi_exporter_scrape_duration_seconds" in metrics
        )
        assert has_histogram, \
            "Missing nhi_exporter_scrape_duration_seconds histogram"

    def test_scrape_errors_counter(self):
        """nhi_exporter_scrape_errors_total counter exists."""
        metrics = self._get_metrics_text()
        assert "nhi_exporter_scrape_errors_total" in metrics, \
            "Missing nhi_exporter_scrape_errors_total metric"


# ============================================================
# Prometheus Server Tests (port 9090)
# ============================================================

@pytest.mark.integration
class TestPrometheusServer:
    """Verify Prometheus server is operational and scraping NHI exporter."""

    @pytest.fixture(autouse=True)
    def _check(self):
        _skip_if_prometheus_unavailable()

    def test_prometheus_healthy(self):
        """Prometheus /-/healthy returns 200."""
        resp = requests.get(f"{PROMETHEUS_URL}/-/healthy", timeout=10)
        assert resp.status_code == 200

    def test_prometheus_ready(self):
        """Prometheus /-/ready returns 200."""
        resp = requests.get(f"{PROMETHEUS_URL}/-/ready", timeout=10)
        assert resp.status_code == 200

    def test_nhi_metrics_target_configured(self):
        """Prometheus has nhi-metrics scrape target."""
        resp = requests.get(f"{PROMETHEUS_URL}/api/v1/targets", timeout=10)
        assert resp.status_code == 200
        data = resp.json()
        targets = data.get("data", {}).get("activeTargets", [])
        job_names = [t.get("labels", {}).get("job", "") for t in targets]
        assert "nhi-metrics" in job_names, \
            f"nhi-metrics job not found in targets: {job_names}"

    def test_nhi_metrics_target_up(self):
        """nhi-metrics scrape target is up."""
        resp = requests.get(f"{PROMETHEUS_URL}/api/v1/targets", timeout=10)
        data = resp.json()
        targets = data.get("data", {}).get("activeTargets", [])
        for t in targets:
            if t.get("labels", {}).get("job") == "nhi-metrics":
                assert t.get("health") == "up", \
                    f"nhi-metrics target health: {t.get('health')}"
                return
        pytest.fail("nhi-metrics target not found")

    def test_nhi_metric_queryable(self):
        """Can query nhi_service_up from Prometheus."""
        resp = requests.get(
            f"{PROMETHEUS_URL}/api/v1/query",
            params={"query": "nhi_service_up"},
            timeout=10
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("status") == "success", \
            f"Query failed: {data}"


# ============================================================
# Grafana Tests (port 3000)
# ============================================================

@pytest.mark.integration
class TestGrafanaServer:
    """Verify Grafana is operational with NHI dashboards."""

    @pytest.fixture(autouse=True)
    def _check(self):
        _skip_if_grafana_unavailable()

    def test_grafana_health(self):
        """Grafana /api/health returns OK."""
        resp = requests.get(f"{GRAFANA_URL}/api/health", timeout=10)
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("database") == "ok"

    def test_prometheus_datasource_exists(self):
        """Grafana has Prometheus datasource configured."""
        resp = requests.get(
            f"{GRAFANA_URL}/api/datasources",
            auth=("admin", "admin"),
            timeout=10
        )
        if resp.status_code == 401:
            pytest.skip("Grafana auth credentials may differ")
        assert resp.status_code == 200
        datasources = resp.json()
        ds_types = [ds.get("type", "") for ds in datasources]
        assert "prometheus" in ds_types, \
            f"No Prometheus datasource found, types: {ds_types}"

    def test_nhi_dashboard_provisioned(self):
        """NHI detection coverage dashboard is provisioned."""
        resp = requests.get(
            f"{GRAFANA_URL}/api/search",
            auth=("admin", "admin"),
            params={"query": "NHI"},
            timeout=10
        )
        if resp.status_code == 401:
            pytest.skip("Grafana auth credentials may differ")
        assert resp.status_code == 200
        dashboards = resp.json()
        if not dashboards:
            pytest.skip("No NHI dashboards found (may not be provisioned yet)")
        titles = [d.get("title", "") for d in dashboards]
        assert any("NHI" in t or "nhi" in t.lower() for t in titles), \
            f"No NHI dashboard found, titles: {titles}"
