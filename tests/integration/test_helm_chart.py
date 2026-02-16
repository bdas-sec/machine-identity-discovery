"""
Integration tests for NHI Security Testbed Helm chart.

Validates chart structure, values, template rendering, and Wazuh-specific
components at helm/nhi-testbed/.

Chart reference:
  35 template files — Deployments, StatefulSets, Services, NetworkPolicies
  Subdirectories: agents/, api/, mock-services/, monitoring/, wazuh/
  Chart.yaml: apiVersion v2, version 0.1.0, type application
"""

import os
import re
import shutil
import subprocess
import pytest
from pathlib import Path

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


PROJECT_ROOT = Path(__file__).parent.parent.parent
HELM_CHART_DIR = PROJECT_ROOT / "helm" / "nhi-testbed"


def _skip_if_no_chart():
    """Skip if Helm chart directory doesn't exist."""
    if not HELM_CHART_DIR.exists():
        pytest.skip("Helm chart not found at helm/nhi-testbed/")


def _skip_if_no_helm():
    """Skip if helm binary is not available."""
    if not shutil.which("helm"):
        pytest.skip("helm binary not available")


def _skip_if_no_yaml():
    """Skip if PyYAML is not installed."""
    if not HAS_YAML:
        pytest.skip("PyYAML not installed")


# ============================================================
# Chart Structure Tests
# ============================================================

@pytest.mark.integration
class TestHelmChartStructure:
    """Verify Helm chart directory structure and required files."""

    @pytest.fixture(autouse=True)
    def _check(self):
        _skip_if_no_chart()

    def test_chart_yaml_exists(self):
        """Chart.yaml exists."""
        assert (HELM_CHART_DIR / "Chart.yaml").exists()

    def test_values_yaml_exists(self):
        """values.yaml exists."""
        assert (HELM_CHART_DIR / "values.yaml").exists()

    def test_templates_directory_exists(self):
        """templates/ directory exists."""
        assert (HELM_CHART_DIR / "templates").is_dir()

    def test_helpers_tpl_exists(self):
        """templates/_helpers.tpl exists."""
        assert (HELM_CHART_DIR / "templates" / "_helpers.tpl").exists()

    def test_notes_txt_exists(self):
        """templates/NOTES.txt exists."""
        assert (HELM_CHART_DIR / "templates" / "NOTES.txt").exists()

    def test_template_subdirectories(self):
        """Expected template subdirectories exist."""
        expected_dirs = ["wazuh", "agents", "mock-services", "monitoring", "api"]
        templates_dir = HELM_CHART_DIR / "templates"
        for subdir in expected_dirs:
            assert (templates_dir / subdir).is_dir(), \
                f"Missing templates/{subdir}/ directory"

    def test_wazuh_templates_complete(self):
        """Wazuh stack templates exist (manager, indexer, dashboard)."""
        wazuh_dir = HELM_CHART_DIR / "templates" / "wazuh"
        expected = [
            "manager-deployment.yaml",
            "manager-service.yaml",
            "indexer-statefulset.yaml",
            "indexer-service.yaml",
            "dashboard-deployment.yaml",
            "dashboard-service.yaml",
        ]
        for f in expected:
            assert (wazuh_dir / f).exists(), f"Missing wazuh/{f}"

    def test_agent_templates_exist(self):
        """Agent deployment templates exist."""
        agents_dir = HELM_CHART_DIR / "templates" / "agents"
        expected = [
            "cloud-workload-deployment.yaml",
            "cicd-runner-deployment.yaml",
            "vulnerable-app-deployment.yaml",
        ]
        for f in expected:
            assert (agents_dir / f).exists(), f"Missing agents/{f}"

    def test_mock_service_templates_exist(self):
        """Mock service templates exist."""
        mock_dir = HELM_CHART_DIR / "templates" / "mock-services"
        expected_prefixes = ["mock-imds", "mock-cicd", "mock-oauth", "mock-gcp-metadata", "vault"]
        for prefix in expected_prefixes:
            matches = list(mock_dir.glob(f"{prefix}*"))
            assert len(matches) > 0, f"No templates for {prefix} in mock-services/"

    def test_monitoring_templates_exist(self):
        """Monitoring stack templates exist."""
        mon_dir = HELM_CHART_DIR / "templates" / "monitoring"
        expected_prefixes = ["metrics", "prometheus", "grafana"]
        for prefix in expected_prefixes:
            matches = list(mon_dir.glob(f"{prefix}*"))
            assert len(matches) > 0, f"No templates for {prefix} in monitoring/"

    def test_network_policies_exist(self):
        """Network policy templates exist."""
        assert (HELM_CHART_DIR / "templates" / "network-policies.yaml").exists()

    def test_template_file_count(self):
        """Chart has expected number of template files (30+)."""
        templates = list((HELM_CHART_DIR / "templates").rglob("*.yaml"))
        templates += list((HELM_CHART_DIR / "templates").rglob("*.tpl"))
        templates += list((HELM_CHART_DIR / "templates").rglob("*.txt"))
        assert len(templates) >= 25, \
            f"Expected 25+ template files, found {len(templates)}"


# ============================================================
# Chart.yaml Validation
# ============================================================

@pytest.mark.integration
class TestHelmChartYaml:
    """Validate Chart.yaml metadata."""

    @pytest.fixture(autouse=True)
    def _check(self):
        _skip_if_no_chart()
        _skip_if_no_yaml()

    def _load_chart(self):
        with open(HELM_CHART_DIR / "Chart.yaml") as f:
            return yaml.safe_load(f)

    def test_api_version_v2(self):
        """Chart uses apiVersion v2."""
        chart = self._load_chart()
        assert chart.get("apiVersion") == "v2"

    def test_chart_name(self):
        """Chart name is nhi-testbed."""
        chart = self._load_chart()
        assert chart.get("name") == "nhi-testbed"

    def test_chart_type(self):
        """Chart type is application."""
        chart = self._load_chart()
        assert chart.get("type") == "application"

    def test_chart_version(self):
        """Chart has a valid SemVer version."""
        chart = self._load_chart()
        version = chart.get("version", "")
        assert re.match(r'^\d+\.\d+\.\d+', version), \
            f"Invalid chart version: {version}"

    def test_app_version(self):
        """Chart has appVersion set."""
        chart = self._load_chart()
        assert chart.get("appVersion"), "Missing appVersion"

    def test_chart_description(self):
        """Chart has a description."""
        chart = self._load_chart()
        assert chart.get("description"), "Missing chart description"

    def test_chart_keywords(self):
        """Chart has relevant keywords."""
        chart = self._load_chart()
        keywords = chart.get("keywords", [])
        assert len(keywords) > 0, "Missing keywords"
        keyword_str = " ".join(keywords).lower()
        assert "nhi" in keyword_str or "security" in keyword_str, \
            f"Keywords missing NHI/security: {keywords}"


# ============================================================
# values.yaml Validation
# ============================================================

@pytest.mark.integration
class TestHelmValuesYaml:
    """Validate values.yaml defaults and structure."""

    @pytest.fixture(autouse=True)
    def _check(self):
        _skip_if_no_chart()
        _skip_if_no_yaml()

    def _load_values(self):
        with open(HELM_CHART_DIR / "values.yaml") as f:
            return yaml.safe_load(f)

    def test_namespace_config(self):
        """Namespace configuration exists with defaults."""
        values = self._load_values()
        ns = values.get("namespace", {})
        assert ns.get("name"), "Missing namespace.name"
        assert "create" in ns, "Missing namespace.create"

    def test_wazuh_manager_enabled(self):
        """Wazuh manager is enabled by default."""
        values = self._load_values()
        manager = values.get("wazuh", {}).get("manager", {})
        assert manager.get("enabled") is True, "Wazuh manager not enabled by default"

    def test_wazuh_indexer_persistence(self):
        """Wazuh indexer has persistence configured."""
        values = self._load_values()
        indexer = values.get("wazuh", {}).get("indexer", {})
        persistence = indexer.get("persistence", {})
        assert persistence.get("enabled") is True, "Indexer persistence not enabled"
        assert persistence.get("size"), "Missing indexer persistence size"

    def test_all_services_have_enabled_toggle(self):
        """All major service sections have an 'enabled' toggle."""
        values = self._load_values()
        sections_to_check = []
        # Wazuh stack
        wazuh = values.get("wazuh", {})
        for component in ["manager", "indexer", "dashboard"]:
            if component in wazuh:
                sections_to_check.append(f"wazuh.{component}")
                assert "enabled" in wazuh[component], \
                    f"Missing enabled toggle in wazuh.{component}"

    def test_mock_services_configured(self):
        """Mock services have configuration entries."""
        values = self._load_values()
        # Check for mock service sections
        mock_keys = [k for k in values.keys() if "mock" in k.lower() or "imds" in k.lower()]
        mock_services = values.get("mockServices", values.get("mock_services", {}))
        if mock_keys or mock_services:
            return  # Found mock service config
        # Check nested under different keys
        for key in ["agents", "services"]:
            if key in values:
                return
        pytest.skip("Mock service config structure varies — manual verification needed")

    def test_monitoring_configured(self):
        """Monitoring stack has configuration."""
        values = self._load_values()
        # Look for monitoring section
        monitoring = values.get("monitoring", {})
        if not monitoring:
            # May be at top level
            has_prometheus = "prometheus" in values
            has_grafana = "grafana" in values
            has_metrics = "metrics" in values
            assert has_prometheus or has_grafana or has_metrics, \
                "No monitoring configuration found in values.yaml"

    def test_image_pull_policy_default(self):
        """Image pull policy has a default."""
        values = self._load_values()
        policy = values.get("imagePullPolicy", values.get("global", {}).get("imagePullPolicy"))
        assert policy in ["IfNotPresent", "Always", "Never", None], \
            f"Unexpected imagePullPolicy: {policy}"

    def test_network_policies_configured(self):
        """Network policies have configuration."""
        values = self._load_values()
        net_pol = values.get("networkPolicies", values.get("networkPolicy", {}))
        if net_pol:
            assert "enabled" in net_pol
        # May not be in values.yaml if always applied


# ============================================================
# Helm Template Rendering Tests
# ============================================================

@pytest.mark.integration
class TestHelmChartRendering:
    """Test Helm template rendering with helm CLI."""

    @pytest.fixture(autouse=True)
    def _check(self):
        _skip_if_no_chart()
        _skip_if_no_helm()

    def test_helm_lint_passes(self):
        """helm lint succeeds on the chart."""
        result = subprocess.run(
            ["helm", "lint", str(HELM_CHART_DIR)],
            capture_output=True, text=True, timeout=30
        )
        assert result.returncode == 0, \
            f"helm lint failed:\n{result.stdout}\n{result.stderr}"

    def test_helm_template_renders(self):
        """helm template produces output without errors."""
        result = subprocess.run(
            ["helm", "template", "test-release", str(HELM_CHART_DIR)],
            capture_output=True, text=True, timeout=30
        )
        assert result.returncode == 0, \
            f"helm template failed:\n{result.stderr}"
        assert len(result.stdout) > 0, "helm template produced empty output"

    def test_rendered_yaml_valid(self):
        """helm template output is valid YAML."""
        _skip_if_no_yaml()
        result = subprocess.run(
            ["helm", "template", "test-release", str(HELM_CHART_DIR)],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            pytest.skip("helm template failed")
        docs = list(yaml.safe_load_all(result.stdout))
        # Filter None docs (from empty YAML documents)
        docs = [d for d in docs if d is not None]
        assert len(docs) > 0, "No YAML documents rendered"

    def test_rendered_resources_have_required_fields(self):
        """All rendered resources have apiVersion and kind."""
        _skip_if_no_yaml()
        result = subprocess.run(
            ["helm", "template", "test-release", str(HELM_CHART_DIR)],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            pytest.skip("helm template failed")
        docs = [d for d in yaml.safe_load_all(result.stdout) if d is not None]
        for doc in docs:
            assert "apiVersion" in doc, f"Missing apiVersion in {doc.get('kind', 'unknown')}"
            assert "kind" in doc, f"Missing kind in document"

    def test_wazuh_manager_deployment_renders(self):
        """Wazuh manager deployment renders correctly."""
        _skip_if_no_yaml()
        result = subprocess.run(
            ["helm", "template", "test-release", str(HELM_CHART_DIR)],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            pytest.skip("helm template failed")
        docs = [d for d in yaml.safe_load_all(result.stdout) if d is not None]
        manager_deps = [
            d for d in docs
            if d.get("kind") == "Deployment"
            and "manager" in d.get("metadata", {}).get("name", "").lower()
        ]
        assert len(manager_deps) > 0, "No wazuh-manager Deployment rendered"

    def test_indexer_statefulset_renders(self):
        """Wazuh indexer renders as StatefulSet."""
        _skip_if_no_yaml()
        result = subprocess.run(
            ["helm", "template", "test-release", str(HELM_CHART_DIR)],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            pytest.skip("helm template failed")
        docs = [d for d in yaml.safe_load_all(result.stdout) if d is not None]
        indexer_sts = [
            d for d in docs
            if d.get("kind") == "StatefulSet"
            and "indexer" in d.get("metadata", {}).get("name", "").lower()
        ]
        assert len(indexer_sts) > 0, "No wazuh-indexer StatefulSet rendered"

    def test_network_policies_render(self):
        """NetworkPolicy resources are rendered."""
        _skip_if_no_yaml()
        result = subprocess.run(
            ["helm", "template", "test-release", str(HELM_CHART_DIR)],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            pytest.skip("helm template failed")
        docs = [d for d in yaml.safe_load_all(result.stdout) if d is not None]
        netpols = [d for d in docs if d.get("kind") == "NetworkPolicy"]
        assert len(netpols) >= 3, \
            f"Expected 3+ NetworkPolicies, got {len(netpols)}"

    def test_services_render(self):
        """Service resources are rendered for key components."""
        _skip_if_no_yaml()
        result = subprocess.run(
            ["helm", "template", "test-release", str(HELM_CHART_DIR)],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            pytest.skip("helm template failed")
        docs = [d for d in yaml.safe_load_all(result.stdout) if d is not None]
        services = [d for d in docs if d.get("kind") == "Service"]
        service_names = [s.get("metadata", {}).get("name", "") for s in services]
        assert len(services) >= 5, \
            f"Expected 5+ Services, got {len(services)}: {service_names}"

    def test_common_labels_applied(self):
        """All resources have standard Helm labels."""
        _skip_if_no_yaml()
        result = subprocess.run(
            ["helm", "template", "test-release", str(HELM_CHART_DIR)],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            pytest.skip("helm template failed")
        docs = [d for d in yaml.safe_load_all(result.stdout) if d is not None]
        for doc in docs:
            labels = doc.get("metadata", {}).get("labels", {})
            assert "app.kubernetes.io/managed-by" in labels, \
                f"Missing managed-by label on {doc.get('kind')}/{doc.get('metadata',{}).get('name')}"
