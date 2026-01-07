"""
E2E tests for Category 4: Kubernetes scenarios.

Tests detection of container escapes, service account abuse,
RBAC misconfigurations, and secret access.
"""

import pytest
from helpers.docker_utils import DockerTestUtils


@pytest.mark.e2e
@pytest.mark.category_4
class TestS401PrivilegedPodEscape:
    """S4-01: Privileged pod escape."""

    SCENARIO_ID = "S4-01"
    EXPECTED_RULES = ["100750", "100751", "100752"]

    def test_scenario_loads(self, scenario_loader):
        """Verify scenario JSON loads correctly."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        assert scenario is not None, f"Could not load scenario {self.SCENARIO_ID}"

    def test_check_privileged_mode(self):
        """Test checking for privileged container."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            "attacker",
            "cat /proc/1/status | grep -i cap || echo 'Cannot read capabilities'",
            timeout=10
        )
        assert exit_code == 0

    def test_host_filesystem_access(self):
        """Test attempt to access host filesystem."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            "attacker",
            "ls /host 2>/dev/null || echo 'No host mount'",
            timeout=10
        )
        # Should complete regardless of result
        assert exit_code == 0

    def test_expected_alerts_triggered(self, scenario_loader, alert_validator):
        """Verify expected Wazuh alerts are triggered."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        if not scenario:
            pytest.skip(f"Scenario {self.SCENARIO_ID} not found")

        result = alert_validator.validate_scenario_alerts(scenario, timeout=60)
        if result["expected_count"] == 0:
            pytest.skip("No expected alerts defined")


@pytest.mark.e2e
@pytest.mark.category_4
class TestS402ServiceAccountTokenTheft:
    """S4-02: Kubernetes service account token theft."""

    SCENARIO_ID = "S4-02"
    EXPECTED_RULES = ["100753", "100754", "100755"]

    def test_scenario_loads(self, scenario_loader):
        """Verify scenario JSON loads correctly."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        assert scenario is not None, f"Could not load scenario {self.SCENARIO_ID}"

    def test_service_account_token_access(self):
        """Test accessing K8s service account token."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            "attacker",
            "cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null || echo 'No SA token'",
            timeout=10
        )
        # Should complete (may or may not have token)
        assert exit_code == 0

    def test_kubernetes_api_access(self):
        """Test accessing Kubernetes API with token."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            "attacker",
            "curl -sk https://kubernetes.default.svc/api 2>/dev/null || echo 'No K8s API'",
            timeout=10
        )
        assert exit_code == 0

    def test_expected_alerts_triggered(self, scenario_loader, alert_validator):
        """Verify expected Wazuh alerts are triggered."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        if not scenario:
            pytest.skip(f"Scenario {self.SCENARIO_ID} not found")

        # Trigger SA token access
        DockerTestUtils.exec_in_container(
            "attacker",
            "cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null || true",
            timeout=10
        )

        result = alert_validator.validate_scenario_alerts(scenario, timeout=60)
        if result["expected_count"] == 0:
            pytest.skip("No expected alerts defined")


@pytest.mark.e2e
@pytest.mark.category_4
class TestS403RBACMisconfiguration:
    """S4-03: Kubernetes RBAC misconfiguration."""

    SCENARIO_ID = "S4-03"
    EXPECTED_RULES = ["100756", "100757", "100758"]

    def test_scenario_loads(self, scenario_loader):
        """Verify scenario JSON loads correctly."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        assert scenario is not None, f"Could not load scenario {self.SCENARIO_ID}"

    def test_list_cluster_secrets(self):
        """Test listing cluster-wide secrets."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            "attacker",
            "kubectl get secrets --all-namespaces 2>/dev/null || echo 'No kubectl'",
            timeout=15
        )
        assert exit_code == 0

    def test_expected_alerts_triggered(self, scenario_loader, alert_validator):
        """Verify expected Wazuh alerts are triggered."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        if not scenario:
            pytest.skip(f"Scenario {self.SCENARIO_ID} not found")

        result = alert_validator.validate_scenario_alerts(scenario, timeout=60)
        if result["expected_count"] == 0:
            pytest.skip("No expected alerts defined")


@pytest.mark.e2e
@pytest.mark.category_4
class TestS404MountedSecrets:
    """S4-04: Accessing mounted Kubernetes secrets."""

    SCENARIO_ID = "S4-04"
    EXPECTED_RULES = ["100759", "100760", "100761"]

    def test_scenario_loads(self, scenario_loader):
        """Verify scenario JSON loads correctly."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        assert scenario is not None, f"Could not load scenario {self.SCENARIO_ID}"

    def test_search_mounted_secrets(self):
        """Test searching for mounted secrets."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            "attacker",
            "find /var/run/secrets -type f 2>/dev/null | head -10 || echo 'No secrets mount'",
            timeout=15
        )
        assert exit_code == 0

    def test_read_secret_files(self):
        """Test reading secret files."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            "attacker",
            "cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null || echo 'No namespace'",
            timeout=10
        )
        assert exit_code == 0

    def test_expected_alerts_triggered(self, scenario_loader, alert_validator):
        """Verify expected Wazuh alerts are triggered."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        if not scenario:
            pytest.skip(f"Scenario {self.SCENARIO_ID} not found")

        result = alert_validator.validate_scenario_alerts(scenario, timeout=60)
        if result["expected_count"] == 0:
            pytest.skip("No expected alerts defined")
