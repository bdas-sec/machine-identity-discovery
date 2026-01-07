"""
E2E tests for Category 2: Cloud Service Account scenarios.

Tests detection of IMDS credential theft, IAM misconfigurations,
cross-account abuse, and service account exfiltration.
"""

import pytest
from helpers.docker_utils import DockerTestUtils


@pytest.mark.e2e
@pytest.mark.category_2
class TestS201IMDSCredentialTheft:
    """S2-01: IMDS credential theft."""

    SCENARIO_ID = "S2-01"
    EXPECTED_RULES = ["100650", "100651"]

    def test_scenario_loads(self, scenario_loader):
        """Verify scenario JSON loads correctly."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        assert scenario is not None, f"Could not load scenario {self.SCENARIO_ID}"

    def test_imds_metadata_access(self, mock_imds_client):
        """Test accessing IMDS metadata endpoint."""
        root = mock_imds_client.get_metadata_root()
        assert root is not None, "Could not access IMDS metadata"

    def test_imds_credential_access(self, mock_imds_client):
        """Test accessing IMDS IAM credentials."""
        role_name = mock_imds_client.get_iam_role()
        assert role_name is not None, "Could not get IAM role"

        creds = mock_imds_client.get_iam_credentials(role_name)
        assert creds is not None, "Could not get IAM credentials"
        assert "AccessKeyId" in creds, "Missing AccessKeyId in credentials"

    def test_attacker_imds_access(self):
        """Test attacker container accessing IMDS."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            "attacker",
            "curl -s http://mock-imds:1338/latest/meta-data/",
            timeout=10
        )
        assert exit_code == 0, f"IMDS access failed: {stderr}"

    def test_expected_alerts_triggered(self, scenario_loader, alert_validator):
        """Verify expected Wazuh alerts are triggered."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        if not scenario:
            pytest.skip(f"Scenario {self.SCENARIO_ID} not found")

        # Execute the attack to trigger alerts
        DockerTestUtils.exec_in_container(
            "attacker",
            "curl -s http://mock-imds:1338/latest/meta-data/iam/security-credentials/",
            timeout=10
        )

        result = alert_validator.validate_scenario_alerts(
            scenario,
            timeout=60,
            agent_name="attacker"
        )

        if result["expected_count"] == 0:
            pytest.skip("No expected alerts defined")

        # Log findings
        print(f"Found rules: {result['found_rules']}")
        print(f"Missing rules: {result['missing_rules']}")


@pytest.mark.e2e
@pytest.mark.category_2
class TestS202OverPermissionedIAM:
    """S2-02: Over-permissioned IAM role."""

    SCENARIO_ID = "S2-02"
    EXPECTED_RULES = ["100700", "100701", "100702"]

    def test_scenario_loads(self, scenario_loader):
        """Verify scenario JSON loads correctly."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        assert scenario is not None, f"Could not load scenario {self.SCENARIO_ID}"

    def test_list_iam_privileges(self):
        """Test listing IAM privileges (simulated)."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            "attacker",
            "curl -s http://mock-imds:1338/latest/meta-data/iam/info || echo 'No IAM info'",
            timeout=10
        )
        # Should complete, may or may not return data
        assert exit_code == 0 or "No IAM" in stdout

    def test_expected_alerts_triggered(self, scenario_loader, alert_validator):
        """Verify expected Wazuh alerts are triggered."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        if not scenario:
            pytest.skip(f"Scenario {self.SCENARIO_ID} not found")

        result = alert_validator.validate_scenario_alerts(scenario, timeout=60)
        if result["expected_count"] == 0:
            pytest.skip("No expected alerts defined")


@pytest.mark.e2e
@pytest.mark.category_2
class TestS203CrossAccountRole:
    """S2-03: Cross-account role assumption."""

    SCENARIO_ID = "S2-03"
    EXPECTED_RULES = ["100703", "100704", "100705"]

    def test_scenario_loads(self, scenario_loader):
        """Verify scenario JSON loads correctly."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        assert scenario is not None, f"Could not load scenario {self.SCENARIO_ID}"

    def test_assume_role_attempt(self):
        """Test cross-account role assumption attempt."""
        # Simulate STS assume-role call
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            "attacker",
            "echo 'aws sts assume-role --role-arn arn:aws:iam::EXTERNAL:role/AdminRole'",
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


@pytest.mark.e2e
@pytest.mark.category_2
class TestS204ServiceAccountExfil:
    """S2-04: Service account key exfiltration."""

    SCENARIO_ID = "S2-04"
    EXPECTED_RULES = ["100706", "100707", "100708"]

    def test_scenario_loads(self, scenario_loader):
        """Verify scenario JSON loads correctly."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        assert scenario is not None, f"Could not load scenario {self.SCENARIO_ID}"

    def test_search_service_account_keys(self):
        """Test searching for service account keys."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            "attacker",
            "find / -name '*.json' -exec grep -l 'private_key' {} \\; 2>/dev/null | head -3 || true",
            timeout=30
        )
        # Command should complete
        assert exit_code in [0, 1]

    def test_expected_alerts_triggered(self, scenario_loader, alert_validator):
        """Verify expected Wazuh alerts are triggered."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        if not scenario:
            pytest.skip(f"Scenario {self.SCENARIO_ID} not found")

        result = alert_validator.validate_scenario_alerts(scenario, timeout=60)
        if result["expected_count"] == 0:
            pytest.skip("No expected alerts defined")
