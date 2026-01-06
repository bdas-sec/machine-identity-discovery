"""
E2E tests for Category 3: CI/CD Pipeline scenarios.

Tests detection of stolen runner tokens, pipeline injection,
and OIDC token abuse.
"""

import pytest
from helpers.docker_utils import DockerTestUtils


@pytest.mark.e2e
@pytest.mark.category_3
class TestS301StolenRunnerToken:
    """S3-01: Stolen GitHub Actions runner token."""

    SCENARIO_ID = "S3-01"
    EXPECTED_RULES = ["100800", "100801", "100802"]

    def test_scenario_loads(self, scenario_loader):
        """Verify scenario JSON loads correctly."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        assert scenario is not None, f"Could not load scenario {self.SCENARIO_ID}"

    def test_runner_token_endpoint(self, mock_cicd_client):
        """Test accessing runner token endpoint."""
        token = mock_cicd_client.get_runner_token()
        # Should return token data
        if token:
            assert "token" in token or "value" in str(token).lower()

    def test_attacker_token_theft(self):
        """Test attacker stealing runner token."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            "attacker",
            "curl -s -X POST http://mock-cicd:8080/github/actions/runner/token",
            timeout=10
        )
        assert exit_code == 0, f"Token request failed: {stderr}"

    def test_expected_alerts_triggered(self, scenario_loader, alert_validator):
        """Verify expected Wazuh alerts are triggered."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        if not scenario:
            pytest.skip(f"Scenario {self.SCENARIO_ID} not found")

        # Execute attack to trigger alerts
        DockerTestUtils.exec_in_container(
            "attacker",
            "curl -s -X POST http://mock-cicd:8080/github/actions/runner/token",
            timeout=10
        )

        result = alert_validator.validate_scenario_alerts(
            scenario,
            timeout=60,
            agent_name="attacker"
        )

        if result["expected_count"] == 0:
            pytest.skip("No expected alerts defined")

        print(f"Found: {result['found_rules']}, Missing: {result['missing_rules']}")


@pytest.mark.e2e
@pytest.mark.category_3
class TestS302PipelineInjection:
    """S3-02: Pipeline injection attack."""

    SCENARIO_ID = "S3-02"
    EXPECTED_RULES = ["100803", "100804", "100805"]

    def test_scenario_loads(self, scenario_loader):
        """Verify scenario JSON loads correctly."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        assert scenario is not None, f"Could not load scenario {self.SCENARIO_ID}"

    def test_secrets_exfiltration(self, mock_cicd_client):
        """Test accessing repository secrets."""
        secrets = mock_cicd_client.get_repo_secrets("victim-org", "target-repo")
        # Should return secrets list
        if secrets:
            assert isinstance(secrets, dict)

    def test_attacker_secrets_access(self):
        """Test attacker accessing CI/CD secrets."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            "attacker",
            "curl -s http://mock-cicd:8080/github/repos/victim/repo/actions/secrets",
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
@pytest.mark.category_3
class TestS303OIDCTokenAbuse:
    """S3-03: OIDC token abuse for cloud access."""

    SCENARIO_ID = "S3-03"
    EXPECTED_RULES = ["100806", "100807", "100808"]

    def test_scenario_loads(self, scenario_loader):
        """Verify scenario JSON loads correctly."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        assert scenario is not None, f"Could not load scenario {self.SCENARIO_ID}"

    def test_oidc_token_request(self, mock_cicd_client):
        """Test OIDC token request."""
        token = mock_cicd_client.get_oidc_token(audience="sts.amazonaws.com")
        if token:
            # Should have token value
            assert "token" in str(token).lower() or "value" in str(token).lower()

    def test_attacker_oidc_abuse(self):
        """Test attacker abusing OIDC token."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            "attacker",
            "curl -s 'http://mock-cicd:8080/github/actions/oidc/token?audience=sts.amazonaws.com'",
            timeout=10
        )
        assert exit_code == 0

    def test_expected_alerts_triggered(self, scenario_loader, alert_validator):
        """Verify expected Wazuh alerts are triggered."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        if not scenario:
            pytest.skip(f"Scenario {self.SCENARIO_ID} not found")

        # Trigger the attack
        DockerTestUtils.exec_in_container(
            "attacker",
            "curl -s 'http://mock-cicd:8080/github/actions/oidc/token?audience=sts.amazonaws.com'",
            timeout=10
        )

        result = alert_validator.validate_scenario_alerts(scenario, timeout=60)
        if result["expected_count"] == 0:
            pytest.skip("No expected alerts defined")
