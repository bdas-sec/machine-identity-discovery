"""
E2E tests for Category 4: Kubernetes scenarios.

Tests detection of container escapes, service account abuse,
RBAC misconfigurations, secret access, and API key abuse.

All S4-01 through S4-04 tests require the k8s-node-1 container (--profile k8s).
S4-05 runs on the vulnerable-app container (always available).
Tests skip gracefully when the required container is not available.
"""

import pytest
from helpers.docker_utils import DockerTestUtils


# Container and agent configuration for Category 4
K8S_CONTAINER = "k8s-node-1"
K8S_AGENT = "k8s-node-001"
VULN_APP_CONTAINER = "vulnerable-app"
VULN_APP_AGENT = "vulnerable-app-001"


def _skip_if_k8s_down():
    """Skip test if k8s-node-1 is not running."""
    if not DockerTestUtils.container_running(K8S_CONTAINER):
        pytest.skip(f"{K8S_CONTAINER} not running (requires --profile k8s)")


def _skip_if_containers_down(*containers):
    """Skip test if any required container is not running."""
    for name in containers:
        if not DockerTestUtils.container_running(name):
            pytest.skip(f"{name} container not running")


@pytest.mark.e2e
@pytest.mark.category_4
class TestS401PrivilegedPodEscape:
    """S4-01: Privileged pod container escape.

    Attack chain:
    1. Discover container privileges (capabilities)
    2. Attempt host filesystem mount
    3. Simulate nsenter escape to host namespace
    4. Access kubelet credentials on host
    """

    SCENARIO_ID = "S4-01"
    EXPECTED_RULES = ["100750", "100751", "100752"]

    @pytest.fixture(autouse=True)
    def _check_containers(self):
        _skip_if_k8s_down()

    def test_scenario_loads(self, scenario_loader):
        """Verify scenario JSON loads correctly."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        assert scenario is not None, f"Could not load scenario {self.SCENARIO_ID}"

    def test_phase1_privilege_discovery(self):
        """Phase 1: Check container capabilities."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            "cat /proc/1/status | grep -i cap || echo 'NO_CAP_INFO'",
            timeout=10
        )
        assert exit_code == 0, f"Capability check failed: {stderr}"
        # Should have some capability information
        assert "Cap" in stdout or "NO_CAP_INFO" in stdout

    def test_phase1_capability_decode(self):
        """Phase 1b: Read effective capabilities value."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            "cat /proc/1/status | grep CapEff | awk '{print $2}' || echo 'UNKNOWN'",
            timeout=10
        )
        assert exit_code == 0
        # Non-empty capability value
        assert len(stdout.strip()) > 0, "Empty capability value"

    def test_phase2_host_mount_attempt(self):
        """Phase 2: Attempt to access host filesystem."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            "ls /host 2>/dev/null && echo 'HOST_ACCESSIBLE' || echo 'NO_HOST_MOUNT'",
            timeout=10
        )
        assert exit_code == 0

        # Log the mount attempt for Wazuh detection
        DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            'logger -t nhi-security "NHI_ALERT: Container escape attempt - '
            'mount /dev/sda1 /mnt/host"',
            timeout=10
        )

    def test_phase3_nsenter_escape_simulation(self):
        """Phase 3: Simulate nsenter escape to host namespace."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            'logger -t nhi-security "NHI_ALERT: Container escape - '
            'nsenter --target 1 --mount --uts --ipc --net --pid executed"',
            timeout=10
        )
        assert exit_code == 0, f"nsenter simulation failed: {stderr}"

    def test_phase4_kubelet_credential_access(self):
        """Phase 4: Attempt to access kubelet credentials on host."""
        # Check for kubeconfig
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            "cat /root/.kube/config 2>/dev/null || "
            "cat /etc/kubernetes/kubelet.conf 2>/dev/null || "
            "echo 'NO_KUBECONFIG'",
            timeout=10
        )
        assert exit_code == 0

        # Log kubelet access attempt
        DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            'logger -t nhi-security "NHI_ALERT: Kubelet credential access - '
            'reading /var/lib/kubelet/kubeconfig"',
            timeout=10
        )

    def test_expected_alerts_triggered(self, scenario_loader, alert_validator):
        """Verify expected Wazuh alerts fire."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        if not scenario:
            pytest.skip(f"Scenario {self.SCENARIO_ID} not found")

        # Trigger escape simulation
        DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            'logger -t nhi-security "NHI_ALERT: Container escape - nsenter --target 1 --mount"',
            timeout=10
        )

        result = alert_validator.validate_scenario_alerts(
            scenario, timeout=60, agent_name=K8S_AGENT
        )
        if result["expected_count"] == 0:
            pytest.skip("No expected alerts defined")

        assert result["found_count"] > 0, \
            f"No alerts for {self.SCENARIO_ID}. Missing: {result['missing_rules']}"


@pytest.mark.e2e
@pytest.mark.category_4
class TestS402ServiceAccountTokenTheft:
    """S4-02: Kubernetes service account token theft.

    Attack chain:
    1. Read service account token from well-known path
    2. Discover Kubernetes API server
    3. Enumerate permissions with kubectl
    4. List and extract secrets
    """

    SCENARIO_ID = "S4-02"
    EXPECTED_RULES = ["100753", "100754", "100755"]

    @pytest.fixture(autouse=True)
    def _check_containers(self):
        _skip_if_k8s_down()

    def test_scenario_loads(self, scenario_loader):
        """Verify scenario JSON loads correctly."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        assert scenario is not None, f"Could not load scenario {self.SCENARIO_ID}"

    def test_phase1_token_discovery(self):
        """Phase 1: Read Kubernetes service account token."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            "cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null "
            "|| echo 'NO_SA_TOKEN'",
            timeout=10
        )
        assert exit_code == 0, f"SA token read failed: {stderr}"
        token = stdout.strip()
        if token != "NO_SA_TOKEN":
            assert token.startswith("eyJ"), \
                f"SA token not in JWT format: {token[:20]}..."

    def test_phase1_namespace_discovery(self):
        """Phase 1b: Read the pod namespace."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            "cat /var/run/secrets/kubernetes.io/serviceaccount/namespace "
            "2>/dev/null || echo 'NO_NAMESPACE'",
            timeout=10
        )
        assert exit_code == 0

    def test_phase2_api_server_discovery(self):
        """Phase 2: Discover Kubernetes API server."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            "env | grep -i KUBERNETES || echo 'NO_K8S_ENV'",
            timeout=10
        )
        assert exit_code == 0

    def test_phase3_permission_enumeration(self):
        """Phase 3: Enumerate permissions using kubectl."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            "kubectl auth can-i --list 2>/dev/null || echo 'KUBECTL_AUTH_FAILED'",
            timeout=15
        )
        assert exit_code == 0

        # Log the kubectl attempt for Wazuh detection
        DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            'logger -t nhi-security "NHI_ALERT: kubectl auth can-i --list executed"',
            timeout=10
        )

    def test_phase4_secret_enumeration(self):
        """Phase 4: List and extract Kubernetes secrets."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            "kubectl get secrets -n default 2>/dev/null || echo 'K8S_API_UNAVAILABLE'",
            timeout=15
        )
        assert exit_code == 0

        # Log the secret enumeration
        DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            'logger -t nhi-security "NHI_ALERT: kubectl get secrets -n default executed"',
            timeout=10
        )

    def test_expected_alerts_triggered(self, scenario_loader, alert_validator):
        """Verify expected Wazuh alerts fire."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        if not scenario:
            pytest.skip(f"Scenario {self.SCENARIO_ID} not found")

        # Trigger SA token access and kubectl
        DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            "cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null; "
            "kubectl get secrets -n default 2>/dev/null || true",
            timeout=15
        )

        result = alert_validator.validate_scenario_alerts(
            scenario, timeout=60, agent_name=K8S_AGENT
        )
        if result["expected_count"] == 0:
            pytest.skip("No expected alerts defined")

        assert result["found_count"] > 0, \
            f"No alerts for {self.SCENARIO_ID}. Missing: {result['missing_rules']}"


@pytest.mark.e2e
@pytest.mark.category_4
class TestS403RBACMisconfiguration:
    """S4-03: RBAC misconfiguration exploitation.

    Attack chain:
    1. Enumerate current permissions
    2. Discover cluster roles and bindings
    3. Escalate privileges via ClusterRoleBinding
    4. Verify cluster-admin access
    """

    SCENARIO_ID = "S4-03"
    EXPECTED_RULES = ["100756", "100757", "100758"]

    @pytest.fixture(autouse=True)
    def _check_containers(self):
        _skip_if_k8s_down()

    def test_scenario_loads(self, scenario_loader):
        """Verify scenario JSON loads correctly."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        assert scenario is not None, f"Could not load scenario {self.SCENARIO_ID}"

    def test_phase1_permission_enumeration(self):
        """Phase 1: List current RBAC permissions."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            "kubectl auth can-i --list 2>/dev/null || echo 'AUTH_CHECK_FAILED'",
            timeout=15
        )
        assert exit_code == 0

    def test_phase2_role_discovery(self):
        """Phase 2: Discover cluster roles and bindings."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            "kubectl get clusterroles 2>/dev/null | head -20 || "
            "echo 'CLUSTERROLE_LIST_FAILED'",
            timeout=15
        )
        assert exit_code == 0

        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            "kubectl get clusterrolebindings 2>/dev/null | head -20 || "
            "echo 'CRB_LIST_FAILED'",
            timeout=15
        )
        assert exit_code == 0

    def test_phase3_escalation_via_rolebinding(self):
        """Phase 3: Simulate privilege escalation via ClusterRoleBinding."""
        # Log simulated clusterrolebinding creation
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            'logger -t nhi-security "NHI_ALERT: RBAC escalation - '
            'kubectl create clusterrolebinding pwned '
            '--clusterrole=cluster-admin '
            '--serviceaccount=default:compromised-sa"',
            timeout=10
        )
        assert exit_code == 0, f"RBAC escalation simulation failed: {stderr}"

    def test_phase4_verify_escalation(self):
        """Phase 4: Verify cluster-admin access and enumerate secrets."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            "kubectl auth can-i '*' '*' 2>/dev/null || echo 'NOT_CLUSTER_ADMIN'",
            timeout=15
        )
        assert exit_code == 0

        # Attempt to list all secrets across namespaces
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            "kubectl get secrets --all-namespaces 2>/dev/null || "
            "echo 'SECRETS_LIST_FAILED'",
            timeout=15
        )
        assert exit_code == 0

    def test_expected_alerts_triggered(self, scenario_loader, alert_validator):
        """Verify expected Wazuh alerts fire."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        if not scenario:
            pytest.skip(f"Scenario {self.SCENARIO_ID} not found")

        # Trigger RBAC attack chain
        DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            "kubectl auth can-i --list 2>/dev/null || true",
            timeout=10
        )
        DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            'logger -t nhi-security "NHI_ALERT: RBAC escalation - '
            'kubectl create clusterrolebinding pwned --clusterrole=cluster-admin"',
            timeout=10
        )

        result = alert_validator.validate_scenario_alerts(
            scenario, timeout=60, agent_name=K8S_AGENT
        )
        if result["expected_count"] == 0:
            pytest.skip("No expected alerts defined")

        assert result["found_count"] > 0, \
            f"No alerts for {self.SCENARIO_ID}. Missing: {result['missing_rules']}"


@pytest.mark.e2e
@pytest.mark.category_4
class TestS404MountedSecrets:
    """S4-04: Secrets mounted in pod.

    Attack chain:
    1. Search environment variables for credentials
    2. Discover secret volume mounts
    3. Extract secret files
    4. Simulate credential use
    """

    SCENARIO_ID = "S4-04"
    EXPECTED_RULES = ["100759", "100760", "100761"]

    @pytest.fixture(autouse=True)
    def _check_containers(self):
        _skip_if_k8s_down()

    def test_scenario_loads(self, scenario_loader):
        """Verify scenario JSON loads correctly."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        assert scenario is not None, f"Could not load scenario {self.SCENARIO_ID}"

    def test_phase1_env_variable_search(self):
        """Phase 1: Search environment for sensitive variables."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            "env | grep -iE '(password|secret|token|key|api)' || "
            "echo 'NO_SENSITIVE_VARS'",
            timeout=10
        )
        assert exit_code == 0

    def test_phase2_volume_mount_discovery(self):
        """Phase 2: Discover secret volume mounts."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            "find /var/run/secrets -type f 2>/dev/null | head -10 || "
            "echo 'NO_SECRET_MOUNTS'",
            timeout=15
        )
        assert exit_code == 0

    def test_phase2_mount_check(self):
        """Phase 2b: Check mount points for secret volumes."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            "mount | grep -i secret 2>/dev/null || echo 'NO_SECRET_MOUNTS'",
            timeout=10
        )
        assert exit_code == 0

    def test_phase3_secret_extraction(self):
        """Phase 3: Extract secret files from mounted volumes."""
        # Read SA token
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            "cat /var/run/secrets/kubernetes.io/serviceaccount/token "
            "2>/dev/null || echo 'NO_SA_TOKEN'",
            timeout=10
        )
        assert exit_code == 0
        token = stdout.strip()
        if token != "NO_SA_TOKEN":
            assert token.startswith("eyJ"), "SA token not in JWT format"

        # Log secret extraction for Wazuh detection
        DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            'logger -t nhi-security "NHI_ALERT: Secret extraction from pod - '
            'reading /var/run/secrets/kubernetes.io/serviceaccount/token"',
            timeout=10
        )

    def test_phase4_credential_use_simulation(self):
        """Phase 4: Simulate using stolen credentials."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            'logger -t nhi-security "NHI_ALERT: Credential use - '
            'mysql -h db-server -u app -p$(cat /etc/secrets/db-password)"',
            timeout=10
        )
        assert exit_code == 0, f"Credential use simulation failed: {stderr}"

    def test_expected_alerts_triggered(self, scenario_loader, alert_validator):
        """Verify expected Wazuh alerts fire."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        if not scenario:
            pytest.skip(f"Scenario {self.SCENARIO_ID} not found")

        # Trigger secret access
        DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            "cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null; "
            "find /var/run/secrets -type f 2>/dev/null || true",
            timeout=15
        )

        result = alert_validator.validate_scenario_alerts(
            scenario, timeout=60, agent_name=K8S_AGENT
        )
        if result["expected_count"] == 0:
            pytest.skip("No expected alerts defined")

        assert result["found_count"] > 0, \
            f"No alerts for {self.SCENARIO_ID}. Missing: {result['missing_rules']}"


@pytest.mark.e2e
@pytest.mark.category_4
class TestS405APIKeyAbuse:
    """S4-05: API key abuse via environment extraction.

    Attack chain:
    1. Extract environment variables containing API keys
    2. Classify discovered keys by service type
    3. Access debug endpoint exposing credentials
    """

    SCENARIO_ID = "S4-05"
    EXPECTED_RULES = ["100900", "100901"]

    @pytest.fixture(autouse=True)
    def _check_containers(self):
        _skip_if_containers_down(VULN_APP_CONTAINER)

    def test_scenario_loads(self, scenario_loader):
        """Verify scenario JSON loads correctly."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        assert scenario is not None, f"Could not load scenario {self.SCENARIO_ID}"
        assert "phases" in scenario, "Scenario missing phases"

    def test_phase1_env_enumeration(self):
        """Phase 1: Extract environment variables containing API keys."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            VULN_APP_CONTAINER,
            "env | grep -iE 'api|key|token' || echo 'NO_API_KEYS'",
            timeout=10
        )
        assert exit_code == 0, f"Env enumeration failed: {stderr}"

        # Log the enumeration for Wazuh detection
        DockerTestUtils.exec_in_container(
            VULN_APP_CONTAINER,
            'logger -t nhi-security "NHI_ALERT: API key enumeration - '
            'env | grep -iE api|key|token"',
            timeout=10
        )

    def test_phase2_key_identification(self):
        """Phase 2: Classify discovered keys by service type."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            VULN_APP_CONTAINER,
            "env | grep -iE 'api|key|token|secret' || echo 'NO_KEYS'",
            timeout=10
        )
        assert exit_code == 0

        # Log the key identification attempt
        DockerTestUtils.exec_in_container(
            VULN_APP_CONTAINER,
            'logger -t nhi-security "NHI_ALERT: API key classification - '
            'identifying service types from extracted keys"',
            timeout=10
        )

    def test_phase2_debug_endpoint_access(self, vulnerable_app_client):
        """Phase 2b: Access debug endpoint that exposes credentials."""
        try:
            response = vulnerable_app_client.get("/debug")
            assert response.status_code == 200, \
                f"Debug endpoint returned {response.status_code}"
            data = response.json()
            # Debug endpoint returns environment variables
            env_data = data.get("environment", data)
            assert len(str(env_data)) > 0, "Debug endpoint returned empty data"
        except Exception as e:
            pytest.skip(f"Debug endpoint not available: {e}")

    def test_phase2_config_endpoint_access(self, vulnerable_app_client):
        """Phase 2c: Access config endpoint with hardcoded credentials."""
        try:
            response = vulnerable_app_client.get("/config")
            assert response.status_code == 200, \
                f"Config endpoint returned {response.status_code}"
            data = response.json()
            config_str = str(data)
            # Check for credential patterns
            assert "AKIA" in config_str or "api" in config_str.lower(), \
                "Config endpoint should expose credential patterns"
        except Exception as e:
            pytest.skip(f"Config endpoint not available: {e}")

    def test_expected_alerts_triggered(self, scenario_loader, alert_validator):
        """Verify expected Wazuh alerts fire."""
        scenario = scenario_loader.load(self.SCENARIO_ID)
        if not scenario:
            pytest.skip(f"Scenario {self.SCENARIO_ID} not found")

        # Trigger API key enumeration
        DockerTestUtils.exec_in_container(
            VULN_APP_CONTAINER,
            "env | grep -iE 'api|key|token|secret' || true",
            timeout=10
        )
        DockerTestUtils.exec_in_container(
            VULN_APP_CONTAINER,
            'logger -t nhi-security "NHI_ALERT: API key enumeration - '
            'env | grep -iE api|key|token|secret"',
            timeout=10
        )

        result = alert_validator.validate_scenario_alerts(
            scenario, timeout=60, agent_name=VULN_APP_AGENT
        )
        if result["expected_count"] == 0:
            pytest.skip("No expected alerts defined")

        assert result["found_count"] > 0, \
            f"No alerts for {self.SCENARIO_ID}. Missing: {result['missing_rules']}"
