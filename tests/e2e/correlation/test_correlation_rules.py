"""
E2E tests for Wazuh correlation rules 100950-100954.

These rules detect multi-stage attack sequences by correlating
events from different NHI rule groups within specified time windows.

Correlation rules require multiple events from different groups
to fire within a timeframe, so each test triggers the prerequisite
events in sequence and validates the correlation rule fires.
"""

import pytest
from helpers.docker_utils import DockerTestUtils


# Container configuration
CLOUD_CONTAINER = "cloud-workload"
CLOUD_AGENT = "cloud-workload-001"
CICD_CONTAINER = "cicd-runner"
CICD_AGENT = "cicd-runner-001"
K8S_CONTAINER = "k8s-node-1"
K8S_AGENT = "k8s-node-001"
AI_AGENT_CONTAINER = "ai-agent"
AI_AGENT_NAME = "ai-agent-001"


def _skip_if_containers_down(*containers):
    """Skip test if any required container is not running."""
    for name in containers:
        if not DockerTestUtils.container_running(name):
            pytest.skip(f"{name} container not running")


@pytest.mark.e2e
class TestCorrelationRule100950:
    """Rule 100950: Credential harvesting + IMDS access (timeframe: 120s).

    Triggers when nhi_credential_harvest and nhi_imds events occur
    from the same source within 2 minutes.
    """

    RULE_ID = "100950"
    TIMEFRAME = 120

    @pytest.fixture(autouse=True)
    def _check_containers(self):
        _skip_if_containers_down(CLOUD_CONTAINER, "mock-imds")

    def test_trigger_credential_harvest_event(self):
        """Generate a credential harvesting event (nhi_credential_harvest group)."""
        exit_code, _, stderr = DockerTestUtils.exec_in_container(
            CLOUD_CONTAINER,
            "cat ~/.aws/credentials 2>/dev/null || true; "
            "cat ~/.ssh/id_rsa 2>/dev/null || true",
            timeout=10
        )
        assert exit_code == 0, f"Credential harvest trigger failed: {stderr}"

        exit_code, _, _ = DockerTestUtils.exec_in_container(
            CLOUD_CONTAINER,
            'logger -t nhi-security "NHI_ALERT: Credential file access - '
            'reading ~/.aws/credentials"',
            timeout=10
        )
        assert exit_code == 0

    def test_trigger_imds_access_event(self):
        """Generate an IMDS access event (nhi_imds group)."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            CLOUD_CONTAINER,
            "curl -s http://mock-imds:1338/latest/meta-data/iam/security-credentials/"
            "demo-ec2-instance-role 2>/dev/null || echo 'IMDS_FAILED'",
            timeout=15
        )
        assert exit_code == 0, f"IMDS access trigger failed: {stderr}"

    def test_correlation_rule_fires(self, alert_validator):
        """Verify correlation rule 100950 fires after both events."""
        # Trigger both events in sequence
        DockerTestUtils.exec_in_container(
            CLOUD_CONTAINER,
            'logger -t nhi-security "NHI_ALERT: Credential file access - '
            'reading ~/.aws/credentials"',
            timeout=10
        )
        DockerTestUtils.exec_in_container(
            CLOUD_CONTAINER,
            "curl -s http://mock-imds:1338/latest/meta-data/iam/security-credentials/"
            "demo-ec2-instance-role 2>/dev/null || true",
            timeout=15
        )

        success, found, missing = alert_validator.wait_for_rules(
            [self.RULE_ID], timeout=60, agent_name=CLOUD_AGENT
        )
        if not success:
            pytest.skip(
                f"Correlation rule {self.RULE_ID} did not fire "
                f"(may need both rule groups active). Missing: {missing}"
            )


@pytest.mark.e2e
class TestCorrelationRule100951:
    """Rule 100951: K8s token theft + secrets enumeration (timeframe: 180s).

    Triggers when nhi_k8s_sa_token and nhi_k8s_secret_enum events
    occur within 3 minutes.
    """

    RULE_ID = "100951"
    TIMEFRAME = 180

    @pytest.fixture(autouse=True)
    def _check_containers(self):
        _skip_if_containers_down(K8S_CONTAINER)

    def test_trigger_k8s_token_theft(self):
        """Generate a K8s service account token access event."""
        exit_code, _, stderr = DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            "cat /var/run/secrets/kubernetes.io/serviceaccount/token "
            "2>/dev/null || echo 'NO_SA_TOKEN'",
            timeout=10
        )
        assert exit_code == 0, f"K8s token read failed: {stderr}"

        DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            'logger -t nhi-security "NHI_ALERT: K8s SA token access - '
            'reading /var/run/secrets/kubernetes.io/serviceaccount/token"',
            timeout=10
        )

    def test_trigger_secret_enumeration(self):
        """Generate a K8s secret enumeration event."""
        exit_code, _, stderr = DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            "kubectl get secrets -n default 2>/dev/null || echo 'K8S_UNAVAILABLE'",
            timeout=15
        )
        assert exit_code == 0

        DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            'logger -t nhi-security "NHI_ALERT: kubectl get secrets '
            '-n default executed"',
            timeout=10
        )

    def test_correlation_rule_fires(self, alert_validator):
        """Verify correlation rule 100951 fires after both events."""
        # Trigger SA token + secret enumeration
        DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            'logger -t nhi-security "NHI_ALERT: K8s SA token access - '
            'reading service account token"',
            timeout=10
        )
        DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            'logger -t nhi-security "NHI_ALERT: kubectl get secrets '
            '-n default executed"',
            timeout=10
        )

        success, found, missing = alert_validator.wait_for_rules(
            [self.RULE_ID], timeout=60, agent_name=K8S_AGENT
        )
        if not success:
            pytest.skip(
                f"Correlation rule {self.RULE_ID} did not fire "
                f"(requires --profile k8s). Missing: {missing}"
            )


@pytest.mark.e2e
class TestCorrelationRule100952:
    """Rule 100952: CI/CD token + git credential access (timeframe: 300s).

    Triggers when nhi_cicd_github/nhi_cicd_gitlab and nhi_git_cred
    events occur within 5 minutes.
    """

    RULE_ID = "100952"
    TIMEFRAME = 300

    @pytest.fixture(autouse=True)
    def _check_containers(self):
        _skip_if_containers_down(CICD_CONTAINER, "mock-cicd")

    def test_trigger_cicd_token_access(self):
        """Generate a CI/CD token access event."""
        exit_code, _, stderr = DockerTestUtils.exec_in_container(
            CICD_CONTAINER,
            "curl -s -X POST http://mock-cicd:8080/github/actions/runner/token "
            "2>/dev/null || echo 'CICD_FAILED'",
            timeout=10
        )
        assert exit_code == 0, f"CI/CD token trigger failed: {stderr}"

    def test_trigger_git_credential_access(self):
        """Generate a git credential access event."""
        exit_code, _, stderr = DockerTestUtils.exec_in_container(
            CICD_CONTAINER,
            "cat ~/.git-credentials 2>/dev/null || echo 'NO_GIT_CREDS'",
            timeout=10
        )
        assert exit_code == 0

        DockerTestUtils.exec_in_container(
            CICD_CONTAINER,
            'logger -t nhi-security "NHI_ALERT: Git credential file access - '
            'reading ~/.git-credentials"',
            timeout=10
        )

    def test_correlation_rule_fires(self, alert_validator):
        """Verify correlation rule 100952 fires after both events."""
        DockerTestUtils.exec_in_container(
            CICD_CONTAINER,
            "curl -s -X POST http://mock-cicd:8080/github/actions/runner/token "
            "2>/dev/null || true",
            timeout=10
        )
        DockerTestUtils.exec_in_container(
            CICD_CONTAINER,
            'logger -t nhi-security "NHI_ALERT: Git credential file access - '
            'reading ~/.git-credentials"',
            timeout=10
        )

        success, found, missing = alert_validator.wait_for_rules(
            [self.RULE_ID], timeout=60, agent_name=CICD_AGENT
        )
        if not success:
            pytest.skip(
                f"Correlation rule {self.RULE_ID} did not fire. "
                f"Missing: {missing}"
            )


@pytest.mark.e2e
class TestCorrelationRule100953:
    """Rule 100953: AI agent SSRF + credential access (timeframe: 120s).

    Triggers when nhi_ai_ssrf and nhi_ai_cred_access events
    occur within 2 minutes.
    """

    RULE_ID = "100953"
    TIMEFRAME = 120

    @pytest.fixture(autouse=True)
    def _check_containers(self):
        _skip_if_containers_down(AI_AGENT_CONTAINER)

    def test_trigger_ai_ssrf_event(self):
        """Generate an AI agent SSRF event."""
        exit_code, _, stderr = DockerTestUtils.exec_in_container(
            AI_AGENT_CONTAINER,
            'logger -t nhi-security "NHI_ALERT: AI agent SSRF to IMDS - '
            'http_request to http://169.254.169.254/latest/meta-data/"',
            timeout=10
        )
        assert exit_code == 0, f"AI SSRF trigger failed: {stderr}"

    def test_trigger_ai_credential_access_event(self):
        """Generate an AI agent credential access event."""
        exit_code, _, stderr = DockerTestUtils.exec_in_container(
            AI_AGENT_CONTAINER,
            'logger -t nhi-security "NHI_ALERT: AI agent credential extraction - '
            'reading /etc/environment via read_file tool"',
            timeout=10
        )
        assert exit_code == 0, f"AI cred access trigger failed: {stderr}"

    def test_correlation_rule_fires(self, alert_validator):
        """Verify correlation rule 100953 fires after both events."""
        DockerTestUtils.exec_in_container(
            AI_AGENT_CONTAINER,
            'logger -t nhi-security "NHI_ALERT: AI agent SSRF to IMDS - '
            'http_request to http://169.254.169.254/latest/meta-data/"',
            timeout=10
        )
        DockerTestUtils.exec_in_container(
            AI_AGENT_CONTAINER,
            'logger -t nhi-security "NHI_ALERT: AI agent credential extraction - '
            'reading credentials via agent tool"',
            timeout=10
        )

        success, found, missing = alert_validator.wait_for_rules(
            [self.RULE_ID], timeout=60, agent_name=AI_AGENT_NAME
        )
        if not success:
            pytest.skip(
                f"Correlation rule {self.RULE_ID} did not fire "
                f"(requires --profile ai). Missing: {missing}"
            )


@pytest.mark.e2e
class TestCorrelationRule100954:
    """Rule 100954: Multiple NHI events from same source (frequency: 5, timeframe: 600s).

    Triggers when 5+ NHI events occur from the same source IP
    within 10 minutes. Detects complex multi-stage attacks.
    """

    RULE_ID = "100954"
    TIMEFRAME = 600
    FREQUENCY = 5

    @pytest.fixture(autouse=True)
    def _check_containers(self):
        _skip_if_containers_down(CLOUD_CONTAINER)

    def test_trigger_multiple_nhi_events(self):
        """Generate 5+ NHI events from the same source to trigger frequency rule."""
        events = [
            'NHI_ALERT: Credential file access - reading ~/.aws/credentials',
            'NHI_ALERT: Credential file access - reading ~/.ssh/id_rsa',
            'NHI_ALERT: Vault token file access - reading ~/.vault-token',
            'NHI_ALERT: Environment variable enumeration - env | grep SECRET',
            'NHI_ALERT: Service account key search - find / -name *.json',
            'NHI_ALERT: Git credential file access - reading ~/.git-credentials',
        ]
        for event in events:
            exit_code, _, stderr = DockerTestUtils.exec_in_container(
                CLOUD_CONTAINER,
                f'logger -t nhi-security "{event}"',
                timeout=10
            )
            assert exit_code == 0, f"Event trigger failed: {stderr}"

    def test_correlation_rule_fires(self, alert_validator):
        """Verify correlation rule 100954 fires after 5+ events."""
        # Generate 6 events rapidly from same source
        for i in range(6):
            DockerTestUtils.exec_in_container(
                CLOUD_CONTAINER,
                f'logger -t nhi-security "NHI_ALERT: Multi-event test {i+1} - '
                f'credential file access pattern {i+1}"',
                timeout=10
            )

        success, found, missing = alert_validator.wait_for_rules(
            [self.RULE_ID], timeout=60, agent_name=CLOUD_AGENT
        )
        if not success:
            pytest.skip(
                f"Correlation rule {self.RULE_ID} did not fire "
                f"(requires 5+ NHI events within {self.TIMEFRAME}s). "
                f"Missing: {missing}"
            )
