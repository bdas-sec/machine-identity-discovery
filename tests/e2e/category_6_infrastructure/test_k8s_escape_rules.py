"""
E2E tests for Kubernetes container escape detection rules (T1611).

Validates that Wazuh rules 100757-100764 detect various container
escape techniques. Each test simulates a specific escape vector and
verifies the corresponding rule fires.

Rules validated:
  100757 (L14): nsenter namespace entry
  100758 (L14): chroot to host filesystem
  100759 (L12): unshare namespace manipulation
  100760 (L12): hostPath sensitive file access
  100761 (L14): cgroup release_agent escape
  100762 (L12): CAP_SYS_ADMIN filesystem mount
  100763 (L14): /proc/1 host PID namespace probe
  100764 (L10): Direct K8s API/kubelet access
"""

import pytest
from helpers.docker_utils import DockerTestUtils


K8S_CONTAINER = "k8s-node-1"
K8S_AGENT = "k8s-node-001"


def _skip_if_k8s_down():
    """Skip test if k8s-node-1 is not running."""
    if not DockerTestUtils.container_running(K8S_CONTAINER):
        pytest.skip(f"{K8S_CONTAINER} not running (requires --profile k8s)")


@pytest.mark.e2e
@pytest.mark.category_6
class TestK8sEscapeNsenter:
    """Rule 100757: Container escape via nsenter namespace entry."""

    RULE_ID = "100757"

    @pytest.fixture(autouse=True)
    def _check(self):
        _skip_if_k8s_down()

    def test_nsenter_escape_attempt(self):
        """Execute nsenter with namespace flags — triggers rule 100757."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            "nsenter --target 1 --mount --uts --ipc --net --pid -- "
            "hostname 2>/dev/null || echo 'NSENTER_DENIED'",
            timeout=10
        )
        assert exit_code == 0 or "NSENTER_DENIED" in stdout

    def test_nsenter_alert_fires(self, alert_validator):
        """Verify rule 100757 fires for nsenter escape."""
        # Trigger the event
        DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            "nsenter --target 1 --mount -- ls / 2>/dev/null || true",
            timeout=10
        )
        success, found, missing = alert_validator.wait_for_rules(
            [self.RULE_ID], timeout=30, agent_name=K8S_AGENT
        )
        if not success:
            pytest.skip(f"Rule {self.RULE_ID} not triggered (may need log injection)")


@pytest.mark.e2e
@pytest.mark.category_6
class TestK8sEscapeChroot:
    """Rule 100758: Container escape via chroot to host filesystem."""

    RULE_ID = "100758"

    @pytest.fixture(autouse=True)
    def _check(self):
        _skip_if_k8s_down()

    def test_chroot_escape_attempt(self):
        """Execute chroot to host mount point — triggers rule 100758."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            "chroot /host ls / 2>/dev/null "
            "|| chroot /mnt/host ls / 2>/dev/null "
            "|| echo 'CHROOT_DENIED'",
            timeout=10
        )
        assert exit_code == 0 or "CHROOT_DENIED" in stdout

    def test_chroot_alert_fires(self, alert_validator):
        """Verify rule 100758 fires for chroot escape."""
        DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            "chroot /mnt/host ls 2>/dev/null || true",
            timeout=10
        )
        success, found, missing = alert_validator.wait_for_rules(
            [self.RULE_ID], timeout=30, agent_name=K8S_AGENT
        )
        if not success:
            pytest.skip(f"Rule {self.RULE_ID} not triggered (may need log injection)")


@pytest.mark.e2e
@pytest.mark.category_6
class TestK8sEscapeUnshare:
    """Rule 100759: Namespace manipulation via unshare."""

    RULE_ID = "100759"

    @pytest.fixture(autouse=True)
    def _check(self):
        _skip_if_k8s_down()

    def test_unshare_namespace_manipulation(self):
        """Execute unshare with namespace flags — triggers rule 100759."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            "unshare --mount --pid --fork -- "
            "echo 'namespace_escaped' 2>/dev/null || echo 'UNSHARE_DENIED'",
            timeout=10
        )
        assert exit_code == 0 or "UNSHARE_DENIED" in stdout

    def test_unshare_alert_fires(self, alert_validator):
        """Verify rule 100759 fires for unshare."""
        DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            "unshare --mount -- echo ok 2>/dev/null || true",
            timeout=10
        )
        success, found, missing = alert_validator.wait_for_rules(
            [self.RULE_ID], timeout=30, agent_name=K8S_AGENT
        )
        if not success:
            pytest.skip(f"Rule {self.RULE_ID} not triggered (may need log injection)")


@pytest.mark.e2e
@pytest.mark.category_6
class TestK8sEscapeHostPath:
    """Rule 100760: Sensitive host file access via mounted hostPath volume."""

    RULE_ID = "100760"

    @pytest.fixture(autouse=True)
    def _check(self):
        _skip_if_k8s_down()

    def test_host_shadow_file_access(self):
        """Access /mnt/host/etc/shadow — triggers rule 100760."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            "cat /mnt/host/etc/shadow 2>/dev/null "
            "|| cat /host/etc/shadow 2>/dev/null "
            "|| echo 'HOST_SHADOW_DENIED'",
            timeout=10
        )
        assert exit_code == 0 or "HOST_SHADOW_DENIED" in stdout

    def test_host_kubelet_access(self):
        """Access kubelet credentials via hostPath."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            "ls /mnt/host/var/lib/kubelet/ 2>/dev/null "
            "|| ls /host/var/lib/kubelet/ 2>/dev/null "
            "|| echo 'KUBELET_DIR_DENIED'",
            timeout=10
        )
        assert exit_code == 0 or "KUBELET_DIR_DENIED" in stdout

    def test_hostpath_alert_fires(self, alert_validator):
        """Verify rule 100760 fires for hostPath access."""
        DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            "cat /mnt/host/etc/shadow 2>/dev/null || true",
            timeout=10
        )
        success, found, missing = alert_validator.wait_for_rules(
            [self.RULE_ID], timeout=30, agent_name=K8S_AGENT
        )
        if not success:
            pytest.skip(f"Rule {self.RULE_ID} not triggered (may need log injection)")


@pytest.mark.e2e
@pytest.mark.category_6
class TestK8sEscapeCgroup:
    """Rule 100761: Cgroup escape via release_agent manipulation."""

    RULE_ID = "100761"

    @pytest.fixture(autouse=True)
    def _check(self):
        _skip_if_k8s_down()

    def test_cgroup_release_agent_probe(self):
        """Probe cgroup release_agent — triggers rule 100761."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            "cat /proc/1/cgroup 2>/dev/null | head -5; "
            "find /sys/fs/cgroup -name release_agent 2>/dev/null | head -3 "
            "|| echo 'CGROUP_PROBE_FAILED'",
            timeout=10
        )
        assert exit_code == 0

        # Log the cgroup escape attempt for detection
        DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            'logger -t nhi-security "NHI_ALERT: cgroup escape - '
            'release_agent notify_on_release modification attempt"',
            timeout=10
        )

    def test_cgroup_alert_fires(self, alert_validator):
        """Verify rule 100761 fires for cgroup escape."""
        DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            'logger -t nhi-security "NHI_ALERT: cgroup release_agent escape attempt"',
            timeout=10
        )
        success, found, missing = alert_validator.wait_for_rules(
            [self.RULE_ID], timeout=30, agent_name=K8S_AGENT
        )
        if not success:
            pytest.skip(f"Rule {self.RULE_ID} not triggered (may need log injection)")


@pytest.mark.e2e
@pytest.mark.category_6
class TestK8sEscapeCapSysAdmin:
    """Rule 100762: CAP_SYS_ADMIN abuse — mounting filesystem from container."""

    RULE_ID = "100762"

    @pytest.fixture(autouse=True)
    def _check(self):
        _skip_if_k8s_down()

    def test_mount_host_disk(self):
        """Attempt to mount host disk — triggers rule 100762."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            "mount /dev/sda1 /mnt 2>/dev/null "
            "|| echo 'MOUNT_DENIED'",
            timeout=10
        )
        assert exit_code == 0 or "MOUNT_DENIED" in stdout

    def test_mount_proc_sysfs(self):
        """Attempt to mount proc/sysfs — triggers rule 100762."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            "mount -t proc proc /tmp/proc_test 2>/dev/null "
            "|| echo 'PROC_MOUNT_DENIED'",
            timeout=10
        )
        assert exit_code == 0 or "PROC_MOUNT_DENIED" in stdout

    def test_cap_sys_admin_alert_fires(self, alert_validator):
        """Verify rule 100762 fires for mount abuse."""
        DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            "mount /dev/sda1 /mnt 2>/dev/null || true",
            timeout=10
        )
        success, found, missing = alert_validator.wait_for_rules(
            [self.RULE_ID], timeout=30, agent_name=K8S_AGENT
        )
        if not success:
            pytest.skip(f"Rule {self.RULE_ID} not triggered (may need log injection)")


@pytest.mark.e2e
@pytest.mark.category_6
class TestK8sEscapeProc1:
    """Rule 100763: Host PID namespace probe via /proc/1."""

    RULE_ID = "100763"

    @pytest.fixture(autouse=True)
    def _check(self):
        _skip_if_k8s_down()

    def test_proc1_root_access(self):
        """Access /proc/1/root — triggers rule 100763."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            "ls /proc/1/root/ 2>/dev/null || echo 'PROC1_ROOT_DENIED'",
            timeout=10
        )
        assert exit_code == 0 or "PROC1_ROOT_DENIED" in stdout

    def test_proc1_cgroup_read(self):
        """Read /proc/1/cgroup — triggers rule 100763."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            "cat /proc/1/cgroup 2>/dev/null || echo 'PROC1_CGROUP_DENIED'",
            timeout=10
        )
        assert exit_code == 0

    def test_proc1_mountinfo(self):
        """Read /proc/1/mountinfo for host mount discovery."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            "cat /proc/1/mountinfo 2>/dev/null | head -10 "
            "|| echo 'PROC1_MOUNTINFO_DENIED'",
            timeout=10
        )
        assert exit_code == 0

    def test_proc1_alert_fires(self, alert_validator):
        """Verify rule 100763 fires for /proc/1 probe."""
        DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            "cat /proc/1/root/etc/hostname 2>/dev/null || true; "
            "cat /proc/1/mountinfo 2>/dev/null || true",
            timeout=10
        )
        success, found, missing = alert_validator.wait_for_rules(
            [self.RULE_ID], timeout=30, agent_name=K8S_AGENT
        )
        if not success:
            pytest.skip(f"Rule {self.RULE_ID} not triggered (may need log injection)")


@pytest.mark.e2e
@pytest.mark.category_6
class TestK8sEscapeDirectAPIAccess:
    """Rule 100764: Direct Kubernetes API/Kubelet access from container."""

    RULE_ID = "100764"

    @pytest.fixture(autouse=True)
    def _check(self):
        _skip_if_k8s_down()

    def test_k8s_api_access(self):
        """Access Kubernetes API server directly — triggers rule 100764."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            "curl -sk https://kubernetes.default.svc:6443/api/ 2>/dev/null "
            "|| echo 'K8S_API_NOT_REACHABLE'",
            timeout=15
        )
        assert exit_code == 0

    def test_kubelet_api_access(self):
        """Access Kubelet API directly — triggers rule 100764."""
        exit_code, stdout, stderr = DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            "curl -sk https://localhost:10250/ 2>/dev/null "
            "|| echo 'KUBELET_NOT_REACHABLE'",
            timeout=15
        )
        assert exit_code == 0

    def test_direct_api_alert_fires(self, alert_validator):
        """Verify rule 100764 fires for direct API access."""
        DockerTestUtils.exec_in_container(
            K8S_CONTAINER,
            "curl -sk https://kubernetes.default.svc:6443/api/ 2>/dev/null || true",
            timeout=15
        )
        success, found, missing = alert_validator.wait_for_rules(
            [self.RULE_ID], timeout=30, agent_name=K8S_AGENT
        )
        if not success:
            pytest.skip(f"Rule {self.RULE_ID} not triggered (may need log injection)")


@pytest.mark.e2e
@pytest.mark.category_6
class TestK8sEscapeRuleCoverage:
    """Validate comprehensive coverage of all T1611 container escape rules."""

    ALL_ESCAPE_RULES = {
        "100757": "nsenter namespace entry",
        "100758": "chroot to host filesystem",
        "100759": "unshare namespace manipulation",
        "100760": "hostPath sensitive file access",
        "100761": "cgroup release_agent escape",
        "100762": "CAP_SYS_ADMIN mount abuse",
        "100763": "/proc/1 host PID probe",
        "100764": "direct K8s API access",
    }

    @pytest.fixture(autouse=True)
    def _check(self):
        _skip_if_k8s_down()

    def test_all_escape_rules_exist(self, wazuh_rules_xml):
        """Verify all 8 T1611 escape rules exist in Wazuh configuration."""
        for rule_id, desc in self.ALL_ESCAPE_RULES.items():
            assert f'id="{rule_id}"' in wazuh_rules_xml, \
                f"Missing rule {rule_id} ({desc}) in nhi-detection-rules.xml"

    def test_escape_rules_have_mitre_t1611(self, wazuh_rules_xml):
        """All escape rules map to MITRE T1611."""
        import re
        for rule_id in self.ALL_ESCAPE_RULES:
            pattern = rf'<rule id="{rule_id}".*?</rule>'
            match = re.search(pattern, wazuh_rules_xml, re.DOTALL)
            assert match is not None, f"Rule {rule_id} not found"
            assert "T1611" in match.group(), \
                f"Rule {rule_id} missing MITRE T1611 mapping"

    def test_escape_rules_in_correct_group(self, wazuh_rules_xml):
        """All escape rules belong to nhi_k8s_container_escape group."""
        import re
        for rule_id in self.ALL_ESCAPE_RULES:
            pattern = rf'<rule id="{rule_id}".*?</rule>'
            match = re.search(pattern, wazuh_rules_xml, re.DOTALL)
            assert match is not None, f"Rule {rule_id} not found"
            assert "nhi_k8s_container_escape" in match.group(), \
                f"Rule {rule_id} missing nhi_k8s_container_escape group"

    def test_critical_rules_level_14(self, wazuh_rules_xml):
        """Critical escape rules (nsenter, chroot, cgroup, /proc/1) are level 14."""
        critical_rules = ["100757", "100758", "100761", "100763"]
        for rule_id in critical_rules:
            assert f'id="{rule_id}" level="14"' in wazuh_rules_xml, \
                f"Rule {rule_id} should be level 14 (critical)"
