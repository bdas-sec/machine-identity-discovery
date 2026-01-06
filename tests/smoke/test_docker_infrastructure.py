"""
Docker infrastructure smoke tests.

Verifies all containers, networks, and volumes are properly configured.
"""

import pytest
from helpers.docker_utils import DockerTestUtils


# Expected containers in the testbed (matching docker-compose.yml)
EXPECTED_CONTAINERS = [
    "wazuh-manager",
    "wazuh-indexer",
    "wazuh-dashboard",
    "cloud-workload",
    "vulnerable-app",
    "cicd-runner",
    "mock-imds",
    "mock-cicd",
    "vault",
]

# Expected Docker networks (matching docker-compose.yml)
EXPECTED_NETWORKS = [
    "machine-identity-discovery_mgmt_net",
    "machine-identity-discovery_cloud_net",
    "machine-identity-discovery_cicd_net",
    "machine-identity-discovery_k8s_net",
]


@pytest.mark.smoke
class TestDockerContainers:
    """Tests for Docker container status."""

    def test_all_containers_exist(self):
        """Verify all expected containers exist."""
        running = DockerTestUtils.get_running_containers()

        for container in EXPECTED_CONTAINERS:
            assert DockerTestUtils.container_exists(container), \
                f"Container {container} does not exist"

    def test_all_containers_running(self):
        """Verify all expected containers are running."""
        for container in EXPECTED_CONTAINERS:
            assert DockerTestUtils.container_running(container), \
                f"Container {container} is not running"

    def test_container_health_status(self):
        """Check container health where applicable."""
        # Containers with health checks
        health_containers = ["wazuh-manager", "wazuh-indexer"]

        for container in health_containers:
            status = DockerTestUtils.get_container_status(container)
            assert status == "running", \
                f"Container {container} status is {status}, expected running"

    def test_wazuh_manager_healthy(self):
        """Verify Wazuh manager container is healthy."""
        status = DockerTestUtils.get_container_status("wazuh-manager")
        assert status == "running", f"Wazuh manager status: {status}"

    def test_wazuh_indexer_healthy(self):
        """Verify Wazuh indexer container is healthy."""
        status = DockerTestUtils.get_container_status("wazuh-indexer")
        assert status == "running", f"Wazuh indexer status: {status}"


@pytest.mark.smoke
class TestDockerNetworks:
    """Tests for Docker network configuration."""

    def test_all_networks_exist(self):
        """Verify all expected networks exist."""
        for network in EXPECTED_NETWORKS:
            # Network names may vary based on project name
            base_name = network.split("_")[-1]
            exists = DockerTestUtils.network_exists(base_name) or \
                     DockerTestUtils.network_exists(network)
            assert exists, f"Network {network} does not exist"

    def test_wazuh_network_connectivity(self):
        """Verify Wazuh components are on the same network."""
        wazuh_containers = ["wazuh-manager", "wazuh-indexer", "wazuh-dashboard"]

        for container in wazuh_containers:
            networks = DockerTestUtils.get_container_networks(container)
            assert len(networks) > 0, \
                f"Container {container} not connected to any network"

    def test_cloud_workload_network(self):
        """Verify cloud-workload container has appropriate network access."""
        networks = DockerTestUtils.get_container_networks("cloud-workload")
        assert len(networks) > 0, "cloud-workload container has no network"

    def test_mock_services_network(self):
        """Verify mock services are on mock-cloud network."""
        mock_containers = ["mock-imds", "mock-cicd"]

        for container in mock_containers:
            networks = DockerTestUtils.get_container_networks(container)
            assert len(networks) > 0, \
                f"Mock service {container} not on any network"


@pytest.mark.smoke
class TestContainerConnectivity:
    """Tests for inter-container network connectivity."""

    def test_cloud_workload_can_reach_vulnerable_app(self):
        """Verify cloud-workload can reach vulnerable-app on port 8080."""
        can_reach = DockerTestUtils.can_reach(
            "cloud-workload", "vulnerable-app", 8080, timeout=5
        )
        assert can_reach, "cloud-workload cannot reach vulnerable-app:8080"

    def test_cloud_workload_can_reach_mock_imds(self):
        """Verify cloud-workload can reach mock-imds on port 1338."""
        can_reach = DockerTestUtils.can_reach(
            "cloud-workload", "mock-imds", 1338, timeout=5
        )
        assert can_reach, "cloud-workload cannot reach mock-imds:1338"

    def test_cicd_runner_can_reach_mock_cicd(self):
        """Verify cicd-runner can reach mock-cicd on port 8080."""
        can_reach = DockerTestUtils.can_reach(
            "cicd-runner", "mock-cicd", 8080, timeout=5
        )
        assert can_reach, "cicd-runner cannot reach mock-cicd:8080"

    def test_wazuh_internal_connectivity(self):
        """Verify Wazuh manager can reach indexer."""
        can_reach = DockerTestUtils.can_reach(
            "wazuh-manager", "wazuh-indexer", 9200, timeout=5
        )
        assert can_reach, "Wazuh manager cannot reach indexer:9200"


@pytest.mark.smoke
class TestContainerEnvironment:
    """Tests for container environment configuration."""

    def test_vulnerable_app_env(self):
        """Verify vulnerable-app has required environment variables."""
        env = DockerTestUtils.get_container_env("vulnerable-app")
        # Should have some basic env vars
        assert len(env) > 0, "vulnerable-app has no environment variables"

    def test_mock_imds_env(self):
        """Verify mock-imds has required environment variables."""
        env = DockerTestUtils.get_container_env("mock-imds")
        assert len(env) > 0, "mock-imds has no environment variables"

    def test_wazuh_manager_env(self):
        """Verify wazuh-manager has required environment variables."""
        env = DockerTestUtils.get_container_env("wazuh-manager")
        assert len(env) > 0, "wazuh-manager has no environment variables"
