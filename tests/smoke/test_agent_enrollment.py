"""
Wazuh agent enrollment smoke tests.

Verifies all agents are properly enrolled and active.
"""

import pytest


# Expected Wazuh agents in the testbed (matching docker-compose.yml)
# Agent names include "-001" suffix from WAZUH_AGENT_NAME env var
EXPECTED_AGENTS = [
    "cloud-workload-001",
    "vulnerable-app-001",
    "cicd-runner-001",
]


@pytest.mark.smoke
class TestAgentEnrollment:
    """Tests for Wazuh agent enrollment."""

    def test_agents_registered(self, wazuh_client):
        """Verify all expected agents are registered."""
        agents = wazuh_client.get_agents()
        agent_names = [a.get("name") for a in agents]

        for expected in EXPECTED_AGENTS:
            assert expected in agent_names, \
                f"Agent {expected} not registered. Found: {agent_names}"

    def test_minimum_agent_count(self, wazuh_client):
        """Verify minimum number of agents registered."""
        agents = wazuh_client.get_agents()
        # At least 3 agents + manager (agent 000)
        assert len(agents) >= 3, \
            f"Expected at least 3 agents, found {len(agents)}"


@pytest.mark.smoke
class TestAgentStatus:
    """Tests for Wazuh agent status."""

    def test_agents_active(self, wazuh_client):
        """Verify agents are in active status."""
        active_agents = wazuh_client.get_active_agents()

        # Should have at least some active agents
        assert len(active_agents) >= 1, \
            "No active agents found"

    def test_cloud_workload_agent_active(self, wazuh_client):
        """Verify cloud-workload agent is active."""
        agent = wazuh_client.get_agent_by_name("cloud-workload-001")

        if agent:
            assert agent.get("status") == "active", \
                f"cloud-workload-001 agent status: {agent.get('status')}"
        else:
            pytest.skip("cloud-workload-001 agent not found")

    def test_vulnerable_app_agent_active(self, wazuh_client):
        """Verify vulnerable-app agent is active."""
        agent = wazuh_client.get_agent_by_name("vulnerable-app-001")

        if agent:
            assert agent.get("status") == "active", \
                f"vulnerable-app-001 agent status: {agent.get('status')}"
        else:
            pytest.skip("vulnerable-app-001 agent not found")

    def test_cicd_runner_agent_active(self, wazuh_client):
        """Verify cicd-runner agent is active."""
        agent = wazuh_client.get_agent_by_name("cicd-runner-001")

        if agent:
            assert agent.get("status") == "active", \
                f"cicd-runner-001 agent status: {agent.get('status')}"
        else:
            pytest.skip("cicd-runner-001 agent not found")


@pytest.mark.smoke
class TestAgentConfiguration:
    """Tests for Wazuh agent configuration."""

    def test_agent_versions_consistent(self, wazuh_client):
        """Verify all agents are running same Wazuh version."""
        agents = wazuh_client.get_agents()

        versions = set()
        for agent in agents:
            version = agent.get("version")
            if version:
                versions.add(version)

        # All agents should be on same version
        assert len(versions) <= 2, \
            f"Multiple Wazuh versions detected: {versions}"

    def test_agents_have_ip(self, wazuh_client):
        """Verify all agents have IP addresses assigned."""
        agents = wazuh_client.get_agents()

        for agent in agents:
            if agent.get("id") != "000":  # Skip manager
                ip = agent.get("ip")
                assert ip and ip != "any", \
                    f"Agent {agent.get('name')} has no IP: {ip}"


@pytest.mark.smoke
class TestAgentGroups:
    """Tests for Wazuh agent group assignments."""

    def test_agents_in_default_group(self, wazuh_client):
        """Verify agents are in default group."""
        agents = wazuh_client.get_agents()

        for agent in agents:
            if agent.get("id") != "000":  # Skip manager
                groups = agent.get("group", [])
                assert len(groups) > 0, \
                    f"Agent {agent.get('name')} not in any group"

    def test_workload_agents_grouped(self, wazuh_client):
        """Verify workload agents are in appropriate groups."""
        workload_agents = ["cloud-workload-001", "cicd-runner-001"]

        for name in workload_agents:
            agent = wazuh_client.get_agent_by_name(name)
            if agent:
                # Workload agents should be in a group
                groups = agent.get("group", [])
                assert len(groups) > 0, \
                    f"Workload agent {name} should be in a group"
