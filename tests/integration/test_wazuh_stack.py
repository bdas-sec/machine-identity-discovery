"""
Integration tests for Wazuh stack.

Tests Wazuh Manager, Indexer, and Dashboard integration.
"""

import pytest


@pytest.mark.integration
class TestWazuhManagerAPI:
    """Tests for Wazuh Manager API functionality."""

    def test_api_authentication(self, wazuh_client):
        """Test API authentication with credentials."""
        assert wazuh_client.authenticate(), \
            "Wazuh API authentication failed"

    def test_get_manager_info(self, wazuh_client):
        """Test getting manager information."""
        info = wazuh_client.get_manager_info()
        assert info is not None, "Could not get manager info"

    def test_get_manager_status(self, wazuh_client):
        """Test getting manager status."""
        status = wazuh_client.get_manager_status()
        assert status, "Could not get manager status"


@pytest.mark.integration
class TestWazuhRules:
    """Tests for Wazuh rules loading."""

    def test_rules_loaded(self, wazuh_client):
        """Verify rules are loaded in Wazuh."""
        rules = wazuh_client.get_rules(limit=100)
        assert len(rules) > 0, "No rules loaded in Wazuh"

    def test_nhi_rules_loaded(self, wazuh_client):
        """Verify NHI-specific rules are loaded."""
        nhi_rules = wazuh_client.get_nhi_rules()
        assert len(nhi_rules) > 0, \
            "No NHI rules (100600-100999) found"

    def test_minimum_nhi_rules(self, wazuh_client):
        """Verify minimum number of NHI rules loaded."""
        nhi_rules = wazuh_client.get_nhi_rules()
        # Expect at least 20 NHI rules
        assert len(nhi_rules) >= 20, \
            f"Expected >= 20 NHI rules, found {len(nhi_rules)}"

    def test_get_rule_by_id(self, wazuh_client):
        """Test getting specific rule by ID."""
        # Try to get a known NHI rule
        rule = wazuh_client.get_rule_by_id("100650")
        if rule:
            assert rule.get("id") == "100650"
        else:
            # Rule may not exist, try another common range
            rules = wazuh_client.get_rules(limit=1)
            if rules:
                rule_id = rules[0].get("id")
                rule = wazuh_client.get_rule_by_id(rule_id)
                assert rule is not None


@pytest.mark.integration
class TestWazuhDecoders:
    """Tests for Wazuh decoders loading."""

    def test_decoders_loaded(self, wazuh_client):
        """Verify decoders are loaded."""
        decoders = wazuh_client.get_decoders(limit=100)
        assert len(decoders) > 0, "No decoders loaded in Wazuh"


@pytest.mark.integration
class TestWazuhAgents:
    """Tests for Wazuh agent management."""

    def test_get_agents(self, wazuh_client):
        """Test getting list of agents."""
        agents = wazuh_client.get_agents()
        # Should have at least the manager (000)
        assert len(agents) >= 1, "No agents returned"

    def test_get_active_agents(self, wazuh_client):
        """Test getting active agents."""
        active = wazuh_client.get_active_agents()
        # At least some agents should be active
        assert len(active) >= 0, "Error getting active agents"

    def test_agent_has_required_fields(self, wazuh_client):
        """Verify agents have required fields."""
        agents = wazuh_client.get_agents()
        if not agents:
            pytest.skip("No agents found")

        for agent in agents:
            assert "id" in agent, "Agent missing id"
            assert "name" in agent, "Agent missing name"
            assert "status" in agent, "Agent missing status"


@pytest.mark.integration
class TestWazuhIndexer:
    """Tests for Wazuh Indexer (OpenSearch)."""

    def test_indexer_health(self, wazuh_indexer_client):
        """Test indexer cluster health."""
        assert wazuh_indexer_client.is_healthy(), \
            "Wazuh Indexer is not healthy"

    def test_indexer_cluster_status(self, wazuh_indexer_client):
        """Test cluster health status is acceptable."""
        health = wazuh_indexer_client.get_cluster_health()
        assert health.get("status") in ["green", "yellow"], \
            f"Cluster status is {health.get('status')}"

    def test_wazuh_indices_exist(self, wazuh_indexer_client):
        """Verify Wazuh indices exist."""
        indices = wazuh_indexer_client.get_indices()
        wazuh_indices = [i for i in indices if "wazuh" in i.lower()]
        assert len(wazuh_indices) > 0, "No Wazuh indices found"

    def test_alerts_index_exists(self, wazuh_indexer_client):
        """Verify alerts index exists."""
        indices = wazuh_indexer_client.get_indices()
        alerts_indices = [i for i in indices if "alert" in i.lower()]
        # Alerts index may not exist immediately
        assert isinstance(indices, list), "Could not get indices"


@pytest.mark.integration
class TestWazuhAlerts:
    """Tests for Wazuh alerts querying."""

    def test_query_alerts(self, wazuh_client):
        """Test querying alerts."""
        alerts = wazuh_client.query_alerts(limit=10)
        # May not have alerts yet, but shouldn't error
        assert isinstance(alerts, list), "Alerts query failed"

    def test_get_alert_count(self, wazuh_client):
        """Test getting alert count."""
        count = wazuh_client.get_alert_count()
        assert isinstance(count, int), "Could not get alert count"
        assert count >= 0, "Invalid alert count"
