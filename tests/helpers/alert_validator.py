"""
Alert validation utilities for scenario testing.
"""

import time
from typing import List, Dict, Tuple, Set, Optional


class AlertValidator:
    """Validates Wazuh alerts for scenario testing."""

    def __init__(self, wazuh_client):
        self.wazuh = wazuh_client

    def wait_for_rules(
        self,
        rule_ids: List[str],
        timeout: int = 30,
        poll_interval: float = 1.0,
        agent_name: str = None
    ) -> Tuple[bool, List[str], List[str]]:
        """
        Wait for specific rules to trigger.

        Args:
            rule_ids: List of rule IDs to wait for
            timeout: Maximum time to wait in seconds
            poll_interval: Time between polling in seconds
            agent_name: Optional filter by agent name

        Returns:
            Tuple of (success, found_rules, missing_rules)
        """
        expected: Set[str] = set(str(r) for r in rule_ids)
        start_time = time.time()
        found: Set[str] = set()

        while time.time() - start_time < timeout:
            alerts = self.wazuh.query_alerts(
                rule_ids=list(expected),
                agent_name=agent_name,
                minutes=5
            )

            for alert in alerts:
                rule_id = str(alert.get("rule", {}).get("id"))
                if rule_id in expected:
                    found.add(rule_id)

            if found >= expected:
                return True, list(found), []

            time.sleep(poll_interval)

        missing = expected - found
        return False, list(found), list(missing)

    def validate_scenario_alerts(
        self,
        scenario: Dict,
        timeout: int = 30,
        agent_name: str = None
    ) -> Dict:
        """
        Validate all expected alerts for a scenario.

        Args:
            scenario: Scenario dictionary with expected_wazuh_alerts
            timeout: Maximum time to wait
            agent_name: Optional filter by agent name

        Returns:
            Dict with validation results
        """
        expected_alerts = scenario.get("expected_wazuh_alerts", [])
        expected_rule_ids = [str(a.get("rule_id")) for a in expected_alerts if a.get("rule_id")]

        if not expected_rule_ids:
            return {
                "success": True,
                "scenario_id": scenario.get("id"),
                "message": "No expected alerts defined",
                "expected_count": 0,
                "found_count": 0,
                "found_rules": [],
                "missing_rules": []
            }

        success, found, missing = self.wait_for_rules(
            expected_rule_ids,
            timeout=timeout,
            agent_name=agent_name
        )

        return {
            "success": success,
            "scenario_id": scenario.get("id"),
            "expected_count": len(expected_rule_ids),
            "found_count": len(found),
            "found_rules": found,
            "missing_rules": missing,
            "expected_alerts": expected_alerts
        }

    def get_alert_details(
        self,
        rule_id: str,
        limit: int = 5,
        agent_name: str = None
    ) -> List[Dict]:
        """Get detailed alert information for a specific rule."""
        return self.wazuh.query_alerts(
            rule_ids=[rule_id],
            agent_name=agent_name,
            limit=limit
        )

    def verify_alert_level(
        self,
        rule_id: str,
        expected_level: int,
        agent_name: str = None
    ) -> bool:
        """Verify that a rule triggers at the expected level."""
        alerts = self.get_alert_details(rule_id, limit=1, agent_name=agent_name)
        if not alerts:
            return False
        actual_level = alerts[0].get("rule", {}).get("level")
        return actual_level == expected_level

    def verify_mitre_mapping(
        self,
        rule_id: str,
        expected_techniques: List[str],
        agent_name: str = None
    ) -> Tuple[bool, List[str]]:
        """
        Verify MITRE ATT&CK mapping for a rule.

        Returns:
            Tuple of (success, missing_techniques)
        """
        alerts = self.get_alert_details(rule_id, limit=1, agent_name=agent_name)
        if not alerts:
            return False, expected_techniques

        mitre = alerts[0].get("rule", {}).get("mitre", {})
        actual_techniques = []

        # Handle different MITRE formats in alerts
        if isinstance(mitre, dict):
            actual_techniques = mitre.get("technique", [])
            if isinstance(actual_techniques, str):
                actual_techniques = [actual_techniques]
        elif isinstance(mitre, list):
            actual_techniques = mitre

        expected_set = set(expected_techniques)
        actual_set = set(actual_techniques)

        missing = expected_set - actual_set
        return len(missing) == 0, list(missing)

    def count_alerts_by_rule(
        self,
        rule_ids: List[str] = None,
        minutes: int = 5,
        agent_name: str = None
    ) -> Dict[str, int]:
        """Count alerts grouped by rule ID."""
        alerts = self.wazuh.query_alerts(
            rule_ids=rule_ids,
            agent_name=agent_name,
            minutes=minutes,
            limit=500
        )

        counts: Dict[str, int] = {}
        for alert in alerts:
            rule_id = str(alert.get("rule", {}).get("id"))
            counts[rule_id] = counts.get(rule_id, 0) + 1

        return counts
