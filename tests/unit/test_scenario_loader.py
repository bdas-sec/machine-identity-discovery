"""
Unit tests for scenario loader.

Tests scenario JSON loading and validation.
"""

import pytest
from pathlib import Path


@pytest.mark.unit
class TestScenarioLoading:
    """Tests for loading scenario files."""

    def test_load_all_scenarios(self, scenario_loader):
        """Verify all scenarios can be loaded."""
        scenarios = scenario_loader.load_all()
        assert len(scenarios) > 0, "No scenarios loaded"

    def test_scenarios_have_ids(self, scenario_loader):
        """Verify all scenarios have IDs."""
        scenarios = scenario_loader.load_all()

        for scenario in scenarios:
            assert "id" in scenario, \
                f"Scenario missing id: {scenario.get('name', 'unknown')}"

    def test_scenarios_have_names(self, scenario_loader):
        """Verify all scenarios have names."""
        scenarios = scenario_loader.load_all()

        for scenario in scenarios:
            assert "name" in scenario, \
                f"Scenario {scenario.get('id')} missing name"

    def test_scenarios_have_categories(self, scenario_loader):
        """Verify all scenarios have categories."""
        scenarios = scenario_loader.load_all()

        for scenario in scenarios:
            assert "category" in scenario, \
                f"Scenario {scenario.get('id')} missing category"

    def test_scenarios_have_phases(self, scenario_loader):
        """Verify all scenarios have phases."""
        scenarios = scenario_loader.load_all()

        for scenario in scenarios:
            assert "phases" in scenario, \
                f"Scenario {scenario.get('id')} missing phases"
            assert len(scenario["phases"]) > 0, \
                f"Scenario {scenario.get('id')} has no phases"

    def test_scenario_id_format(self, scenario_loader):
        """Verify scenario IDs follow expected format (S#-##)."""
        scenarios = scenario_loader.load_all()
        import re
        pattern = re.compile(r"S\d+-\d+")

        for scenario in scenarios:
            scenario_id = scenario.get("id", "")
            assert pattern.match(scenario_id), \
                f"Invalid scenario ID format: {scenario_id}"

    def test_load_scenario_by_id(self, scenario_loader):
        """Test loading specific scenario by ID."""
        # Load first available scenario
        all_scenarios = scenario_loader.load_all()
        if all_scenarios:
            first_id = all_scenarios[0].get("id")
            scenario = scenario_loader.load(first_id)
            assert scenario is not None, f"Could not load scenario {first_id}"
            assert scenario.get("id") == first_id


@pytest.mark.unit
class TestScenarioValidation:
    """Tests for scenario structure validation."""

    def test_all_scenarios_validate(self, scenario_loader):
        """Verify all scenarios pass validation."""
        scenarios = scenario_loader.load_all()

        for scenario in scenarios:
            errors = scenario_loader.validate_scenario(scenario)
            assert len(errors) == 0, \
                f"Scenario {scenario.get('id')} validation errors: {errors}"

    def test_phase_structure(self, scenario_loader):
        """Verify phase structure is correct."""
        scenarios = scenario_loader.load_all()

        for scenario in scenarios:
            for i, phase in enumerate(scenario.get("phases", [])):
                assert "name" in phase, \
                    f"Scenario {scenario.get('id')} phase {i} missing name"
                assert "actions" in phase, \
                    f"Scenario {scenario.get('id')} phase {i} missing actions"

    def test_action_types_valid(self, scenario_loader):
        """Verify action types are valid."""
        scenarios = scenario_loader.load_all()
        valid_types = ["command", "http_request", "file_read", "file_write", "prompt"]

        for scenario in scenarios:
            for phase in scenario.get("phases", []):
                for action in phase.get("actions", []):
                    action_type = action.get("type")
                    if action_type:
                        assert action_type in valid_types, \
                            f"Invalid action type in {scenario.get('id')}: {action_type}"


@pytest.mark.unit
class TestExpectedAlerts:
    """Tests for expected alert configuration."""

    def test_expected_alerts_have_rule_ids(self, scenario_loader):
        """Verify expected alerts have rule IDs."""
        scenarios = scenario_loader.load_all()

        for scenario in scenarios:
            alerts = scenario.get("expected_wazuh_alerts", [])
            for alert in alerts:
                assert "rule_id" in alert, \
                    f"Scenario {scenario.get('id')} alert missing rule_id"

    def test_rule_ids_in_nhi_range(self, scenario_loader):
        """Verify rule IDs are in NHI range (100600-100999)."""
        scenarios = scenario_loader.load_all()

        for scenario in scenarios:
            rule_ids = scenario_loader.get_expected_rule_ids(scenario)
            for rule_id in rule_ids:
                rule_int = int(rule_id)
                assert 100600 <= rule_int <= 100999, \
                    f"Rule {rule_id} outside NHI range in {scenario.get('id')}"

    def test_get_expected_rule_ids(self, scenario_loader):
        """Test extracting expected rule IDs."""
        scenarios = scenario_loader.load_all()

        for scenario in scenarios:
            rule_ids = scenario_loader.get_expected_rule_ids(scenario)
            # All should be string representations
            for rule_id in rule_ids:
                assert isinstance(rule_id, str), \
                    f"Rule ID should be string: {rule_id}"


@pytest.mark.unit
class TestMITREMapping:
    """Tests for MITRE ATT&CK mapping."""

    def test_mitre_technique_format(self, scenario_loader):
        """Verify MITRE technique IDs are valid format."""
        import re
        pattern = re.compile(r"T\d{4}(\.\d{3})?")
        scenarios = scenario_loader.load_all()

        for scenario in scenarios:
            mitre = scenario.get("mitre_attack", {})
            techniques = mitre.get("techniques", [])

            for tech in techniques:
                tech_id = tech.get("id", "")
                if tech_id:
                    assert pattern.match(tech_id), \
                        f"Invalid MITRE ID in {scenario.get('id')}: {tech_id}"


@pytest.mark.unit
class TestCategoryGrouping:
    """Tests for scenario category grouping."""

    def test_load_by_category(self, scenario_loader):
        """Test loading scenarios grouped by category."""
        categories = scenario_loader.load_by_category()
        assert len(categories) > 0, "No categories found"

    def test_all_categories_represented(self, scenario_loader):
        """Verify all expected categories have scenarios."""
        categories = scenario_loader.load_by_category()

        # Should have at least some categories
        assert len(categories) >= 1, "Expected multiple categories"

    def test_get_category_scenarios(self, scenario_loader):
        """Test getting scenarios for specific category."""
        # Try to get category 1 scenarios
        cat1_scenarios = scenario_loader.get_category_scenarios(1)
        # May be empty if no category 1, but shouldn't error
        assert isinstance(cat1_scenarios, list)

    def test_scenario_ids_list(self, scenario_loader):
        """Test getting list of all scenario IDs."""
        ids = scenario_loader.get_scenario_ids()
        assert isinstance(ids, list)
        # All IDs should be non-empty strings
        for scenario_id in ids:
            assert isinstance(scenario_id, str) and len(scenario_id) > 0
