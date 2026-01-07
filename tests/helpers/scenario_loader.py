"""
Scenario JSON loader and validator.
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Any


class ScenarioLoader:
    """Loads and validates scenario JSON files."""

    def __init__(self, scenarios_dir: Path):
        self.scenarios_dir = Path(scenarios_dir)

    def load(self, scenario_id: str) -> Optional[Dict]:
        """Load a specific scenario by ID (e.g., 'S2-01')."""
        scenario_id_lower = scenario_id.lower().replace("-", "")

        for category_dir in self.scenarios_dir.iterdir():
            if category_dir.is_dir() and category_dir.name.startswith("category-"):
                for scenario_file in category_dir.glob("*.json"):
                    # Match by ID pattern in filename
                    filename_lower = scenario_file.stem.lower().replace("-", "")
                    if scenario_id_lower in filename_lower:
                        return self._load_file(scenario_file)
        return None

    def load_all(self) -> List[Dict]:
        """Load all scenarios from all categories."""
        scenarios = []
        for category_dir in sorted(self.scenarios_dir.iterdir()):
            if category_dir.is_dir() and category_dir.name.startswith("category-"):
                for scenario_file in sorted(category_dir.glob("*.json")):
                    scenario = self._load_file(scenario_file)
                    if scenario:
                        scenario["_file_path"] = str(scenario_file)
                        scenario["_category_dir"] = category_dir.name
                        scenarios.append(scenario)
        return scenarios

    def load_by_category(self) -> Dict[str, List[Dict]]:
        """Load scenarios grouped by category name."""
        categories: Dict[str, List[Dict]] = {}
        for scenario in self.load_all():
            category = scenario.get("category", "Unknown")
            if category not in categories:
                categories[category] = []
            categories[category].append(scenario)
        return categories

    def get_category_scenarios(self, category_num: int) -> List[Dict]:
        """Get scenarios for a specific category number (1-5)."""
        prefix = f"category-{category_num}"
        scenarios = []
        for category_dir in self.scenarios_dir.iterdir():
            if category_dir.is_dir() and prefix in category_dir.name:
                for scenario_file in sorted(category_dir.glob("*.json")):
                    scenario = self._load_file(scenario_file)
                    if scenario:
                        scenarios.append(scenario)
        return scenarios

    def get_scenario_ids(self) -> List[str]:
        """Get list of all scenario IDs."""
        return [s.get("id") for s in self.load_all() if s.get("id")]

    def _load_file(self, path: Path) -> Optional[Dict]:
        """Load a scenario JSON file."""
        try:
            with open(path, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            print(f"Error loading {path}: {e}")
            return None

    def validate_scenario(self, scenario: Dict) -> List[str]:
        """
        Validate scenario structure and return list of errors.

        Required fields:
        - id: Scenario ID (e.g., "S2-01")
        - name: Human-readable name
        - category: Category name
        - phases: List of attack phases

        Optional but recommended:
        - expected_wazuh_alerts: List of expected alerts
        - mitre_attack: MITRE ATT&CK mapping
        - remediation: Fix guidance
        """
        errors = []

        # Required fields
        required_fields = ["id", "name", "category", "phases"]
        for field in required_fields:
            if field not in scenario:
                errors.append(f"Missing required field: {field}")

        # Validate ID format
        scenario_id = scenario.get("id", "")
        if scenario_id and not scenario_id.startswith("S"):
            errors.append(f"Invalid scenario ID format: {scenario_id}")

        # Validate phases
        if "phases" in scenario:
            for i, phase in enumerate(scenario["phases"]):
                if "name" not in phase:
                    errors.append(f"Phase {i} missing 'name'")
                if "actions" not in phase:
                    errors.append(f"Phase {i} missing 'actions'")
                else:
                    for j, action in enumerate(phase.get("actions", [])):
                        if "type" not in action:
                            errors.append(f"Phase {i}, action {j} missing 'type'")
                        action_type = action.get("type")
                        valid_types = ["command", "http_request", "file_read", "file_write", "prompt"]
                        if action_type and action_type not in valid_types:
                            errors.append(f"Phase {i}, action {j} has invalid type: {action_type}")

        # Validate expected alerts
        if "expected_wazuh_alerts" in scenario:
            for alert in scenario["expected_wazuh_alerts"]:
                if "rule_id" not in alert:
                    errors.append("Expected alert missing 'rule_id'")
                else:
                    rule_id = alert.get("rule_id")
                    if isinstance(rule_id, str):
                        if not rule_id.isdigit():
                            errors.append(f"Invalid rule_id format: {rule_id}")
                    elif isinstance(rule_id, int):
                        if not (100600 <= rule_id <= 100999):
                            errors.append(f"Rule ID {rule_id} outside NHI range")

        # Validate MITRE mapping
        if "mitre_attack" in scenario:
            mitre = scenario["mitre_attack"]
            if "techniques" in mitre:
                import re
                mitre_pattern = re.compile(r"T\d{4}(\.\d{3})?")
                for tech in mitre["techniques"]:
                    tech_id = tech.get("id", "")
                    if not mitre_pattern.match(tech_id):
                        errors.append(f"Invalid MITRE technique ID: {tech_id}")

        return errors

    def get_expected_rule_ids(self, scenario: Dict) -> List[str]:
        """Extract expected rule IDs from a scenario."""
        alerts = scenario.get("expected_wazuh_alerts", [])
        return [str(a.get("rule_id")) for a in alerts if a.get("rule_id")]

    def get_required_containers(self, scenario: Dict) -> List[str]:
        """Extract required containers from a scenario."""
        prereqs = scenario.get("prerequisites", {})
        return prereqs.get("containers", [])
