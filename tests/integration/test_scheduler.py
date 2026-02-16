"""
Integration tests for NHI scenario scheduler.

Validates the scheduler CLI (scripts/scheduler.py) including scenario
listing, selection, execution modes, and report generation.

Scheduler reference:
  Entry point: scripts/scheduler.py (or `nhi-schedule` CLI)
  Modes: single-run (default), --cron, --interval, --daemon
  Classes: ScenarioDef, ScenarioRunResult, SchedulerSession
  24 built-in scenarios (s1-01 to s5-04), levels 1-5
  Config via env vars: CONTAINER_RUNTIME, WAZUH_API_URL, NHI_METRICS_URL
"""

import importlib
import json
import os
import re
import subprocess
import sys
import pytest
from pathlib import Path


PROJECT_ROOT = Path(__file__).parent.parent.parent
SCHEDULER_PATH = PROJECT_ROOT / "scripts" / "scheduler.py"


def _skip_if_no_scheduler():
    """Skip if scheduler script doesn't exist."""
    if not SCHEDULER_PATH.exists():
        pytest.skip("Scheduler not found at scripts/scheduler.py")


# ============================================================
# Scheduler Module Tests
# ============================================================

@pytest.mark.integration
class TestSchedulerModule:
    """Verify scheduler module structure and imports."""

    @pytest.fixture(autouse=True)
    def _check(self):
        _skip_if_no_scheduler()

    def test_scheduler_is_valid_python(self):
        """scheduler.py is valid Python syntax."""
        import ast
        content = SCHEDULER_PATH.read_text()
        ast.parse(content)

    def test_scheduler_has_main(self):
        """scheduler.py defines a main() function."""
        content = SCHEDULER_PATH.read_text()
        assert re.search(r'^def main\(', content, re.MULTILINE), \
            "Missing main() function"

    def test_scheduler_has_scenario_defs(self):
        """scheduler.py defines ScenarioDef class."""
        content = SCHEDULER_PATH.read_text()
        assert "class ScenarioDef" in content, "Missing ScenarioDef class"

    def test_scheduler_has_result_class(self):
        """scheduler.py defines ScenarioRunResult class."""
        content = SCHEDULER_PATH.read_text()
        assert "class ScenarioRunResult" in content, "Missing ScenarioRunResult class"

    def test_scheduler_has_session_class(self):
        """scheduler.py defines SchedulerSession class."""
        content = SCHEDULER_PATH.read_text()
        assert "class SchedulerSession" in content, "Missing SchedulerSession class"

    def test_scheduler_has_detect_runtime(self):
        """scheduler.py defines detect_runtime() function."""
        content = SCHEDULER_PATH.read_text()
        assert re.search(r'def detect_runtime', content), \
            "Missing detect_runtime() function"

    def test_scheduler_has_validate_alerts(self):
        """scheduler.py defines validate_alerts() function."""
        content = SCHEDULER_PATH.read_text()
        assert re.search(r'def validate_alerts', content), \
            "Missing validate_alerts() function"

    def test_scheduler_has_metrics_reporting(self):
        """scheduler.py defines report_to_metrics() function."""
        content = SCHEDULER_PATH.read_text()
        assert re.search(r'def report_to_metrics', content), \
            "Missing report_to_metrics() function"

    def test_scheduler_has_execute_scenario(self):
        """scheduler.py defines execute_scenario() function."""
        content = SCHEDULER_PATH.read_text()
        assert re.search(r'def execute_scenario', content), \
            "Missing execute_scenario() function"


# ============================================================
# Scheduler CLI Tests
# ============================================================

@pytest.mark.integration
class TestSchedulerCLI:
    """Test scheduler CLI arguments and basic operation."""

    @pytest.fixture(autouse=True)
    def _check(self):
        _skip_if_no_scheduler()

    def test_scheduler_help(self):
        """scheduler.py --help returns usage info."""
        result = subprocess.run(
            [sys.executable, str(SCHEDULER_PATH), "--help"],
            capture_output=True, text=True, timeout=15
        )
        assert result.returncode == 0, f"--help failed: {result.stderr}"
        assert "scenario" in result.stdout.lower(), \
            "Help output doesn't mention scenarios"

    def test_scheduler_list(self):
        """scheduler.py --list shows available scenarios."""
        result = subprocess.run(
            [sys.executable, str(SCHEDULER_PATH), "--list"],
            capture_output=True, text=True, timeout=15
        )
        assert result.returncode == 0, f"--list failed: {result.stderr}"
        output = result.stdout
        # Should list scenario IDs
        assert "s1-01" in output.lower() or "S1-01" in output, \
            "Scenario s1-01 not in --list output"
        assert "s2-01" in output.lower() or "S2-01" in output, \
            "Scenario s2-01 not in --list output"

    def test_scheduler_list_shows_all_levels(self):
        """--list shows scenarios from all 5 levels."""
        result = subprocess.run(
            [sys.executable, str(SCHEDULER_PATH), "--list"],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode != 0:
            pytest.skip(f"--list failed: {result.stderr}")
        output = result.stdout.lower()
        for level in range(1, 6):
            assert f"s{level}" in output, \
                f"No level {level} scenarios in --list output"

    def test_scheduler_list_shows_24_scenarios(self):
        """--list shows all 24 scenarios."""
        result = subprocess.run(
            [sys.executable, str(SCHEDULER_PATH), "--list"],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode != 0:
            pytest.skip(f"--list failed: {result.stderr}")
        # Count scenario IDs (sN-NN pattern)
        ids = re.findall(r's\d-\d\d', result.stdout.lower())
        unique_ids = set(ids)
        assert len(unique_ids) >= 24, \
            f"Expected 24 scenarios, found {len(unique_ids)}: {sorted(unique_ids)}"

    def test_scheduler_accepts_scenario_flag(self):
        """scheduler.py accepts --scenario flag without crashing."""
        result = subprocess.run(
            [sys.executable, str(SCHEDULER_PATH), "--help"],
            capture_output=True, text=True, timeout=15
        )
        assert "--scenario" in result.stdout or "-s" in result.stdout, \
            "--scenario flag not in help output"

    def test_scheduler_accepts_level_flag(self):
        """scheduler.py accepts --level flag."""
        result = subprocess.run(
            [sys.executable, str(SCHEDULER_PATH), "--help"],
            capture_output=True, text=True, timeout=15
        )
        assert "--level" in result.stdout or "-l" in result.stdout, \
            "--level flag not in help output"

    def test_scheduler_accepts_validate_flag(self):
        """scheduler.py accepts --validate flag."""
        result = subprocess.run(
            [sys.executable, str(SCHEDULER_PATH), "--help"],
            capture_output=True, text=True, timeout=15
        )
        assert "--validate" in result.stdout or "-v" in result.stdout, \
            "--validate flag not in help output"

    def test_scheduler_accepts_report_flag(self):
        """scheduler.py accepts --report flag with text/json."""
        result = subprocess.run(
            [sys.executable, str(SCHEDULER_PATH), "--help"],
            capture_output=True, text=True, timeout=15
        )
        assert "--report" in result.stdout, "--report flag not in help output"

    def test_scheduler_accepts_cron_flag(self):
        """scheduler.py accepts --cron flag."""
        result = subprocess.run(
            [sys.executable, str(SCHEDULER_PATH), "--help"],
            capture_output=True, text=True, timeout=15
        )
        assert "--cron" in result.stdout, "--cron flag not in help output"

    def test_scheduler_accepts_interval_flag(self):
        """scheduler.py accepts --interval flag."""
        result = subprocess.run(
            [sys.executable, str(SCHEDULER_PATH), "--help"],
            capture_output=True, text=True, timeout=15
        )
        assert "--interval" in result.stdout, "--interval flag not in help output"

    def test_scheduler_accepts_daemon_flag(self):
        """scheduler.py accepts --daemon flag."""
        result = subprocess.run(
            [sys.executable, str(SCHEDULER_PATH), "--help"],
            capture_output=True, text=True, timeout=15
        )
        assert "--daemon" in result.stdout, "--daemon flag not in help output"

    def test_scheduler_accepts_no_metrics_flag(self):
        """scheduler.py accepts --no-metrics flag."""
        result = subprocess.run(
            [sys.executable, str(SCHEDULER_PATH), "--help"],
            capture_output=True, text=True, timeout=15
        )
        assert "--no-metrics" in result.stdout, "--no-metrics flag not in help output"

    def test_scheduler_accepts_runtime_flag(self):
        """scheduler.py accepts --runtime flag."""
        result = subprocess.run(
            [sys.executable, str(SCHEDULER_PATH), "--help"],
            capture_output=True, text=True, timeout=15
        )
        assert "--runtime" in result.stdout, "--runtime flag not in help output"


# ============================================================
# Scheduler Scenario Definition Tests
# ============================================================

@pytest.mark.integration
class TestSchedulerScenarios:
    """Verify hardcoded scenario definitions are complete."""

    @pytest.fixture(autouse=True)
    def _check(self):
        _skip_if_no_scheduler()

    def test_all_levels_represented(self):
        """Scenarios cover all 5 levels."""
        content = SCHEDULER_PATH.read_text()
        for level in range(1, 6):
            assert f"level={level}" in content or f"level: {level}" in content, \
                f"Level {level} scenarios not found in scheduler"

    def test_scenarios_have_target_containers(self):
        """Scenarios reference target containers."""
        content = SCHEDULER_PATH.read_text()
        expected_targets = ["cloud-workload", "cicd-runner"]
        for target in expected_targets:
            assert target in content, \
                f"Target container '{target}' not referenced in scheduler"

    def test_scenarios_have_detection_rules(self):
        """Scenarios define expected detection rule IDs."""
        content = SCHEDULER_PATH.read_text()
        # Look for NHI rule IDs (100xxx)
        rule_ids = re.findall(r'"(100\d{3})"', content)
        assert len(rule_ids) >= 20, \
            f"Expected 20+ detection rules, found {len(rule_ids)}"

    def test_scenarios_have_commands(self):
        """Scenarios define execution commands."""
        content = SCHEDULER_PATH.read_text()
        # Should have docker/podman exec commands or shell commands
        assert "commands" in content, "No 'commands' field in scenarios"


# ============================================================
# Entry Point Tests
# ============================================================

@pytest.mark.integration
class TestSchedulerEntryPoint:
    """Verify nhi-schedule entry point configuration."""

    def test_pyproject_toml_has_entry_point(self):
        """pyproject.toml defines nhi-schedule entry point."""
        pyproject = PROJECT_ROOT / "pyproject.toml"
        if not pyproject.exists():
            pytest.skip("pyproject.toml not found")
        content = pyproject.read_text()
        assert "nhi-schedule" in content, \
            "nhi-schedule entry point not in pyproject.toml"

    def test_entry_point_references_scheduler(self):
        """Entry point references scheduler module."""
        pyproject = PROJECT_ROOT / "pyproject.toml"
        if not pyproject.exists():
            pytest.skip("pyproject.toml not found")
        content = pyproject.read_text()
        assert "scheduler" in content, \
            "Entry point doesn't reference scheduler module"
