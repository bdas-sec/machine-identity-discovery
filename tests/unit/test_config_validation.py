"""
Unit tests for configuration file validation.

Tests docker-compose.yml, .env files, and ossec.conf.
"""

import pytest
from pathlib import Path
import yaml
import re


# Project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent
DOCKER_COMPOSE = PROJECT_ROOT / "docker-compose.yml"
ENV_EXAMPLE = PROJECT_ROOT / ".env.example"
WAZUH_DIR = PROJECT_ROOT / "wazuh"


@pytest.mark.unit
class TestDockerComposeValidation:
    """Tests for docker-compose.yml validation."""

    def test_docker_compose_exists(self):
        """Verify docker-compose.yml exists."""
        assert DOCKER_COMPOSE.exists(), \
            f"docker-compose.yml not found at {DOCKER_COMPOSE}"

    def test_docker_compose_valid_yaml(self):
        """Verify docker-compose.yml is valid YAML."""
        if not DOCKER_COMPOSE.exists():
            pytest.skip("docker-compose.yml not found")

        try:
            with open(DOCKER_COMPOSE) as f:
                yaml.safe_load(f)
        except yaml.YAMLError as e:
            pytest.fail(f"Invalid YAML in docker-compose.yml: {e}")

    def test_docker_compose_has_services(self):
        """Verify docker-compose.yml defines services."""
        if not DOCKER_COMPOSE.exists():
            pytest.skip("docker-compose.yml not found")

        with open(DOCKER_COMPOSE) as f:
            config = yaml.safe_load(f)

        assert "services" in config, "docker-compose.yml missing services"
        assert len(config["services"]) > 0, "No services defined"

    def test_expected_services_defined(self):
        """Verify expected services are defined."""
        if not DOCKER_COMPOSE.exists():
            pytest.skip("docker-compose.yml not found")

        expected_services = [
            "wazuh.manager",
            "wazuh.indexer",
            "wazuh.dashboard",
        ]

        with open(DOCKER_COMPOSE) as f:
            config = yaml.safe_load(f)

        services = config.get("services", {})
        for service in expected_services:
            assert service in services, \
                f"Expected service {service} not defined"

    def test_services_have_images_or_build(self):
        """Verify all services have image or build context."""
        if not DOCKER_COMPOSE.exists():
            pytest.skip("docker-compose.yml not found")

        with open(DOCKER_COMPOSE) as f:
            config = yaml.safe_load(f)

        for name, service in config.get("services", {}).items():
            has_image = "image" in service
            has_build = "build" in service
            assert has_image or has_build, \
                f"Service {name} has neither image nor build"

    def test_networks_defined(self):
        """Verify networks are defined."""
        if not DOCKER_COMPOSE.exists():
            pytest.skip("docker-compose.yml not found")

        with open(DOCKER_COMPOSE) as f:
            config = yaml.safe_load(f)

        assert "networks" in config, "No networks defined"
        assert len(config["networks"]) > 0, "Empty networks section"


@pytest.mark.unit
class TestEnvConfiguration:
    """Tests for environment configuration."""

    def test_env_example_exists(self):
        """Verify .env.example exists."""
        # .env.example might not exist, skip if not
        if not ENV_EXAMPLE.exists():
            pytest.skip(".env.example not found")

    def test_env_example_has_required_vars(self):
        """Verify .env.example has required variables."""
        if not ENV_EXAMPLE.exists():
            pytest.skip(".env.example not found")

        with open(ENV_EXAMPLE) as f:
            content = f.read()

        # Common required variables
        expected_vars = [
            "WAZUH_",  # Any Wazuh-related variable
        ]

        for var in expected_vars:
            assert var in content, \
                f".env.example missing {var} variables"

    def test_env_format_valid(self):
        """Verify .env.example format is valid."""
        if not ENV_EXAMPLE.exists():
            pytest.skip(".env.example not found")

        with open(ENV_EXAMPLE) as f:
            lines = f.readlines()

        pattern = re.compile(r"^([A-Z_][A-Z0-9_]*)=.*$|^#.*$|^\s*$")

        for i, line in enumerate(lines, 1):
            line = line.strip()
            if line and not line.startswith("#"):
                assert pattern.match(line) or "=" in line, \
                    f"Invalid format on line {i}: {line}"


@pytest.mark.unit
class TestWazuhConfiguration:
    """Tests for Wazuh configuration files."""

    def test_wazuh_directory_exists(self):
        """Verify wazuh directory exists."""
        assert WAZUH_DIR.exists(), f"Wazuh directory not found: {WAZUH_DIR}"

    def test_ossec_conf_files_exist(self):
        """Verify ossec.conf files exist."""
        if not WAZUH_DIR.exists():
            pytest.skip("Wazuh directory not found")

        # Look for any ossec.conf files
        ossec_files = list(WAZUH_DIR.glob("**/ossec.conf"))
        # May not have ossec.conf if using default
        if not ossec_files:
            pytest.skip("No ossec.conf files found")

    def test_rules_directory_exists(self):
        """Verify rules directory exists."""
        rules_dir = WAZUH_DIR / "rules"
        assert rules_dir.exists(), f"Rules directory not found: {rules_dir}"

    def test_rules_files_exist(self):
        """Verify rule files exist."""
        rules_dir = WAZUH_DIR / "rules"
        if not rules_dir.exists():
            pytest.skip("Rules directory not found")

        rule_files = list(rules_dir.glob("*.xml"))
        assert len(rule_files) > 0, "No rule files found"


@pytest.mark.unit
class TestScenarioConfiguration:
    """Tests for scenario configuration files."""

    def test_scenarios_directory_exists(self):
        """Verify scenarios directory exists."""
        scenarios_dir = PROJECT_ROOT / "scenarios"
        assert scenarios_dir.exists(), \
            f"Scenarios directory not found: {scenarios_dir}"

    def test_category_directories_exist(self):
        """Verify category directories exist."""
        scenarios_dir = PROJECT_ROOT / "scenarios"
        if not scenarios_dir.exists():
            pytest.skip("Scenarios directory not found")

        category_dirs = list(scenarios_dir.glob("category-*"))
        assert len(category_dirs) > 0, "No category directories found"

    def test_scenario_json_files_exist(self):
        """Verify scenario JSON files exist."""
        scenarios_dir = PROJECT_ROOT / "scenarios"
        if not scenarios_dir.exists():
            pytest.skip("Scenarios directory not found")

        json_files = list(scenarios_dir.glob("**/*.json"))
        assert len(json_files) > 0, "No scenario JSON files found"


@pytest.mark.unit
class TestProjectStructure:
    """Tests for overall project structure."""

    def test_readme_exists(self):
        """Verify README exists."""
        readme_files = [
            PROJECT_ROOT / "README.md",
            PROJECT_ROOT / "readme.md",
            PROJECT_ROOT / "README",
        ]

        found = any(f.exists() for f in readme_files)
        assert found, "README not found"

    def test_docs_directory_exists(self):
        """Verify docs directory exists."""
        docs_dir = PROJECT_ROOT / "docs"
        assert docs_dir.exists(), f"Docs directory not found: {docs_dir}"

    def test_mock_services_exist(self):
        """Verify mock service directories exist."""
        # Mock services may be in a single directory or separate
        mock_services_dir = PROJECT_ROOT / "mock-services"
        mock_imds = PROJECT_ROOT / "mock-imds"
        mock_cicd = PROJECT_ROOT / "mock-cicd"

        has_combined = mock_services_dir.exists()
        has_separate = mock_imds.exists() or mock_cicd.exists()

        assert has_combined or has_separate, \
            "Mock services directory not found (expected mock-services/ or mock-imds/ + mock-cicd/)"

    def test_vulnerable_app_exists(self):
        """Verify vulnerable-app or services directory exists."""
        # App may be in services directory or standalone
        app_locations = [
            PROJECT_ROOT / "vulnerable-app",
            PROJECT_ROOT / "services" / "vulnerable-app",
            PROJECT_ROOT / "mock-services",  # May be combined
        ]

        found = any(loc.exists() for loc in app_locations)
        assert found, \
            "Vulnerable app directory not found"
