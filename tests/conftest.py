"""
Global pytest fixtures for NHI Security Testbed testing.
"""

import os
import pytest
import json
from pathlib import Path
from typing import Dict, List, Optional, Generator, Any

# Suppress SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ============================================================
# Configuration Constants
# ============================================================

PROJECT_ROOT = Path(__file__).parent.parent
SCENARIOS_DIR = PROJECT_ROOT / "scenarios"
WAZUH_RULES_FILE = PROJECT_ROOT / "wazuh" / "rules" / "nhi-detection-rules.xml"
WAZUH_DECODERS_FILE = PROJECT_ROOT / "wazuh" / "decoders" / "nhi-decoders.xml"
DOCKER_COMPOSE_FILE = PROJECT_ROOT / "docker-compose.yml"

# Service endpoints (configurable via environment)
WAZUH_API_URL = os.environ.get("WAZUH_API_URL", "https://localhost:55000")
WAZUH_INDEXER_URL = os.environ.get("WAZUH_INDEXER_URL", "https://localhost:9200")
WAZUH_DASHBOARD_URL = os.environ.get("WAZUH_DASHBOARD_URL", "https://localhost:443")
MOCK_IMDS_URL = os.environ.get("MOCK_IMDS_URL", "http://localhost:1338")
MOCK_CICD_URL = os.environ.get("MOCK_CICD_URL", "http://localhost:8080")
VULNERABLE_APP_URL = os.environ.get("VULNERABLE_APP_URL", "http://localhost:8888")
VAULT_URL = os.environ.get("VAULT_URL", "http://localhost:8200")

# Wazuh credentials
WAZUH_API_USER = os.environ.get("WAZUH_API_USER", "wazuh-wui")
WAZUH_API_PASSWORD = os.environ.get("WAZUH_API_PASSWORD", "MyS3cr3tP@ssw0rd")
WAZUH_INDEXER_USER = os.environ.get("WAZUH_INDEXER_USER", "admin")
WAZUH_INDEXER_PASSWORD = os.environ.get("WAZUH_INDEXER_PASSWORD", "admin")

# Test timeouts
DEFAULT_TIMEOUT = 30
ALERT_PROPAGATION_TIMEOUT = 15


# ============================================================
# Pytest Configuration Hooks
# ============================================================

def pytest_configure(config):
    """Register custom markers."""
    # Markers are defined in pytest.ini, this is for programmatic access
    pass


def pytest_collection_modifyitems(config, items):
    """Apply markers based on test location."""
    for item in items:
        # Auto-apply markers based on path
        path_str = str(item.fspath)

        if "/smoke/" in path_str:
            item.add_marker(pytest.mark.smoke)
        elif "/unit/" in path_str:
            item.add_marker(pytest.mark.unit)
        elif "/integration/" in path_str:
            item.add_marker(pytest.mark.integration)
        elif "/e2e/" in path_str:
            item.add_marker(pytest.mark.e2e)
        elif "/rules/" in path_str:
            item.add_marker(pytest.mark.rules)

        # Category markers for e2e tests
        if "category_1" in path_str:
            item.add_marker(pytest.mark.category_1)
        elif "category_2" in path_str:
            item.add_marker(pytest.mark.category_2)
        elif "category_3" in path_str:
            item.add_marker(pytest.mark.category_3)
        elif "category_4" in path_str:
            item.add_marker(pytest.mark.category_4)
            item.add_marker(pytest.mark.requires_k8s)
        elif "category_5" in path_str:
            item.add_marker(pytest.mark.category_5)
            item.add_marker(pytest.mark.requires_ai)


# ============================================================
# Path Fixtures
# ============================================================

@pytest.fixture(scope="session")
def project_root() -> Path:
    """Return project root path."""
    return PROJECT_ROOT


@pytest.fixture(scope="session")
def scenarios_dir() -> Path:
    """Return scenarios directory path."""
    return SCENARIOS_DIR


@pytest.fixture(scope="session")
def wazuh_rules_path() -> Path:
    """Return Wazuh rules file path."""
    return WAZUH_RULES_FILE


@pytest.fixture(scope="session")
def wazuh_decoders_path() -> Path:
    """Return Wazuh decoders file path."""
    return WAZUH_DECODERS_FILE


# ============================================================
# Docker Fixtures
# ============================================================

@pytest.fixture(scope="session")
def docker_client():
    """Provide Docker client for container operations."""
    try:
        import docker
        client = docker.from_env()
        yield client
        client.close()
    except Exception as e:
        pytest.skip(f"Docker not available: {e}")


@pytest.fixture(scope="session")
def testbed_containers(docker_client) -> Dict[str, Any]:
    """Get all running testbed containers."""
    containers = {}
    for container in docker_client.containers.list():
        name = container.name
        # Match our testbed containers
        if any(x in name for x in [
            "wazuh", "mock-imds", "mock-cicd", "vulnerable-app",
            "cloud-workload", "cicd-runner", "k8s-node", "ai-agent", "vault"
        ]):
            containers[name] = container
    return containers


@pytest.fixture(scope="session")
def testbed_networks(docker_client) -> Dict[str, Any]:
    """Get all testbed networks."""
    networks = {}
    expected = ["mgmt_net", "cloud_net", "cicd_net", "k8s_net"]
    for network in docker_client.networks.list():
        for exp in expected:
            if exp in network.name:
                networks[exp] = network
    return networks


# ============================================================
# Wazuh Fixtures
# ============================================================

@pytest.fixture(scope="session")
def wazuh_client():
    """Provide authenticated Wazuh API client."""
    from helpers.wazuh_client import WazuhTestClient
    client = WazuhTestClient(
        base_url=WAZUH_API_URL,
        username=WAZUH_API_USER,
        password=WAZUH_API_PASSWORD
    )
    return client


@pytest.fixture(scope="session")
def wazuh_indexer_client():
    """Provide Wazuh Indexer client."""
    from helpers.wazuh_client import WazuhIndexerClient
    client = WazuhIndexerClient(
        base_url=WAZUH_INDEXER_URL,
        username=WAZUH_INDEXER_USER,
        password=WAZUH_INDEXER_PASSWORD
    )
    return client


# ============================================================
# HTTP Client Fixtures
# ============================================================

@pytest.fixture(scope="session")
def mock_imds_client():
    """HTTP client for Mock IMDS service."""
    from helpers.http_client import MockIMDSClient
    return MockIMDSClient(base_url=MOCK_IMDS_URL)


@pytest.fixture(scope="session")
def mock_cicd_client():
    """HTTP client for Mock CI/CD service."""
    from helpers.http_client import MockCICDClient
    return MockCICDClient(base_url=MOCK_CICD_URL)


@pytest.fixture(scope="session")
def vulnerable_app_client():
    """HTTP client for Vulnerable App service."""
    from helpers.http_client import TestHttpClient
    return TestHttpClient(base_url=VULNERABLE_APP_URL)


# ============================================================
# Scenario Fixtures
# ============================================================

@pytest.fixture(scope="session")
def scenario_loader():
    """Provide scenario loader utility."""
    from helpers.scenario_loader import ScenarioLoader
    return ScenarioLoader(SCENARIOS_DIR)


@pytest.fixture(scope="session")
def all_scenarios(scenario_loader) -> List[Dict]:
    """Load all scenario definitions."""
    return scenario_loader.load_all()


@pytest.fixture(scope="session")
def scenarios_by_category(scenario_loader) -> Dict[str, List[Dict]]:
    """Load scenarios grouped by category."""
    return scenario_loader.load_by_category()


# ============================================================
# Alert Validation Fixtures
# ============================================================

@pytest.fixture(scope="function")
def alert_validator(wazuh_client):
    """Provide alert validation utility."""
    from helpers.alert_validator import AlertValidator
    return AlertValidator(wazuh_client)


@pytest.fixture(scope="function")
def wait_for_alerts(alert_validator):
    """Factory fixture for waiting on specific alerts."""
    def _wait(rule_ids: List[str], timeout: int = ALERT_PROPAGATION_TIMEOUT):
        return alert_validator.wait_for_rules(rule_ids, timeout=timeout)
    return _wait


# ============================================================
# Test Data Fixtures
# ============================================================

@pytest.fixture(scope="session")
def wazuh_rules_xml() -> str:
    """Load Wazuh rules XML content."""
    if WAZUH_RULES_FILE.exists():
        return WAZUH_RULES_FILE.read_text()
    return ""


@pytest.fixture(scope="session")
def wazuh_decoders_xml() -> str:
    """Load Wazuh decoders XML content."""
    if WAZUH_DECODERS_FILE.exists():
        return WAZUH_DECODERS_FILE.read_text()
    return ""


@pytest.fixture(scope="session")
def docker_compose_config() -> Dict:
    """Load docker-compose.yml as dict."""
    import yaml
    if DOCKER_COMPOSE_FILE.exists():
        with open(DOCKER_COMPOSE_FILE) as f:
            return yaml.safe_load(f)
    return {}


@pytest.fixture(scope="session")
def expected_containers() -> List[str]:
    """List of expected container names."""
    return [
        "wazuh-manager",
        "wazuh-indexer",
        "wazuh-dashboard",
        "mock-imds",
        "mock-cicd",
        "vulnerable-app",
        "cloud-workload",
        "cicd-runner",
        "vault"
    ]


@pytest.fixture(scope="session")
def expected_networks() -> List[str]:
    """List of expected network names."""
    return ["mgmt_net", "cloud_net", "cicd_net", "k8s_net"]


@pytest.fixture(scope="session")
def nhi_rule_range() -> tuple:
    """Expected NHI rule ID range."""
    return (100600, 100999)
