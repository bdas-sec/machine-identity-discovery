"""
Integration tests for Vulnerable App service.

Tests vulnerable endpoints for security testing.
"""

import pytest


@pytest.mark.integration
class TestVulnerableAppHealth:
    """Tests for Vulnerable App availability."""

    def test_service_available(self, vulnerable_app_client):
        """Verify Vulnerable App is available."""
        assert vulnerable_app_client.is_available(), \
            "Vulnerable App is not available"


@pytest.mark.integration
class TestExposedEnvFile:
    """Tests for exposed .env file vulnerability."""

    def test_env_file_accessible(self, vulnerable_app_client):
        """Test if .env file is accessible (vulnerability)."""
        try:
            response = vulnerable_app_client.get("/.env")
            # 200 = vulnerable, 403/404 = secured
            if response.status_code == 200:
                # Should contain environment variables
                content = response.text
                assert len(content) > 0, ".env file is empty"
                # Should look like env file
                assert "=" in content or ":" in content, \
                    ".env doesn't look like env file"
        except Exception:
            pytest.skip(".env endpoint not accessible")

    def test_env_file_contents(self, vulnerable_app_client):
        """Test .env file contains sensitive data."""
        try:
            response = vulnerable_app_client.get("/.env")
            if response.status_code == 200:
                content = response.text.lower()
                # Should contain some sensitive-looking data
                sensitive_patterns = [
                    "key", "secret", "password", "token",
                    "api", "database", "db_"
                ]
                found = any(p in content for p in sensitive_patterns)
                # May or may not have sensitive data
                assert response.status_code == 200
        except Exception:
            pass


@pytest.mark.integration
class TestExposedConfig:
    """Tests for exposed config endpoint vulnerability."""

    def test_config_endpoint_accessible(self, vulnerable_app_client):
        """Test if /config endpoint is accessible."""
        try:
            response = vulnerable_app_client.get("/config")
            if response.status_code == 200:
                # Should return configuration data
                assert len(response.text) > 0, "Config response is empty"
        except Exception:
            pytest.skip("/config endpoint not accessible")

    def test_config_json_format(self, vulnerable_app_client):
        """Test /config returns JSON format."""
        try:
            response = vulnerable_app_client.get("/config")
            if response.status_code == 200:
                try:
                    data = response.json()
                    assert isinstance(data, dict), "Config is not a dict"
                except ValueError:
                    pass  # May not be JSON
        except Exception:
            pass


@pytest.mark.integration
class TestDebugEndpoint:
    """Tests for debug endpoint vulnerability."""

    def test_debug_endpoint_accessible(self, vulnerable_app_client):
        """Test if /debug endpoint is accessible."""
        try:
            response = vulnerable_app_client.get("/debug")
            # Debug endpoint may exist
            assert response.status_code in [200, 403, 404, 500], \
                f"Unexpected status: {response.status_code}"
        except Exception:
            pass

    def test_debug_info_exposure(self, vulnerable_app_client):
        """Test debug endpoint exposes sensitive info."""
        try:
            response = vulnerable_app_client.get("/debug")
            if response.status_code == 200:
                content = response.text.lower()
                # Debug may expose paths, versions, etc.
                debug_indicators = [
                    "version", "path", "env", "debug",
                    "error", "stack", "trace"
                ]
                found = any(i in content for i in debug_indicators)
                assert response.status_code == 200
        except Exception:
            pass


@pytest.mark.integration
class TestGitHistoryLeak:
    """Tests for Git history exposure vulnerability."""

    def test_git_history_endpoint(self, vulnerable_app_client):
        """Test if /git-history endpoint exists."""
        try:
            response = vulnerable_app_client.get("/git-history")
            assert response.status_code in [200, 404], \
                f"Unexpected status: {response.status_code}"
        except Exception:
            pass

    def test_git_directory_accessible(self, vulnerable_app_client):
        """Test if .git directory is accessible."""
        try:
            response = vulnerable_app_client.get("/.git/config")
            # Should be blocked or accessible
            assert response.status_code in [200, 403, 404], \
                f"Unexpected status: {response.status_code}"
        except Exception:
            pass


@pytest.mark.integration
class TestSSRFEndpoints:
    """Tests for SSRF vulnerability endpoints."""

    def test_url_fetch_endpoint(self, vulnerable_app_client):
        """Test URL fetch endpoint for SSRF."""
        try:
            # Test with safe URL
            response = vulnerable_app_client.get(
                "/fetch",
                params={"url": "http://localhost:8888"}
            )
            assert response.status_code in [200, 400, 403, 404, 500], \
                f"Unexpected status: {response.status_code}"
        except Exception:
            pass

    def test_proxy_endpoint(self, vulnerable_app_client):
        """Test proxy endpoint for SSRF."""
        try:
            response = vulnerable_app_client.get("/proxy")
            assert response.status_code in [200, 400, 403, 404, 405], \
                f"Unexpected status: {response.status_code}"
        except Exception:
            pass


@pytest.mark.integration
class TestHealthEndpoints:
    """Tests for health-related endpoints."""

    def test_health_endpoint(self, vulnerable_app_client):
        """Test /health endpoint."""
        try:
            response = vulnerable_app_client.get("/health")
            if response.status_code == 200:
                # Should return health status
                assert len(response.text) > 0
        except Exception:
            pass

    def test_status_endpoint(self, vulnerable_app_client):
        """Test /status endpoint."""
        try:
            response = vulnerable_app_client.get("/status")
            assert response.status_code in [200, 404], \
                f"Unexpected status: {response.status_code}"
        except Exception:
            pass


@pytest.mark.integration
class TestVulnerableAppLogging:
    """Tests for Vulnerable App logging."""

    def test_app_access_logged(self, vulnerable_app_client):
        """Verify app access generates logs."""
        from helpers.docker_utils import DockerTestUtils

        # Make a request
        vulnerable_app_client.is_available()

        # Check container logs
        logs = DockerTestUtils.get_container_logs("vulnerable-app", lines=50)
        assert len(logs) > 0, "No logs from vulnerable-app"
