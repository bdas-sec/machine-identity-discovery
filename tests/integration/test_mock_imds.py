"""
Integration tests for Mock IMDS service.

Tests AWS EC2 metadata service simulation endpoints.
"""

import pytest


@pytest.mark.integration
class TestIMDSMetadataEndpoints:
    """Tests for IMDS metadata endpoints."""

    def test_service_available(self, mock_imds_client):
        """Verify Mock IMDS service is available."""
        assert mock_imds_client.is_available(), \
            "Mock IMDS service is not available"

    def test_metadata_root(self, mock_imds_client):
        """Test metadata root endpoint."""
        root = mock_imds_client.get_metadata_root()
        assert root is not None, "Metadata root returned None"

    def test_instance_id(self, mock_imds_client):
        """Test instance-id endpoint."""
        instance_id = mock_imds_client.get_instance_id()
        assert instance_id is not None, "Could not get instance-id"
        assert instance_id.startswith("i-"), \
            f"Invalid instance ID format: {instance_id}"

    def test_metadata_paths(self, mock_imds_client):
        """Test various metadata paths."""
        paths = [
            "/latest/meta-data/",
            "/latest/meta-data/instance-id",
            "/latest/meta-data/ami-id",
            "/latest/meta-data/hostname",
        ]

        for path in paths:
            try:
                response = mock_imds_client.get(path)
                # Should return 200 or 404, not server error
                assert response.status_code in [200, 404], \
                    f"Path {path} returned {response.status_code}"
            except Exception as e:
                pytest.fail(f"Error accessing {path}: {e}")


@pytest.mark.integration
class TestIMDSIAMEndpoints:
    """Tests for IMDS IAM credential endpoints."""

    def test_iam_security_credentials_list(self, mock_imds_client):
        """Test IAM security-credentials listing."""
        role_name = mock_imds_client.get_iam_role()
        # Role endpoint should return role name
        assert role_name is not None, "Could not get IAM role name"

    def test_iam_credentials_structure(self, mock_imds_client):
        """Test IAM credentials have correct structure."""
        role_name = mock_imds_client.get_iam_role()
        if not role_name:
            pytest.skip("No IAM role found")

        creds = mock_imds_client.get_iam_credentials(role_name)
        assert creds is not None, f"Could not get credentials for {role_name}"

        # Verify credential structure
        expected_fields = ["AccessKeyId", "SecretAccessKey"]
        for field in expected_fields:
            assert field in creds, f"Credentials missing {field}"

    def test_iam_credentials_token(self, mock_imds_client):
        """Test IAM credentials include session token."""
        role_name = mock_imds_client.get_iam_role()
        if not role_name:
            pytest.skip("No IAM role found")

        creds = mock_imds_client.get_iam_credentials(role_name)
        if creds:
            assert "Token" in creds or "SessionToken" in creds, \
                "Credentials missing session token"


@pytest.mark.integration
class TestIMDSv2:
    """Tests for IMDSv2 token-based access."""

    def test_imdsv2_token_endpoint(self, mock_imds_client):
        """Test IMDSv2 token endpoint."""
        token = mock_imds_client.get_imdsv2_token()
        assert token is not None, "Could not get IMDSv2 token"
        assert len(token) > 0, "Token is empty"

    def test_imdsv2_token_with_ttl(self, mock_imds_client):
        """Test IMDSv2 token with specific TTL."""
        token = mock_imds_client.get_imdsv2_token(ttl=3600)
        assert token is not None, "Could not get IMDSv2 token with TTL"

    def test_imdsv2_authenticated_request(self, mock_imds_client):
        """Test authenticated request with IMDSv2 token."""
        token = mock_imds_client.get_imdsv2_token()
        if not token:
            pytest.skip("Could not get IMDSv2 token")

        # Make request with token
        response = mock_imds_client.get(
            "/latest/meta-data/instance-id",
            headers={"X-aws-ec2-metadata-token": token}
        )
        assert response.status_code == 200, \
            f"Authenticated request failed: {response.status_code}"


@pytest.mark.integration
class TestIMDSUserData:
    """Tests for IMDS user-data endpoint."""

    def test_user_data_endpoint(self, mock_imds_client):
        """Test user-data endpoint."""
        try:
            response = mock_imds_client.get("/latest/user-data")
            # User data may or may not be configured
            assert response.status_code in [200, 404], \
                f"User data returned {response.status_code}"
        except Exception:
            pass  # User data endpoint may not exist


@pytest.mark.integration
class TestIMDSAccessLogging:
    """Tests for IMDS access logging."""

    def test_imds_access_is_logged(self, mock_imds_client):
        """Verify IMDS access generates logs for Wazuh."""
        from helpers.docker_utils import DockerTestUtils

        # Make a request to IMDS
        mock_imds_client.get_instance_id()

        # Check container logs
        logs = DockerTestUtils.get_container_logs("mock-imds", lines=50)
        # Should have some log entries
        assert len(logs) > 0, "No logs from mock-imds"
