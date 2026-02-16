"""
Integration tests for Mock GCP Metadata service.

Tests GCP metadata and Workload Identity Federation endpoint simulations
for credential theft and identity federation attack scenarios.
"""

import pytest


@pytest.mark.integration
class TestGCPMetadataServiceHealth:
    """Tests for GCP Metadata service availability."""

    def test_service_available(self, mock_gcp_metadata_client):
        """Verify Mock GCP Metadata service is available."""
        assert mock_gcp_metadata_client.health_check("/health"), \
            "Mock GCP Metadata service is not available"


@pytest.mark.integration
class TestGCPMetadataHeaderEnforcement:
    """Tests for Metadata-Flavor header enforcement."""

    def test_metadata_requires_header(self, mock_gcp_metadata_client):
        """Test that metadata endpoints require Metadata-Flavor header."""
        response = mock_gcp_metadata_client.get(
            "/computeMetadata/v1/project/project-id"
            # No Metadata-Flavor header
        )
        assert response.status_code == 403, \
            "Should return 403 without Metadata-Flavor header"

    def test_metadata_with_header_succeeds(self, mock_gcp_metadata_client):
        """Test that metadata endpoints work with correct header."""
        response = mock_gcp_metadata_client.get(
            "/computeMetadata/v1/project/project-id",
            headers={"Metadata-Flavor": "Google"}
        )
        assert response.status_code == 200

    def test_health_without_header(self, mock_gcp_metadata_client):
        """Test that health endpoint works without Metadata-Flavor header."""
        response = mock_gcp_metadata_client.get("/health")
        assert response.status_code == 200


@pytest.mark.integration
class TestGCPProjectMetadata:
    """Tests for GCP project metadata endpoints."""

    def test_project_id(self, mock_gcp_metadata_client):
        """Test project-id endpoint."""
        project_id = mock_gcp_metadata_client.get_project_id()
        assert project_id is not None, "Could not get project ID"
        assert "demo-project" in project_id, "Unexpected project ID"

    def test_metadata_root(self, mock_gcp_metadata_client):
        """Test metadata root listing."""
        response = mock_gcp_metadata_client.get(
            "/computeMetadata/v1/",
            headers={"Metadata-Flavor": "Google"}
        )
        assert response.status_code == 200
        assert "instance/" in response.text
        assert "project/" in response.text


@pytest.mark.integration
class TestGCPServiceAccountEndpoints:
    """Tests for GCP service account endpoints."""

    def test_service_accounts_list(self, mock_gcp_metadata_client):
        """Test service account enumeration."""
        accounts = mock_gcp_metadata_client.get_service_accounts()
        assert accounts is not None, "Could not list service accounts"
        assert "default/" in accounts

    def test_service_account_token(self, mock_gcp_metadata_client):
        """Test service account access token endpoint."""
        token = mock_gcp_metadata_client.get_service_account_token()
        assert token is not None, "Could not get service account token"
        assert "access_token" in token, "Token missing access_token"
        assert token["access_token"].startswith("ya29."), "Token should start with ya29."
        assert token["token_type"] == "Bearer"
        assert "expires_in" in token

    def test_service_account_identity(self, mock_gcp_metadata_client):
        """Test service account identity token endpoint."""
        identity = mock_gcp_metadata_client.get_service_account_identity()
        assert identity is not None, "Could not get identity token"
        # Should be JWT format (3 parts)
        parts = identity.split(".")
        assert len(parts) == 3, "Identity token should be JWT format"


@pytest.mark.integration
class TestGCPWIFEndpoints:
    """Tests for GCP Workload Identity Federation endpoints."""

    def test_wif_token_exchange(self, mock_gcp_metadata_client):
        """Test WIF STS token exchange."""
        token = mock_gcp_metadata_client.exchange_wif_token(
            subject_token="eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.FAKE"
        )
        assert token is not None, "WIF token exchange returned None"
        assert "access_token" in token, "WIF response missing access_token"
        assert "token_type" in token
        assert token["token_type"] == "Bearer"

    def test_wif_requires_subject_token(self, mock_gcp_metadata_client):
        """Test WIF exchange fails without subject token."""
        response = mock_gcp_metadata_client.post(
            "/v1/token",
            json={
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token_type": "urn:ietf:params:oauth:token-type:jwt"
                # Missing subject_token
            }
        )
        assert response.status_code == 400

    def test_wif_requires_correct_grant_type(self, mock_gcp_metadata_client):
        """Test WIF exchange fails with wrong grant type."""
        response = mock_gcp_metadata_client.post(
            "/v1/token",
            json={
                "grant_type": "client_credentials",
                "subject_token": "fake.jwt.token"
            }
        )
        assert response.status_code == 400


@pytest.mark.integration
class TestGCPServiceAccountImpersonation:
    """Tests for GCP service account impersonation endpoint."""

    def test_sa_impersonation(self, mock_gcp_metadata_client):
        """Test service account impersonation."""
        result = mock_gcp_metadata_client.impersonate_service_account(
            "demo-compute@demo-project-12345.iam.gserviceaccount.com"
        )
        assert result is not None, "SA impersonation returned None"
        assert "accessToken" in result, "Response missing accessToken"
        assert "expireTime" in result, "Response missing expireTime"
