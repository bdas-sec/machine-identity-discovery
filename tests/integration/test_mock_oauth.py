"""
Integration tests for Mock OAuth Provider service.

Tests OAuth2/OIDC endpoint simulations for consent phishing
and token theft attack scenarios.
"""

import pytest


@pytest.mark.integration
class TestOAuthServiceHealth:
    """Tests for OAuth Provider service availability."""

    def test_service_available(self, mock_oauth_client):
        """Verify Mock OAuth Provider is available."""
        assert mock_oauth_client.is_available(), \
            "Mock OAuth Provider is not available"

    def test_health_endpoint(self, mock_oauth_client):
        """Verify health endpoint returns healthy."""
        assert mock_oauth_client.health_check("/health"), \
            "Mock OAuth Provider health check failed"


@pytest.mark.integration
class TestOIDCDiscovery:
    """Tests for OIDC discovery endpoints."""

    def test_oidc_discovery_document(self, mock_oauth_client):
        """Test OIDC discovery endpoint returns valid configuration."""
        discovery = mock_oauth_client.get_oidc_discovery()
        assert discovery is not None, "OIDC discovery returned None"

        required_fields = [
            "issuer", "authorization_endpoint", "token_endpoint",
            "jwks_uri", "response_types_supported", "grant_types_supported"
        ]
        for field in required_fields:
            assert field in discovery, f"OIDC discovery missing {field}"

    def test_oidc_discovery_endpoints_consistent(self, mock_oauth_client):
        """Verify discovery endpoints match the issuer."""
        discovery = mock_oauth_client.get_oidc_discovery()
        assert discovery is not None
        issuer = discovery["issuer"]
        assert discovery["authorization_endpoint"].startswith(issuer)
        assert discovery["token_endpoint"].startswith(issuer)

    def test_jwks_endpoint(self, mock_oauth_client):
        """Test JWKS endpoint returns valid key set."""
        jwks = mock_oauth_client.get_jwks()
        assert jwks is not None, "JWKS endpoint returned None"
        assert "keys" in jwks, "JWKS missing 'keys' array"
        assert len(jwks["keys"]) > 0, "JWKS has no keys"

        key = jwks["keys"][0]
        assert key.get("kty") == "RSA", "Key type should be RSA"
        assert key.get("use") == "sig", "Key use should be 'sig'"
        assert key.get("alg") == "RS256", "Algorithm should be RS256"
        assert "n" in key and "e" in key, "RSA key missing n or e"


@pytest.mark.integration
class TestOAuthConsentPhishing:
    """Tests for OAuth consent phishing simulation."""

    def test_authorize_returns_html(self, mock_oauth_client):
        """Test authorize endpoint returns HTML consent screen."""
        response = mock_oauth_client.get("/authorize")
        assert response.status_code == 200
        assert "text/html" in response.headers.get("content-type", "")
        assert "Authorize" in response.text

    def test_authorize_shows_dangerous_scopes(self, mock_oauth_client):
        """Test that consent screen shows dangerous scope requests."""
        response = mock_oauth_client.get(
            "/authorize",
            params={"scope": "admin:org repo user:email"}
        )
        assert "admin:org" in response.text
        assert "repo" in response.text

    def test_authorize_includes_redirect(self, mock_oauth_client):
        """Test authorization includes redirect URI."""
        redirect = "https://attacker.example.com/callback"
        response = mock_oauth_client.get(
            "/authorize",
            params={"redirect_uri": redirect}
        )
        assert redirect in response.text


@pytest.mark.integration
class TestOAuthTokenEndpoints:
    """Tests for OAuth token endpoints."""

    def test_client_credentials_grant(self, mock_oauth_client):
        """Test client credentials grant type."""
        token = mock_oauth_client.get_token(grant_type="client_credentials")
        assert token is not None, "Token endpoint returned None"
        assert "access_token" in token, "Response missing access_token"
        assert "token_type" in token, "Response missing token_type"
        assert token["token_type"] == "Bearer"

    def test_token_is_jwt(self, mock_oauth_client):
        """Test that returned token has JWT structure."""
        token = mock_oauth_client.get_token(grant_type="client_credentials")
        assert token is not None
        parts = token["access_token"].split(".")
        assert len(parts) == 3, "Token is not a valid JWT (expected 3 parts)"

    def test_token_includes_refresh_token(self, mock_oauth_client):
        """Test that response includes refresh token."""
        token = mock_oauth_client.get_token(grant_type="client_credentials")
        assert token is not None
        assert "refresh_token" in token, "Response missing refresh_token"

    def test_token_includes_id_token(self, mock_oauth_client):
        """Test that response includes ID token."""
        token = mock_oauth_client.get_token(grant_type="client_credentials")
        assert token is not None
        assert "id_token" in token, "Response missing id_token"

    def test_unsupported_grant_type(self, mock_oauth_client):
        """Test that unsupported grant types return error."""
        response = mock_oauth_client.post(
            "/oauth/token",
            data={"grant_type": "invalid_type"}
        )
        assert response.status_code == 400

    def test_token_introspection(self, mock_oauth_client):
        """Test token introspection endpoint."""
        # Get a token first
        token = mock_oauth_client.get_token(grant_type="client_credentials")
        assert token is not None

        # Introspect it
        result = mock_oauth_client.introspect_token(token["access_token"])
        assert result is not None
        assert result.get("active") is True
        assert "scope" in result
        assert "client_id" in result


@pytest.mark.integration
class TestOAuthUserInfo:
    """Tests for OAuth userinfo endpoint."""

    def test_userinfo_returns_identity(self, mock_oauth_client):
        """Test userinfo returns user identity."""
        info = mock_oauth_client.get_userinfo()
        assert info is not None
        assert "sub" in info
        assert "email" in info
        assert "groups" in info
