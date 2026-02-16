"""
HTTP client utilities for testing.
"""

import requests
from typing import Dict, Optional, Any
from tenacity import retry, stop_after_attempt, wait_exponential


class TestHttpClient:
    """HTTP client with retry logic for testing services."""

    def __init__(self, base_url: str, timeout: int = 10):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()

    def _url(self, path: str) -> str:
        """Construct full URL."""
        if path.startswith("/"):
            return f"{self.base_url}{path}"
        return f"{self.base_url}/{path}"

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=4))
    def get(
        self,
        path: str,
        headers: Dict[str, str] = None,
        params: Dict[str, Any] = None
    ) -> requests.Response:
        """GET request with retry."""
        return self.session.get(
            self._url(path),
            headers=headers,
            params=params,
            timeout=self.timeout,
            verify=False
        )

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=4))
    def post(
        self,
        path: str,
        headers: Dict[str, str] = None,
        json: Dict[str, Any] = None,
        data: Any = None
    ) -> requests.Response:
        """POST request with retry."""
        return self.session.post(
            self._url(path),
            headers=headers,
            json=json,
            data=data,
            timeout=self.timeout,
            verify=False
        )

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=4))
    def put(
        self,
        path: str,
        headers: Dict[str, str] = None,
        json: Dict[str, Any] = None
    ) -> requests.Response:
        """PUT request with retry."""
        return self.session.put(
            self._url(path),
            headers=headers,
            json=json,
            timeout=self.timeout,
            verify=False
        )

    def is_available(self) -> bool:
        """Check if service is available."""
        try:
            response = self.session.get(
                self.base_url,
                timeout=5,
                verify=False
            )
            return response.status_code < 500
        except Exception:
            return False

    def health_check(self, path: str = "/health") -> bool:
        """Check service health endpoint."""
        try:
            response = self.get(path)
            return response.status_code == 200
        except Exception:
            return False


class MockIMDSClient(TestHttpClient):
    """Specialized client for Mock IMDS service."""

    def get_metadata_root(self) -> Optional[str]:
        """Get metadata root listing."""
        try:
            response = self.get("/latest/meta-data/")
            if response.status_code == 200:
                return response.text
            return None
        except Exception:
            return None

    def get_instance_id(self) -> Optional[str]:
        """Get instance ID."""
        try:
            response = self.get("/latest/meta-data/instance-id")
            if response.status_code == 200:
                return response.text
            return None
        except Exception:
            return None

    def get_iam_role(self) -> Optional[str]:
        """Get IAM role name."""
        try:
            response = self.get("/latest/meta-data/iam/security-credentials/")
            if response.status_code == 200:
                return response.text.strip()
            return None
        except Exception:
            return None

    def get_iam_credentials(self, role_name: str) -> Optional[Dict]:
        """Get IAM credentials for a role."""
        try:
            response = self.get(f"/latest/meta-data/iam/security-credentials/{role_name}")
            if response.status_code == 200:
                return response.json()
            return None
        except Exception:
            return None

    def get_imdsv2_token(self, ttl: int = 21600) -> Optional[str]:
        """Get IMDSv2 token."""
        try:
            response = self.put(
                "/latest/api/token",
                headers={"X-aws-ec2-metadata-token-ttl-seconds": str(ttl)}
            )
            if response.status_code == 200:
                return response.text
            return None
        except Exception:
            return None


class MockCICDClient(TestHttpClient):
    """Specialized client for Mock CI/CD service."""

    def get_runner_token(self) -> Optional[Dict]:
        """Get GitHub Actions runner token."""
        try:
            response = self.post("/github/actions/runner/token")
            if response.status_code == 200:
                return response.json()
            return None
        except Exception:
            return None

    def get_repo_secrets(self, owner: str, repo: str) -> Optional[Dict]:
        """Get repository secrets list."""
        try:
            response = self.get(f"/github/repos/{owner}/{repo}/actions/secrets")
            if response.status_code == 200:
                return response.json()
            return None
        except Exception:
            return None

    def get_oidc_token(self, audience: str = "sts.amazonaws.com") -> Optional[Dict]:
        """Get OIDC token for workload identity."""
        try:
            response = self.get(
                "/github/actions/oidc/token",
                params={"audience": audience}
            )
            if response.status_code == 200:
                return response.json()
            return None
        except Exception:
            return None

    def get_gitlab_variables(self, project_id: int) -> Optional[Dict]:
        """Get GitLab CI variables."""
        try:
            response = self.get(f"/gitlab/api/v4/projects/{project_id}/variables")
            if response.status_code == 200:
                return response.json()
            return None
        except Exception:
            return None

    def get_app_installations(self) -> Optional[list]:
        """Get GitHub App installations."""
        try:
            response = self.get("/github/app/installations")
            if response.status_code == 200:
                return response.json()
            return None
        except Exception:
            return None

    def get_app_installation_token(self, installation_id: int = 1) -> Optional[Dict]:
        """Get GitHub App installation access token."""
        try:
            response = self.post(f"/github/app/installations/{installation_id}/access_tokens")
            if response.status_code == 200:
                return response.json()
            return None
        except Exception:
            return None

    def get_app_repositories(self, installation_id: int = 1) -> Optional[Dict]:
        """Get repositories accessible to a GitHub App installation."""
        try:
            response = self.get(f"/github/app/installations/{installation_id}/repositories")
            if response.status_code == 200:
                return response.json()
            return None
        except Exception:
            return None


class MockOAuthClient(TestHttpClient):
    """Specialized client for Mock OAuth Provider."""

    def get_oidc_discovery(self) -> Optional[Dict]:
        """Get OIDC discovery document."""
        try:
            response = self.get("/.well-known/openid-configuration")
            if response.status_code == 200:
                return response.json()
            return None
        except Exception:
            return None

    def get_jwks(self) -> Optional[Dict]:
        """Get JWKS document."""
        try:
            response = self.get("/.well-known/jwks.json")
            if response.status_code == 200:
                return response.json()
            return None
        except Exception:
            return None

    def get_token(
        self,
        grant_type: str = "client_credentials",
        client_id: str = "demo-malicious-app",
        client_secret: str = "demo-client-secret-FAKE",
        scope: str = "admin:org repo user:email"
    ) -> Optional[Dict]:
        """Request OAuth token."""
        try:
            response = self.post(
                "/oauth/token",
                data={
                    "grant_type": grant_type,
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "scope": scope
                }
            )
            if response.status_code == 200:
                return response.json()
            return None
        except Exception:
            return None

    def introspect_token(self, token: str) -> Optional[Dict]:
        """Introspect an OAuth token."""
        try:
            response = self.post(
                "/oauth/token/introspect",
                data={"token": token}
            )
            if response.status_code == 200:
                return response.json()
            return None
        except Exception:
            return None

    def get_userinfo(self, access_token: str = None) -> Optional[Dict]:
        """Get userinfo endpoint."""
        try:
            headers = {}
            if access_token:
                headers["Authorization"] = f"Bearer {access_token}"
            response = self.get("/userinfo", headers=headers)
            if response.status_code == 200:
                return response.json()
            return None
        except Exception:
            return None


class MockGCPMetadataClient(TestHttpClient):
    """Specialized client for Mock GCP Metadata service."""

    GCP_HEADERS = {"Metadata-Flavor": "Google"}

    def get_project_id(self) -> Optional[str]:
        """Get GCP project ID."""
        try:
            response = self.get(
                "/computeMetadata/v1/project/project-id",
                headers=self.GCP_HEADERS
            )
            if response.status_code == 200:
                return response.text
            return None
        except Exception:
            return None

    def get_service_accounts(self) -> Optional[str]:
        """List service accounts."""
        try:
            response = self.get(
                "/computeMetadata/v1/instance/service-accounts/",
                headers=self.GCP_HEADERS
            )
            if response.status_code == 200:
                return response.text
            return None
        except Exception:
            return None

    def get_service_account_token(self) -> Optional[Dict]:
        """Get service account access token."""
        try:
            response = self.get(
                "/computeMetadata/v1/instance/service-accounts/default/token",
                headers=self.GCP_HEADERS
            )
            if response.status_code == 200:
                return response.json()
            return None
        except Exception:
            return None

    def get_service_account_identity(self, audience: str = "https://example.com") -> Optional[str]:
        """Get service account identity token."""
        try:
            response = self.get(
                "/computeMetadata/v1/instance/service-accounts/default/identity",
                headers=self.GCP_HEADERS,
                params={"audience": audience}
            )
            if response.status_code == 200:
                return response.text
            return None
        except Exception:
            return None

    def exchange_wif_token(self, subject_token: str) -> Optional[Dict]:
        """Exchange WIF token via STS."""
        try:
            response = self.post(
                "/v1/token",
                json={
                    "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                    "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
                    "subject_token": subject_token,
                    "scope": "https://www.googleapis.com/auth/cloud-platform"
                }
            )
            if response.status_code == 200:
                return response.json()
            return None
        except Exception:
            return None

    def impersonate_service_account(self, sa_email: str) -> Optional[Dict]:
        """Impersonate a service account via generateAccessToken."""
        try:
            response = self.post(
                f"/v1/projects/-/serviceAccounts/{sa_email}:generateAccessToken",
                json={"scope": ["https://www.googleapis.com/auth/cloud-platform"]}
            )
            if response.status_code == 200:
                return response.json()
            return None
        except Exception:
            return None
