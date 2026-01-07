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
