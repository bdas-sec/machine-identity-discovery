"""Async Wazuh Manager API client."""

import time
from typing import Any

import httpx

from api.config import settings


class WazuhClient:
    """Async HTTP client for the Wazuh Manager REST API."""

    def __init__(self):
        self._token: str | None = None
        self._token_ts: float = 0
        self._client: httpx.AsyncClient | None = None

    @property
    def base_url(self) -> str:
        return settings.wazuh_api_url

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(verify=False, timeout=15)
        return self._client

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def authenticate(self) -> bool:
        """Obtain a JWT bearer token from the Wazuh API."""
        client = self._get_client()
        try:
            resp = await client.post(
                f"{self.base_url}/security/user/authenticate",
                auth=(settings.wazuh_api_user, settings.wazuh_api_password),
            )
            if resp.status_code == 200:
                self._token = resp.json().get("data", {}).get("token")
                self._token_ts = time.time()
                return bool(self._token)
        except httpx.ConnectError:
            pass
        return False

    async def _headers(self) -> dict[str, str]:
        """Return auth headers, refreshing the token if older than 13 minutes."""
        if not self._token or (time.time() - self._token_ts > 780):
            await self.authenticate()
        return {"Authorization": f"Bearer {self._token}"}

    async def _get(self, path: str, params: dict[str, Any] | None = None) -> dict:
        """Perform an authenticated GET request."""
        client = self._get_client()
        headers = await self._headers()
        resp = await client.get(f"{self.base_url}{path}", headers=headers, params=params)
        if resp.status_code == 401:
            # Token expired mid-session — retry once
            await self.authenticate()
            headers = await self._headers()
            resp = await client.get(f"{self.base_url}{path}", headers=headers, params=params)
        resp.raise_for_status()
        return resp.json()

    async def get_alerts(
        self,
        limit: int = 20,
        offset: int = 0,
        rule_id: str | None = None,
        agent_name: str | None = None,
        min_level: int | None = None,
    ) -> dict:
        """Query Wazuh alerts."""
        params: dict[str, Any] = {"limit": limit, "offset": offset, "sort": "-timestamp"}
        if min_level:
            params["level"] = f">={min_level}"
        data = await self._get("/alerts", params)
        alerts = data.get("data", {}).get("affected_items", [])

        # Client-side filtering for rule_id (API doesn't support direct rule_id filter)
        if rule_id:
            alerts = [a for a in alerts if str(a.get("rule", {}).get("id")) == rule_id]
        if agent_name:
            alerts = [a for a in alerts if a.get("agent", {}).get("name") == agent_name]

        return {
            "total": data.get("data", {}).get("total_affected_items", 0),
            "alerts": alerts,
        }

    async def get_rules(self, limit: int = 500) -> list[dict]:
        """Get loaded Wazuh rules."""
        data = await self._get("/rules", {"limit": limit})
        return data.get("data", {}).get("affected_items", [])

    async def get_agents(self) -> list[dict]:
        """Get registered agents."""
        data = await self._get("/agents", {"limit": 100})
        return data.get("data", {}).get("affected_items", [])


# Singleton used across the application
wazuh_client = WazuhClient()
