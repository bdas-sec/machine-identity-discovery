"""
Wazuh API clients for testing.
"""

import requests
import time
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta


class WazuhTestClient:
    """Client for Wazuh Manager API testing."""

    def __init__(self, base_url: str, username: str, password: str):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self._token: Optional[str] = None
        self._token_expiry: Optional[datetime] = None

    def authenticate(self) -> bool:
        """Authenticate with Wazuh API."""
        try:
            response = requests.post(
                f"{self.base_url}/security/user/authenticate",
                auth=(self.username, self.password),
                verify=False,
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                self._token = data.get("data", {}).get("token")
                self._token_expiry = datetime.now() + timedelta(minutes=14)
                return True
            return False
        except Exception:
            return False

    def _get_headers(self) -> Dict[str, str]:
        """Get authenticated headers, refreshing token if needed."""
        if not self._token or (self._token_expiry and datetime.now() > self._token_expiry):
            self.authenticate()
        return {"Authorization": f"Bearer {self._token}"}

    def is_available(self) -> bool:
        """Check if Wazuh API is available."""
        try:
            response = requests.get(
                f"{self.base_url}/",
                verify=False,
                timeout=5
            )
            return response.status_code in [200, 401]
        except Exception:
            return False

    def get_manager_info(self) -> Optional[Dict]:
        """Get Wazuh manager information."""
        try:
            response = requests.get(
                f"{self.base_url}/",
                headers=self._get_headers(),
                verify=False,
                timeout=10
            )
            if response.status_code == 200:
                return response.json()
            return None
        except Exception:
            return None

    def get_manager_status(self) -> Dict[str, Any]:
        """Get Wazuh manager status."""
        try:
            response = requests.get(
                f"{self.base_url}/manager/status",
                headers=self._get_headers(),
                verify=False,
                timeout=10
            )
            return response.json()
        except Exception:
            return {}

    def get_agents(self, status: str = None) -> List[Dict]:
        """Get list of registered agents."""
        params: Dict[str, Any] = {"limit": 500}
        if status:
            params["status"] = status

        try:
            response = requests.get(
                f"{self.base_url}/agents",
                headers=self._get_headers(),
                params=params,
                verify=False,
                timeout=30
            )
            data = response.json()
            return data.get("data", {}).get("affected_items", [])
        except Exception:
            return []

    def get_agent_by_name(self, name: str) -> Optional[Dict]:
        """Get agent by name."""
        agents = self.get_agents()
        for agent in agents:
            if agent.get("name") == name:
                return agent
        return None

    def get_active_agents(self) -> List[Dict]:
        """Get list of active agents."""
        return self.get_agents(status="active")

    def get_rules(
        self,
        rule_id: str = None,
        group: str = None,
        level: int = None,
        limit: int = 500
    ) -> List[Dict]:
        """Get loaded Wazuh rules."""
        params: Dict[str, Any] = {"limit": limit}
        if rule_id:
            params["rule_ids"] = rule_id
        if group:
            params["group"] = group
        if level:
            params["level"] = level

        try:
            response = requests.get(
                f"{self.base_url}/rules",
                headers=self._get_headers(),
                params=params,
                verify=False,
                timeout=30
            )
            data = response.json()
            return data.get("data", {}).get("affected_items", [])
        except Exception:
            return []

    def get_rule_by_id(self, rule_id: str) -> Optional[Dict]:
        """Get a specific rule by ID."""
        rules = self.get_rules(rule_id=rule_id)
        return rules[0] if rules else None

    def get_nhi_rules(self) -> List[Dict]:
        """Get all NHI-specific rules (100600-100999)."""
        all_rules = self.get_rules(limit=1000)
        return [
            r for r in all_rules
            if 100600 <= int(r.get("id", 0)) <= 100999
        ]

    def get_decoders(self, limit: int = 500) -> List[Dict]:
        """Get loaded decoders."""
        try:
            response = requests.get(
                f"{self.base_url}/decoders",
                headers=self._get_headers(),
                params={"limit": limit},
                verify=False,
                timeout=30
            )
            data = response.json()
            return data.get("data", {}).get("affected_items", [])
        except Exception:
            return []

    def get_alert_count(self) -> int:
        """Get current alert count."""
        try:
            response = requests.get(
                f"{self.base_url}/alerts",
                headers=self._get_headers(),
                params={"limit": 1},
                verify=False,
                timeout=30
            )
            data = response.json()
            return data.get("data", {}).get("total_affected_items", 0)
        except Exception:
            return 0

    def query_alerts(
        self,
        rule_ids: List[str] = None,
        agent_name: str = None,
        level_min: int = None,
        minutes: int = 5,
        limit: int = 100
    ) -> List[Dict]:
        """Query alerts with filters."""
        params: Dict[str, Any] = {
            "limit": limit,
            "sort": "-timestamp"
        }
        if agent_name:
            params["agent_name"] = agent_name
        if level_min:
            params["level"] = f">={level_min}"

        try:
            response = requests.get(
                f"{self.base_url}/alerts",
                headers=self._get_headers(),
                params=params,
                verify=False,
                timeout=30
            )

            data = response.json()
            alerts = data.get("data", {}).get("affected_items", [])

            if rule_ids:
                alerts = [
                    a for a in alerts
                    if str(a.get("rule", {}).get("id")) in [str(r) for r in rule_ids]
                ]

            return alerts
        except Exception:
            return []


class WazuhIndexerClient:
    """Client for Wazuh Indexer (OpenSearch) API."""

    def __init__(self, base_url: str, username: str, password: str):
        self.base_url = base_url.rstrip("/")
        self.auth = (username, password)

    def is_healthy(self) -> bool:
        """Check cluster health."""
        try:
            response = requests.get(
                f"{self.base_url}/_cluster/health",
                auth=self.auth,
                verify=False,
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                return data.get("status") in ["green", "yellow"]
            return False
        except Exception:
            return False

    def get_cluster_health(self) -> Dict:
        """Get detailed cluster health."""
        try:
            response = requests.get(
                f"{self.base_url}/_cluster/health",
                auth=self.auth,
                verify=False,
                timeout=10
            )
            if response.status_code == 200:
                return response.json()
            return {}
        except Exception:
            return {}

    def get_indices(self) -> List[str]:
        """Get list of indices."""
        try:
            response = requests.get(
                f"{self.base_url}/_cat/indices?format=json",
                auth=self.auth,
                verify=False,
                timeout=10
            )
            if response.status_code == 200:
                return [idx.get("index") for idx in response.json()]
            return []
        except Exception:
            return []

    def search_alerts(
        self,
        rule_ids: List[str] = None,
        time_range: str = "5m",
        size: int = 100
    ) -> List[Dict]:
        """Search alerts in Wazuh index."""
        query: Dict[str, Any] = {
            "size": size,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "must": [
                        {"range": {"timestamp": {"gte": f"now-{time_range}"}}}
                    ]
                }
            }
        }

        if rule_ids:
            query["query"]["bool"]["must"].append({
                "terms": {"rule.id": [str(r) for r in rule_ids]}
            })

        try:
            response = requests.post(
                f"{self.base_url}/wazuh-alerts-*/_search",
                auth=self.auth,
                json=query,
                verify=False,
                timeout=30
            )

            data = response.json()
            hits = data.get("hits", {}).get("hits", [])
            return [hit.get("_source", {}) for hit in hits]
        except Exception:
            return []
