"""Alert querying endpoints — proxies to Wazuh API."""

from datetime import datetime
from fastapi import APIRouter, HTTPException, Query
import httpx

from api.config import settings
from api.models.alerts import Alert, AlertSummary

router = APIRouter(prefix="/alerts", tags=["alerts"])


async def _get_wazuh_token() -> str:
    """Authenticate with Wazuh API and return JWT token."""
    async with httpx.AsyncClient(verify=False) as client:
        resp = await client.post(
            f"{settings.wazuh_api_url}/security/user/authenticate",
            auth=(settings.wazuh_api_user, settings.wazuh_api_password),
            timeout=10,
        )
        if resp.status_code != 200:
            raise HTTPException(status_code=502, detail="Failed to authenticate with Wazuh API")
        return resp.json()["data"]["token"]


async def _query_wazuh_alerts(
    token: str,
    limit: int = 20,
    offset: int = 0,
    rule_id: str | None = None,
    level_min: int | None = None,
) -> dict:
    """Query Wazuh API for alerts."""
    headers = {"Authorization": f"Bearer {token}"}
    params: dict = {"limit": limit, "offset": offset, "sort": "-timestamp"}
    if rule_id:
        params["q"] = f"rule.id={rule_id}"
    if level_min:
        params["q"] = params.get("q", "") + f";rule.level>={level_min}" if "q" in params else f"rule.level>={level_min}"

    async with httpx.AsyncClient(verify=False) as client:
        resp = await client.get(
            f"{settings.wazuh_api_url}/alerts",
            headers=headers,
            params=params,
            timeout=15,
        )
        if resp.status_code != 200:
            raise HTTPException(status_code=502, detail=f"Wazuh API error: {resp.status_code}")
        return resp.json().get("data", {})


def _parse_alert(raw: dict) -> Alert:
    """Convert raw Wazuh alert dict to our Alert model."""
    rule = raw.get("rule", {})
    agent = raw.get("agent", {})
    ts = raw.get("timestamp", "")
    try:
        timestamp = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        timestamp = datetime.now()

    return Alert(
        id=raw.get("id", ""),
        timestamp=timestamp,
        rule_id=str(rule.get("id", "")),
        rule_description=rule.get("description", ""),
        rule_level=int(rule.get("level", 0)),
        agent_name=agent.get("name", ""),
        agent_id=str(agent.get("id", "")),
        groups=rule.get("groups", []),
        full_log=raw.get("full_log"),
    )


@router.get("", response_model=AlertSummary)
async def list_alerts(
    limit: int = Query(20, ge=1, le=100, description="Max alerts to return"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    rule_id: str | None = Query(None, description="Filter by rule ID"),
    level_min: int | None = Query(None, ge=1, le=15, description="Minimum alert level"),
):
    """Query recent NHI alerts from Wazuh."""
    try:
        token = await _get_wazuh_token()
        data = await _query_wazuh_alerts(token, limit, offset, rule_id, level_min)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Cannot reach Wazuh API: {e}")

    items = data.get("affected_items", [])
    total = data.get("total_affected_items", len(items))
    alerts = [_parse_alert(item) for item in items]

    return AlertSummary(total=total, alerts=alerts, offset=offset, limit=limit)
