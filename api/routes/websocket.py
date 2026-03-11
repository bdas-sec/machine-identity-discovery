"""WebSocket endpoint for real-time alert streaming."""

import asyncio
import json
import logging
from datetime import datetime

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from api.services.wazuh_client import wazuh_client

logger = logging.getLogger(__name__)
router = APIRouter()

# Connected clients
_clients: set[WebSocket] = set()
# Last seen alert timestamp to avoid duplicates
_last_alert_ts: str = ""


async def _poll_and_broadcast():
    """Background task: poll Wazuh every 2 seconds, broadcast new alerts."""
    global _last_alert_ts
    while True:
        try:
            if _clients:
                result = await wazuh_client.get_alerts(limit=10)
                alerts = result.get("alerts", [])
                new_alerts = []
                for alert in alerts:
                    ts = alert.get("timestamp", "")
                    if ts > _last_alert_ts:
                        new_alerts.append(alert)
                if new_alerts:
                    _last_alert_ts = max(a.get("timestamp", "") for a in new_alerts)
                    message = json.dumps({
                        "type": "alerts",
                        "data": new_alerts,
                        "timestamp": datetime.utcnow().isoformat()
                    })
                    disconnected = set()
                    for client in _clients:
                        try:
                            await client.send_text(message)
                        except Exception:
                            disconnected.add(client)
                    _clients -= disconnected
        except Exception as e:
            logger.warning(f"Alert poll error: {e}")
        await asyncio.sleep(2)


# Start background polling task
_poll_task = None


def start_polling():
    """Start the background alert polling task if not already running."""
    global _poll_task
    if _poll_task is None or _poll_task.done():
        _poll_task = asyncio.create_task(_poll_and_broadcast())


@router.websocket("/ws/alerts")
async def alerts_websocket(websocket: WebSocket):
    """Accept a WebSocket connection and stream alerts in real time."""
    await websocket.accept()
    _clients.add(websocket)
    start_polling()
    logger.info(f"WebSocket client connected. Total: {len(_clients)}")
    try:
        # Send initial batch of recent alerts
        result = await wazuh_client.get_alerts(limit=20)
        await websocket.send_text(json.dumps({
            "type": "initial",
            "data": result.get("alerts", []),
            "timestamp": datetime.utcnow().isoformat()
        }))
        # Keep connection alive, handle incoming messages (ping/pong)
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))
    except WebSocketDisconnect:
        pass
    finally:
        _clients.discard(websocket)
        logger.info(f"WebSocket client disconnected. Total: {len(_clients)}")
