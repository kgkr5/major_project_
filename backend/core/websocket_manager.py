"""
WebSocket connection manager for real-time event broadcasting.
"""

import json
import logging
from typing import Any

from fastapi import WebSocket

logger = logging.getLogger(__name__)


class ConnectionManager:
    """Manages active WebSocket connections and broadcasts messages."""

    def __init__(self) -> None:
        self._connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self._connections.append(websocket)
        logger.info("WebSocket connected. Total connections: %d", len(self._connections))

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self._connections:
            self._connections.remove(websocket)
        logger.info("WebSocket disconnected. Total connections: %d", len(self._connections))

    async def broadcast(self, message: dict[str, Any]) -> None:
        """Broadcast a JSON message to all connected clients."""
        if not self._connections:
            return
        payload = json.dumps(message, default=str)
        dead: list[WebSocket] = []
        for ws in list(self._connections):
            try:
                await ws.send_text(payload)
            except Exception as exc:
                logger.warning("Failed to send to WebSocket client: %s", exc)
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

    async def send_personal(self, websocket: WebSocket, message: dict[str, Any]) -> None:
        """Send a message to a single WebSocket client."""
        try:
            await websocket.send_text(json.dumps(message, default=str))
        except Exception as exc:
            logger.warning("Failed to send personal message: %s", exc)
            self.disconnect(websocket)

    @property
    def connection_count(self) -> int:
        return len(self._connections)


# Global singleton — import this in routers and agents
manager = ConnectionManager()
