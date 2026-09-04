"""
Live broadcast module — shared between ws.py (WebSocket handler) and
ingestion.py (flow processor) to avoid circular imports.

BUG-01 fix: broadcast() was defined in ws.py but never called from ingestion.py
because importing ws.py from ingestion.py would create a circular dependency.
Extracting the connection registry here breaks the cycle cleanly.
"""
import json
import logging
from typing import Set

from fastapi import WebSocket

logger = logging.getLogger(__name__)

# Registry of all currently connected WebSocket clients
_active_connections: Set[WebSocket] = set()


def register(ws: WebSocket):
    """Add a new WebSocket client to the registry."""
    _active_connections.add(ws)
    logger.info("WebSocket client registered (%d total)", len(_active_connections))


def unregister(ws: WebSocket):
    """Remove a WebSocket client from the registry."""
    _active_connections.discard(ws)
    logger.info("WebSocket client removed (%d remaining)", len(_active_connections))


async def broadcast(event: dict):
    """
    Broadcast an event dict to every connected WebSocket client.
    Silently removes any client that has disconnected since the last send.
    """
    if not _active_connections:
        return
    message = json.dumps(event, default=str)
    disconnected = set()
    for ws in _active_connections:
        try:
            await ws.send_text(message)
        except Exception:
            disconnected.add(ws)
    if disconnected:
        _active_connections.difference_update(disconnected)
        logger.debug("Pruned %d stale WebSocket connections", len(disconnected))
