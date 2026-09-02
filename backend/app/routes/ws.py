"""
WebSocket /ws/live — real-time flow feed + sessions list endpoint.
"""
import json
import asyncio
import logging
from datetime import datetime, timezone
from typing import Set

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func

from ..database import get_db, SessionDB, FlowRecordDB

logger = logging.getLogger(__name__)
router = APIRouter()

# Active WebSocket connections
_active_connections: Set[WebSocket] = set()


async def broadcast(event: dict):
    """Broadcast an event to all connected WebSocket clients."""
    if not _active_connections:
        return
    message = json.dumps(event, default=str)
    disconnected = set()
    for ws in _active_connections:
        try:
            await ws.send_text(message)
        except Exception:
            disconnected.add(ws)
    _active_connections -= disconnected


@router.websocket("/ws/live")
@router.websocket("/api/packets/ws")
async def live_feed(websocket: WebSocket):
    """
    WebSocket endpoint for live flow events.
    Clients connect and receive real-time predictions/alerts as flows are ingested.
    """
    await websocket.accept()
    _active_connections.add(websocket)
    logger.info("WebSocket client connected (%d total)", len(_active_connections))

    try:
        while True:
            # Keep connection alive; client can send pings
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))
    except WebSocketDisconnect:
        pass
    finally:
        _active_connections.discard(websocket)
        logger.info("WebSocket client disconnected (%d remaining)", len(_active_connections))


@router.get("/sessions")
async def get_sessions(
    limit: int = Query(50, ge=1, le=200),
    sort_by: str = Query("last_seen", description="Sort field: last_seen, latest_risk_score, flow_count"),
    db: AsyncSession = Depends(get_db),
):
    """Get tracked sessions with their latest risk scores."""
    sort_col = {
        "last_seen": desc(SessionDB.last_seen),
        "latest_risk_score": desc(SessionDB.latest_risk_score),
        "flow_count": desc(SessionDB.flow_count),
    }.get(sort_by, desc(SessionDB.last_seen))

    stmt = select(SessionDB).order_by(sort_col).limit(limit)
    result = await db.execute(stmt)
    sessions = result.scalars().all()

    return [
        {
            "id": s.id,
            "session_key": s.session_key,
            "src_ip": s.src_ip,
            "dst_ip": s.dst_ip,
            "flow_count": s.flow_count,
            "latest_risk_score": s.latest_risk_score,
            "latest_stage": s.latest_stage,
            "first_seen": s.first_seen.isoformat() if s.first_seen else None,
            "last_seen": s.last_seen.isoformat() if s.last_seen else None,
        }
        for s in sessions
    ]


@router.get("/sessions/{session_key}/flows")
async def get_session_flows(
    session_key: str,
    limit: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
):
    """Get flow records for a specific session (for building forecast windows)."""
    stmt = (
        select(FlowRecordDB)
        .where(FlowRecordDB.session_key == session_key)
        .order_by(desc(FlowRecordDB.timestamp))
        .limit(limit)
    )
    result = await db.execute(stmt)
    flows = result.scalars().all()

    from ..config import FLOW_FEATURES
    return [
        {
            "id": f.id,
            "timestamp": f.timestamp.isoformat() if f.timestamp else None,
            "features": {feat: getattr(f, feat) for feat in FLOW_FEATURES},
            "infiltration_prob": f.infiltration_prob,
            "predicted_stage": f.predicted_stage,
        }
        for f in flows
    ]


@router.get("/dashboard/stats")
async def dashboard_stats(db: AsyncSession = Depends(get_db)):
    """Aggregate stats for the dashboard header."""
    total_sessions = await db.execute(select(func.count(SessionDB.id)))
    total_flows = await db.execute(select(func.count(FlowRecordDB.id)))
    active_alerts = await db.execute(
        select(func.count()).select_from(
            select(SessionDB).where(SessionDB.latest_risk_score > 0.5).subquery()
        )
    )

    return {
        "total_sessions": total_sessions.scalar() or 0,
        "total_flows": total_flows.scalar() or 0,
        "at_risk_sessions": active_alerts.scalar() or 0,
    }
