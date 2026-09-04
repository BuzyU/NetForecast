"""
WebSocket /ws/live — real-time flow feed + sessions list endpoint.

BUG-01 fix: _active_connections and broadcast() moved to live.py to allow
ingestion.py to import broadcast without a circular dependency.
"""
import logging
from typing import Optional

from fastapi import APIRouter, Depends, Query, WebSocket, WebSocketDisconnect
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import FlowRecordDB, SessionDB, get_db
from ..live import (  # noqa: F401 (re-exported for convenience)
    broadcast,
    register,
    unregister,
)

logger = logging.getLogger(__name__)
router = APIRouter()


@router.websocket("/ws/live")
@router.websocket("/api/packets/ws")
async def websocket_live_feed(
    websocket: WebSocket,
    session_key: Optional[str] = Query(None),
):
    """
    WebSocket endpoint for real-time flow events.
    Clients can optionally filter by session_key (?session_key=...).
    """
    await websocket.accept()
    register(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        unregister(websocket)
    except Exception as e:
        logger.debug("WebSocket client disconnected: %s", e)
        unregister(websocket)


@router.get("/sessions")
async def get_sessions(
    limit: int = Query(50, ge=1, le=200),
    sort_by: str = Query("last_seen", description="Sort field: last_seen, latest_risk_score, flow_count"),
    source: Optional[str] = Query(None, description="Filter by source: live, simulated, or all"),
    db: AsyncSession = Depends(get_db),
):
    """Get tracked sessions with their latest risk scores."""
    sort_col = {
        "last_seen": desc(SessionDB.last_seen),
        "latest_risk_score": desc(SessionDB.latest_risk_score),
        "flow_count": desc(SessionDB.flow_count),
    }.get(sort_by, desc(SessionDB.last_seen))

    stmt = select(SessionDB)
    if source == "live":
        stmt = stmt.where(SessionDB.source != "simulated")
    elif source == "simulated":
        stmt = stmt.where(SessionDB.source == "simulated")

    stmt = stmt.order_by(sort_col).limit(limit)
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
            "max_stage_reached": s.max_stage_reached,
            "direction": s.direction,
            "source": s.source,
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
            "source": f.source,
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

    # Check if any simulated data is present (§7 — data-provenance labeling)
    sim_count = await db.execute(
        select(func.count(SessionDB.id)).where(SessionDB.source == "simulated")
    )
    has_simulated = (sim_count.scalar() or 0) > 0

    # Direction breakdown
    inbound_count = await db.execute(
        select(func.count(SessionDB.id)).where(SessionDB.direction == "inbound")
    )
    outbound_count = await db.execute(
        select(func.count(SessionDB.id)).where(SessionDB.direction == "outbound")
    )
    internal_count = await db.execute(
        select(func.count(SessionDB.id)).where(SessionDB.direction == "internal")
    )

    return {
        "total_sessions": total_sessions.scalar() or 0,
        "total_flows": total_flows.scalar() or 0,
        "at_risk_sessions": active_alerts.scalar() or 0,
        "has_simulated_data": has_simulated,
        "direction_breakdown": {
            "inbound": inbound_count.scalar() or 0,
            "outbound": outbound_count.scalar() or 0,
            "internal": internal_count.scalar() or 0,
        },
    }


@router.get("/dashboard/stage-distribution")
async def stage_distribution(db: AsyncSession = Depends(get_db)):
    """Count flows grouped by predicted_stage for reports."""
    stmt = (
        select(
            FlowRecordDB.predicted_stage,
            func.count(FlowRecordDB.id).label("count"),
        )
        .where(FlowRecordDB.predicted_stage.isnot(None))
        .group_by(FlowRecordDB.predicted_stage)
        .order_by(func.count(FlowRecordDB.id).desc())
    )
    result = await db.execute(stmt)
    rows = result.all()
    return [{"stage": row[0], "count": row[1]} for row in rows]
