"""
GET /reports/export/csv and GET /reports/export/json
Export comprehensive security analysis reports for defenders.
"""
import csv
import io
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse, StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import (
    ADAPTIVE_THRESHOLD_ENABLED,
    DEFAULT_THRESHOLD,
    FLOW_FEATURES,
    HIDDEN_SIZE,
    NUM_LSTM_LAYERS,
    STAGES,
    WINDOW_SIZE,
)
from ..database import AlertDB, FlowRecordDB, SessionDB, get_db
from ..model_loader import artifacts

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/reports/export/csv")
async def export_csv(
    report_type: str = Query("sessions", pattern="^(sessions|alerts|flows)$"),
    db: AsyncSession = Depends(get_db),
):
    """
    Export sessions, alerts, or flows as a downloadable CSV report.
    """
    output = io.StringIO()
    writer = csv.writer(output)

    if report_type == "alerts":
        writer.writerow([
            "alert_id", "session_key", "severity", "predicted_stage",
            "infiltration_prob", "recommended_action", "acknowledged", "created_at"
        ])
        result = await db.execute(
            select(AlertDB).order_by(AlertDB.created_at.desc()).limit(1000)
        )
        for a in result.scalars().all():
            writer.writerow([
                a.id, a.session_key, a.severity, a.predicted_stage,
                f"{a.infiltration_prob:.4f}", a.recommended_action,
                a.acknowledged, a.created_at.isoformat() if a.created_at else ""
            ])
        filename = f"netforecast_alerts_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"

    elif report_type == "flows":
        writer.writerow(["id", "session_key", "src_ip", "dst_ip", "timestamp", "source", "predicted_stage", "infiltration_prob"] + FLOW_FEATURES)
        result = await db.execute(
            select(FlowRecordDB).order_by(FlowRecordDB.timestamp.desc()).limit(1000)
        )
        for f in result.scalars().all():
            row = [
                f.id, f.session_key, f.src_ip, f.dst_ip,
                f.timestamp.isoformat() if f.timestamp else "",
                f.source, f.predicted_stage or "Benign",
                f"{f.infiltration_prob:.4f}" if f.infiltration_prob is not None else ""
            ]
            row.extend([getattr(f, feat, 0.0) for feat in FLOW_FEATURES])
            writer.writerow(row)
        filename = f"netforecast_flows_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"

    else:  # sessions
        writer.writerow([
            "session_key", "src_ip", "dst_ip", "flow_count",
            "latest_risk_score", "latest_stage", "max_stage_reached",
            "direction", "source", "first_seen", "last_seen"
        ])
        result = await db.execute(
            select(SessionDB).order_by(SessionDB.last_seen.desc()).limit(1000)
        )
        for s in result.scalars().all():
            writer.writerow([
                s.session_key, s.src_ip or "", s.dst_ip or "", s.flow_count,
                f"{s.latest_risk_score:.4f}" if s.latest_risk_score is not None else "0.0000",
                s.latest_stage or "Benign", s.max_stage_reached or "Benign",
                s.direction or "unknown", s.source or "api",
                s.first_seen.isoformat() if s.first_seen else "",
                s.last_seen.isoformat() if s.last_seen else "",
            ])
        filename = f"netforecast_sessions_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/reports/export/json")
async def export_json(db: AsyncSession = Depends(get_db)):
    """
    Export comprehensive structured JSON report with system telemetry,
    attack forecasts, and defender decision support.
    """
    now = datetime.now(timezone.utc)

    # 1. Total sessions and at-risk count
    total_sessions = (await db.execute(select(func.count(SessionDB.id)))).scalar_one() or 0
    at_risk_sessions = (await db.execute(
        select(func.count(SessionDB.id)).where(SessionDB.latest_risk_score > DEFAULT_THRESHOLD)
    )).scalar_one() or 0

    # 2. Total flows
    total_flows = (await db.execute(select(func.count(FlowRecordDB.id)))).scalar_one() or 0

    # 3. Alert stats
    total_alerts = (await db.execute(select(func.count(AlertDB.id)))).scalar_one() or 0
    unack_alerts = (await db.execute(
        select(func.count(AlertDB.id)).where(AlertDB.acknowledged == False)
    )).scalar_one() or 0
    critical_unack = (await db.execute(
        select(func.count(AlertDB.id)).where(
            AlertDB.acknowledged == False, AlertDB.severity == "critical"
        )
    )).scalar_one() or 0

    # 4. Stage distribution
    stage_dist_res = await db.execute(
        select(SessionDB.latest_stage, func.count(SessionDB.id))
        .group_by(SessionDB.latest_stage)
    )
    stage_distribution = {
        row[0] or "Benign": row[1] for row in stage_dist_res.all()
    }

    # 5. Top at-risk sessions
    top_sessions_res = await db.execute(
        select(SessionDB).order_by(SessionDB.latest_risk_score.desc()).limit(50)
    )
    top_sessions = [
        {
            "session_key": s.session_key,
            "src_ip": s.src_ip,
            "dst_ip": s.dst_ip,
            "flow_count": s.flow_count,
            "latest_risk_score": s.latest_risk_score,
            "latest_stage": s.latest_stage,
            "max_stage_reached": s.max_stage_reached,
            "direction": s.direction,
            "source": s.source,
            "last_seen": s.last_seen.isoformat() if s.last_seen else None,
        }
        for s in top_sessions_res.scalars().all()
    ]

    report = {
        "report_title": "NetForecast — AI Cyber Attack Progression Report",
        "generated_at": now.isoformat(),
        "model_telemetry": {
            "model_type": "LSTM World Model (Multi-head)",
            "num_layers": NUM_LSTM_LAYERS,
            "hidden_size": HIDDEN_SIZE,
            "window_size": WINDOW_SIZE,
            "num_features": len(FLOW_FEATURES),
            "features": FLOW_FEATURES,
            "stages": STAGES,
            "alert_threshold": DEFAULT_THRESHOLD,
            "adaptive_threshold_enabled": ADAPTIVE_THRESHOLD_ENABLED,
            "model_loaded": artifacts.is_loaded,
        },
        "summary": {
            "total_sessions": total_sessions,
            "total_flows": total_flows,
            "at_risk_sessions": at_risk_sessions,
            "total_alerts": total_alerts,
            "unacknowledged_alerts": unack_alerts,
            "critical_unacknowledged": critical_unack,
            "stage_distribution": stage_distribution,
        },
        "top_at_risk_sessions": top_sessions,
    }

    return JSONResponse(
        content=report,
        headers={
            "Content-Disposition": f"attachment; filename=netforecast_report_{now.strftime('%Y%m%d_%H%M%S')}.json"
        },
    )
