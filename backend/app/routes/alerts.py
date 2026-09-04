"""GET /alerts — real alert data from SQLite. POST /alerts/{id}/acknowledge."""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import AlertDB, get_db
from ..schemas import AlertOut

router = APIRouter()


@router.get("/alerts", response_model=list[AlertOut])
async def get_alerts(
    severity: str | None = Query(None, description="Filter by severity: critical, high, medium, low"),
    acknowledged: bool | None = Query(None, description="Filter by acknowledged status"),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(AlertDB).order_by(desc(AlertDB.created_at))

    if severity:
        stmt = stmt.where(AlertDB.severity == severity)
    if acknowledged is not None:
        stmt = stmt.where(AlertDB.acknowledged == acknowledged)

    stmt = stmt.limit(limit)
    result = await db.execute(stmt)
    alerts = result.scalars().all()
    return [AlertOut.model_validate(a) for a in alerts]


@router.post("/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(AlertDB).where(AlertDB.id == alert_id))
    alert = result.scalar_one_or_none()

    if alert is None:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")

    alert.acknowledged = True
    await db.commit()
    return {"status": "acknowledged", "alert_id": alert_id}


@router.get("/alerts/stats")
async def alert_stats(db: AsyncSession = Depends(get_db)):
    """Summary counts for the dashboard header."""
    total = await db.execute(select(func.count(AlertDB.id)))
    unack = await db.execute(
        select(func.count(AlertDB.id)).where(AlertDB.acknowledged.is_(False))
    )
    critical = await db.execute(
        select(func.count(AlertDB.id)).where(
            AlertDB.severity == "critical", AlertDB.acknowledged.is_(False)
        )
    )
    return {
        "total": total.scalar() or 0,
        "unacknowledged": unack.scalar() or 0,
        "critical_unacknowledged": critical.scalar() or 0,
    }
