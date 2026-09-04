"""
System control routes — Mode toggle (Live vs Simulated), simulator control,
and simulated data purging.
"""
import logging
import os
import subprocess
import sys
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import AlertDB, FlowRecordDB, SessionDB, get_db

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/system", tags=["System"])


class SystemState:
    mode: str = "live"  # "live" (strict real packets only) | "simulated" (simulator allowed)
    simulator_proc: Optional[subprocess.Popen] = None

    @classmethod
    def is_simulator_running(cls) -> bool:
        if cls.simulator_proc is not None:
            if cls.simulator_proc.poll() is None:
                return True
            cls.simulator_proc = None
        return False

    @classmethod
    def stop_simulator(cls) -> bool:
        if cls.simulator_proc is not None:
            try:
                cls.simulator_proc.terminate()
                cls.simulator_proc.wait(timeout=2.0)
            except Exception:
                try:
                    cls.simulator_proc.kill()
                except Exception:
                    pass
            cls.simulator_proc = None
            return True
        return False


class ModeUpdateRequest(BaseModel):
    mode: str  # "live" | "simulated"


@router.get("/mode")
async def get_system_mode():
    """Get current operating mode and simulator status."""
    return {
        "mode": SystemState.mode,
        "allow_simulation": SystemState.mode == "simulated",
        "simulator_running": SystemState.is_simulator_running(),
    }


@router.post("/mode")
async def set_system_mode(req: ModeUpdateRequest):
    """
    Switch between 'live' and 'simulated' modes.
    When switching to 'live', automatically stops any running simulator.
    """
    new_mode = req.mode.strip().lower()
    if new_mode not in ("live", "simulated"):
        raise HTTPException(
            status_code=400,
            detail="Invalid mode. Must be 'live' or 'simulated'.",
        )

    SystemState.mode = new_mode
    if new_mode == "live":
        stopped = SystemState.stop_simulator()
        if stopped:
            logger.info("Switched to LIVE mode — stopped background simulator.")

    logger.info("System operating mode changed to: %s", new_mode.upper())
    return {
        "mode": SystemState.mode,
        "allow_simulation": SystemState.mode == "simulated",
        "simulator_running": SystemState.is_simulator_running(),
    }


@router.post("/simulator/start")
async def start_simulator(speed: float = 1.0, sessions: int = 4):
    """
    Launch traffic simulator subprocess.
    Only permitted when system mode is 'simulated'.
    """
    if SystemState.mode != "simulated":
        raise HTTPException(
            status_code=403,
            detail=(
                "Simulator cannot be started in LIVE mode. "
                "Switch mode to 'Simulated' in Settings first."
            ),
        )

    if SystemState.is_simulator_running():
        return {
            "status": "already_running",
            "pid": SystemState.simulator_proc.pid if SystemState.simulator_proc else None,
        }

    # Resolve path to demo/traffic_simulator.py
    backend_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    project_root = os.path.dirname(backend_dir)
    sim_script = os.path.join(project_root, "demo", "traffic_simulator.py")

    if not os.path.exists(sim_script):
        raise HTTPException(
            status_code=404,
            detail=f"Traffic simulator script not found at {sim_script}",
        )

    cmd = [
        sys.executable,
        sim_script,
        "--api", "http://localhost:8000",
        "--sessions", str(sessions),
        "--speed", str(speed),
    ]

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        SystemState.simulator_proc = proc
        logger.info("Traffic simulator launched (PID %d)", proc.pid)
        return {"status": "started", "pid": proc.pid}
    except Exception as e:
        logger.error("Failed to launch traffic simulator: %s", e)
        raise HTTPException(status_code=500, detail=f"Failed to start simulator: {e}")


@router.post("/simulator/stop")
async def stop_simulator():
    """Stop the running traffic simulator."""
    was_running = SystemState.stop_simulator()
    return {"status": "stopped", "was_running": was_running}


@router.post("/purge-simulated")
async def purge_simulated_data(db: AsyncSession = Depends(get_db)):
    """
    Delete all simulated flows, sessions, and alerts from the database.
    Leaves real live capture and CSV data completely untouched.
    """
    # 1. Find all simulated session keys
    from sqlalchemy import select
    res = await db.execute(select(SessionDB.session_key).where(SessionDB.source == "simulated"))
    sim_keys = [r[0] for r in res.all()]

    deleted_alerts = 0
    deleted_flows = 0
    deleted_sessions = 0

    if sim_keys:
        # Delete alerts tied to simulated sessions
        stmt_alerts = delete(AlertDB).where(AlertDB.session_key.in_(sim_keys))
        del_a = await db.execute(stmt_alerts)
        deleted_alerts = del_a.rowcount or 0

    # Delete flows marked simulated
    stmt_flows = delete(FlowRecordDB).where(FlowRecordDB.source == "simulated")
    del_f = await db.execute(stmt_flows)
    deleted_flows = del_f.rowcount or 0

    # Delete sessions marked simulated
    stmt_sessions = delete(SessionDB).where(SessionDB.source == "simulated")
    del_s = await db.execute(stmt_sessions)
    deleted_sessions = del_s.rowcount or 0

    await db.commit()
    logger.info(
        "Purged simulated data: %d flows, %d sessions, %d alerts deleted",
        deleted_flows,
        deleted_sessions,
        deleted_alerts,
    )
    return {
        "status": "purged",
        "deleted_flows": deleted_flows,
        "deleted_sessions": deleted_sessions,
        "deleted_alerts": deleted_alerts,
    }
