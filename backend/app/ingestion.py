"""
Flow ingestion logic — accepts raw flow records, validates, scales, buffers
into windows, auto-runs prediction, creates alerts.
"""
import logging
from datetime import datetime, timezone
from collections import defaultdict
from typing import Optional

import numpy as np
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from .model_loader import artifacts
from .config import (
    FLOW_FEATURES, WINDOW_SIZE, DEFAULT_THRESHOLD,
    SESSION_TIME_BUCKET_SECONDS, STAGES,
)
from .database import FlowRecordDB, SessionDB, AlertDB
from .inference import predict_single
from .schemas import FlowRecord

logger = logging.getLogger(__name__)

# In-memory buffer for building windows per session
# Key: session_key, Value: list of scaled feature arrays
_session_buffers: dict[str, list[np.ndarray]] = defaultdict(list)


def derive_session_key(src_ip: Optional[str], dst_ip: Optional[str],
                       timestamp: Optional[datetime] = None) -> str:
    """
    Group flows into sessions by (src_ip, dst_ip, time_bucket).
    Falls back to a counter-based key if IPs aren't provided.
    """
    src = src_ip or "unknown"
    dst = dst_ip or "unknown"
    if timestamp:
        bucket = int(timestamp.timestamp()) // SESSION_TIME_BUCKET_SECONDS
    else:
        bucket = int(datetime.now(timezone.utc).timestamp()) // SESSION_TIME_BUCKET_SECONDS
    return f"{src}->{dst}@{bucket}"


def _severity_from_prob(prob: float) -> str:
    if prob >= 0.8:
        return "critical"
    elif prob >= 0.6:
        return "high"
    elif prob >= DEFAULT_THRESHOLD:
        return "medium"
    return "low"


def _recommended_action(stage: str, session_key: str) -> str:
    """Generate a concrete, actionable recommendation based on predicted stage."""
    parts = session_key.split("->")
    src = parts[0] if len(parts) > 0 else "source"
    dst = parts[1].split("@")[0] if len(parts) > 1 else "destination"

    actions = {
        "Reconnaissance": f"Investigate port scanning activity from {src}. Check firewall logs for SYN sweeps targeting {dst}.",
        "Initial Access": f"Block suspicious authentication attempts from {src} to {dst}. Review access logs for brute-force patterns.",
        "Lateral Movement": f"Isolate {dst} from internal network. Audit lateral connections from {src} for credential reuse.",
        "C2": f"Inspect outbound traffic from {dst} for beaconing patterns. Check DNS queries for DGA indicators.",
        "Exfiltration": f"URGENT: Block outbound data transfer from {dst}. Capture traffic for forensic analysis. Check for large file uploads.",
        "Benign": "No action required — traffic appears normal.",
    }
    return actions.get(stage, f"Review traffic between {src} and {dst}.")


async def ingest_single_flow(
    flow: FlowRecord,
    db: AsyncSession,
) -> dict:
    """
    Process a single flow record:
    1. Validate + extract features
    2. Store raw record in DB
    3. Scale and buffer for windowing
    4. If window is full → run prediction
    5. If alert → persist alert

    Returns dict with prediction results (if window was full) or buffer status.
    """
    if not artifacts.is_loaded:
        raise RuntimeError("Model not loaded — cannot ingest flows")

    raw_features = np.array([flow.to_feature_array()], dtype=np.float32)

    # Validate no NaN/Inf
    if np.any(~np.isfinite(raw_features)):
        raise ValueError("Flow contains NaN or Inf values — rejected")

    session_key = derive_session_key(flow.src_ip, flow.dst_ip, flow.timestamp)

    # ── Store raw record ──────────────────────────────────────────
    db_record = FlowRecordDB(
        session_key=session_key,
        src_ip=flow.src_ip,
        dst_ip=flow.dst_ip,
        timestamp=flow.timestamp or datetime.now(timezone.utc),
        **{f: getattr(flow, f) for f in FLOW_FEATURES},
    )
    db.add(db_record)

    # ── Update or create session ──────────────────────────────────
    result = await db.execute(
        select(SessionDB).where(SessionDB.session_key == session_key)
    )
    session = result.scalar_one_or_none()
    now = datetime.now(timezone.utc)

    if session is None:
        session = SessionDB(
            session_key=session_key,
            src_ip=flow.src_ip,
            dst_ip=flow.dst_ip,
            flow_count=1,
            first_seen=now,
            last_seen=now,
        )
        db.add(session)
    else:
        session.flow_count += 1
        session.last_seen = now

    # ── Scale and buffer ──────────────────────────────────────────
    scaled = artifacts.scale_features(raw_features)[0]
    _session_buffers[session_key].append(scaled)

    # Keep only the latest WINDOW_SIZE flows in buffer
    if len(_session_buffers[session_key]) > WINDOW_SIZE * 2:
        _session_buffers[session_key] = _session_buffers[session_key][-WINDOW_SIZE:]

    result_data = {
        "session_key": session_key,
        "buffer_size": len(_session_buffers[session_key]),
        "prediction": None,
        "alert": None,
    }

    # ── Run prediction if window is full ──────────────────────────
    if len(_session_buffers[session_key]) >= WINDOW_SIZE:
        window = np.array(
            _session_buffers[session_key][-WINDOW_SIZE:], dtype=np.float32
        )
        prediction = predict_single(window)
        result_data["prediction"] = prediction

        # Update session with latest prediction
        session.latest_risk_score = prediction["infiltration_probability"]
        session.latest_stage = prediction["predicted_stage"]

        # Update the flow record with prediction
        db_record.infiltration_prob = prediction["infiltration_probability"]
        db_record.predicted_stage = prediction["predicted_stage"]

        # ── Create alert if threshold exceeded ────────────────────
        if prediction["is_alert"]:
            severity = _severity_from_prob(prediction["infiltration_probability"])
            action = _recommended_action(prediction["predicted_stage"], session_key)

            alert = AlertDB(
                session_key=session_key,
                severity=severity,
                infiltration_prob=prediction["infiltration_probability"],
                predicted_stage=prediction["predicted_stage"],
                recommended_action=action,
                created_at=now,
            )
            db.add(alert)
            result_data["alert"] = {
                "severity": severity,
                "predicted_stage": prediction["predicted_stage"],
                "infiltration_prob": prediction["infiltration_probability"],
                "recommended_action": action,
            }

    await db.commit()
    return result_data


def clear_session_buffer(session_key: str):
    """Clear the in-memory buffer for a session."""
    _session_buffers.pop(session_key, None)


def get_buffer_status() -> dict:
    """Return current buffer status for debugging."""
    return {
        key: len(buf) for key, buf in _session_buffers.items()
    }
