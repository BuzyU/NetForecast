"""
Flow ingestion logic — accepts raw flow records, validates, scales, buffers
into windows, auto-runs prediction, creates alerts, broadcasts via WebSocket.

Fixes applied:
  BUG-01  — broadcast() now called after db.commit() so Live Logs actually receive events
  BUG-02  — _session_buffers evicted via TTL sweep in evict_stale_buffers()
  §7      — data provenance (source field) stored per flow and per session
  §11A    — RFC1918-based traffic direction classification on session create
  §5 (KillChain flapping) — max_stage_reached is monotonic (never decreases)
"""
import ipaddress
import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Optional

import numpy as np
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .config import (
    DEFAULT_THRESHOLD,
    FLOW_FEATURES,
    SESSION_TIME_BUCKET_SECONDS,
    STAGES,
    WINDOW_SIZE,
)
from .database import AlertDB, FlowRecordDB, SessionDB
from .inference import predict_single
from .live import broadcast  # BUG-01 fix
from .model_loader import artifacts
from .schemas import FlowRecord

logger = logging.getLogger(__name__)

# ── In-memory buffer ──────────────────────────────────────────────────
# Key: session_key  →  {"flows": [np.ndarray], "last_updated": datetime}
# BUG-02 fix: each entry carries a timestamp so stale keys can be evicted.
_session_buffers: dict[str, dict] = defaultdict(
    lambda: {"flows": [], "last_updated": datetime.now(timezone.utc)}
)

# BUG-02: evict buffer entries that haven't been touched for this many seconds
_BUFFER_TTL_SECONDS = SESSION_TIME_BUCKET_SECONDS * 2  # 10 minutes


def evict_stale_buffers():
    """
    Remove buffer entries that haven't been updated in >TTL seconds.
    Call periodically (e.g., from a background task) or opportunistically
    during ingestion to prevent unbounded memory growth.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=_BUFFER_TTL_SECONDS)
    stale = [k for k, v in _session_buffers.items() if v["last_updated"] < cutoff]
    for k in stale:
        del _session_buffers[k]
    if stale:
        logger.info("Evicted %d stale session buffers", len(stale))
    return len(stale)


# ── RFC1918 private ranges (§11A) ──────────────────────────────────────
_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]


def _is_private(ip_str: Optional[str]) -> bool:
    if not ip_str:
        return False
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return False


def classify_direction(src_ip: Optional[str], dst_ip: Optional[str]) -> str:
    """
    Classify traffic direction using RFC1918 private-range heuristic.
    Returns "inbound" | "outbound" | "internal" | "unknown"
    """
    src_private = _is_private(src_ip)
    dst_private = _is_private(dst_ip)

    if src_private and dst_private:
        return "internal"
    elif not src_private and dst_private:
        return "inbound"   # external → protected host
    elif src_private and not dst_private:
        return "outbound"  # protected host → external
    return "unknown"


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
    """
    Playbook-style recommendation template keyed on predicted MITRE stage.
    These are rule-based templates, not model-generated text.
    """
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


def _stage_index(stage: str) -> int:
    """Return the integer index of a stage name, or 0 for Benign."""
    try:
        return STAGES.index(stage)
    except ValueError:
        return 0


async def ingest_single_flow(
    flow: FlowRecord,
    db: AsyncSession,
) -> dict:
    """
    Process a single flow record:
    1. Validate + extract features
    2. Store raw record in DB (with provenance)
    3. Scale and buffer for windowing
    4. If window is full → run prediction
    5. If alert → persist alert
    6. Broadcast result via WebSocket (BUG-01 fix)

    Returns dict with prediction results (if window was full) or buffer status.
    """
    if not artifacts.is_loaded:
        raise RuntimeError("Model not loaded — cannot ingest flows")

    raw_features = np.array([flow.to_feature_array()], dtype=np.float32)

    # Validate no NaN/Inf
    if np.any(~np.isfinite(raw_features)):
        raise ValueError("Flow contains NaN or Inf values — rejected")

    # Opportunistic buffer eviction (BUG-02 fix) — ~1% of requests trigger a sweep
    import random
    if random.random() < 0.01:
        evict_stale_buffers()

    session_key = derive_session_key(flow.src_ip, flow.dst_ip, flow.timestamp)
    source = getattr(flow, "source", None) or "api"
    direction = classify_direction(flow.src_ip, flow.dst_ip)

    # ── Store raw record ──────────────────────────────────────────
    db_record = FlowRecordDB(
        session_key=session_key,
        src_ip=flow.src_ip,
        dst_ip=flow.dst_ip,
        timestamp=flow.timestamp or datetime.now(timezone.utc),
        source=source,
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
            source=source,
            direction=direction,
            max_stage_reached="Benign",
        )
        db.add(session)
    else:
        session.flow_count += 1
        session.last_seen = now
        # Update direction if we can resolve it (first flows may lack IPs)
        if session.direction == "unknown" and direction != "unknown":
            session.direction = direction

    # ── Scale and buffer ──────────────────────────────────────────
    scaled = artifacts.scale_features(raw_features)[0]
    buf = _session_buffers[session_key]
    buf["flows"].append(scaled)
    buf["last_updated"] = now

    # Keep only the latest WINDOW_SIZE flows (+ one extra for safety)
    if len(buf["flows"]) > WINDOW_SIZE * 2:
        buf["flows"] = buf["flows"][-WINDOW_SIZE:]

    result_data = {
        "session_key": session_key,
        "buffer_size": len(buf["flows"]),
        "prediction": None,
        "alert": None,
    }

    # ── Run prediction if window is full ──────────────────────────
    if len(buf["flows"]) >= WINDOW_SIZE:
        window = np.array(buf["flows"][-WINDOW_SIZE:], dtype=np.float32)
        prediction = predict_single(window)
        result_data["prediction"] = prediction

        predicted_stage = prediction["predicted_stage"]

        # Update session with latest prediction
        session.latest_risk_score = prediction["infiltration_probability"]
        session.latest_stage = predicted_stage

        # Monotonic max_stage_reached (§5 kill-chain flapping fix)
        current_max_idx = _stage_index(session.max_stage_reached or "Benign")
        new_stage_idx = _stage_index(predicted_stage)
        if new_stage_idx > current_max_idx:
            session.max_stage_reached = predicted_stage

        # Update the flow record with prediction
        db_record.infiltration_prob = prediction["infiltration_probability"]
        db_record.predicted_stage = predicted_stage

        # ── Create alert if threshold exceeded ────────────────────
        if prediction["is_alert"]:
            severity = _severity_from_prob(prediction["infiltration_probability"])
            action = _recommended_action(predicted_stage, session_key)

            alert = AlertDB(
                session_key=session_key,
                severity=severity,
                infiltration_prob=prediction["infiltration_probability"],
                predicted_stage=predicted_stage,
                recommended_action=action,
                created_at=now,
            )
            db.add(alert)
            result_data["alert"] = {
                "severity": severity,
                "predicted_stage": predicted_stage,
                "infiltration_prob": prediction["infiltration_probability"],
                "recommended_action": action,
            }

    await db.commit()

    # ── Broadcast to live WebSocket clients (BUG-01 fix) ──────────
    # Fire-and-forget: errors in broadcast must NOT prevent ingestion response.
    try:
        event_type = "alert" if result_data["alert"] else (
            "prediction" if result_data["prediction"] else "flow_ingested"
        )
        await broadcast({
            "type": event_type,
            "session_key": session_key,
            "src_ip": flow.src_ip,
            "dst_ip": flow.dst_ip,
            "direction": direction,
            "source": source,
            "flow_count": session.flow_count,
            "infiltration_prob": (
                result_data["prediction"]["infiltration_probability"]
                if result_data["prediction"] else None
            ),
            "predicted_stage": (
                result_data["prediction"]["predicted_stage"]
                if result_data["prediction"] else None
            ),
            "max_stage_reached": session.max_stage_reached,
            "alert": result_data["alert"],
            "timestamp": now.isoformat(),
        })
    except Exception as exc:
        logger.warning("WebSocket broadcast failed (non-fatal): %s", exc)

    return result_data


def clear_session_buffer(session_key: str):
    """Clear the in-memory buffer for a session."""
    _session_buffers.pop(session_key, None)


def get_buffer_status() -> dict:
    """Return current buffer status for debugging."""
    return {
        key: len(val["flows"]) for key, val in _session_buffers.items()
    }
