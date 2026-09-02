"""
Pydantic request/response schemas.
Every endpoint has explicit types — no untyped dicts flying around.
"""
from __future__ import annotations
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, field_validator
from .config import N_FEATURES, WINDOW_SIZE, FLOW_FEATURES, DEFAULT_K_STEPS, DEFAULT_MC_SAMPLES


# ── Flow record (single row of 22 features) ──────────────────────────
class FlowRecord(BaseModel):
    """A single network flow with all 22 CIC-IDS features + optional metadata."""
    flow_duration: float
    tot_fwd_pkts: float
    tot_bwd_pkts: float
    fwd_pkt_len_mean: float
    bwd_pkt_len_mean: float
    flow_bytes_s: float
    flow_pkts_s: float
    flow_iat_mean: float
    flow_iat_std: float
    fwd_iat_mean: float
    bwd_iat_mean: float
    syn_flag_cnt: float
    ack_flag_cnt: float
    fin_flag_cnt: float
    rst_flag_cnt: float
    psh_flag_cnt: float
    urg_flag_cnt: float
    down_up_ratio: float
    pkt_size_avg: float
    ttl_variance: float
    tcp_win_size: float
    retransmit_cnt: float

    # Optional metadata for session grouping
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    timestamp: Optional[datetime] = None

    def to_feature_array(self) -> list[float]:
        """Extract the 22 features in the correct order."""
        return [getattr(self, f) for f in FLOW_FEATURES]


# ── Prediction request/response ──────────────────────────────────────
class PredictRequest(BaseModel):
    """A window of 6 flow records for single-step prediction."""
    window: list[list[float]] = Field(
        ..., description=f"A {WINDOW_SIZE}x{N_FEATURES} matrix of feature values"
    )
    needs_scaling: bool = Field(
        default=False, description="Whether raw features should be scaled before inference"
    )

    @field_validator("window")
    @classmethod
    def validate_window(cls, v):
        if len(v) != WINDOW_SIZE:
            raise ValueError(f"Window must have exactly {WINDOW_SIZE} rows, got {len(v)}")
        for i, row in enumerate(v):
            if len(row) != N_FEATURES:
                raise ValueError(
                    f"Row {i} has {len(row)} features, expected {N_FEATURES}"
                )
            for j, val in enumerate(row):
                if not isinstance(val, (int, float)):
                    raise ValueError(f"Row {i}, feature {j} is not numeric: {val}")
        return v


class PredictResponse(BaseModel):
    infiltration_probability: float = Field(..., ge=0.0, le=1.0)
    predicted_stage: str
    predicted_stage_id: int
    is_alert: bool
    threshold: float


# ── Forecast request/response ────────────────────────────────────────
class ForecastRequest(BaseModel):
    window: list[list[float]]
    k_steps: int = Field(default=DEFAULT_K_STEPS, ge=1, le=20)
    n_mc_samples: int = Field(default=DEFAULT_MC_SAMPLES, ge=1, le=100)
    needs_scaling: bool = Field(
        default=False, description="Whether raw features should be scaled before inference"
    )

    @field_validator("window")
    @classmethod
    def validate_window(cls, v):
        if len(v) != WINDOW_SIZE:
            raise ValueError(f"Window must have exactly {WINDOW_SIZE} rows, got {len(v)}")
        for i, row in enumerate(v):
            if len(row) != N_FEATURES:
                raise ValueError(f"Row {i} has {len(row)} features, expected {N_FEATURES}")
        return v


class ForecastStep(BaseModel):
    step: int
    infiltration_prob_mean: float
    infiltration_prob_std: float
    infiltration_prob_ema: float
    predicted_stage: str


class ForecastResponse(BaseModel):
    steps: list[ForecastStep]
    threshold: float
    alert_triggered: bool
    alert_at_step: Optional[int] = None


# ── Explain request/response ─────────────────────────────────────────
class ExplainRequest(BaseModel):
    window: list[list[float]]
    top_k: int = Field(default=10, ge=1, le=22)
    needs_scaling: bool = Field(
        default=False, description="Whether raw features should be scaled before inference"
    )

    @field_validator("window")
    @classmethod
    def validate_window(cls, v):
        if len(v) != WINDOW_SIZE:
            raise ValueError(f"Window must have exactly {WINDOW_SIZE} rows, got {len(v)}")
        for i, row in enumerate(v):
            if len(row) != N_FEATURES:
                raise ValueError(f"Row {i} has {len(row)} features, expected {N_FEATURES}")
        return v


class FeatureAttribution(BaseModel):
    feature: str
    importance: float
    direction: str  # "malicious" or "benign"


class ExplainResponse(BaseModel):
    attributions: list[FeatureAttribution]
    infiltration_probability: float
    predicted_stage: str


# ── Alert models ─────────────────────────────────────────────────────
class AlertOut(BaseModel):
    id: int
    session_key: str
    severity: str  # "critical", "high", "medium", "low"
    infiltration_prob: float
    predicted_stage: str
    recommended_action: str
    created_at: datetime
    acknowledged: bool

    class Config:
        from_attributes = True


# ── Ingest response ──────────────────────────────────────────────────
class IngestResponse(BaseModel):
    flows_accepted: int
    flows_rejected: int
    errors: list[str]
    alerts_generated: int


# ── Health check ─────────────────────────────────────────────────────
class HealthResponse(BaseModel):
    status: str  # "ok" or "degraded"
    model_loaded: bool
    db_connected: bool
    artifacts_path: str
    features_count: int
    stages: list[str]
    device: str


# ── WebSocket messages ───────────────────────────────────────────────
class LiveFlowEvent(BaseModel):
    event_type: str  # "flow_ingested", "prediction", "alert"
    session_key: str
    data: dict
    timestamp: datetime
