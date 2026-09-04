"""
Configuration and settings for the backend service.
All paths, constants, and tunable parameters live here.
"""
import os
from pathlib import Path

# ── Paths ──────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent
ARTIFACTS_DIR = Path(os.environ.get("ARTIFACTS_DIR", BASE_DIR / "artifacts"))
DB_DIR = Path(os.environ.get("DB_DIR", BASE_DIR / "data"))

MODEL_PATH = ARTIFACTS_DIR / "world_model.pt"
SCALER_PATH = ARTIFACTS_DIR / "scaler.pkl"
CONFIG_PATH = ARTIFACTS_DIR / "config.json"
DATABASE_URL = f"sqlite+aiosqlite:///{DB_DIR / 'forecaster.db'}"

# ── Model constants (must match config.json / pipeline_fixed.py) ──────
WINDOW_SIZE = 6
N_FEATURES = 22
HIDDEN_SIZE = 64
N_STAGES = 6
STAGES = [
    "Benign", "Reconnaissance", "Initial Access",
    "Lateral Movement", "C2", "Exfiltration",
]
STAGE2ID = {s: i for i, s in enumerate(STAGES)}

FLOW_FEATURES = [
    "flow_duration", "tot_fwd_pkts", "tot_bwd_pkts", "fwd_pkt_len_mean",
    "bwd_pkt_len_mean", "flow_bytes_s", "flow_pkts_s", "flow_iat_mean",
    "flow_iat_std", "fwd_iat_mean", "bwd_iat_mean", "syn_flag_cnt",
    "ack_flag_cnt", "fin_flag_cnt", "rst_flag_cnt", "psh_flag_cnt",
    "urg_flag_cnt", "down_up_ratio", "pkt_size_avg", "ttl_variance",
    "tcp_win_size", "retransmit_cnt",
]

# ── Inference defaults ────────────────────────────────────────────────
DEFAULT_THRESHOLD = float(os.environ.get("ALERT_THRESHOLD", "0.5"))
DEFAULT_K_STEPS = 6
DEFAULT_MC_SAMPLES = 20
DEFAULT_MC_NOISE_STD = 0.05
EMA_ALPHA = 0.4

# ── CORS (Vercel frontend + local dev) ────────────────────────────────
# BUG-05 fix: parse FRONTEND_URL as a comma-separated list so multiple
# Vercel preview URLs (or a staging + prod URL) can be allowed without
# redeploying the backend. Set in Render dashboard or render.yaml envVars.
_extra_origins = [
    url.strip()
    for url in os.environ.get("FRONTEND_URL", "").split(",")
    if url.strip()
]
ALLOWED_ORIGINS = list({
    "http://localhost:5173",
    "http://localhost:3000",
    "http://127.0.0.1:5173",
    *_extra_origins,
})

# ── Session grouping ──────────────────────────────────────────────────
SESSION_TIME_BUCKET_SECONDS = 300  # 5 minutes
