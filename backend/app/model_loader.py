"""
Model loader — loads world_model.pt, scaler.pkl, config.json at startup.
Fails loudly if anything is wrong. No silent fallbacks.
"""
import json
import pickle
import logging
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn

from .config import (
    MODEL_PATH, SCALER_PATH, CONFIG_PATH,
    N_FEATURES, HIDDEN_SIZE, N_STAGES, STAGES, FLOW_FEATURES, WINDOW_SIZE,
)

logger = logging.getLogger(__name__)


# ── WorldModel architecture (exact copy from pipeline_fixed.py) ───────
class WorldModel(nn.Module):
    def __init__(self, n_features: int = N_FEATURES, hidden: int = HIDDEN_SIZE,
                 n_stages: int = N_STAGES):
        super().__init__()
        self.lstm = nn.LSTM(n_features, hidden, batch_first=True)
        self.next_state_head = nn.Linear(hidden, n_features)
        self.infiltration_head = nn.Sequential(
            nn.Linear(hidden, 32), nn.ReLU(), nn.Linear(32, 1)
        )
        self.stage_head = nn.Linear(hidden, n_stages)

    def forward(self, x: torch.Tensor):
        out, (h_n, _) = self.lstm(x)
        h = h_n[-1]
        next_state = self.next_state_head(h)
        infiltration_logit = self.infiltration_head(h).squeeze(-1)
        stage_logits = self.stage_head(h)
        return next_state, infiltration_logit, stage_logits


class ModelArtifacts:
    """Container for all loaded artifacts. Validates shapes on load."""

    def __init__(self):
        self.model: WorldModel | None = None
        self.scaler = None
        self.config: dict | None = None
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self._loaded = False

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    def load(self) -> None:
        """Load all artifacts. Raises on any failure — never returns a half-loaded state."""
        logger.info("Loading model artifacts...")

        # ── config.json ───────────────────────────────────────────────
        if not CONFIG_PATH.exists():
            raise FileNotFoundError(f"config.json not found at {CONFIG_PATH}")
        with open(CONFIG_PATH) as f:
            self.config = json.load(f)

        cfg_features = self.config.get("features", [])
        cfg_stages = self.config.get("stages", [])
        cfg_window = self.config.get("window")

        if len(cfg_features) != N_FEATURES:
            raise ValueError(
                f"config.json has {len(cfg_features)} features, expected {N_FEATURES}. "
                f"Missing: {set(FLOW_FEATURES) - set(cfg_features)}"
            )
        if cfg_features != FLOW_FEATURES:
            raise ValueError(
                f"config.json feature order doesn't match expected order. "
                f"Got: {cfg_features[:5]}... Expected: {FLOW_FEATURES[:5]}..."
            )
        if len(cfg_stages) != N_STAGES:
            raise ValueError(f"config.json has {len(cfg_stages)} stages, expected {N_STAGES}")
        if cfg_window != WINDOW_SIZE:
            raise ValueError(f"config.json window={cfg_window}, expected {WINDOW_SIZE}")

        logger.info("  config.json: OK (%d features, %d stages, window=%d)",
                     len(cfg_features), len(cfg_stages), cfg_window)

        # ── scaler.pkl ────────────────────────────────────────────────
        if not SCALER_PATH.exists():
            raise FileNotFoundError(f"scaler.pkl not found at {SCALER_PATH}")
        with open(SCALER_PATH, "rb") as f:
            self.scaler = pickle.load(f)

        if hasattr(self.scaler, "n_features_in_"):
            if self.scaler.n_features_in_ != N_FEATURES:
                raise ValueError(
                    f"scaler.pkl fitted on {self.scaler.n_features_in_} features, "
                    f"expected {N_FEATURES}"
                )
        logger.info("  scaler.pkl: OK (n_features=%d)", N_FEATURES)

        # ── world_model.pt ────────────────────────────────────────────
        if not MODEL_PATH.exists():
            raise FileNotFoundError(f"world_model.pt not found at {MODEL_PATH}")

        self.model = WorldModel(
            n_features=N_FEATURES, hidden=HIDDEN_SIZE, n_stages=N_STAGES
        )
        state_dict = torch.load(MODEL_PATH, map_location=self.device, weights_only=True)
        self.model.load_state_dict(state_dict)
        self.model.to(self.device)
        self.model.eval()

        # ── Shape validation: run a dummy forward pass ────────────────
        dummy = torch.randn(1, WINDOW_SIZE, N_FEATURES, device=self.device)
        with torch.no_grad():
            next_state, inf_logit, stage_logits = self.model(dummy)

        assert next_state.shape == (1, N_FEATURES), \
            f"next_state head shape {next_state.shape}, expected (1, {N_FEATURES})"
        assert inf_logit.shape == (1,), \
            f"infiltration head shape {inf_logit.shape}, expected (1,)"
        assert stage_logits.shape == (1, N_STAGES), \
            f"stage head shape {stage_logits.shape}, expected (1, {N_STAGES})"

        logger.info("  world_model.pt: OK (dummy forward pass validated)")
        self._loaded = True
        logger.info("All artifacts loaded successfully on device=%s", self.device)

    def scale_features(self, raw_features: np.ndarray) -> np.ndarray:
        """Scale raw features using the loaded scaler. Input: (n_samples, 22)."""
        if not self._loaded:
            raise RuntimeError("Artifacts not loaded — call load() first")
        return self.scaler.transform(raw_features)


# ── Singleton ─────────────────────────────────────────────────────────
artifacts = ModelArtifacts()
