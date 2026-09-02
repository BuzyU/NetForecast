"""POST /forecast — k-step Monte Carlo rollout with EMA smoothing."""
from fastapi import APIRouter, HTTPException
import numpy as np

from ..schemas import ForecastRequest, ForecastResponse, ForecastStep
from ..inference import forecast_rollout
from ..model_loader import artifacts

router = APIRouter()


@router.post("/forecast", response_model=ForecastResponse)
async def forecast(req: ForecastRequest):
    try:
        window = np.array(req.window, dtype=np.float32)
        if req.needs_scaling:
            window = artifacts.scale_features(window)
        result = forecast_rollout(
            window,
            k_steps=req.k_steps,
            n_mc_samples=req.n_mc_samples,
        )
        return ForecastResponse(
            steps=[ForecastStep(**s) for s in result["steps"]],
            threshold=result["threshold"],
            alert_triggered=result["alert_triggered"],
            alert_at_step=result["alert_at_step"],
        )
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
