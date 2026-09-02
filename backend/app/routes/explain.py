"""POST /explain — feature attribution for a prediction window."""
from fastapi import APIRouter, HTTPException
import numpy as np

from ..schemas import ExplainRequest, ExplainResponse, FeatureAttribution
from ..inference import explain_window
from ..model_loader import artifacts

router = APIRouter()


@router.post("/explain", response_model=ExplainResponse)
async def explain(req: ExplainRequest):
    try:
        window = np.array(req.window, dtype=np.float32)
        if req.needs_scaling:
            window = artifacts.scale_features(window)
        result = explain_window(window, top_k=req.top_k)
        return ExplainResponse(
            attributions=[FeatureAttribution(**a) for a in result["attributions"]],
            infiltration_probability=result["infiltration_probability"],
            predicted_stage=result["predicted_stage"],
        )
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
