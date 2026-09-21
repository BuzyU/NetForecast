"""POST /explain — feature attribution for a prediction window."""
import numpy as np
from fastapi import APIRouter, HTTPException

from ..inference import explain_window, explain_window_shap
from ..model_loader import artifacts
from ..schemas import ExplainRequest, ExplainResponse, FeatureAttribution

router = APIRouter()


@router.post("/explain", response_model=ExplainResponse)
async def explain(req: ExplainRequest):
    try:
        window = np.array(req.window, dtype=np.float32)
        if req.needs_scaling:
            window = artifacts.scale_features(window)

        if req.method.lower() == "gradient":
            result = explain_window(window, top_k=req.top_k)
            method_used = "gradient"
        else:
            result = explain_window_shap(window, top_k=req.top_k)
            method_used = result.get("method_used", "shap")

        return ExplainResponse(
            attributions=[FeatureAttribution(**a) for a in result["attributions"]],
            infiltration_probability=result["infiltration_probability"],
            predicted_stage=result["predicted_stage"],
            method_used=method_used,
        )
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
