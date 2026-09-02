"""POST /predict — single-step prediction from a pre-scaled window."""
from fastapi import APIRouter, HTTPException
import numpy as np

from ..schemas import PredictRequest, PredictResponse
from ..inference import predict_single
from ..model_loader import artifacts

router = APIRouter()


@router.post("/predict", response_model=PredictResponse)
async def predict(req: PredictRequest):
    try:
        window = np.array(req.window, dtype=np.float32)
        if req.needs_scaling:
            window = artifacts.scale_features(window)
        result = predict_single(window)
        return PredictResponse(**result)
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
