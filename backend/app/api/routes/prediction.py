from fastapi import APIRouter, Request

from ...core.config import get_settings
from ...ml.feature_extraction import URLValidationError
from ...schemas.prediction import BatchPredictionResponse, BatchPredictRequest, PredictionResult, PredictRequest
from ...services.prediction_service import PredictionService
from ..errors import APIError

router = APIRouter()


def _service(request: Request) -> PredictionService:
    model = request.app.state.model
    if model is None:
        raise APIError(503, "model_unavailable", "The model is not loaded. Train the model and restart the server.")
    return PredictionService(model)


@router.post("/predict", response_model=PredictionResult)
def predict(body: PredictRequest, request: Request) -> PredictionResult:
    svc = _service(request)
    explain = get_settings().explain_by_default if body.explain is None else body.explain
    try:
        return svc.predict_one(body.url, explain)
    except URLValidationError as exc:
        raise APIError(422, "invalid_url", exc.message, {"reason": exc.code})


@router.post("/predict/batch", response_model=BatchPredictionResponse)
def predict_batch(body: BatchPredictRequest, request: Request) -> BatchPredictionResponse:
    svc = _service(request)
    limit = get_settings().max_batch_size
    if len(body.urls) > limit:
        raise APIError(413, "batch_too_large", f"A batch may contain at most {limit} URLs.", {"limit": limit, "received": len(body.urls)})
    return svc.predict_batch(body.urls, body.explain)
