from fastapi import APIRouter, Request

from ...schemas.analytics import HealthResponse

router = APIRouter()


@router.get("/health", response_model=HealthResponse)
def health(request: Request) -> HealthResponse:
    model = request.app.state.model
    if model is None:
        return HealthResponse(status="degraded", model_loaded=False, detail=request.app.state.model_error)
    return HealthResponse(status="ok", model_loaded=True, model_version=model.version)
