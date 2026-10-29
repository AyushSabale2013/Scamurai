from fastapi import APIRouter, Request

from ...core.config import get_settings
from ...schemas.analytics import ModelInfoResponse
from ...services import analytics_service as an
from ..errors import APIError

router = APIRouter()


@router.get("/model-info", response_model=ModelInfoResponse)
def model_info(request: Request) -> ModelInfoResponse:
    model = request.app.state.model
    if model is None:
        raise APIError(503, "model_unavailable", "The model is not loaded.")
    m = model.metadata
    try:
        head = an.headline(an.load_report(get_settings().artifact_dir))
    except an.ReportUnavailableError:
        head = None
    return ModelInfoResponse(
        model_name=m["model_name"], model_display_name=m["model_display_name"], model_version=m["model_version"], trained_at=m["trained_at"],
        feature_count=m["feature_count"], feature_names=m["feature_names"], feature_definitions=m["feature_definitions"],
        decision_threshold=m["decision_threshold"], threshold_selection=m["threshold_selection"], class_mapping=m["class_mapping"],
        score_definition=m["score_definition"], explanation_method=m["explanation_method"], hyperparameters=m["hyperparameters"],
        preprocessing=m["preprocessing"], dataset=m["dataset"], dependencies=m["dependencies"], headline_metrics=head)
