from fastapi import APIRouter

from ...core.config import get_settings
from ...services import analytics_service as an
from ..errors import APIError

router = APIRouter()


def _guard(fn):
    try:
        return fn()
    except an.ReportUnavailableError as exc:
        raise APIError(503, "report_unavailable", str(exc))


@router.get("/analytics/summary")
def analytics_summary() -> dict:
    return _guard(lambda: an.summary(get_settings().artifact_dir))


@router.get("/model-metrics")
def model_metrics() -> dict:
    """Full saved evaluation report (metrics, curves, feature importance, error analysis)."""
    return _guard(lambda: an.load_report(get_settings().artifact_dir))
