from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    model_version: str | None = None
    detail: str | None = None


class ModelInfoResponse(BaseModel):
    model_name: str
    model_display_name: str
    model_version: str
    trained_at: str
    feature_count: int
    feature_names: list[str]
    feature_definitions: dict[str, dict[str, str]]
    decision_threshold: float
    threshold_selection: dict[str, Any]
    class_mapping: dict[str, str]
    score_definition: str
    explanation_method: str
    hyperparameters: dict[str, Any]
    preprocessing: dict[str, Any]
    dataset: dict[str, Any]
    dependencies: dict[str, str]
    headline_metrics: dict[str, Any] | None = None
