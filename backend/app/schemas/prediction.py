from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

DISCLAIMER = ("Machine learning predictions are estimates, not guarantees. A legitimate-looking URL may still be malicious. "
              "Verify the sender and destination before sharing credentials or sensitive information.")


class PredictRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=4096, description="URL to analyse. It is never visited.")
    explain: bool | None = Field(None, description="Include model explanations (default: server setting).")


class BatchPredictRequest(BaseModel):
    urls: list[str] = Field(..., min_length=1, max_length=1000)
    explain: bool = False


class ExplanationItem(BaseModel):
    feature: str
    label: str
    description: str
    value: float
    contribution: float
    direction: Literal["toward_phishing", "toward_legitimate"]
    training_percentile: float | None = None


class URLParts(BaseModel):
    scheme: str
    subdomain: str
    registered_domain: str
    port: int | None
    path: str
    query: str
    fragment: str
    scheme_assumed: bool


class PredictionResult(BaseModel):
    predicted_class: Literal[0, 1]
    class_name: Literal["phishing", "legitimate"]
    label: str
    phishing_score: float
    threshold: float
    model_version: str
    features: dict[str, float]
    risk_tier: Literal["likely_safe", "suspicious", "likely_phishing"] = "likely_safe"
    threshold_high: float = 0.5
    threshold_low: float = 0.2
    top_reasons: list[str] = []
    domain_reputation: str | None = None
    limitations: list[str] = [
        "Pure URL-only analysis without page content or DNS resolution.",
        "Compromised legitimate domains or novel zero-day attacks may evade detection.",
    ]
    url_parts: URLParts | None = None
    explanation: list[ExplanationItem] | None = None
    explanation_method: str | None = None
    explanation_unit: str | None = None
    notes: list[str] = []
    disclaimer: str = DISCLAIMER


class BatchItemError(BaseModel):
    code: str
    message: str


class BatchItem(BaseModel):
    index: int
    status: Literal["ok", "invalid"]
    predicted_class: Literal[0, 1] | None = None
    class_name: Literal["phishing", "legitimate"] | None = None
    label: str | None = None
    phishing_score: float | None = None
    risk_tier: Literal["likely_safe", "suspicious", "likely_phishing"] | None = None
    threshold_high: float | None = None
    threshold_low: float | None = None
    top_reasons: list[str] = []
    notes: list[str] = []
    error: BatchItemError | None = None
    explanation: list[ExplanationItem] | None = None


class BatchPredictionResponse(BaseModel):
    model_version: str
    threshold: float
    total: int
    ok: int
    invalid: int
    results: list[BatchItem]
    disclaimer: str = DISCLAIMER


class ErrorBody(BaseModel):
    code: str
    message: str
    details: Any | None = None


class ErrorResponse(BaseModel):
    error: ErrorBody
