"""Prediction logic. Uses the SAME extractor and scoring helper as training.

No network access happens here: the submitted URL is only parsed as a string.
"""

from __future__ import annotations

import pandas as pd

from ..ml.evaluation import CLASS_NAMES, LEGITIMATE, PHISHING, phishing_scores
from ..ml.explainability import build_explanation
from ..ml.feature_extraction import (
    FEATURE_NAMES, ParsedURL, URLValidationError, extract_features_from_parsed, parse_url,
)
from ..ml.model_loader import LoadedModel
from ..schemas.prediction import (
    BatchItem, BatchItemError, BatchPredictionResponse, ExplanationItem, PredictionResult, URLParts,
)

LABELS = {PHISHING: "Potential phishing URL", LEGITIMATE: "Likely legitimate URL"}


def _parts(p: ParsedURL) -> URLParts:
    if p.is_ip:
        sub = ""
        reg = p.host
    else:
        reg = p.registrable
        sub = p.host[: -len(reg)].rstrip(".") if p.host.endswith(reg) else ""
    return URLParts(scheme=p.scheme, subdomain=sub, registered_domain=reg, port=p.port, path=p.path,
                    query=p.query, fragment=p.fragment, scheme_assumed=p.normalized.scheme_assumed)


class PredictionService:
    def __init__(self, model: LoadedModel):
        self.model = model

    def _score(self, rows: list[dict[str, float]]):
        X = pd.DataFrame(rows, columns=FEATURE_NAMES, dtype="float64")
        return X, phishing_scores(self.model.pipeline, X)

    def _classify(self, score: float) -> int:
        return PHISHING if score >= self.model.threshold else LEGITIMATE

    def _explain(self, X: pd.DataFrame, rows: list[dict[str, float]]) -> list[list[ExplanationItem] | None]:
        ex = self.model.explainer
        if ex is None:
            return [None] * len(rows)
        contrib = ex.contributions(X)
        q = self.model.metadata.get("feature_quantiles")
        return [[ExplanationItem(**i) for i in build_explanation(r, contrib[k], q)] for k, r in enumerate(rows)]

    def predict_one(self, url: str, explain: bool) -> PredictionResult:
        parsed = parse_url(url)  # raises URLValidationError
        feats = extract_features_from_parsed(parsed)
        X, scores = self._score([feats])
        score = float(scores[0])
        cls = self._classify(score)
        explanation = self._explain(X, [feats])[0] if explain else None
        return PredictionResult(
            predicted_class=cls, class_name=CLASS_NAMES[cls], label=LABELS[cls], phishing_score=score,
            threshold=self.model.threshold, model_version=self.model.version, features=feats, url_parts=_parts(parsed),
            explanation=explanation,
            explanation_method=self.model.explainer.method_label if (explain and self.model.explainer) else None,
            explanation_unit=self.model.explainer.unit if (explain and self.model.explainer) else None,
            notes=list(parsed.normalized.notes),
        )

    def predict_batch(self, urls: list[str], explain: bool) -> BatchPredictionResponse:
        items: dict[int, BatchItem] = {}
        ok_idx, rows, notes = [], [], []
        for i, u in enumerate(urls):
            try:
                p = parse_url(u)
                rows.append(extract_features_from_parsed(p))
                ok_idx.append(i)
                notes.append(list(p.normalized.notes))
            except URLValidationError as exc:
                items[i] = BatchItem(index=i, status="invalid", error=BatchItemError(code=exc.code, message=exc.message))
        if rows:
            X, scores = self._score(rows)
            expl = self._explain(X, rows) if explain else [None] * len(rows)
            for k, i in enumerate(ok_idx):
                s = float(scores[k])
                c = self._classify(s)
                items[i] = BatchItem(index=i, status="ok", predicted_class=c, class_name=CLASS_NAMES[c], label=LABELS[c],
                                     phishing_score=s, notes=notes[k], explanation=expl[k])
        ordered = [items[i] for i in range(len(urls))]
        return BatchPredictionResponse(model_version=self.model.version, threshold=self.model.threshold, total=len(urls),
                                       ok=len(ok_idx), invalid=len(urls) - len(ok_idx), results=ordered)
