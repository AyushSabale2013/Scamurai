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
    if p.is_ip_host:
        sub = ""
        reg = p.host
    else:
        reg = p.registrable
        sub = p.subdomain
    return URLParts(
        scheme=p.scheme,
        subdomain=sub,
        registered_domain=reg,
        port=p.port,
        path=p.path,
        query=p.query,
        fragment=p.fragment,
        scheme_assumed=not p.has_explicit_scheme,
    )


REPUTATION_LABELS = {
    4.0: "Top 1,000 Global Domain (High Authority)",
    3.0: "Top 10,000 Global Domain (Well Known)",
    2.0: "Top 100,000 Global Domain (Established)",
    1.0: "Top 1 Million Domain (Standard)",
    0.0: "Unranked / Low Traffic Domain",
}


def _get_risk_tier(score: float, t_high: float, t_low: float) -> tuple[str, str, int, str]:
    if score >= t_high:
        return "likely_phishing", "Potential Phishing (High Risk)", PHISHING, "phishing"
    elif score >= t_low:
        return "suspicious", "Suspicious URL (Review Advised)", PHISHING, "phishing"
    return "likely_safe", "Likely Legitimate", LEGITIMATE, "legitimate"


def _extract_top_reasons(feats: dict[str, float], tier: str, score: float) -> list[str]:
    reasons: list[str] = []
    if feats.get("is_ip_host", 0) > 0:
        reasons.append("Raw IP address used instead of a registered domain name")
    if feats.get("brand_in_subdomain", 0) > 0:
        reasons.append("Target brand name detected inside a subdomain on an unrelated domain")
    if feats.get("brand_in_path", 0) > 0:
        reasons.append("Brand name impersonated in URL path on a non-authentic domain")
    if feats.get("brand_typosquatting", 0) > 0:
        reasons.append("Domain name appears to typosquat or visually mimic a trusted brand")
    if feats.get("brand_keyword_combo", 0) > 0:
        reasons.append("Brand name combined with sensitive authentication or security keywords")
    if feats.get("is_risky_tld", 0) > 0:
        reasons.append("High-risk top-level domain frequently abused in malicious campaigns")
    if feats.get("is_punycode", 0) > 0:
        reasons.append("Internationalized Domain Name (Punycode / homograph spoofing risk)")
    if feats.get("is_url_shortener", 0) > 0:
        reasons.append("URL shortener conceals the real destination host and path")
    if feats.get("has_embedded_url", 0) > 0:
        reasons.append("Contains an embedded redirection URL parameter (possible open redirect)")
    if feats.get("is_user_content_platform", 0) > 0 and score >= 0.2:
        reasons.append("Hosted on a free user-generated content platform commonly abused by phishers")
    if feats.get("has_userinfo", 0) > 0:
        reasons.append("URL contains embedded username credentials (RFC 3986 userinfo evasion)")
    if feats.get("is_nonstandard_port", 0) > 0:
        reasons.append("Uses non-standard network port (outside standard 80 / 443)")

    if not reasons:
        if tier == "likely_safe":
            reasons.append("No strong phishing signals detected. Clean domain reputation and standard URL structure.")
        elif tier == "suspicious":
            reasons.append("Unranked domain with atypical URL structural attributes; caution advised.")
        else:
            reasons.append("Multiple statistical anomaly signals detected by machine learning model.")
    return reasons[:4]


class PredictionService:
    def __init__(self, model: LoadedModel):
        self.model = model

    def _score(self, rows: list[dict[str, float]]):
        X = pd.DataFrame(rows, columns=FEATURE_NAMES, dtype="float64")
        return X, phishing_scores(self.model.pipeline, X)

    def _explain(self, X: pd.DataFrame, rows: list[dict[str, float]]) -> list[list[ExplanationItem] | None]:
        ex = self.model.explainer
        if ex is None or getattr(ex, "kind", None) == "unavailable":
            return [None] * len(rows)
        try:
            contrib = ex.contributions(X)
            q = self.model.metadata.get("feature_quantiles")
            return [[ExplanationItem(**i) for i in build_explanation(r, contrib[k], q)] for k, r in enumerate(rows)]
        except Exception:
            return [None] * len(rows)

    def predict_one(self, url: str, explain: bool) -> PredictionResult:
        parsed = parse_url(url)  # raises URLValidationError
        feats = extract_features_from_parsed(parsed)
        X, scores = self._score([feats])
        score = float(scores[0])
        t_high = self.model.threshold
        t_low = self.model.threshold_low
        tier, label_text, cls, cls_name = _get_risk_tier(score, t_high, t_low)
        explanation = self._explain(X, [feats])[0] if explain else None
        top_reasons = _extract_top_reasons(feats, tier, score)
        rep_bucket = feats.get("tranco_rank_bucket", 0.0)
        domain_rep = REPUTATION_LABELS.get(rep_bucket, "Unranked Domain")
        notes = ["No scheme given; 'http' was assumed."] if not parsed.has_explicit_scheme else []

        ex = self.model.explainer
        if explain:
            if ex is not None and getattr(ex, "kind", None) != "unavailable" and explanation is not None:
                exp_method: str | None = ex.method_label
                exp_unit: str | None = ex.unit
            else:
                exp_method = "unavailable"
                exp_unit = None
        else:
            exp_method = None
            exp_unit = None

        return PredictionResult(
            predicted_class=cls,
            class_name=cls_name,
            label=label_text,
            phishing_score=round(score, 4),
            threshold=t_high,
            threshold_high=t_high,
            threshold_low=t_low,
            risk_tier=tier,
            top_reasons=top_reasons,
            domain_reputation=domain_rep,
            model_version=self.model.version,
            features=feats,
            url_parts=_parts(parsed),
            explanation=explanation,
            explanation_method=exp_method,
            explanation_unit=exp_unit,
            notes=notes,
        )

    def predict_batch(self, urls: list[str], explain: bool) -> BatchPredictionResponse:
        items: dict[int, BatchItem] = {}
        ok_idx, rows, notes = [], [], []
        t_high = self.model.threshold
        t_low = self.model.threshold_low

        for i, u in enumerate(urls):
            try:
                p = parse_url(u)
                rows.append(extract_features_from_parsed(p))
                ok_idx.append(i)
                notes.append(["No scheme given; 'http' was assumed."] if not p.has_explicit_scheme else [])
            except URLValidationError as exc:
                items[i] = BatchItem(index=i, status="invalid", error=BatchItemError(code=exc.code, message=exc.message))

        if rows:
            X, scores = self._score(rows)
            expl = self._explain(X, rows) if explain else [None] * len(rows)
            for k, i in enumerate(ok_idx):
                s = float(scores[k])
                f = rows[k]
                tier, label_text, cls, cls_name = _get_risk_tier(s, t_high, t_low)
                reasons = _extract_top_reasons(f, tier, s)
                items[i] = BatchItem(
                    index=i,
                    status="ok",
                    predicted_class=cls,
                    class_name=cls_name,
                    label=label_text,
                    phishing_score=round(s, 4),
                    risk_tier=tier,
                    threshold_high=t_high,
                    threshold_low=t_low,
                    top_reasons=reasons,
                    notes=notes[k],
                    explanation=expl[k],
                )

        ordered = [items[i] for i in range(len(urls))]
        return BatchPredictionResponse(
            model_version=self.model.version,
            threshold=t_high,
            total=len(urls),
            ok=len(ok_idx),
            invalid=len(urls) - len(ok_idx),
            results=ordered,
        )
