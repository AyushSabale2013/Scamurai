"""Per-prediction explanations computed from the real trained model.

* Tree models (XGBoost / Random Forest): SHAP ``TreeExplainer`` values.
* Logistic Regression: exact additive contributions ``coef * standardised value``.

All contributions are expressed **toward phishing**: positive pushes the score
up, negative pushes it toward "legitimate". They describe how the model reached
its score; they are not evidence that a URL is malicious.
"""

from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd

from .evaluation import PHISHING
from .feature_extraction import FEATURE_DEFINITIONS, FEATURE_NAMES


class ModelExplainer:
    def __init__(self, pipeline: Any):
        self.pipeline = pipeline
        self.clf = pipeline.steps[-1][1]
        self.classes = list(pipeline.classes_)
        self.phish_idx = self.classes.index(PHISHING)
        name = type(self.clf).__name__
        self.scaler = pipeline.named_steps.get("scaler") if hasattr(pipeline, "named_steps") else None
        if name == "LogisticRegression":
            self.kind, self.unit = "linear_contributions", "log-odds"
            self._explainer = None
        else:
            import shap  # imported lazily: only needed for tree models

            self._explainer = shap.TreeExplainer(self.clf)
            self.kind = "shap_tree"
            self.unit = "log-odds" if name == "XGBClassifier" else "probability"

    @property
    def method_label(self) -> str:
        return "SHAP TreeExplainer" if self.kind == "shap_tree" else "Logistic regression coefficient contributions"

    def contributions(self, X: pd.DataFrame) -> np.ndarray:
        """(n_rows, n_features) contributions toward the phishing class."""
        if self.kind == "linear_contributions":
            Z = self.scaler.transform(X) if self.scaler is not None else X.to_numpy()
            toward_class1 = Z * self.clf.coef_[0]
            sign = 1.0 if self.classes[1] == PHISHING else -1.0
            return toward_class1 * sign
        vals = self._explainer.shap_values(X)
        if isinstance(vals, list):  # older shap: one array per class
            return np.asarray(vals[self.phish_idx])
        vals = np.asarray(vals)
        if vals.ndim == 3:  # (n, features, classes)
            return vals[:, :, self.phish_idx]
        sign = 1.0 if self.classes[1] == PHISHING else -1.0  # binary margin refers to classes_[1]
        return vals * sign


def percentile_rank(value: float, quantile_grid: list[float]) -> float:
    """Mid-rank percentile (0-100) of ``value`` within a stored 101-point quantile grid."""
    q = np.asarray(quantile_grid)
    lo = np.searchsorted(q, value, side="left")
    hi = np.searchsorted(q, value, side="right")
    return float(np.clip((lo + hi) / 2 - 0.5, 0, 100))


def build_explanation(
    features: dict[str, float],
    contributions: np.ndarray,
    quantiles: dict[str, list[float]] | None,
    top_k: int = 6,
    min_abs: float = 1e-9,
) -> list[dict[str, Any]]:
    """Strongest feature contributions for one URL, with training-set context."""
    order = np.argsort(-np.abs(contributions))
    items: list[dict[str, Any]] = []
    for i in order:
        c = float(contributions[i])
        if abs(c) <= min_abs:
            continue
        name = FEATURE_NAMES[i]
        value = float(features[name])
        item: dict[str, Any] = {
            "feature": name,
            "label": FEATURE_DEFINITIONS[name].label,
            "description": FEATURE_DEFINITIONS[name].description,
            "value": value,
            "contribution": c,
            "direction": "toward_phishing" if c > 0 else "toward_legitimate",
        }
        if quantiles and name in quantiles:
            item["training_percentile"] = round(percentile_rank(value, quantiles[name]), 1)
        items.append(item)
        if len(items) >= top_k:
            break
    return items
