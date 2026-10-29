"""Metric, threshold and scoring helpers.

Convention used everywhere: dataset labels are ``0 = phishing`` and
``1 = legitimate``. The *positive class for evaluation is phishing* and the
"phishing score" is ``P(class == 0)``.
"""

from __future__ import annotations

import time
from typing import Any

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score, average_precision_score, brier_score_loss, classification_report,
    confusion_matrix, f1_score, precision_recall_curve, precision_recall_fscore_support,
    roc_auc_score, roc_curve,
)

PHISHING = 0
LEGITIMATE = 1
CLASS_NAMES = {PHISHING: "phishing", LEGITIMATE: "legitimate"}


def phishing_scores(model: Any, X: pd.DataFrame) -> np.ndarray:
    """P(phishing) for every row, using the model's own class ordering."""
    classes = list(model.classes_)
    if PHISHING not in classes:
        raise ValueError(f"Model classes {classes} do not include the phishing class 0.")
    return model.predict_proba(X)[:, classes.index(PHISHING)]


def predict_from_scores(scores: np.ndarray, threshold: float) -> np.ndarray:
    """Score >= threshold -> 0 (phishing) else 1 (legitimate)."""
    return np.where(scores >= threshold, PHISHING, LEGITIMATE)


def tune_threshold(y_true: np.ndarray, scores: np.ndarray, beta: float = 2.0) -> dict[str, float]:
    """Pick the threshold that maximises F-beta for phishing on VALIDATION data.

    beta=2 weights phishing recall four times as much as precision, matching the
    project priority (missed phishing is costlier than a false alarm) while
    still penalising false alarms.
    """
    y_phish = (np.asarray(y_true) == PHISHING).astype(int)
    prec, rec, thr = precision_recall_curve(y_phish, scores)
    prec, rec = prec[:-1], rec[:-1]
    denom = (beta**2) * prec + rec
    fbeta = np.divide((1 + beta**2) * prec * rec, denom, out=np.zeros_like(denom), where=denom > 0)
    i = int(np.argmax(fbeta))
    return {"threshold": float(thr[i]), "val_precision": float(prec[i]), "val_recall": float(rec[i]),
            "val_fbeta": float(fbeta[i]), "beta": beta}


def expected_calibration_error(y_phish: np.ndarray, scores: np.ndarray, bins: int = 10) -> float:
    edges = np.linspace(0, 1, bins + 1)
    idx = np.clip(np.digitize(scores, edges[1:-1]), 0, bins - 1)
    ece = 0.0
    for b in range(bins):
        m = idx == b
        if m.any():
            ece += m.mean() * abs(y_phish[m].mean() - scores[m].mean())
    return float(ece)


def _thin(a: np.ndarray, k: int = 200) -> np.ndarray:
    if len(a) <= k:
        return a
    return a[np.unique(np.linspace(0, len(a) - 1, k).astype(int))]


def compute_metrics(y_true: np.ndarray, scores: np.ndarray, threshold: float, with_curves: bool = False) -> dict[str, Any]:
    y_true = np.asarray(y_true)
    y_pred = predict_from_scores(scores, threshold)
    y_phish = (y_true == PHISHING).astype(int)
    p, r, f, s = precision_recall_fscore_support(y_true, y_pred, labels=[PHISHING, LEGITIMATE], zero_division=0)
    cm = confusion_matrix(y_true, y_pred, labels=[PHISHING, LEGITIMATE])
    tn_leg, fp_leg = int(cm[1, 1]), int(cm[1, 0])  # legit predicted legit / legit predicted phishing
    fn_ph, tp_ph = int(cm[0, 1]), int(cm[0, 0])
    single_class = len(np.unique(y_phish)) < 2
    out: dict[str, Any] = {
        "n": int(len(y_true)),
        "threshold": float(threshold),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "per_class": {
            "phishing": {"precision": float(p[0]), "recall": float(r[0]), "f1": float(f[0]), "support": int(s[0])},
            "legitimate": {"precision": float(p[1]), "recall": float(r[1]), "f1": float(f[1]), "support": int(s[1])},
        },
        "macro_f1": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
        "weighted_f1": float(f1_score(y_true, y_pred, average="weighted", zero_division=0)),
        "roc_auc": None if single_class else float(roc_auc_score(y_phish, scores)),
        "pr_auc_phishing": None if single_class else float(average_precision_score(y_phish, scores)),
        "brier_score": float(brier_score_loss(y_phish, scores)),
        "expected_calibration_error": expected_calibration_error(y_phish, scores),
        "confusion_matrix": {
            "labels": ["phishing", "legitimate"],
            "matrix": cm.tolist(),
            "phishing_false_negative_rate": float(fn_ph / max(fn_ph + tp_ph, 1)),
            "legitimate_false_positive_rate": float(fp_leg / max(fp_leg + tn_leg, 1)),
        },
        "classification_report": classification_report(
            y_true, y_pred, labels=[PHISHING, LEGITIMATE], target_names=["phishing", "legitimate"],
            output_dict=True, zero_division=0,
        ),
    }
    if with_curves and not single_class:
        fpr, tpr, _ = roc_curve(y_phish, scores)
        pr, rc, _ = precision_recall_curve(y_phish, scores)
        ri = np.unique(np.linspace(0, len(fpr) - 1, min(200, len(fpr))).astype(int))
        pi = np.unique(np.linspace(0, len(pr) - 1, min(200, len(pr))).astype(int))
        out["roc_curve"] = {"fpr": fpr[ri].round(6).tolist(), "tpr": tpr[ri].round(6).tolist()}
        out["pr_curve"] = {"recall": rc[pi].round(6).tolist(), "precision": pr[pi].round(6).tolist()}
    return out


def measure_latency(model: Any, X: pd.DataFrame, repeats: int = 200) -> dict[str, float]:
    """Single-row predict_proba latency (milliseconds), model only."""
    rows = [X.iloc[[i % len(X)]] for i in range(repeats)]
    model.predict_proba(rows[0])  # warm-up
    times = []
    for r in rows:
        t = time.perf_counter()
        model.predict_proba(r)
        times.append((time.perf_counter() - t) * 1000)
    times_a = np.asarray(times)
    return {"p50_ms": float(np.percentile(times_a, 50)), "p95_ms": float(np.percentile(times_a, 95)),
            "mean_ms": float(times_a.mean()), "repeats": repeats}


def slice_errors(y_true: np.ndarray, scores: np.ndarray, threshold: float, slices: dict[str, np.ndarray]) -> list[dict[str, Any]]:
    """Error rates by named boolean slices (aggregated only; no raw URLs)."""
    y_true = np.asarray(y_true)
    y_pred = predict_from_scores(scores, threshold)
    rows = []
    for name, mask in slices.items():
        mask = np.asarray(mask, dtype=bool)
        n = int(mask.sum())
        if n == 0:
            continue
        yt, yp = y_true[mask], y_pred[mask]
        fn = int(((yt == PHISHING) & (yp == LEGITIMATE)).sum())
        fp = int(((yt == LEGITIMATE) & (yp == PHISHING)).sum())
        rows.append({"slice": name, "n": n, "phishing": int((yt == PHISHING).sum()), "legitimate": int((yt == LEGITIMATE).sum()),
                     "missed_phishing": fn, "false_alarms": fp, "error_rate": float((fn + fp) / n)})
    return rows
