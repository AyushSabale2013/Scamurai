"""Metric calculation, threshold tuning, and calibration for Scamurai."""

from __future__ import annotations

import math
from typing import Any

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score, average_precision_score, balanced_accuracy_score,
    brier_score_loss, confusion_matrix, f1_score, fbeta_score,
    matthews_corrcoef, precision_recall_curve, precision_recall_fscore_support,
    roc_auc_score, roc_curve,
)

# Convention: 0 = phishing, 1 = legitimate
# For evaluation, positive class = phishing (label == 0)
PHISHING = 0
LEGITIMATE = 1


def compute_phishing_prob(model: Any, X: np.ndarray) -> np.ndarray:
    """Extract P(class == 0) = P(phishing) from model.predict_proba."""
    classes = list(model.classes_)
    if PHISHING not in classes:
        raise ValueError(f"Model classes {classes} do not include phishing class 0.")
    col_idx = classes.index(PHISHING)
    return model.predict_proba(X)[:, col_idx]


def expected_calibration_error(y_phish: np.ndarray, probs: np.ndarray, bins: int = 10) -> float:
    """Compute Expected Calibration Error (ECE)."""
    edges = np.linspace(0, 1, bins + 1)
    idx = np.clip(np.digitize(probs, edges[1:-1]), 0, bins - 1)
    ece = 0.0
    for b in range(bins):
        m = idx == b
        if m.any():
            acc = y_phish[m].mean()
            conf = probs[m].mean()
            ece += (m.sum() / len(y_phish)) * abs(acc - conf)
    return float(ece)


def tune_thresholds_preregistered(
    y_true: np.ndarray,
    probs: np.ndarray,
    target_fpr: float = 0.01,
    target_recall: float = 0.98,
) -> dict[str, Any]:
    """Select t_high and t_low on VALIDATION set using preregistered rules:
    - t_high: highest threshold such that legitimate FPR <= target_fpr (1%)
    - t_low: threshold such that phishing recall >= target_recall (98%)
    """
    y_phish = (np.asarray(y_true) == PHISHING).astype(int)
    
    # Sort probabilities
    order = np.argsort(probs)[::-1]
    sorted_probs = probs[order]
    sorted_y = y_phish[order]

    total_phish = int(y_phish.sum())
    total_legit = int(len(y_phish) - total_phish)

    cum_tp = np.cumsum(sorted_y)
    cum_fp = np.cumsum(1 - sorted_y)

    recalls = cum_tp / max(total_phish, 1)
    fprs = cum_fp / max(total_legit, 1)

    # 1. t_high: max recall such that FPR <= target_fpr
    valid_fpr_idx = np.where(fprs <= target_fpr)[0]
    if len(valid_fpr_idx) > 0:
        idx_high = valid_fpr_idx[-1]
        t_high = float(sorted_probs[idx_high])
        t_high_rec = float(recalls[idx_high])
        t_high_fpr = float(fprs[idx_high])
    else:
        t_high = 0.90
        t_high_rec = float(recalls[0])
        t_high_fpr = 0.0

    # 2. t_low: recall >= target_recall
    valid_rec_idx = np.where(recalls >= target_recall)[0]
    if len(valid_rec_idx) > 0:
        idx_low = valid_rec_idx[0]
        t_low = float(sorted_probs[idx_low])
        t_low_rec = float(recalls[idx_low])
        t_low_fpr = float(fprs[idx_low])
    else:
        t_low = 0.10
        t_low_rec = float(recalls[-1])
        t_low_fpr = float(fprs[-1])

    # Ensure t_low <= t_high
    if t_low > t_high:
        t_low = max(0.01, t_high * 0.5)

    return {
        "t_high": round(t_high, 4),
        "t_low": round(t_low, 4),
        "val_recall_at_t_high": round(t_high_rec, 4),
        "val_fpr_at_t_high": round(t_high_fpr, 4),
        "val_recall_at_t_low": round(t_low_rec, 4),
        "val_fpr_at_t_low": round(t_low_fpr, 4),
        "rule_t_high": f"Max recall with validation FPR <= {target_fpr*100:.1f}%",
        "rule_t_low": f"Validation recall >= {target_recall*100:.1f}%",
    }


def evaluate_predictions(
    y_true: np.ndarray,
    probs: np.ndarray,
    threshold: float,
    threshold_low: float = 0.20,
) -> dict[str, Any]:
    """Compute comprehensive performance metrics at threshold."""
    y_true = np.asarray(y_true, dtype=int)
    probs = np.asarray(probs, dtype=float)
    y_phish = (y_true == PHISHING).astype(int)

    # Binary verdict at threshold: score >= threshold -> phishing (0), else legitimate (1)
    y_pred = np.where(probs >= threshold, PHISHING, LEGITIMATE)

    # Three-tier counts:
    # likely_phishing: prob >= threshold
    # suspicious: threshold_low <= prob < threshold
    # likely_safe: prob < threshold_low
    likely_phish = probs >= threshold
    suspicious = (probs >= threshold_low) & (probs < threshold)
    likely_safe = probs < threshold_low

    cm = confusion_matrix(y_true, y_pred, labels=[PHISHING, LEGITIMATE])
    tp_ph = int(cm[0, 0])
    fn_ph = int(cm[0, 1])
    fp_ph = int(cm[1, 0])
    tn_ph = int(cm[1, 1])

    acc = float(accuracy_score(y_true, y_pred))
    bal_acc = float(balanced_accuracy_score(y_true, y_pred))
    p, r, f1, _ = precision_recall_fscore_support(y_true, y_pred, labels=[PHISHING, LEGITIMATE], zero_division=0)
    f2 = float(fbeta_score(y_true, y_pred, beta=2, pos_label=PHISHING, zero_division=0))
    mcc = float(matthews_corrcoef(y_true, y_pred)) if len(np.unique(y_true)) > 1 else 0.0

    fpr = float(fp_ph / max(fp_ph + tn_ph, 1))
    fnr = float(fn_ph / max(fn_ph + tp_ph, 1))
    specificity = float(tn_ph / max(tn_ph + fp_ph, 1))

    roc_auc = float(roc_auc_score(y_phish, probs)) if len(np.unique(y_phish)) > 1 else None
    pr_auc = float(average_precision_score(y_phish, probs)) if len(np.unique(y_phish)) > 1 else None
    brier = float(brier_score_loss(y_phish, probs))
    ece = expected_calibration_error(y_phish, probs)

    # Prevalence-adjusted precision at 1% and 0.1% base rates
    # PPV = (Recall * Prevalence) / (Recall * Prevalence + FPR * (1 - Prevalence))
    def adjusted_ppv(recall_val: float, fpr_val: float, prev: float) -> float:
        num = recall_val * prev
        den = num + fpr_val * (1.0 - prev)
        return float(round(num / den, 4)) if den > 0 else 0.0

    ppv_1pct = adjusted_ppv(r[0], fpr, 0.01)
    ppv_01pct = adjusted_ppv(r[0], fpr, 0.001)

    return {
        "n": len(y_true),
        "threshold": threshold,
        "threshold_low": threshold_low,
        "accuracy": round(acc, 4),
        "balanced_accuracy": round(bal_acc, 4),
        "phishing_precision": round(float(p[0]), 4),
        "phishing_recall": round(float(r[0]), 4),
        "phishing_f1": round(float(f1[0]), 4),
        "phishing_f2": round(f2, 4),
        "legitimate_precision": round(float(p[1]), 4),
        "legitimate_recall": round(float(r[1]), 4),
        "legitimate_f1": round(float(f1[1]), 4),
        "mcc": round(mcc, 4),
        "roc_auc": round(roc_auc, 4) if roc_auc is not None else None,
        "pr_auc": round(pr_auc, 4) if pr_auc is not None else None,
        "fpr": round(fpr, 4),
        "fnr": round(fnr, 4),
        "specificity": round(specificity, 4),
        "brier_score": round(brier, 4),
        "ece": round(ece, 4),
        "prevalence_adjusted": {
            "ppv_at_1pct_prevalence": ppv_1pct,
            "ppv_at_0.1pct_prevalence": ppv_01pct,
            "expected_false_alarms_per_10k": round(fpr * 10000, 1),
        },
        "confusion_matrix": {
            "tp_phishing": tp_ph,
            "fn_phishing": fn_ph,
            "fp_legitimate": fp_ph,
            "tn_legitimate": tn_ph,
        },
        "three_tier_distribution": {
            "likely_phishing": int(likely_phish.sum()),
            "suspicious": int(suspicious.sum()),
            "likely_safe": int(likely_safe.sum()),
        },
    }
