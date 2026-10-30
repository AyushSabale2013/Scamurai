"""Shortcut audit gate.

Trains a tiny linear/logistic model using ONLY shape features (has_www, is_https,
has_path, has_query, has_fragment, path_segments, url_length_bucket).
Reports ROC-AUC on the held-out test split.
Fails if shape-only ROC-AUC > 0.75, verifying that collection artifacts
do not leak the label.
"""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score

PROJ = Path(__file__).resolve().parents[2]
DATASET_CSV = PROJ / "data" / "processed" / "dataset.csv"
SPLITS_CSV = PROJ / "data" / "processed" / "splits.csv"
OUT_JSON = PROJ / "reports" / "shortcut_audit.json"

SHAPE_FEATURES = [
    "is_https",
    "has_www",
    "has_path",
    "has_query",
    "has_fragment",
    "path_segments",
    "url_length_bucket",
]


def run_shortcut_audit(max_allowed_auc: float = 0.75) -> dict:
    print("=== Running Shortcut Audit Gate ===")
    
    if not DATASET_CSV.exists() or not SPLITS_CSV.exists():
        raise FileNotFoundError(f"Missing {DATASET_CSV} or {SPLITS_CSV}. Run make data first.")

    df = pd.read_csv(DATASET_CSV)
    splits = pd.read_csv(SPLITS_CSV)
    df["split"] = splits["split"]

    train_df = df[df["split"] == "train"]
    test_df = df[df["split"] == "test"]

    X_train = train_df[SHAPE_FEATURES].to_numpy(dtype=float)
    y_train = (train_df["label"] == 0).to_numpy(dtype=int)  # 1 if phishing, 0 if legit

    X_test = test_df[SHAPE_FEATURES].to_numpy(dtype=float)
    y_test = (test_df["label"] == 0).to_numpy(dtype=int)

    # Train tiny shape-only logistic regression
    clf = LogisticRegression(max_iter=500, random_state=42)
    clf.fit(X_train, y_train)

    train_preds = clf.predict_proba(X_train)[:, 1]
    test_preds = clf.predict_proba(X_test)[:, 1]

    train_auc = float(roc_auc_score(y_train, train_preds))
    test_auc = float(roc_auc_score(y_test, test_preds))

    passed = test_auc <= max_allowed_auc

    result = {
        "shape_features": SHAPE_FEATURES,
        "train_rows": len(train_df),
        "test_rows": len(test_df),
        "train_shape_auc": round(train_auc, 4),
        "test_shape_auc": round(test_auc, 4),
        "max_allowed_auc": max_allowed_auc,
        "gate_passed": passed,
        "coefficients": {k: round(float(v), 4) for k, v in zip(SHAPE_FEATURES, clf.coef_[0])},
        "intercept": round(float(clf.intercept_[0]), 4),
    }

    print(f"  Shape-only Train ROC-AUC: {train_auc:.4f}")
    print(f"  Shape-only Test ROC-AUC:  {test_auc:.4f} (Threshold: <= {max_allowed_auc:.2f})")
    print(f"  Gate status: {'PASS' if passed else 'FAIL'}")

    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    print(f"  Saved audit report to {OUT_JSON}")

    if not passed:
        raise ValueError(
            f"SHORTCUT AUDIT FAILED: Shape-only Test ROC-AUC was {test_auc:.4f} > {max_allowed_auc:.2f}."
        )

    return result


if __name__ == "__main__":
    try:
        run_shortcut_audit()
        sys.exit(0)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
