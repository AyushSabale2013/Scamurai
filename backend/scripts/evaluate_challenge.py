"""Evaluate any Scamurai model artifact against the held-out challenge test set.

Usage:
    python backend/scripts/evaluate_challenge.py [--artifact-dir backend/artifacts]
"""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support, brier_score_loss

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.ml.evaluation import PHISHING, LEGITIMATE, expected_calibration_error, phishing_scores
from app.ml.feature_extraction import extract_features, FEATURE_NAMES
from app.ml.model_loader import load_model


def evaluate_on_challenge(artifact_dir: Path, challenge_csv: Path | None = None) -> dict:
    if challenge_csv is None:
        challenge_csv = Path(__file__).resolve().parents[1] / "tests" / "challenge_set.csv"

    if not challenge_csv.is_file():
        raise FileNotFoundError(f"Challenge CSV not found at {challenge_csv}")

    model = load_model(artifact_dir)
    df = pd.read_csv(challenge_csv)
    y_true = df["label"].to_numpy().astype(int)

    rows = []
    failed_urls = []
    for u in df["url"]:
        try:
            f = extract_features(u)
            rows.append(f)
        except Exception as e:
            failed_urls.append((u, str(e)))

    if failed_urls:
        print(f"Warning: {len(failed_urls)} URLs failed extraction: {failed_urls[:3]}")

    X = pd.DataFrame(rows, columns=FEATURE_NAMES, dtype="float64")
    scores = phishing_scores(model.pipeline, X)
    threshold = model.threshold

    y_pred = np.where(scores >= threshold, PHISHING, LEGITIMATE)

    cm = confusion_matrix(y_true, y_pred, labels=[PHISHING, LEGITIMATE])
    # cm: [[TP_phish, FN_phish], [FP_phish, TN_phish]]
    tp = int(cm[0, 0])
    fn = int(cm[0, 1])
    fp = int(cm[1, 0])
    tn = int(cm[1, 1])

    prec, rec, f1, _ = precision_recall_fscore_support(y_true, y_pred, labels=[PHISHING, LEGITIMATE], zero_division=0)
    acc = float(accuracy_score(y_true, y_pred))
    fpr_legit = float(fp / max(fp + tn, 1))
    fnr_phish = float(fn / max(fn + tp, 1))

    y_phish = (y_true == PHISHING).astype(int)
    brier = float(brier_score_loss(y_phish, scores))
    ece = float(expected_calibration_error(y_phish, scores))

    # Evaluate ChatGPT URL specifically
    chatgpt_url = "https://chatgpt.com/c/6ae3364a-1440-83e8-be31-1e5aefa525c5"
    chatgpt_feat = extract_features(chatgpt_url)
    chatgpt_score = float(phishing_scores(model.pipeline, pd.DataFrame([chatgpt_feat], columns=FEATURE_NAMES))[0])
    chatgpt_pred = "phishing" if chatgpt_score >= threshold else "legitimate"

    results = {
        "model_version": model.version,
        "decision_threshold": threshold,
        "samples_total": len(df),
        "legitimate_samples": int((y_true == LEGITIMATE).sum()),
        "phishing_samples": int((y_true == PHISHING).sum()),
        "accuracy": acc,
        "phishing_precision": float(prec[0]),
        "phishing_recall": float(rec[0]),
        "phishing_f1": float(f1[0]),
        "legitimate_precision": float(prec[1]),
        "legitimate_recall": float(rec[1]),
        "legitimate_fpr": fpr_legit,
        "phishing_fnr": fnr_phish,
        "confusion_matrix": {
            "TP_phish": tp,
            "FN_phish": fn,
            "FP_phish": fp,
            "TN_phish": tn,
            "matrix": cm.tolist()
        },
        "brier_score": brier,
        "ece": ece,
        "chatgpt_test": {
            "url": chatgpt_url,
            "score": chatgpt_score,
            "threshold": threshold,
            "verdict": chatgpt_pred,
            "is_false_positive": (chatgpt_pred == "phishing")
        }
    }

    print("\n" + "=" * 60)
    print(f"CHALLENGE EVALUATION RESULTS ({model.version})")
    print("=" * 60)
    print(f"Total Samples: {len(df)} | Phishing: {results['phishing_samples']}, Legit: {results['legitimate_samples']}")
    print(f"Decision Threshold: {threshold:.4f}")
    print(f"Accuracy:           {acc:.4f} ({acc*100:.2f}%)")
    print(f"Phishing Recall:    {results['phishing_recall']:.4f} ({results['phishing_recall']*100:.2f}%)")
    print(f"Phishing Precision: {results['phishing_precision']:.4f} ({results['phishing_precision']*100:.2f}%)")
    print(f"Legit FPR (False Alarm): {fpr_legit:.4f} ({fpr_legit*100:.2f}%)")
    print(f"Confusion Matrix:   TP={tp}, FN={fn}, FP={fp}, TN={tn}")
    print(f"Brier Score:        {brier:.4f}")
    print(f"ECE:                {ece:.4f}")
    print("-" * 60)
    print(f"ChatGPT URL Score:  {chatgpt_score:.4f} -> {chatgpt_pred.upper()} (False Positive: {results['chatgpt_test']['is_false_positive']})")
    print("=" * 60 + "\n")

    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-dir", type=Path, default=Path(__file__).resolve().parents[1] / "artifacts")
    parser.add_argument("--challenge-csv", type=Path, default=None)
    parser.add_argument("--output-json", type=Path, default=None)
    args = parser.parse_args()

    res = evaluate_on_challenge(args.artifact_dir, args.challenge_csv)
    if args.output_json:
        args.output_json.parent.mkdir(parents=True, exist_ok=True)
        args.output_json.write_text(json.dumps(res, indent=2))
