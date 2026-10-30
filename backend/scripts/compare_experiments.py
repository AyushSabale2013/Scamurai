"""Experimental comparison of Feature Normalization, Feature Ablations, and Model Architectures.

Evaluates on:
1. Domain-Grouped Validation Partition (for threshold selection and tuning)
2. Domain-Grouped Test Partition (offline benchmark)
3. Untouched Held-Out Challenge Test Set (generalization benchmark)
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support, roc_auc_score, average_precision_score, brier_score_loss
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.ml import preprocessing as prep
from app.ml.evaluation import PHISHING, LEGITIMATE, expected_calibration_error, phishing_scores, tune_threshold
from app.ml.feature_extraction import (
    FEATURE_NAMES, extract_features, extract_features_from_parsed, parse_url
)


def extract_features_v2_normalized(raw: str) -> dict[str, float]:
    """Feature Extractor V2: Normalizes 'www.' before calculating hostname labels and subdomains.
    
    This neutralizes the artificial shortcut where naked domains (like chatgpt.com)
    are penalized as having '0 subdomains' and 'only 2 labels'.
    """
    p = parse_url(raw)
    feats = extract_features_from_parsed(p)
    
    # Neutralize 'www.' bias in hostname properties
    host = p.host
    if host.startswith("www."):
        clean_host = host[4:]
    else:
        clean_host = host
        
    labels = clean_host.split(".") if not p.is_ip else [clean_host]
    reg_labels = p.registrable.count(".") + 1
    
    feats["subdomain_count"] = 0.0 if p.is_ip else float(max(0, len(labels) - reg_labels))
    feats["hostname_label_count"] = float(len(labels))
    feats["longest_label_length"] = float(max(len(x) for x in labels)) if labels else 0.0
    
    # Path slash count rather than total URL slash count (which counted scheme slashes)
    feats["slash_count"] = float(p.path.count("/"))
    
    return feats


def run_ablation_and_model_study(csv_path: Path, challenge_csv: Path, sample_size: int = 50000, seed: int = 42):
    print("=" * 70)
    print("STARTING FEATURE & MODEL COMPARISON STUDY")
    print(f"Data source: {csv_path} | Sample size: {sample_size if sample_size else 'Full'}")
    print("=" * 70)

    # 1. Load Data
    raw = prep.load_raw(csv_path)
    if sample_size and len(raw) > sample_size:
        raw = raw.sample(sample_size, random_state=seed).reset_index(drop=True)
    
    print(f"Auditing & extracting features for {len(raw)} samples...")
    frame, summary = prep.clean_and_extract(raw)
    
    # Load Challenge Set
    ch_df = pd.read_csv(challenge_csv)
    y_ch = ch_df["label"].to_numpy().astype(int)
    
    # 2. Domain-grouped Split
    split_b = prep.grouped_split(frame, seed=seed)
    train_idx = split_b["train"]
    val_idx = split_b["val"]
    test_idx = split_b["test"]
    
    y_tr = frame["label"].iloc[train_idx].to_numpy()
    y_va = frame["label"].iloc[val_idx].to_numpy()
    y_te = frame["label"].iloc[test_idx].to_numpy()

    # Precompute Feature Variants
    print("\nComputing Feature Sets...")
    
    # Variant 1: Original Features
    X1_tr = frame.iloc[train_idx][FEATURE_NAMES]
    X1_va = frame.iloc[val_idx][FEATURE_NAMES]
    X1_te = frame.iloc[test_idx][FEATURE_NAMES]
    X1_ch = pd.DataFrame([extract_features(u) for u in ch_df["url"]], columns=FEATURE_NAMES)
    
    # Variant 2: Normalized 'www.' Features
    print("Extracting V2 Normalized features...")
    v2_feats_all = [extract_features_v2_normalized(u) for u in frame["url"]]
    frame_v2 = pd.DataFrame(v2_feats_all, columns=FEATURE_NAMES)
    X2_tr = frame_v2.iloc[train_idx]
    X2_va = frame_v2.iloc[val_idx]
    X2_te = frame_v2.iloc[test_idx]
    X2_ch = pd.DataFrame([extract_features_v2_normalized(u) for u in ch_df["url"]], columns=FEATURE_NAMES)

    # Variant 3: Ablation (Excluding slash_count, subdomain_count, path_length)
    ablation_cols = [c for c in FEATURE_NAMES if c not in ("slash_count", "subdomain_count", "path_length")]
    X3_tr = X2_tr[ablation_cols]
    X3_va = X2_va[ablation_cols]
    X3_te = X2_te[ablation_cols]
    X3_ch = X2_ch[ablation_cols]

    experiments = [
        ("V1_Original_XGBoost", X1_tr, X1_va, X1_te, X1_ch, "xgboost", {}),
        ("V2_Normalized_XGBoost", X2_tr, X2_va, X2_te, X2_ch, "xgboost", {}),
        ("V3_Ablation_XGBoost", X3_tr, X3_va, X3_te, X3_ch, "xgboost", {}),
        ("V2_RandomForest", X2_tr, X2_va, X2_te, X2_ch, "random_forest", {"n_estimators": 100, "min_samples_leaf": 3}),
        ("V2_LogisticRegression", X2_tr, X2_va, X2_te, X2_ch, "logistic_regression", {"C": 0.1}),
    ]
    
    # Check if LightGBM or CatBoost are available
    try:
        import lightgbm
        experiments.append(("V2_LightGBM", X2_tr, X2_va, X2_te, X2_ch, "lightgbm", {}))
    except ImportError:
        pass

    results_table = []
    
    chatgpt_url = "https://chatgpt.com/c/6ae3364a-1440-83e8-be31-1e5aefa525c5"
    cg1 = pd.DataFrame([extract_features(chatgpt_url)], columns=FEATURE_NAMES)
    cg2 = pd.DataFrame([extract_features_v2_normalized(chatgpt_url)], columns=FEATURE_NAMES)
    cg3 = cg2[ablation_cols]

    for exp_name, Xtr, Xva, Xte, Xch, model_type, extra_params in experiments:
        print(f"\n--- Running Experiment: {exp_name} ({model_type}) ---")
        t0 = time.perf_counter()
        
        if model_type == "xgboost":
            clf = XGBClassifier(n_estimators=300, max_depth=4, learning_rate=0.1, subsample=0.8,
                                colsample_bytree=0.8, tree_method="hist", eval_metric="logloss",
                                early_stopping_rounds=20, random_state=seed, n_jobs=-1)
            clf.fit(Xtr, ytr, eval_set=[(Xva, yva)], verbose=False)
        elif model_type == "random_forest":
            clf = RandomForestClassifier(n_estimators=extra_params.get("n_estimators", 100),
                                         min_samples_leaf=extra_params.get("min_samples_leaf", 3),
                                         random_state=seed, n_jobs=-1)
            clf.fit(Xtr, ytr)
        elif model_type == "logistic_regression":
            from sklearn.preprocessing import StandardScaler
            from sklearn.pipeline import Pipeline
            clf = Pipeline([("scaler", StandardScaler()),
                            ("clf", LogisticRegression(C=extra_params.get("C", 0.1), max_iter=2000, random_state=seed))])
            clf.fit(Xtr, ytr)
        elif model_type == "lightgbm":
            from lightgbm import LGBMClassifier
            clf = LGBMClassifier(n_estimators=300, max_depth=4, learning_rate=0.1, random_state=seed, n_jobs=-1, verbose=-1)
            clf.fit(Xtr, ytr, eval_set=[(Xva, yva)])
        else:
            continue
            
        fit_time = round(time.perf_counter() - t0, 2)
        
        # Validation Tuning
        va_scores = phishing_scores(clf, Xva)
        thr_data = tune_threshold(yva, va_scores)
        thr = thr_data["threshold"]
        
        # Test Set Metrics
        te_scores = phishing_scores(clf, Xte)
        te_pred = np.where(te_scores >= thr, PHISHING, LEGITIMATE)
        te_acc = accuracy_score(yte, te_pred)
        te_prec, te_rec, te_f1, _ = precision_recall_fscore_support(yte, te_pred, labels=[PHISHING, LEGITIMATE], zero_division=0)
        te_pr_auc = average_precision_score((yte == PHISHING).astype(int), te_scores)
        
        # Challenge Set Metrics
        ch_scores = phishing_scores(clf, Xch)
        ch_pred = np.where(ch_scores >= thr, PHISHING, LEGITIMATE)
        ch_cm = confusion_matrix(y_ch, ch_pred, labels=[PHISHING, LEGITIMATE])
        ch_tp, ch_fn = int(ch_cm[0, 0]), int(ch_cm[0, 1])
        ch_fp, ch_tn = int(ch_cm[1, 0]), int(ch_cm[1, 1])
        
        ch_acc = accuracy_score(y_ch, ch_pred)
        ch_prec, ch_rec, ch_f1, _ = precision_recall_fscore_support(y_ch, ch_pred, labels=[PHISHING, LEGITIMATE], zero_division=0)
        ch_fpr = float(ch_fp / max(ch_fp + ch_tn, 1))
        ch_brier = float(brier_score_loss((y_ch == PHISHING).astype(int), ch_scores))
        ch_ece = float(expected_calibration_error((y_ch == PHISHING).astype(int), ch_scores))
        
        # ChatGPT Score
        if "V1" in exp_name:
            cg_x = cg1
        elif "V3" in exp_name:
            cg_x = cg3
        else:
            cg_x = cg2
        cg_score = float(phishing_scores(clf, cg_x)[0])
        cg_verdict = "phishing" if cg_score >= thr else "legitimate"
        
        row = {
            "experiment": exp_name,
            "model_type": model_type,
            "threshold": round(thr, 4),
            "fit_seconds": fit_time,
            "val_fbeta": round(thr_data["val_fbeta"], 4),
            "test_acc": round(te_acc, 4),
            "test_phish_recall": round(float(te_rec[0]), 4),
            "test_phish_precision": round(float(te_prec[0]), 4),
            "test_pr_auc": round(float(te_pr_auc), 4),
            "challenge_acc": round(ch_acc, 4),
            "challenge_phish_recall": round(float(ch_rec[0]), 4),
            "challenge_phish_precision": round(float(ch_prec[0]), 4),
            "challenge_legit_fpr": round(ch_fpr, 4),
            "challenge_brier": round(ch_brier, 4),
            "challenge_ece": round(ch_ece, 4),
            "challenge_TP": ch_tp,
            "challenge_FP": ch_fp,
            "challenge_TN": ch_tn,
            "challenge_FN": ch_fn,
            "chatgpt_score": round(cg_score, 4),
            "chatgpt_verdict": cg_verdict,
        }
        results_table.append(row)
        print(f"  Threshold={thr:.4f} | Test Acc={te_acc:.4f} | Challenge Acc={ch_acc:.4f} | Challenge FPR={ch_fpr:.4f}")
        print(f"  ChatGPT URL: score={cg_score:.4f} -> {cg_verdict.upper()} (False Positive: {cg_verdict == 'phishing'})")

    res_df = pd.DataFrame(results_table)
    out_csv = Path(__file__).resolve().parents[2] / "reports" / "model_comparison.csv"
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    res_df.to_csv(out_csv, index=False)
    print(f"\nSaved model comparison table to {out_csv}")
    print(res_df[["experiment", "threshold", "test_acc", "challenge_acc", "challenge_legit_fpr", "chatgpt_score", "chatgpt_verdict"]])
    return res_df


if __name__ == "__main__":
    raw_csv = Path(__file__).resolve().parents[2] / "data" / "raw" / "PhiUSIIL_Phishing_URL_Dataset.csv"
    ch_csv = Path(__file__).resolve().parents[1] / "tests" / "challenge_set.csv"
    run_ablation_and_model_study(raw_csv, ch_csv, sample_size=50000)
