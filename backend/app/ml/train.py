"""End-to-end, reproducible training + evaluation pipeline.

Usage (from ``backend/``)::

    python -m app.ml.train --csv ../data/raw/PhiUSIIL_Phishing_URL_Dataset.csv

Outputs
-------
* ``artifacts/model.joblib``, ``artifacts/model_metadata.json``
* ``artifacts/evaluation_report.json``, ``artifacts/dataset_audit.json``
* ``../reports/figures/*.png`` plus a Markdown summary

Nothing here is hard-coded: every number in the reports is computed by this
script from the CSV you point it at.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import platform
import sys
import time
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from . import preprocessing as prep
from .evaluation import (
    CLASS_NAMES, PHISHING, compute_metrics, measure_latency, phishing_scores,
    predict_from_scores, slice_errors, tune_threshold,
)
from .explainability import ModelExplainer
from .feature_extraction import EXTRACTOR_VERSION, FEATURE_DEFINITIONS, FEATURE_NAMES, MAX_URL_LENGTH, SUSPICIOUS_TOKENS, extract_features

DISPLAY = {"logistic_regression": "Logistic Regression", "random_forest": "Random Forest", "xgboost": "XGBoost"}
MODEL_ORDER = ["logistic_regression", "random_forest", "xgboost"]
PROBE_URLS = [  # hand-written sanity probe of well-known legitimate URLs that contain paths; NOT a metric
    "https://github.com/anthropics/anthropic-sdk-python",
    "https://en.wikipedia.org/wiki/Phishing",
    "https://docs.python.org/3/library/urllib.parse.html",
    "https://www.google.com/search?q=weather+today",
    "https://www.bbc.com/news/technology",
    "https://stackoverflow.com/questions/tagged/python",
    "https://www.nytimes.com/section/world",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://www.google.com",
    "https://www.wikipedia.org",
]


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


# ----------------------------------------------------------------------------- model factories
def make_pipeline(name: str, params: dict[str, Any], seed: int, rf_trees: int) -> Pipeline:
    if name == "logistic_regression":
        return Pipeline([("scaler", StandardScaler()),
                         ("clf", LogisticRegression(C=params["C"], max_iter=3000, solver="lbfgs", random_state=seed))])
    if name == "random_forest":
        return Pipeline([("clf", RandomForestClassifier(n_estimators=rf_trees, min_samples_leaf=params["min_samples_leaf"],
                                                        max_features="sqrt", n_jobs=-1, random_state=seed))])
    raise ValueError(name)


def fit_one(name: str, params: dict[str, Any], Xtr, ytr, Xva, yva, seed: int, rf_trees: int) -> tuple[Pipeline, float]:
    t = time.perf_counter()
    if name == "xgboost":
        from xgboost import XGBClassifier

        clf = XGBClassifier(n_estimators=800, learning_rate=0.1, max_depth=params["max_depth"], subsample=0.8,
                            colsample_bytree=0.8, tree_method="hist", eval_metric="logloss",
                            early_stopping_rounds=30, n_jobs=os.cpu_count() or 1, random_state=seed)
        clf.fit(Xtr, ytr, eval_set=[(Xva, yva)], verbose=False)  # validation set is disjoint from train
        pipe = Pipeline([("clf", clf)])
    else:
        pipe = make_pipeline(name, params, seed, rf_trees)
        pipe.fit(Xtr, ytr)
    return pipe, time.perf_counter() - t


GRIDS: dict[str, list[dict[str, Any]]] = {
    "logistic_regression": [{"C": c} for c in (0.01, 0.1, 1.0, 10.0)],
    "random_forest": [{"min_samples_leaf": m} for m in (1, 5)],
    "xgboost": [{"max_depth": d} for d in (4, 6)],
}


def native_importance(pipe: Pipeline) -> dict[str, float]:
    clf = pipe.steps[-1][1]
    if hasattr(clf, "feature_importances_"):
        v = np.asarray(clf.feature_importances_, dtype=float)
    else:
        v = np.abs(clf.coef_[0])  # coefficients of standardised features
    return {n: float(x) for n, x in zip(FEATURE_NAMES, v)}


def model_size_bytes(pipe: Pipeline, tmp: Path) -> int:
    joblib.dump(pipe, tmp, compress=3)
    size = tmp.stat().st_size
    tmp.unlink()
    return int(size)


# ----------------------------------------------------------------------------- experiments
def run_experiment(label: str, frame: pd.DataFrame, split: dict[str, np.ndarray], seed: int, rf_trees: int, tmp_dir: Path):
    Xtr, ytr = frame.iloc[split["train"]][FEATURE_NAMES], frame["label"].iloc[split["train"]].to_numpy()
    Xva, yva = frame.iloc[split["val"]][FEATURE_NAMES], frame["label"].iloc[split["val"]].to_numpy()
    Xte, yte = frame.iloc[split["test"]][FEATURE_NAMES], frame["label"].iloc[split["test"]].to_numpy()
    results: dict[str, Any] = {}
    fitted: dict[str, Pipeline] = {}
    for name in MODEL_ORDER:
        log(f"[{label}] tuning {DISPLAY[name]} over {len(GRIDS[name])} setting(s)")
        grid_rows, best = [], None
        t_tune = time.perf_counter()
        for params in GRIDS[name]:
            pipe, secs = fit_one(name, params, Xtr, ytr, Xva, yva, seed, rf_trees)
            va_scores = phishing_scores(pipe, Xva)
            pr = float(average_precision_score((yva == PHISHING).astype(int), va_scores))
            extra = {"best_iteration": int(pipe.steps[-1][1].best_iteration)} if name == "xgboost" else {}
            grid_rows.append({"params": params, "val_pr_auc_phishing": pr, "fit_seconds": round(secs, 2), **extra})
            log(f"    {params} val PR-AUC={pr:.5f} fit={secs:.1f}s")
            if best is None or pr > best[0]:
                best = (pr, params, pipe, secs)
        tuning_seconds = time.perf_counter() - t_tune
        _, params, pipe, secs = best
        va_scores = phishing_scores(pipe, Xva)
        thr = tune_threshold(yva, va_scores)
        te_scores = phishing_scores(pipe, Xte)
        entry = {
            "display_name": DISPLAY[name],
            "best_params": params,
            "tuning": {"grid": grid_rows, "tuning_seconds": round(tuning_seconds, 2), "selection_metric": "validation PR-AUC (phishing)"},
            "fit_seconds": round(secs, 2),
            "threshold": thr,
            "validation": compute_metrics(yva, va_scores, thr["threshold"]),
            "test": compute_metrics(yte, te_scores, thr["threshold"], with_curves=True),
            "latency": measure_latency(pipe, Xte.head(300)),
            "model_size_bytes": model_size_bytes(pipe, tmp_dir / f"_size_{label}_{name}.joblib"),
            "native_importance": native_importance(pipe),
        }
        if name == "xgboost":
            entry["best_iteration"] = int(pipe.steps[-1][1].best_iteration)
        results[name] = entry
        fitted[name] = pipe
        t = entry["test"]
        log(f"    -> test acc={t['accuracy']:.4f} phish recall={t['per_class']['phishing']['recall']:.4f} "
            f"precision={t['per_class']['phishing']['precision']:.4f} pr_auc={t['pr_auc_phishing']:.5f}")
    return results, fitted


def select_model(results: dict[str, Any]) -> dict[str, Any]:
    """Documented rule applied to the DOMAIN-GROUPED VALIDATION results only."""
    rows = []
    for n in MODEL_ORDER:
        r = results[n]
        v = r["validation"]
        rows.append({"model": n, "val_pr_auc": r["tuning"]["grid"] and max(g["val_pr_auc_phishing"] for g in r["tuning"]["grid"]),
                     "val_phishing_recall": v["per_class"]["phishing"]["recall"], "val_phishing_precision": v["per_class"]["phishing"]["precision"],
                     "val_phishing_f1": v["per_class"]["phishing"]["f1"], "p50_latency_ms": r["latency"]["p50_ms"],
                     "model_size_bytes": r["model_size_bytes"]})
    best_f1 = max(x["val_phishing_f1"] for x in rows)
    for x in rows:
        x["eligible"] = bool(x["val_phishing_f1"] >= best_f1 - 0.001)
    eligible = [x for x in rows if x["eligible"]]
    chosen = min(eligible, key=lambda x: (x["p50_latency_ms"], x["model_size_bytes"]))
    return {
        "chosen": chosen["model"],
        "rule": ("Using domain-grouped VALIDATION results only: rank models by phishing F1 at each model's own validation-tuned "
                 "threshold (F1 reflects both phishing recall and precision). Models within 0.001 F1 of the best are treated as tied; "
                 "among tied models choose the lowest single-row inference latency, then the smallest file. Test results and raw "
                 "accuracy are not used."),
        "rule_revision_note": ("A first draft of this rule (PR-AUC within 0.002 and recall within 0.005 of the best, then fastest) selected "
                               "Logistic Regression because those tolerances were wider than the real spread between the models and ignored "
                               "a precision gap on validation. It was replaced by the F1-based rule above before the final run. All three "
                               "models' test metrics had been printed in the training log at that point."),
        "candidates": rows,
        "reason": (f"{DISPLAY[chosen['model']]} reached validation phishing F1 {chosen['val_phishing_f1']:.4f} "
                   f"(recall {chosen['val_phishing_recall']:.4f}, precision {chosen['val_phishing_precision']:.4f}); it is within 0.001 F1 of "
                   f"the best model and has the lowest latency among those."),
    }


def build_slices(frame: pd.DataFrame, ix: np.ndarray) -> dict[str, np.ndarray]:
    f = frame.iloc[ix]
    tm = f["is_template"].to_numpy()
    return {
        "all test rows": np.ones(len(f), bool),
        "https://www.<host> without path (collection template)": tm,
        "everything else (has path/query, no www, or http)": ~tm,
        "HTTPS": f["is_https"].to_numpy() == 1,
        "HTTP": f["is_https"].to_numpy() == 0,
        "has path or query": (f["path_length"].to_numpy() > 1) | (f["query_length"].to_numpy() > 0),
        "IP-address host": f["is_ip_host"].to_numpy() == 1,
        "URL length <= 30": f["url_length"].to_numpy() <= 30,
        "URL length 31-60": (f["url_length"].to_numpy() > 30) & (f["url_length"].to_numpy() <= 60),
        "URL length > 60": f["url_length"].to_numpy() > 60,
        "contains suspicious keyword": f["has_suspicious_token"].to_numpy() == 1,
    }


# ----------------------------------------------------------------------------- plots
def make_plots(report: dict[str, Any], fig_dir: Path) -> list[str]:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig_dir.mkdir(parents=True, exist_ok=True)
    made: list[str] = []
    colors = {"logistic_regression": "#7c8aa5", "random_forest": "#d99a2b", "xgboost": "#1fa39a"}
    exps = report["experiments"]

    def save(fig, name):
        fig.tight_layout()
        fig.savefig(fig_dir / name, dpi=130)
        plt.close(fig)
        made.append(name)

    for ek, ex in exps.items():
        fig, axes = plt.subplots(1, 3, figsize=(13, 4))
        for ax, n in zip(axes, MODEL_ORDER):
            m = np.array(ex["models"][n]["test"]["confusion_matrix"]["matrix"])
            ax.imshow(m, cmap="Blues")
            for (i, j), v in np.ndenumerate(m):
                ax.text(j, i, f"{v:,}", ha="center", va="center", color="white" if v > m.max() / 2 else "black")
            ax.set_xticks([0, 1], ["phishing", "legitimate"])
            ax.set_yticks([0, 1], ["phishing", "legitimate"])
            ax.set_xlabel("Predicted")
            ax.set_ylabel("Actual")
            ax.set_title(DISPLAY[n])
        fig.suptitle(f"Test confusion matrices ({ek.replace('_', ' ')})")
        save(fig, f"confusion_{ek}.png")

        fig, (a1, a2) = plt.subplots(1, 2, figsize=(11, 4.5))
        for n in MODEL_ORDER:
            t = ex["models"][n]["test"]
            a1.plot(t["roc_curve"]["fpr"], t["roc_curve"]["tpr"], label=f"{DISPLAY[n]} (AUC {t['roc_auc']:.4f})", color=colors[n])
            a2.plot(t["pr_curve"]["recall"], t["pr_curve"]["precision"], label=f"{DISPLAY[n]} (AP {t['pr_auc_phishing']:.4f})", color=colors[n])
        a1.set(xlabel="False positive rate", ylabel="True positive rate (phishing recall)", title="ROC (phishing = positive)")
        a2.set(xlabel="Recall", ylabel="Precision", title="Precision-recall (phishing = positive)")
        a1.legend(loc="lower right")
        a2.legend(loc="lower left")
        save(fig, f"roc_pr_{ek}.png")

    fig, ax = plt.subplots(figsize=(9, 4.5))
    w = 0.12
    labels, vals = [], []
    for k, ek in enumerate(exps):
        for j, n in enumerate(MODEL_ORDER):
            t = exps[ek]["models"][n]["test"]["per_class"]["phishing"]
            for mi, (mk, ml) in enumerate((("precision", "Precision"), ("recall", "Recall"), ("f1", "F1"))):
                x = k * 3.6 + j * 1.1 + mi * w * 1.3
                ax.bar(x, t[mk], width=w, color=colors[n], alpha=[0.55, 0.8, 1][mi])
    ax.set_xticks([k * 3.6 + 1.2 for k in range(len(exps))], [e.replace("_", " ") for e in exps])
    ax.set_ylim(min(0.9, ax.get_ylim()[0]), 1.002)
    ax.set_ylabel("Phishing-class score (test)")
    ax.set_title("Model comparison: precision / recall / F1 per model (pale to solid)")
    ax.legend(handles=[plt.Rectangle((0, 0), 1, 1, color=colors[n]) for n in MODEL_ORDER], labels=[DISPLAY[n] for n in MODEL_ORDER], loc="lower right")
    save(fig, "model_comparison.png")

    fi = report["feature_importance"]["selected_model_shap"]
    top = fi[:15][::-1]
    fig, ax = plt.subplots(figsize=(8, 5.5))
    ax.barh([t["label"] for t in top], [t["mean_abs_contribution"] for t in top], color="#1fa39a")
    ax.set_xlabel(f"Mean |contribution| ({report['feature_importance']['unit']})")
    ax.set_title(f"Feature importance: {report['feature_importance']['method']}")
    save(fig, "feature_importance.png")

    ea = report["error_analysis"]["domain_grouped"]
    fig, ax = plt.subplots(figsize=(9, 5))
    rows = [r for r in ea["slices"] if r["slice"] != "all test rows"][::-1]
    ax.barh([r["slice"] for r in rows], [r["error_rate"] * 100 for r in rows], color="#d99a2b")
    ax.set_xlabel("Error rate (%) on test slice")
    ax.set_title("Error analysis by slice (domain-grouped test, selected model)")
    save(fig, "error_analysis.png")
    return made


def write_markdown(report: dict[str, Any], path: Path) -> None:
    L = ["# PhishGuard AI: evaluation summary", "", f"Generated: {report['generated_at']}", "",
         f"Selected model: **{DISPLAY[report['selected']['chosen']]}**. {report['selected']['reason']}", "",
         "> Both experiments are reported separately. The stratified holdout lets the same domain appear in train and test and is therefore optimistic.", ""]
    for ek, ex in report["experiments"].items():
        L += [f"## Experiment: {ek.replace('_', ' ')}", "", "| Model | Acc | Phish P | Phish R | Phish F1 | ROC-AUC | PR-AUC | Threshold |", "|---|---|---|---|---|---|---|---|"]
        for n in MODEL_ORDER:
            t = ex["models"][n]["test"]
            p = t["per_class"]["phishing"]
            L.append(f"| {DISPLAY[n]} | {t['accuracy']:.4f} | {p['precision']:.4f} | {p['recall']:.4f} | {p['f1']:.4f} | {t['roc_auc']:.5f} | {t['pr_auc_phishing']:.5f} | {t['threshold']:.3f} |")
        L.append("")
    sd = report["shortcut_diagnostics"]
    L += ["## Shortcut diagnostics", "", sd["summary"], ""]
    path.write_text("\n".join(L), encoding="utf-8")


# ----------------------------------------------------------------------------- main
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Train PhishGuard AI models")
    ap.add_argument("--csv", type=Path, required=True)
    ap.add_argument("--artifacts", type=Path, default=Path(__file__).resolve().parents[2] / "artifacts")
    ap.add_argument("--reports", type=Path, default=Path(__file__).resolve().parents[3] / "reports")
    ap.add_argument("--seed", type=int, default=prep.SEED)
    ap.add_argument("--rf-trees", type=int, default=150)
    ap.add_argument("--sample", type=int, default=0, help="Use a random subset of N rows (development only).")
    args = ap.parse_args(argv)
    t_start = time.perf_counter()
    args.artifacts.mkdir(parents=True, exist_ok=True)
    args.reports.mkdir(parents=True, exist_ok=True)

    # ---- Step 2: dataset audit
    log(f"Loading {args.csv}")
    raw = prep.load_raw(args.csv)
    audit = prep.audit_dataset(raw, args.csv)
    if args.sample:
        raw = raw.sample(args.sample, random_state=args.seed)
        audit["development_subsample_rows"] = int(args.sample)
        log(f"DEVELOPMENT SUBSAMPLE: {args.sample} rows")
    log(f"Audit: {audit['rows']:,} rows, {audit['duplicate_url_rows']} duplicate URL rows, "
        f"{audit['duplicate_url_groups_with_conflicting_labels']} conflicting duplicates")

    # ---- Step 4: preprocessing
    log("Extracting features with the shared extractor")
    frame, summary = prep.clean_and_extract(raw)
    del raw
    log(f"Cleaned frame: {len(frame):,} rows; extractor dropped {summary['dropped_by_extractor_total']}")

    split_a = prep.stratified_split(frame, args.seed)
    split_b = prep.grouped_split(frame, args.seed)
    ver_a = prep.verify_split(frame, split_a, grouped=False)
    ver_b = prep.verify_split(frame, split_b, grouped=True)

    # ---- Steps 5-6: train + evaluate both experiments
    exp_a, _ = run_experiment("stratified", frame, split_a, args.seed, args.rf_trees, args.artifacts)
    exp_b, fitted_b = run_experiment("domain_grouped", frame, split_b, args.seed, args.rf_trees, args.artifacts)

    # ---- Step 7: model selection (domain-grouped validation only)
    selection = select_model(exp_b)
    chosen = selection["chosen"]
    log(f"Selected: {DISPLAY[chosen]}")
    final = fitted_b[chosen]
    thr = exp_b[chosen]["threshold"]["threshold"]
    Xte_b = frame.iloc[split_b["test"]][FEATURE_NAMES]
    yte_b = frame["label"].iloc[split_b["test"]].to_numpy()
    te_scores = phishing_scores(final, Xte_b)

    # ---- explainability / feature importance on the real model
    log("Computing explanation summary")
    explainer = ModelExplainer(final)
    sample = Xte_b.sample(min(1000, len(Xte_b)), random_state=args.seed)
    contrib = explainer.contributions(sample)
    fi_rows = sorted(({"feature": n, "label": FEATURE_DEFINITIONS[n].label, "mean_abs_contribution": float(np.abs(contrib[:, i]).mean()),
                       "mean_signed_contribution": float(contrib[:, i].mean())} for i, n in enumerate(FEATURE_NAMES)),
                     key=lambda r: -r["mean_abs_contribution"])

    # ---- error analysis for the selected model type, both experiments
    error_analysis = {}
    for ek, ex, sp in (("stratified", exp_a, split_a), ("domain_grouped", exp_b, split_b)):
        pipe = fitted_b[chosen] if ek == "domain_grouped" else None
        if pipe is None:  # stratified-experiment model is not retained in memory; rebuild scores from stored curve is impossible, refit cheaply
            Xtr = frame.iloc[sp["train"]][FEATURE_NAMES]; ytr = frame["label"].iloc[sp["train"]].to_numpy()
            Xva = frame.iloc[sp["val"]][FEATURE_NAMES]; yva = frame["label"].iloc[sp["val"]].to_numpy()
            pipe, _ = fit_one(chosen, ex[chosen]["best_params"], Xtr, ytr, Xva, yva, args.seed, args.rf_trees)
        X = frame.iloc[sp["test"]][FEATURE_NAMES]
        y = frame["label"].iloc[sp["test"]].to_numpy()
        s = phishing_scores(pipe, X)
        error_analysis[ek] = {"model": chosen, "threshold": ex[chosen]["threshold"]["threshold"],
                              "slices": slice_errors(y, s, ex[chosen]["threshold"]["threshold"], build_slices(frame, sp["test"]))}

    # ---- Experiment C + rule baseline: shortcut diagnostics (domain-grouped partitions)
    log("Shortcut diagnostics")
    tm_tr = frame["is_template"].to_numpy()[split_b["train"]]
    tm_va = frame["is_template"].to_numpy()[split_b["val"]]
    tm_te = frame["is_template"].to_numpy()[split_b["test"]]
    def _both(y, m):
        return len(np.unique(y[m])) == 2
    can_c = _both(ytr_b_all := frame["label"].to_numpy()[split_b["train"]], tm_tr) and _both(frame["label"].to_numpy()[split_b["val"]], tm_va) and _both(yte_b, tm_te)
    Xtr_b = frame.iloc[split_b["train"]][FEATURE_NAMES]; ytr_b = ytr_b_all
    Xva_b = frame.iloc[split_b["val"]][FEATURE_NAMES]; yva_b = frame["label"].iloc[split_b["val"]].to_numpy()
    rule_scores = np.where(tm_te, 0.0, 1.0)  # phishing score 0 for template URLs, 1 otherwise
    rule_metrics = compute_metrics(yte_b, rule_scores, 0.5)
    sd = {
        "template_definition": "scheme is https, hostname starts with 'www.', and the URL has no path, query or fragment",
        "template_rows_by_class": summary["template_rows"],
        "test_template_rows_by_class": {CLASS_NAMES[l]: int(((yte_b == l) & tm_te).sum()) for l in (0, 1)},
        "rule_baseline_domain_grouped_test": rule_metrics,
    }
    share = audit["shortcut_analysis"]["share_matching_template_https_www_no_path"]
    text = (f"{share['legitimate']:.1%} of legitimate URLs in the dataset match the https://www.<host> no-path template (phishing: {share['phishing']:.1%}), "
            f"so a one-line rule that predicts 'legitimate' only for that template already reaches accuracy {rule_metrics['accuracy']:.4f} and phishing recall "
            f"{rule_metrics['per_class']['phishing']['recall']:.4f} on the domain-grouped test set.")
    if can_c:
        slice_eval = compute_metrics(yte_b[tm_te], te_scores[tm_te], thr, with_curves=False)
        pipe_c, secs_c = fit_one(chosen, exp_b[chosen]["best_params"], Xtr_b[tm_tr], ytr_b[tm_tr], Xva_b[tm_va], yva_b[tm_va], args.seed, args.rf_trees)
        thr_c = tune_threshold(yva_b[tm_va], phishing_scores(pipe_c, Xva_b[tm_va]))
        exp_c_metrics = compute_metrics(yte_b[tm_te], phishing_scores(pipe_c, Xte_b[tm_te]), thr_c["threshold"])
        sd["selected_model_on_template_slice_domain_grouped_test"] = slice_eval
        sd["experiment_c_retrained_on_template_rows_only"] = {"model": chosen, "fit_seconds": round(secs_c, 2), "threshold": thr_c, "test_template_slice": exp_c_metrics}
        text += (f" Restricted to template-shaped URLs only, the selected model's phishing recall is {slice_eval['per_class']['phishing']['recall']:.4f} "
                 f"(precision {slice_eval['per_class']['phishing']['precision']:.4f}); a model retrained only on those rows reaches recall "
                 f"{exp_c_metrics['per_class']['phishing']['recall']:.4f} (precision {exp_c_metrics['per_class']['phishing']['precision']:.4f}). "
                 "Headline scores overstate how well the model will do on real legitimate URLs that contain paths, which this dataset does not include.")
    else:
        sd["experiment_c_skipped"] = "Template-shaped rows did not contain both classes in every partition."
        text += " Experiment C was skipped because template-shaped rows lack both classes in every partition."
    sd["summary"] = text

    # ---- manual probe (documented, not a metric)
    probe = []
    quant = {n: np.percentile(Xtr_b[n].to_numpy(), np.arange(101)).tolist() for n in FEATURE_NAMES}
    pf = pd.DataFrame([extract_features(u) for u in PROBE_URLS], columns=FEATURE_NAMES)
    ps = phishing_scores(final, pf)
    for u, s in zip(PROBE_URLS, ps):
        probe.append({"url": u, "phishing_score": float(s), "predicted": CLASS_NAMES[int(predict_from_scores(np.array([s]), thr)[0])]})

    # ---- Step 8: artifacts
    log("Saving artifacts")
    model_path = args.artifacts / "model.joblib"
    joblib.dump(final, model_path, compress=3)
    version = f"{EXTRACTOR_VERSION}-{chosen}-{prep.sha256_file(model_path)[:8]}"
    now = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    deps = {"python": platform.python_version(), "scikit-learn": sklearn.__version__, "numpy": np.__version__, "pandas": pd.__version__, "joblib": joblib.__version__}
    for pkg in ("xgboost", "shap", "publicsuffix2"):
        try:
            deps[pkg] = __import__(pkg).__version__ if pkg != "publicsuffix2" else __import__("importlib.metadata").metadata.version(pkg)
        except Exception:
            pass
    best_params = exp_b[chosen]["best_params"]
    metadata = {
        "model_name": chosen, "model_display_name": DISPLAY[chosen], "model_version": version, "trained_at": now,
        "extractor_version": EXTRACTOR_VERSION, "feature_names": FEATURE_NAMES, "feature_count": len(FEATURE_NAMES),
        "feature_definitions": {k: {"label": v.label, "description": v.description} for k, v in FEATURE_DEFINITIONS.items()},
        "class_mapping": {"0": "phishing", "1": "legitimate"}, "score_definition": "phishing_score = P(class 0) as estimated by the model; not a calibrated real-world probability",
        "decision_threshold": thr, "threshold_selection": exp_b[chosen]["threshold"],
        "hyperparameters": best_params, "explanation_method": explainer.method_label, "explanation_unit": explainer.unit,
        "artifact_file": "model.joblib", "artifact_sha256": prep.sha256_file(model_path), "artifact_format": "joblib (sklearn Pipeline), compress=3",
        "trained_on": "domain-grouped training partition (the same model that was evaluated; the test partition was never used for fitting or tuning)",
        "preprocessing": {"max_url_length": MAX_URL_LENGTH, "suspicious_tokens": list(SUSPICIOUS_TOKENS), "scheme_policy": "inputs without a scheme are analysed as http://<input>",
                          "dedup_policy": "exact duplicate URLs and same-label near duplicates (case-insensitive, trailing slash) removed; conflicting labels dropped (none found)"},
        "dataset": {"name": "PhiUSIIL Phishing URL Dataset", "source": "UCI ML Repository #967", "license": "CC BY 4.0",
                    "citation": "Prasad, A. & Chandra, S. (2024). PhiUSIIL: A diverse security profile empowered phishing URL detection framework based on similarity index and incremental learning. Computers & Security, 136, 103545. https://doi.org/10.1016/j.cose.2023.103545",
                    "file_sha256": audit["sha256"], "rows_raw": audit["rows"], "rows_clean": summary["rows_out"]},
        "dependencies": deps, "seed": args.seed, "feature_quantiles": quant,
    }
    (args.artifacts / "model_metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    report = {
        "generated_at": now, "seed": args.seed, "total_runtime_seconds": round(time.perf_counter() - t_start, 1),
        "selected": selection, "headline_experiment": "domain_grouped",
        "preprocessing_summary": summary,
        "experiments": {
            "stratified": {"description": "Stratified 70/15/15 holdout on de-duplicated URLs. Domains may appear in several partitions, so scores are optimistic.",
                           "split": prep.describe_split(frame, split_a), "verification": ver_a, "models": exp_a},
            "domain_grouped": {"description": "StratifiedGroupKFold-derived ~70/15/15 split grouped by registrable domain: no domain appears in more than one partition.",
                               "split": prep.describe_split(frame, split_b), "verification": ver_b, "models": exp_b},
        },
        "shortcut_diagnostics": sd,
        "feature_importance": {"model": chosen, "method": explainer.method_label, "unit": explainer.unit, "sample_rows": int(len(sample)),
                               "selected_model_shap": fi_rows, "native": exp_b[chosen]["native_importance"]},
        "error_analysis": error_analysis,
        "manual_probe": {"note": "Ten hand-picked, well-known legitimate URLs scored by the final model. This is a sanity check, not a metric.", "results": probe},
        "limitations": [
            "URL-only: no page content, no live reputation, no WHOIS/DNS data.",
            "All legitimate training URLs are https://www.<host> homepages without paths; phishing URLs are far more varied. The model may flag real legitimate URLs that contain paths or lack 'www'.",
            "Domain-grouped results are more conservative than the stratified holdout but still come from one collection of URLs from a limited time window.",
            "Scores are model estimates and were not calibrated against real-world base rates.",
        ],
    }
    (args.artifacts / "evaluation_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (args.artifacts / "dataset_audit.json").write_text(json.dumps(audit, indent=2), encoding="utf-8")
    (args.reports / "dataset_audit.json").write_text(json.dumps(audit, indent=2), encoding="utf-8")
    log("Rendering figures")
    figs = make_plots(report, args.reports / "figures")
    write_markdown(report, args.reports / "evaluation_summary.md")
    log(f"Done in {time.perf_counter() - t_start:.0f}s. Figures: {figs}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
