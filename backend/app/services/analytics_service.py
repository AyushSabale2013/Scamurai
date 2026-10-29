"""Builds API payloads from the SAVED evaluation report and dataset audit only."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..ml.model_loader import AUDIT_FILE, REPORT_FILE, load_json

MODEL_ORDER = ["logistic_regression", "random_forest", "xgboost"]


class ReportUnavailableError(RuntimeError):
    pass


def load_report(artifact_dir: Path) -> dict[str, Any]:
    r = load_json(artifact_dir / REPORT_FILE)
    if r is None:
        raise ReportUnavailableError("Evaluation report not found. Run the training script to generate it.")
    return r


def load_audit(artifact_dir: Path) -> dict[str, Any]:
    a = load_json(artifact_dir / AUDIT_FILE)
    if a is None:
        raise ReportUnavailableError("Dataset audit not found. Run the training script to generate it.")
    return a


def compact_model_rows(report: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for ek, ex in report["experiments"].items():
        for n in MODEL_ORDER:
            m = ex["models"][n]
            t = m["test"]
            p = t["per_class"]["phishing"]
            rows.append({
                "experiment": ek, "model": n, "display_name": m["display_name"], "accuracy": t["accuracy"],
                "phishing_precision": p["precision"], "phishing_recall": p["recall"], "phishing_f1": p["f1"],
                "legitimate_recall": t["per_class"]["legitimate"]["recall"], "macro_f1": t["macro_f1"], "weighted_f1": t["weighted_f1"],
                "roc_auc": t["roc_auc"], "pr_auc": t["pr_auc_phishing"], "threshold": t["threshold"],
                "fit_seconds": m["fit_seconds"], "tuning_seconds": m["tuning"]["tuning_seconds"],
                "latency_p50_ms": m["latency"]["p50_ms"], "latency_p95_ms": m["latency"]["p95_ms"], "model_size_bytes": m["model_size_bytes"],
                "false_negative_rate": t["confusion_matrix"]["phishing_false_negative_rate"],
                "false_positive_rate": t["confusion_matrix"]["legitimate_false_positive_rate"],
            })
    return rows


def headline(report: dict[str, Any]) -> dict[str, Any]:
    chosen = report["selected"]["chosen"]
    ek = report["headline_experiment"]
    m = report["experiments"][ek]["models"][chosen]
    p = m["test"]["per_class"]["phishing"]
    return {"experiment": ek, "model": chosen, "display_name": m["display_name"], "phishing_recall": p["recall"],
            "phishing_precision": p["precision"], "phishing_f1": p["f1"], "pr_auc": m["test"]["pr_auc_phishing"],
            "accuracy": m["test"]["accuracy"], "latency_p50_ms": m["latency"]["p50_ms"], "threshold": m["threshold"]["threshold"]}


def summary(artifact_dir: Path) -> dict[str, Any]:
    report, audit = load_report(artifact_dir), load_audit(artifact_dir)
    pre = report["preprocessing_summary"]
    return {
        "generated_at": report["generated_at"],
        "dataset": {
            "raw_rows": audit["rows"], "clean_rows": pre["rows_out"], "columns": audit["columns"],
            "missing_values": audit["missing_values_total"], "exact_duplicate_rows": audit["exact_duplicate_rows"],
            "duplicate_url_rows": audit["duplicate_url_rows"], "conflicting_duplicate_groups": audit["duplicate_url_groups_with_conflicting_labels"],
            "label_counts_raw": audit["label_counts"], "label_counts_clean": pre["label_counts_out"],
            "label_mapping": {"0": "phishing", "1": "legitimate"},
            "model_features": len(report["experiments"]["domain_grouped"]["models"]["xgboost"]["native_importance"]),
            "unique_registrable_domains": pre["unique_registrable_domains"], "excluded_columns": audit["excluded_columns_and_reason"],
            "shortcut_analysis": audit["shortcut_analysis"], "label_mapping_evidence": audit["label_mapping_evidence"],
            "file_sha256": audit["sha256"],
        },
        "cleaning": pre,
        "splits": {k: {"split": v["split"], "verification": v["verification"], "description": v["description"]} for k, v in report["experiments"].items()},
        "selected": {"chosen": report["selected"]["chosen"], "reason": report["selected"]["reason"], "rule": report["selected"]["rule"]},
        "headline": headline(report),
        "models": compact_model_rows(report),
        "limitations": report["limitations"],
    }
