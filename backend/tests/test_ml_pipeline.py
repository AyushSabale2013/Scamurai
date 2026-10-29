import json

import joblib
import numpy as np
import pandas as pd

from app.ml import preprocessing as prep
from app.ml.evaluation import PHISHING, phishing_scores, predict_from_scores, tune_threshold
from app.ml.feature_extraction import FEATURE_NAMES, extract_features
from app.ml.model_loader import ModelUnavailableError, load_model


def _frame(csv):
    raw = prep.load_raw(csv)
    return raw, *prep.clean_and_extract(raw)


def test_label_mapping_documented_and_applied(synthetic_csv):
    raw, frame, _ = _frame(synthetic_csv)
    # legitimate synthetic URLs are the short https://www.* ones and carry label 1
    assert frame.loc[frame.url.str.startswith("https://www."), "label"].eq(1).all()
    assert prep.LABEL_MAP == {0: "phishing", 1: "legitimate"}


def test_duplicates_removed_and_counted(synthetic_csv):
    raw, frame, summary = _frame(synthetic_csv)
    assert summary["exact_duplicate_rows_removed"] >= 1
    assert frame["url"].is_unique
    assert summary["rows_in"] - summary["rows_out"] == summary["rows_removed_total"]


def test_features_finite_and_ordered(synthetic_csv):
    _, frame, _ = _frame(synthetic_csv)
    assert np.isfinite(frame[FEATURE_NAMES].to_numpy()).all()
    assert list(frame[FEATURE_NAMES].columns) == FEATURE_NAMES


def test_splits_reproducible_disjoint_and_grouped(synthetic_csv):
    _, frame, _ = _frame(synthetic_csv)
    a1, a2 = prep.stratified_split(frame, 7), prep.stratified_split(frame, 7)
    b1, b2 = prep.grouped_split(frame, 7), prep.grouped_split(frame, 7)
    for k in a1:
        assert np.array_equal(a1[k], a2[k]) and np.array_equal(b1[k], b2[k])
    va = prep.verify_split(frame, a1, grouped=False)
    vb = prep.verify_split(frame, b1, grouped=True)  # asserts zero URL + domain overlap internally
    assert all(v == 0 for v in va["url_overlap"].values())
    assert all(v == 0 for v in vb["domain_overlap"].values())
    # both classes present in every grouped partition
    for part in b1.values():
        assert set(frame["label"].iloc[part]) == {0, 1}


def test_feature_consistency_training_vs_inference(synthetic_csv):
    """Training-time matrix rows must equal what the API path computes for the same URL."""
    _, frame, _ = _frame(synthetic_csv)
    for i in range(0, len(frame), 97):
        row = frame.iloc[i]
        assert extract_features(row["url"]) == {k: row[k] for k in FEATURE_NAMES}


def test_artifacts_saved_and_loadable(trained_dir):
    meta = json.loads((trained_dir / "model_metadata.json").read_text())
    assert meta["feature_names"] == FEATURE_NAMES and meta["class_mapping"] == {"0": "phishing", "1": "legitimate"}
    assert 0.0 < meta["decision_threshold"] < 1.0 and meta["model_version"] and meta["dependencies"]["scikit-learn"]
    loaded = load_model(trained_dir)
    again = joblib.load(trained_dir / "model.joblib")
    X = pd.DataFrame([extract_features("https://www.example.com"), extract_features("http://x-login99.xyz/a/b.php?id=1")], columns=FEATURE_NAMES)
    assert np.allclose(loaded.pipeline.predict_proba(X), again.predict_proba(X))


def test_probability_maps_to_correct_class(trained_dir):
    m = load_model(trained_dir)
    X = pd.DataFrame([extract_features("https://www.example.com"), extract_features("http://secure-login123.xyz/abcdefgh/ijklm.php?id=777")], columns=FEATURE_NAMES)
    scores = phishing_scores(m.pipeline, X)
    assert list(m.pipeline.classes_) == [0, 1]
    assert np.allclose(scores, m.pipeline.predict_proba(X)[:, 0])  # column 0 == class 0 == phishing
    assert scores[1] > scores[0]
    assert list(predict_from_scores(scores, m.threshold)) == [1, 0]


def test_threshold_tuned_on_validation_only_signature():
    y = np.array([0, 0, 0, 1, 1, 1])
    s = np.array([0.9, 0.8, 0.4, 0.3, 0.2, 0.1])
    t = tune_threshold(y, s)
    assert 0.0 <= t["threshold"] <= 1.0 and t["val_recall"] == 1.0


def test_report_contains_both_experiments_and_all_models(trained_dir):
    rep = json.loads((trained_dir / "evaluation_report.json").read_text())
    assert set(rep["experiments"]) == {"stratified", "domain_grouped"}
    for ex in rep["experiments"].values():
        assert set(ex["models"]) == {"logistic_regression", "random_forest", "xgboost"}
        for m in ex["models"].values():
            for key in ("accuracy", "macro_f1", "weighted_f1", "roc_auc", "pr_auc_phishing", "confusion_matrix", "classification_report"):
                assert key in m["test"]
            assert m["fit_seconds"] >= 0 and m["latency"]["p50_ms"] > 0 and m["model_size_bytes"] > 0
    assert rep["selected"]["chosen"] in ex["models"]


def test_loader_rejects_tampered_or_missing_artifacts(trained_dir, tmp_path):
    import shutil

    try:
        load_model(tmp_path)
        raise AssertionError("expected failure")
    except ModelUnavailableError:
        pass
    for f in ("model.joblib", "model_metadata.json"):
        shutil.copy(trained_dir / f, tmp_path / f)
    (tmp_path / "model.joblib").write_bytes((tmp_path / "model.joblib").read_bytes() + b"x")
    try:
        load_model(tmp_path)
        raise AssertionError("expected checksum failure")
    except ModelUnavailableError as e:
        assert "checksum" in str(e)
