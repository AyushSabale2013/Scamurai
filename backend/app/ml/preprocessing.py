"""Dataset audit, cleaning, feature-matrix construction and split strategies.

Training examples come ONLY from the raw ``URL`` column and the ``label``
column. Every other dataset column (``FILENAME``, ``Title``, ``Domain``,
``TLD`` and all precomputed / webpage-derived features) is excluded because the
deployed model must only use values reproducible from a URL string.
"""

from __future__ import annotations

import hashlib
import collections
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedGroupKFold, train_test_split

from .feature_extraction import (
    FEATURE_NAMES, URLValidationError, extract_features_from_parsed, parse_url,
)

SEED = 42
LABEL_MAP = {0: "phishing", 1: "legitimate"}


def sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while block := fh.read(chunk):
            h.update(block)
    return h.hexdigest()


def load_raw(csv_path: Path) -> pd.DataFrame:
    # utf-8-sig strips the byte-order mark that is present in the original file.
    return pd.read_csv(csv_path, encoding="utf-8-sig")


def audit_dataset(df: pd.DataFrame, csv_path: Path) -> dict[str, Any]:
    """Recompute every dataset statistic from the file as it is now."""
    audit: dict[str, Any] = {
        "file": csv_path.name,
        "sha256": sha256_file(csv_path),
        "size_bytes": csv_path.stat().st_size,
        "encoding": "utf-8 with BOM (read with utf-8-sig)",
        "rows": int(len(df)),
        "columns": int(df.shape[1]),
        "column_names": list(df.columns),
        "missing_values_total": int(df.isna().sum().sum()),
        "exact_duplicate_rows": int(df.duplicated().sum()),
        "duplicate_url_rows": int(df["URL"].duplicated().sum()),
        "label_counts": {str(k): int(v) for k, v in df["label"].value_counts().sort_index().items()},
    }
    dup = df[df["URL"].duplicated(keep=False)]
    per_url = dup.groupby("URL")["label"].nunique()
    audit["duplicate_url_groups"] = int(len(per_url))
    audit["duplicate_url_groups_with_conflicting_labels"] = int((per_url > 1).sum())
    key = df["URL"].str.lower().str.rstrip("/")
    audit["case_insensitive_duplicate_rows"] = int(df["URL"].str.lower().duplicated().sum())
    audit["near_duplicate_rows_lowercase_trailing_slash"] = int(key.duplicated().sum())

    # --- label-mapping evidence (documentation says 1=legitimate, 0=phishing) ---
    ev_cols = [c for c in ("URLSimilarityIndex", "HasSocialNet", "HasCopyrightInfo", "HasDescription") if c in df.columns]
    ev = df.groupby("label")[ev_cols].mean() if ev_cols else pd.DataFrame()
    audit["label_mapping_evidence"] = {
        "documented_mapping": {"0": "phishing", "1": "legitimate"},
        "documentation_source": "UCI ML Repository dataset 967: 'Label 1 corresponds to a legitimate URL, label 0 to a phishing URL'.",
        "mean_of_webpage_columns_by_label": {str(k): {c: round(float(v), 4) for c, v in row.items()} for k, row in ev.iterrows()},
        "interpretation": "Label 1 rows have a higher mean URLSimilarityIndex and more social/copyright markers, consistent with label 1 = legitimate.",
    }

    # --- shortcut / collection-artifact analysis (URL string only) ---
    scheme = df["URL"].str.extract(r"^(\w+)://")[0]
    www = df["URL"].str.contains(r"^\w+://www\.", regex=True)
    rest = df["URL"].str.replace(r"^\w+://[^/?#]*", "", regex=True)
    has_path = ~rest.isin(["", "/"])
    tmpl = (scheme == "https") & www & ~has_path

    def share(mask: pd.Series) -> dict[str, float]:
        return {LABEL_MAP[l]: round(float(mask[df["label"] == l].mean()), 4) for l in (0, 1)}

    audit["shortcut_analysis"] = {
        "share_https_scheme": share(scheme == "https"),
        "share_www_prefix": share(www),
        "share_with_path_query_or_fragment": share(has_path),
        "share_matching_template_https_www_no_path": share(tmpl),
        "finding": ("Every legitimate URL in this file is an https://www.<host> address with no path, query "
                    "or fragment, while phishing URLs vary. A URL-only model can therefore reach very high "
                    "accuracy by learning this collection pattern, which may not hold for real legitimate URLs "
                    "that contain paths."),
    }
    if "URLLength" in df.columns:
        audit["url_length_vs_URLLength_column_equal_share"] = round(float((df["URL"].str.len() == df["URLLength"]).mean()), 4)
    audit["url_length_distribution"] = {k: float(v) for k, v in df["URL"].str.len().describe().items()}
    audit["excluded_columns_and_reason"] = {
        "FILENAME": "identifier of the crawled page; may encode collection order",
        "Title": "webpage text, not available from a URL string",
        "Domain": "derived from URL; recomputed consistently by the shared extractor instead",
        "TLD": "derived from URL; recomputed by the shared extractor using the Public Suffix List",
        "precomputed URL features (URLLength, NoOfLettersInURL, ...)": "stored values did not reproduce from the URL (e.g. URLLength equals len(URL) for only the share above)",
        "URLSimilarityIndex, TLDLegitimateProb, URLCharProb, CharContinuationRate, DomainTitleMatchScore, URLTitleMatchScore": "need webpage content or dataset-wide reference tables",
        "all HTML/JS/page columns (LineOfCode, HasPasswordField, NoOfImage, NoOfJS, ...)": "require fetching the page, which this project never does",
    }
    return audit


def clean_and_extract(df: pd.DataFrame) -> tuple[pd.DataFrame, dict[str, Any]]:
    """Validate, de-duplicate and extract features. Returns (frame, summary).

    The frame has: url, label, group (registrable domain), is_template (the
    https://www.<host> no-path pattern) and the FEATURE_NAMES columns.
    """
    summary: dict[str, Any] = {"rows_in": int(len(df))}
    d = df[["URL", "label"]].copy()

    bad_url = d["URL"].isna() | (d["URL"].astype(str).str.strip() == "")
    bad_label = ~d["label"].isin([0, 1])
    summary["dropped_invalid_url_or_label"] = int((bad_url | bad_label).sum())
    d = d[~(bad_url | bad_label)].copy()
    d["URL"] = d["URL"].astype(str)
    d["label"] = d["label"].astype(int)

    # 1. exact duplicate URLs. Conflicting labels would be dropped entirely.
    nlab = d.groupby("URL")["label"].transform("nunique")
    conflicts = d[nlab > 1]
    summary["exact_duplicate_conflicting_label_rows_dropped"] = int(len(conflicts))
    d = d[nlab == 1]
    before = len(d)
    d = d.drop_duplicates(subset="URL", keep="first")
    summary["exact_duplicate_rows_removed"] = int(before - len(d))

    # 2. near duplicates (case-insensitive, trailing slash). Same label -> keep first; conflicting -> keep all.
    key = d["URL"].str.lower().str.rstrip("/")
    nlab_key = d.groupby(key)["label"].transform("nunique")
    dup_key = key.duplicated(keep="first") & (nlab_key == 1)
    summary["near_duplicate_rows_removed_same_label"] = int(dup_key.sum())
    summary["near_duplicate_groups_with_conflicting_labels_kept"] = int(((nlab_key > 1) & key.duplicated(keep="first")).sum())
    d = d[~dup_key]

    # 3. feature extraction with the shared extractor
    feats, urls, labels, groups, tmpl = [], [], [], [], []
    failures: collections.Counter[str] = collections.Counter()
    for url, lab in zip(d["URL"].to_numpy(), d["label"].to_numpy()):
        try:
            p = parse_url(url)
            f = extract_features_from_parsed(p)
        except URLValidationError as exc:
            failures[exc.code] += 1
            continue
        feats.append([f[k] for k in FEATURE_NAMES])
        urls.append(url)
        labels.append(lab)
        groups.append(p.registrable)
        tmpl.append(p.scheme == "https" and p.host.startswith("www.") and p.path in ("", "/") and not p.query and not p.fragment)
    summary["dropped_by_extractor"] = dict(failures)
    summary["dropped_by_extractor_total"] = int(sum(failures.values()))

    X = pd.DataFrame(feats, columns=FEATURE_NAMES, dtype="float64")
    X.insert(0, "is_template", np.asarray(tmpl, dtype=bool))
    X.insert(0, "group", groups)
    X.insert(0, "label", np.asarray(labels, dtype=int))
    X.insert(0, "url", urls)
    assert np.isfinite(X[FEATURE_NAMES].to_numpy()).all(), "non-finite feature values"

    summary["rows_out"] = int(len(X))
    summary["rows_removed_total"] = int(summary["rows_in"] - len(X))
    summary["label_counts_out"] = {str(k): int(v) for k, v in X["label"].value_counts().sort_index().items()}
    summary["unique_registrable_domains"] = int(X["group"].nunique())
    g = X.groupby("group")["label"].agg(["nunique", "size"])
    summary["domains_with_mixed_labels"] = int((g["nunique"] > 1).sum())
    summary["domains_with_multiple_urls"] = int((g["size"] > 1).sum())
    summary["largest_domain_groups"] = [{"rows": int(n)} for n in g["size"].sort_values(ascending=False).head(5)]
    summary["template_rows"] = {LABEL_MAP[l]: int(((X["label"] == l) & X["is_template"]).sum()) for l in (0, 1)}
    return X.reset_index(drop=True), summary


def _dist(y: np.ndarray) -> dict[str, int]:
    return {LABEL_MAP[k]: int((y == k).sum()) for k in (0, 1)}


def stratified_split(frame: pd.DataFrame, seed: int = SEED) -> dict[str, np.ndarray]:
    """Experiment A: 70/15/15 stratified split on URL-level examples."""
    idx = np.arange(len(frame))
    y = frame["label"].to_numpy()
    tr, rest = train_test_split(idx, test_size=0.30, stratify=y, random_state=seed)
    va, te = train_test_split(rest, test_size=0.50, stratify=y[rest], random_state=seed)
    return {"train": tr, "val": va, "test": te}


def grouped_split(frame: pd.DataFrame, seed: int = SEED) -> dict[str, np.ndarray]:
    """Experiment B: ~70/15/15 split in which no registrable domain crosses partitions."""
    idx = np.arange(len(frame))
    y = frame["label"].to_numpy()
    g = frame["group"].to_numpy()
    outer = StratifiedGroupKFold(n_splits=7, shuffle=True, random_state=seed)
    rest, te = next(outer.split(idx, y, g))
    inner = StratifiedGroupKFold(n_splits=6, shuffle=True, random_state=seed)
    tr_i, va_i = next(inner.split(rest, y[rest], g[rest]))
    return {"train": rest[tr_i], "val": rest[va_i], "test": te}


def describe_split(frame: pd.DataFrame, split: dict[str, np.ndarray]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    total = len(frame)
    for name, ix in split.items():
        y = frame["label"].to_numpy()[ix]
        out[name] = {"rows": int(len(ix)), "share": round(len(ix) / total, 4), "labels": _dist(y),
                     "phishing_share": round(float((y == 0).mean()), 4),
                     "domains": int(frame["group"].iloc[ix].nunique())}
    return out


def verify_split(frame: pd.DataFrame, split: dict[str, np.ndarray], grouped: bool) -> dict[str, Any]:
    urls = {k: set(frame["url"].iloc[v]) for k, v in split.items()}
    doms = {k: set(frame["group"].iloc[v]) for k, v in split.items()}
    pairs = [("train", "val"), ("train", "test"), ("val", "test")]
    res = {
        "url_overlap": {f"{a}-{b}": len(urls[a] & urls[b]) for a, b in pairs},
        "domain_overlap": {f"{a}-{b}": len(doms[a] & doms[b]) for a, b in pairs},
        "indices_disjoint": all(not (set(split[a]) & set(split[b])) for a, b in pairs),
    }
    assert all(v == 0 for v in res["url_overlap"].values()), "URL leaked across partitions"
    assert res["indices_disjoint"]
    if grouped:
        assert all(v == 0 for v in res["domain_overlap"].values()), "domain leaked across partitions"
    return res
