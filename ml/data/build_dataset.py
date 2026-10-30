"""Build the final combined dataset from phishing and legitimate URL CSVs.

Workflow:
  1. Load interim/phishing_urls.csv and interim/legitimate_urls.csv
  2. Normalize, clean, deduplicate
  3. Resolve cross-class conflicts
  4. Shape-audit: check for collection artifacts
  5. Create temporal-grouped + stratified splits
  6. Save processed dataset, splits, manifest, and shape audit

Never visits any URL. All processing is string-based.
"""

import csv
import datetime as dt
import hashlib
import json
import os
import random
import re
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

import numpy as np

PROJ = Path(__file__).resolve().parents[2]
INTERIM = PROJ / "data" / "interim"
PROCESSED = PROJ / "data" / "processed"
SEED = 42

# User-content platforms where both phishing and legit URLs coexist
USER_CONTENT_PLATFORMS = {
    "github.io", "pages.dev", "weebly.com", "wixsite.com", "firebaseapp.com",
    "blogspot.com", "wordpress.com", "herokuapp.com", "netlify.app", "vercel.app",
    "web.app", "appspot.com", "azurewebsites.net", "000webhostapp.com",
    "sites.google.com", "docs.google.com", "forms.gle",
}


def normalize_url(url: str) -> str:
    """Lowercase scheme and host, strip fragment, basic cleanup."""
    url = url.strip()
    if not url:
        return ""

    # Add scheme if missing
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.\-]*://', url):
        url = "http://" + url

    try:
        parsed = urlparse(url)
    except Exception:
        return ""

    scheme = (parsed.scheme or "http").lower()
    if scheme not in ("http", "https"):
        return ""  # reject non-http schemes

    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        return ""

    port = ""
    if parsed.port and parsed.port not in (80, 443):
        port = f":{parsed.port}"

    path = parsed.path or ""
    query = f"?{parsed.query}" if parsed.query else ""
    # Keep fragments for analysis but normalize
    fragment = ""  # strip fragments for dedup purposes

    return f"{scheme}://{host}{port}{path}{query}{fragment}"


def get_registrable_domain(url: str) -> str:
    """Simple registrable domain extraction."""
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower().rstrip(".")
        if not host:
            return ""
        parts = host.split(".")
        if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "gov", "ac", "net", "edu"):
            return ".".join(parts[-3:])
        elif len(parts) >= 2:
            return ".".join(parts[-2:])
        return host
    except Exception:
        return ""


def is_valid_url(url: str) -> bool:
    """Basic URL validity check."""
    if not url or len(url) < 8 or len(url) > 4096:
        return False
    try:
        parsed = urlparse(url)
        return bool(parsed.scheme in ("http", "https") and parsed.hostname)
    except Exception:
        return False


def compute_shape(url: str) -> dict:
    """Compute shape features for shortcut audit."""
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        return {
            "is_https": int(parsed.scheme == "https"),
            "has_www": int(host.startswith("www.")),
            "has_path": int(bool(parsed.path) and parsed.path not in ("", "/")),
            "has_query": int(bool(parsed.query)),
            "has_fragment": int(bool(parsed.fragment)),
            "path_segments": len([s for s in parsed.path.split("/") if s]),
            "url_length_bucket": min(len(url) // 20, 15),  # 0-15
        }
    except Exception:
        return {
            "is_https": 0, "has_www": 0, "has_path": 0,
            "has_query": 0, "has_fragment": 0, "path_segments": 0,
            "url_length_bucket": 0,
        }


def main():
    random.seed(SEED)
    np.random.seed(SEED)
    PROCESSED.mkdir(parents=True, exist_ok=True)

    print("=== Building combined dataset ===")

    # Load interim CSVs
    phishing_csv = INTERIM / "phishing_urls.csv"
    legit_csv = INTERIM / "legitimate_urls.csv"

    if not phishing_csv.exists():
        print(f"ERROR: {phishing_csv} not found. Run fetch_phishing.py first.")
        return 1
    if not legit_csv.exists():
        print(f"ERROR: {legit_csv} not found. Run fetch_legit.py first.")
        return 1

    phishing = []
    with open(phishing_csv, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            phishing.append(row)

    legit = []
    with open(legit_csv, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            legit.append(row)

    print(f"  Loaded: {len(phishing)} phishing, {len(legit)} legitimate")

    # Combine
    all_rows = []
    for row in phishing:
        norm = normalize_url(row["url"])
        if norm and is_valid_url(norm):
            all_rows.append({
                "url": norm,
                "url_raw": row["url"],
                "label": 0,  # phishing
                "source": row.get("source", "unknown"),
            })

    for row in legit:
        norm = normalize_url(row["url"])
        if norm and is_valid_url(norm):
            all_rows.append({
                "url": norm,
                "url_raw": row["url"],
                "label": 1,  # legitimate
                "source": row.get("source", "unknown"),
            })

    print(f"  After normalization: {len(all_rows)} rows")

    # Deduplicate by normalized URL
    # If same URL appears with different labels, check if it's a user-content platform
    url_labels = {}
    url_sources = {}
    for row in all_rows:
        key = row["url"].lower().rstrip("/")
        if key not in url_labels:
            url_labels[key] = set()
            url_sources[key] = row
        url_labels[key].add(row["label"])

    deduped = []
    conflicts_dropped = 0
    conflicts_kept = 0
    for key, labels in url_labels.items():
        row = url_sources[key]
        if len(labels) > 1:
            # URL appears as both phishing and legitimate
            rd = get_registrable_domain(row["url"])
            if any(rd.endswith(p) for p in USER_CONTENT_PLATFORMS):
                # User-content platform: keep as phishing (conservative)
                row["label"] = 0
                row["source"] = row["source"] + "_conflict_resolved_phishing"
                conflicts_kept += 1
                deduped.append(row)
            else:
                # Non-platform conflict: drop
                conflicts_dropped += 1
        else:
            deduped.append(row)

    print(f"  Cross-class conflicts: {conflicts_dropped} dropped, {conflicts_kept} kept (user-content platforms)")
    print(f"  After dedup: {len(deduped)} rows")

    # Add registrable domain and shape features
    for row in deduped:
        row["registrable_domain"] = get_registrable_domain(row["url"])
        shape = compute_shape(row["url"])
        row.update(shape)

    # ---- Shape audit ----
    print("\n=== Shape audit ===")
    phish_rows = [r for r in deduped if r["label"] == 0]
    legit_rows = [r for r in deduped if r["label"] == 1]

    shape_keys = ["is_https", "has_www", "has_path", "has_query", "has_fragment"]
    shape_report = {}
    for key in shape_keys:
        phish_share = sum(r[key] for r in phish_rows) / max(len(phish_rows), 1)
        legit_share = sum(r[key] for r in legit_rows) / max(len(legit_rows), 1)
        shape_report[key] = {
            "phishing": round(phish_share, 4),
            "legitimate": round(legit_share, 4),
            "gap": round(abs(phish_share - legit_share), 4),
        }
        flag = " ⚠️ LARGE GAP" if abs(phish_share - legit_share) > 0.3 else ""
        print(f"  {key}: phish={phish_share:.3f} legit={legit_share:.3f}{flag}")

    # URL length distribution
    phish_lengths = [len(r["url"]) for r in phish_rows]
    legit_lengths = [len(r["url"]) for r in legit_rows]
    shape_report["url_length_mean"] = {
        "phishing": round(np.mean(phish_lengths), 1) if phish_lengths else 0,
        "legitimate": round(np.mean(legit_lengths), 1) if legit_lengths else 0,
    }
    print(f"  URL length mean: phish={shape_report['url_length_mean']['phishing']} legit={shape_report['url_length_mean']['legitimate']}")

    # ---- Save processed dataset ----
    out_csv = PROCESSED / "dataset.csv"
    fieldnames = ["url", "label", "source", "registrable_domain"] + shape_keys + ["path_segments", "url_length_bucket"]
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        for row in deduped:
            w.writerow(row)
    print(f"\n  Saved dataset to {out_csv}")

    # ---- Create splits ----
    # Stratified-grouped split by registrable domain
    domains = list(set(r["registrable_domain"] for r in deduped if r["registrable_domain"]))
    random.shuffle(domains)

    # Group domains by their primary label
    domain_label = {}
    for row in deduped:
        rd = row["registrable_domain"]
        if rd not in domain_label:
            domain_label[rd] = Counter()
        domain_label[rd][row["label"]] += 1

    # Assign each domain to its majority label class
    phish_domains = [d for d in domains if domain_label[d].most_common(1)[0][0] == 0]
    legit_domains = [d for d in domains if domain_label[d].most_common(1)[0][0] == 1]

    # 70/15/15 split
    def split_list(lst, train_frac=0.70, val_frac=0.15):
        n = len(lst)
        n_train = int(n * train_frac)
        n_val = int(n * val_frac)
        return lst[:n_train], lst[n_train:n_train+n_val], lst[n_train+n_val:]

    phish_train_d, phish_val_d, phish_test_d = split_list(phish_domains)
    legit_train_d, legit_val_d, legit_test_d = split_list(legit_domains)

    train_domains = set(phish_train_d + legit_train_d)
    val_domains = set(phish_val_d + legit_val_d)
    test_domains = set(phish_test_d + legit_test_d)

    split_map = {}
    for i, row in enumerate(deduped):
        rd = row["registrable_domain"]
        if rd in train_domains:
            split_map[i] = "train"
        elif rd in val_domains:
            split_map[i] = "val"
        elif rd in test_domains:
            split_map[i] = "test"
        else:
            split_map[i] = "train"  # fallback

    split_counts = Counter(split_map.values())
    split_labels = {}
    for split_name in ["train", "val", "test"]:
        indices = [i for i, s in split_map.items() if s == split_name]
        labels = Counter(deduped[i]["label"] for i in indices)
        split_labels[split_name] = {
            "total": len(indices),
            "phishing": labels.get(0, 0),
            "legitimate": labels.get(1, 0),
        }
        print(f"  {split_name}: {len(indices)} rows (phishing: {labels.get(0, 0)}, legitimate: {labels.get(1, 0)})")

    # Save split assignments
    split_csv = PROCESSED / "splits.csv"
    with open(split_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["index", "split"])
        for i, s in sorted(split_map.items()):
            w.writerow([i, s])
    print(f"  Saved splits to {split_csv}")

    # ---- Manifest ----
    manifest = {
        "generated_at": dt.datetime.utcnow().isoformat() + "Z",
        "total_rows": len(deduped),
        "label_counts": {
            "phishing": len(phish_rows),
            "legitimate": len(legit_rows),
        },
        "source_counts": dict(Counter(r["source"] for r in deduped)),
        "unique_domains": len(domains),
        "conflicts_dropped": conflicts_dropped,
        "conflicts_kept_user_content": conflicts_kept,
        "shape_audit": shape_report,
        "splits": split_labels,
        "split_method": "domain-grouped stratified 70/15/15",
    }

    manifest_path = PROCESSED / "dataset_manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    print(f"  Saved manifest to {manifest_path}")

    # ---- Data manifest for repo (committed) ----
    data_manifest = {
        "generated_at": manifest["generated_at"],
        "sources": [
            {"name": "OpenPhish", "type": "phishing", "url": "https://openphish.com/feed.txt", "license": "Free community feed"},
            {"name": "Phishing.Database", "type": "phishing", "url": "https://github.com/mitchellkrogza/Phishing.Database", "license": "MIT"},
            {"name": "PhiUSIIL", "type": "both", "url": "https://archive.ics.uci.edu/dataset/967", "license": "CC BY 4.0"},
            {"name": "Tranco", "type": "legitimate", "url": "https://tranco-list.eu", "license": "Free (academic use)"},
            {"name": "Common Crawl CDX", "type": "legitimate", "url": "https://index.commoncrawl.org", "license": "CC0 / Terms of Use"},
            {"name": "Hand-verified URLs", "type": "legitimate", "url": "N/A", "license": "N/A"},
        ],
        "total_rows": manifest["total_rows"],
        "label_counts": manifest["label_counts"],
        "splits": manifest["splits"],
    }
    dm_path = PROJ / "data" / "MANIFEST.json"
    with open(dm_path, "w", encoding="utf-8") as f:
        json.dump(data_manifest, f, indent=2)
    print(f"  Saved data manifest to {dm_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
