"""Fetch phishing URLs from free, public feeds.

Sources:
  1. OpenPhish community feed (https://openphish.com/feed.txt)
  2. Phishing.Database (GitHub, mitchellkrogza) — active URLs
  3. PhiUSIIL dataset phishing class (supplementary, from local CSV)

Never visits, renders or executes any URL.
"""

import csv
import datetime as dt
import hashlib
import json
import os
import sys
import time
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError

PROJ = Path(__file__).resolve().parents[2]
RAW = PROJ / "data" / "raw"
INTERIM = PROJ / "data" / "interim"

USER_AGENT = "Scamurai-DataCollector/1.0 (+https://github.com/AyushSabale2013/Scamurai; research)"
TIMEOUT = 30


def _fetch(url: str, label: str) -> tuple[list[str], dict]:
    """Download a text file of URLs, one per line. Returns (urls, metadata)."""
    print(f"  Fetching {label}: {url}")
    req = Request(url, headers={"User-Agent": USER_AGENT})
    meta = {"source": label, "url": url, "retrieved_at": dt.datetime.utcnow().isoformat() + "Z"}
    try:
        with urlopen(req, timeout=TIMEOUT) as resp:
            raw = resp.read()
            meta["status"] = resp.status
            meta["content_length"] = len(raw)
            text = raw.decode("utf-8", errors="replace")
    except (URLError, OSError) as e:
        print(f"    FAILED: {e}")
        meta["error"] = str(e)
        return [], meta

    urls = []
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and ("://" in line or "." in line):
            urls.append(line)
    meta["url_count"] = len(urls)
    meta["sha256"] = hashlib.sha256(raw).hexdigest()
    print(f"    Got {len(urls)} URLs")
    return urls, meta


def fetch_openphish() -> tuple[list[str], dict]:
    return _fetch("https://openphish.com/feed.txt", "openphish_community")


def fetch_phishing_database() -> tuple[list[str], dict]:
    """Fetch from Phishing.Database GitHub repo (mitchellkrogza)."""
    base = "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master"
    all_urls = []
    metas = []
    
    # 1. NEW-today
    urls, meta = _fetch(base + "/phishing-links-NEW-today.txt", "phishing_database_new_today")
    all_urls.extend(urls)
    metas.append(meta)

    # 2. Sample from ACTIVE using Range request or chunk limit (first 2MB ~ 25,000 URLs)
    print("  Fetching sample from ACTIVE phishing links...")
    req = Request(base + "/phishing-links-ACTIVE.txt", headers={"User-Agent": USER_AGENT})
    try:
        with urlopen(req, timeout=15) as resp:
            raw = resp.read(2097152)  # Read first 2MB only
            text = raw.decode("utf-8", errors="replace")
            active_urls = [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#") and ("://" in line or "." in line)]
            all_urls.extend(active_urls)
            metas.append({"source": "phishing_database_active_sample", "url_count": len(active_urls), "retrieved_bytes": len(raw)})
            print(f"    Got {len(active_urls)} active phishing URLs from sample")
    except Exception as e:
        print(f"    Sample failed: {e}")
        metas.append({"source": "phishing_database_active_sample", "error": str(e)})

    combined_meta = {
        "source": "phishing_database_github",
        "sub_sources": metas,
        "total_urls": len(all_urls),
        "retrieved_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "license": "MIT (https://github.com/mitchellkrogza/Phishing.Database/blob/master/LICENSE.md)",
    }
    return all_urls, combined_meta


def load_phiusiil_phishing(csv_path: Path) -> tuple[list[str], dict]:
    """Extract phishing URLs (label=0) from the PhiUSIIL dataset."""
    print(f"  Loading PhiUSIIL phishing from {csv_path}")
    urls = []
    with open(csv_path, encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get("label", "").strip() == "0":
                url = row.get("URL", "").strip()
                if url:
                    urls.append(url)
    meta = {
        "source": "phiusiil_uci_967_phishing_class",
        "file": csv_path.name,
        "sha256": hashlib.sha256(csv_path.read_bytes()).hexdigest(),
        "url_count": len(urls),
        "license": "CC BY 4.0",
        "citation": "Prasad, A. & Chandra, S. (2024). PhiUSIIL Phishing URL Dataset. UCI ML Repository #967.",
    }
    print(f"    Got {len(urls)} phishing URLs")
    return urls, meta


def main():
    INTERIM.mkdir(parents=True, exist_ok=True)
    all_phishing = []
    all_meta = []

    print("=== Fetching phishing URLs ===")

    # 1. OpenPhish
    urls, meta = fetch_openphish()
    for u in urls:
        all_phishing.append({"url": u, "source": "openphish", "label": 0})
    all_meta.append(meta)
    time.sleep(2)

    # 2. Phishing.Database
    urls, meta = fetch_phishing_database()
    for u in urls:
        all_phishing.append({"url": u, "source": "phishing_database", "label": 0})
    all_meta.append(meta)

    # 3. PhiUSIIL
    phiusiil_csv = RAW / "PhiUSIIL_Phishing_URL_Dataset.csv"
    if phiusiil_csv.exists():
        urls, meta = load_phiusiil_phishing(phiusiil_csv)
        for u in urls:
            all_phishing.append({"url": u, "source": "phiusiil", "label": 0})
        all_meta.append(meta)
    else:
        print(f"  PhiUSIIL CSV not found at {phiusiil_csv}, skipping")
        all_meta.append({"source": "phiusiil", "error": "file not found"})

    # Deduplicate by lowercased URL
    seen = set()
    deduped = []
    for entry in all_phishing:
        key = entry["url"].lower().rstrip("/")
        if key not in seen:
            seen.add(key)
            deduped.append(entry)

    print(f"\n=== Summary ===")
    print(f"  Total phishing URLs (raw): {len(all_phishing)}")
    print(f"  Total phishing URLs (deduped): {len(deduped)}")

    # Save
    out_csv = INTERIM / "phishing_urls.csv"
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["url", "source", "label"])
        w.writeheader()
        w.writerows(deduped)
    print(f"  Saved to {out_csv}")

    manifest_path = INTERIM / "phishing_manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump({
            "generated_at": dt.datetime.utcnow().isoformat() + "Z",
            "sources": all_meta,
            "total_raw": len(all_phishing),
            "total_deduped": len(deduped),
        }, f, indent=2)
    print(f"  Manifest: {manifest_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
