"""Build real external challenge set and synthetic smoke tests.

1. `backend/tests/challenge_set.csv`:
   - 500 genuine phishing URLs from live feeds (OpenPhish, Phishing.Database)
   - 500 genuine legitimate URLs from held-out domains and hand-verified list
   - REAL provenance recorded honestly in `data/MANIFEST.json`

2. `backend/tests/synthetic_smoke_tests.csv`:
   - Hand-crafted edge-case patterns (punycode, @ trick, IP hosts, UUIDs)
   - Clearly documented as synthetic test vectors, NOT empirical threat feeds.
"""

import csv
import json
import random
from pathlib import Path

PROJ = Path(__file__).resolve().parents[2]
INTERIM = PROJ / "data" / "interim"
PROCESSED = PROJ / "data" / "processed"
TESTS = PROJ / "backend" / "tests"
SEED = 42

random.seed(SEED)

def build_real_challenge():
    # 1. Genuine phishing from OpenPhish / Phishing.Database
    phish_path = INTERIM / "phishing_urls.csv"
    real_phish = []
    with open(phish_path, encoding="utf-8") as f:
        for r in csv.DictReader(f):
            # Prefer fresh feeds over PhiUSIIL
            if r["source"] in ("openphish", "phishing_database"):
                real_phish.append(r["url"])
    
    # 2. Genuine legitimate from known good + held-out test set
    kg_path = TESTS / "known_good_urls.csv"
    real_legit = []
    if kg_path.exists():
        with open(kg_path, encoding="utf-8") as f:
            for r in csv.DictReader(f):
                real_legit.append(r["url"])

    dataset_path = PROCESSED / "dataset.csv"
    splits_path = PROCESSED / "splits.csv"
    test_indices = set()
    with open(splits_path, encoding="utf-8") as f:
        for r in csv.DictReader(f):
            if r["split"] == "test":
                test_indices.add(int(r["index"]))

    with open(dataset_path, encoding="utf-8") as f:
        for i, r in enumerate(csv.DictReader(f)):
            if i in test_indices and r["label"] == "1":
                real_legit.append(r["url"])

    # Sample 500 of each
    random.shuffle(real_phish)
    random.shuffle(real_legit)

    sampled_phish = real_phish[:500]
    sampled_legit = real_legit[:500]

    out_csv = TESTS / "challenge_set.csv"
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["url", "label", "category", "provenance"])
        for u in sampled_phish:
            w.writerow([u, 0, "phishing", "live_threat_feed_openphish_or_phishing_db"])
        for u in sampled_legit:
            w.writerow([u, 1, "legitimate", "held_out_domains_and_verified_sites"])

    print(f"Wrote {len(sampled_phish)} phishing and {len(sampled_legit)} legitimate URLs to {out_csv}")

    # Also build synthetic_smoke_tests.csv
    smoke_csv = TESTS / "synthetic_smoke_tests.csv"
    with open(smoke_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["url", "label", "pattern_type", "description"])
        w.writerow(["http://192.168.1.100:8080/secure/paypal/login.php", 0, "ip_host", "Synthetic IP host pattern"])
        w.writerow(["http://paypal.com@evil-attacker-site.com/verify", 0, "userinfo_at_trick", "Synthetic @ sign authority trick"])
        w.writerow(["http://xn--pypal-4ve.com/account/security/update", 0, "punycode_homograph", "Synthetic Cyrillic homograph"])
        w.writerow(["https://chatgpt.com/c/6ae3364a-1440-83e8-be31-1e5aefa525c5", 1, "uuid_route", "Real ChatGPT chat session"])
        w.writerow(["https://claude.ai/chat/305c187a-fc1f-4d9a-9063-3f0b53b47a2a", 1, "uuid_route", "Real Claude chat session"])
        w.writerow(["https://onlinesbi.sbi/sbijava/retail/login.htm", 1, "indian_banking", "Real State Bank of India login"])
        w.writerow(["https://irctc.co.in/nget/train-search", 1, "indian_gov", "Real IRCTC booking search"])
    print(f"Wrote synthetic smoke tests to {smoke_csv}")

if __name__ == "__main__":
    build_real_challenge()
