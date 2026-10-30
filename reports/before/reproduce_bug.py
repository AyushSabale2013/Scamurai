"""Reproduce the reported bug with the current model and save before-results."""
import json, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'backend'))

import joblib
import numpy as np
from app.ml.feature_extraction import extract_features, features_to_vector, FEATURE_NAMES
from app.ml.evaluation import phishing_scores, predict_from_scores

MODEL = os.path.join(os.path.dirname(__file__), '..', '..', 'backend', 'artifacts', 'model.joblib')
META = os.path.join(os.path.dirname(__file__), '..', '..', 'backend', 'artifacts', 'model_metadata.json')

model = joblib.load(MODEL)
with open(META) as f:
    meta = json.load(f)

_dt = meta["decision_threshold"]
threshold = _dt["threshold"] if isinstance(_dt, dict) else float(_dt)

BUG_URLS = [
    "https://claude.ai/chat/305c187a-fc1f-4d9a-9063-3f0b53b47a2a",
    "https://chatgpt.com/c/6ae3364a-1440-83e8-be31-1e5aefa525c5",
    "https://github.com/anthropics/anthropic-sdk-python",
    "https://en.wikipedia.org/wiki/Phishing",
    "https://docs.python.org/3/library/urllib.parse.html",
    "https://www.google.com/search?q=weather+today",
    "https://stackoverflow.com/questions/tagged/python",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://www.google.com",
    "https://www.wikipedia.org",
    "https://mail.google.com/mail/u/0/#inbox",
    "https://irctc.co.in/nget/train-search",
    "https://onlinesbi.sbi/sbijava/retail/login.htm",
    "https://paytm.com/recharge",
]

results = []
for url in BUG_URLS:
    feat = extract_features(url)
    vec = features_to_vector(feat).reshape(1, -1)
    import pandas as pd
    df = pd.DataFrame(vec, columns=FEATURE_NAMES)
    score = phishing_scores(model, df)[0]
    pred = "phishing" if score >= threshold else "legitimate"
    results.append({
        "url": url,
        "phishing_score": round(float(score), 6),
        "threshold": round(threshold, 6),
        "prediction": pred,
        "is_false_positive": pred == "phishing" and url in BUG_URLS[:10],  # all are legit
    })
    print(f"  {pred:12s}  score={score:.4f}  {url}")

out_path = os.path.join(os.path.dirname(__file__), "before_results.json")
with open(out_path, "w") as f:
    json.dump({
        "model_version": meta.get("model_version", "unknown"),
        "model_name": meta.get("model_name", "unknown"),
        "threshold": threshold,
        "results": results,
        "false_positive_count": sum(1 for r in results if r["is_false_positive"]),
        "total_urls": len(results),
    }, f, indent=2)
print(f"\nSaved to {out_path}")
print(f"False positives: {sum(1 for r in results if r['is_false_positive'])}/{len(results)}")
