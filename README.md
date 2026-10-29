# PhishGuard AI

A machine-learning phishing **URL** risk assessor: paste a URL, a trained model scores it from the URL text alone, and the app shows the verdict, the score, and which features moved it. **No submitted URL is ever visited, fetched or rendered.**

* **Backend:** Python, FastAPI, Pydantic, scikit-learn, XGBoost, SHAP
* **Frontend:** React, TypeScript, Vite, Tailwind CSS, TanStack Query, React Router, Recharts, Lucide
* **Data:** [PhiUSIIL Phishing URL Dataset](https://archive.ics.uci.edu/dataset/967) (CC BY 4.0)

> ## Read this first: what the numbers do and do not mean
>
> Every figure below was computed by `python -m app.ml.train` on your copy of the CSV. They are **very high, and you should be sceptical of them.**
>
> The audit found that in this dataset **100.0% of legitimate URLs are plain `https://www.<host>` homepages with no path, query or fragment**, versus 1.0% of phishing URLs. A one-line rule ("legitimate only if the URL looks like that") scores **99.58% accuracy** on the domain-grouped test set, about the same as the trained models. 0.0% of legitimate URLs have a path; 28.4% of phishing URLs do.
>
> Consequences you can verify in the app (Model Lab → "Sanity probe") and in `reports/`:
> * Real, well-known legitimate URLs **with paths** (GitHub repos, Wikipedia articles, news pages) are scored as phishing at ~100%. The app warns about this next to any result whose URL has a path or query.
> * Restricted to template-shaped URLs only (where the shortcut gives no help), the selected model's phishing recall is 57.4% with precision 76.4% (n=141 phishing URLs).
>
> The dataset cannot tell us how the model behaves on real-world legitimate URLs that contain paths. Do not use this project as a production phishing filter, and do not quote the headline numbers as real-world accuracy. Fixing this needs additional legitimate URLs with realistic paths from an independent source, which was out of scope here.

## Results

Phishing is the positive class. Thresholds were tuned on **validation** data only (maximising F2); test partitions were used once, for the numbers below. The two experiments are separate and never averaged.

### Experiment B: domain-grouped (no registrable domain appears in more than one partition). *The more conservative one.*

| Model | Accuracy | Phish. precision | Phish. recall | Phish. F1 | ROC-AUC | PR-AUC | Threshold | Latency p50 | Size |
|---|---|---|---|---|---|---|---|---|---|
| Logistic Regression | 0.9926 | 0.9897 | 0.9927 | 0.9912 | 0.99798 | 0.99849 | 0.084 | 1.04 ms | 2 KB |
| Random Forest | 0.9962 | 0.9956 | 0.9954 | 0.9955 | 0.99851 | 0.99886 | 0.250 | 15.90 ms | 4415 KB |
| XGBoost ★ | 0.9972 | 0.9982 | 0.9951 | 0.9966 | 0.99852 | 0.99884 | 0.229 | 2.14 ms | 90 KB |

Selected model ★ **XGBoost** on its test set: 14,123 of 14,193 phishing URLs caught, 70 missed; 19,240 of 19,265 legitimate URLs passed, 25 falsely flagged.

### Experiment A: stratified holdout (optimistic: 2,346 domains appear in both train and test)

| Model | Accuracy | Phish. precision | Phish. recall | Phish. F1 | ROC-AUC | PR-AUC | Threshold | Latency p50 | Size |
|---|---|---|---|---|---|---|---|---|---|
| Logistic Regression | 0.9926 | 0.9896 | 0.9930 | 0.9913 | 0.99820 | 0.99867 | 0.075 | 1.76 ms | 2 KB |
| Random Forest | 0.9960 | 0.9945 | 0.9962 | 0.9953 | 0.99879 | 0.99905 | 0.197 | 10.64 ms | 4388 KB |
| XGBoost ★ | 0.9976 | 0.9983 | 0.9959 | 0.9971 | 0.99868 | 0.99900 | 0.191 | 3.72 ms | 133 KB |

### Model selection

Rule (domain-grouped **validation** only): rank by phishing F1 at each model's tuned threshold; models within 0.001 F1 of the best are tied; among ties pick the lowest latency, then the smallest file. Accuracy and test results are not used.

| Model | Val F1 | Val recall | Val precision | Latency | Tied for best |
|---|---|---|---|---|---|
| logistic_regression | 0.9919 | 0.9918 | 0.9920 | 1.04 ms | no |
| random_forest | 0.9964 | 0.9952 | 0.9975 | 15.90 ms | yes |
| xgboost | 0.9969 | 0.9951 | 0.9988 | 2.14 ms | yes |

**Revision history, stated openly:** a first draft of the rule (PR-AUC within 0.002 and recall within 0.005 of the best, then fastest) picked Logistic Regression, because those tolerances were wider than the true spread between models and ignored a precision gap on validation. It was replaced with the F1 rule above *before the final run*. By then all three models' test metrics had been printed in the training log, so the choice was not made blind to them, although the rule itself only reads validation numbers. XGBoost and Random Forest are statistically close; XGBoost is smaller and several times faster per request in the timings recorded in the report (single-core machine, so treat latency as indicative).

### Sanity probe (not a metric)

Ten hand-picked, well-known legitimate URLs scored by the shipped model:

| URL | Phishing score | Model says |
|---|---|---|
| `https://github.com/anthropics/anthropic-sdk-python` | 1.000 | phishing |
| `https://en.wikipedia.org/wiki/Phishing` | 1.000 | phishing |
| `https://docs.python.org/3/library/urllib.parse.html` | 1.000 | phishing |
| `https://www.google.com/search?q=weather+today` | 1.000 | phishing |
| `https://www.bbc.com/news/technology` | 1.000 | phishing |
| `https://stackoverflow.com/questions/tagged/python` | 1.000 | phishing |
| `https://www.nytimes.com/section/world` | 1.000 | phishing |
| `https://www.youtube.com/watch?v=dQw4w9WgXcQ` | 1.000 | phishing |
| `https://www.google.com` | 0.003 | legitimate |
| `https://www.wikipedia.org` | 0.002 | legitimate |

## Quick start

Prerequisites: Python 3.11+, Node 20+.

```bash
# 1. Backend
cd backend
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
uvicorn app.main:app --reload --port 8000              # serves the shipped artifacts in backend/artifacts

# 2. Frontend (second terminal)
cd frontend
cp .env.example .env                                    # VITE_API_BASE_URL=http://localhost:8000
npm install
npm run dev                                             # http://localhost:5173
```

API docs (Swagger UI): http://localhost:8000/docs

## Training and evaluation

The CSV is not included in the zip. Place it at `data/raw/PhiUSIIL_Phishing_URL_Dataset.csv` (or pass any path):

```bash
cd backend
python -m app.ml.train --csv ../data/raw/PhiUSIIL_Phishing_URL_Dataset.csv
# options: --seed 42  --rf-trees 150  --sample N (development subset only)
```

It runs the full pipeline in about 5 minutes on one CPU core: dataset audit, cleaning, both split strategies, three models with limited grids, validation threshold tuning, model selection, SHAP summary, error analysis, shortcut diagnostics, plots, and artifact writing. Outputs:

| Path | Content |
|---|---|
| `backend/artifacts/model.joblib` | Selected model (sklearn `Pipeline`), SHA-256 recorded in the metadata |
| `backend/artifacts/model_metadata.json` | Version, feature names and order, threshold, hyperparameters, dependency versions, dataset provenance, feature quantiles |
| `backend/artifacts/evaluation_report.json` | All metrics, curves, tuning grids, importance, error analysis, probe |
| `backend/artifacts/dataset_audit.json` | Recomputed dataset statistics |
| `reports/figures/*.png`, `reports/evaluation_summary.md`, `reports/train.log` | Plots and summaries |

Retraining overwrites the artifacts; restart the API afterwards. The API refuses to load an artifact whose checksum, feature order or **extractor version** differs from the code (`EXTRACTOR_VERSION` in `feature_extraction.py`), so changing the extractor forces a retrain.

## Tests

```bash
cd backend && pytest -q          # 56 tests: extractor, pipeline, API (uses a tiny synthetic dataset; no CSV needed)
cd frontend && npm test          # 21 tests: navigation, validation, loading, success, API failure, CSV errors, keyboard
cd frontend && npm run build     # type-check + production build
```

## API

Base path `/api`. Errors always look like `{"error": {"code", "message", "details?"}}`.

| Method & path | Purpose |
|---|---|
| `GET /health` | `status`, `model_loaded`, `model_version` (200 even when degraded) |
| `GET /model-info` | Model name/version, feature names and definitions, threshold, dataset metadata, headline metrics (503 if no model) |
| `POST /predict` | Body `{"url": "...", "explain": true}` → class, label, `phishing_score`, `threshold`, features, `url_parts`, SHAP explanation, notes, disclaimer. 422 `invalid_url` for unanalysable input |
| `POST /predict/batch` | Body `{"urls": [...], "explain": false}`, max 100 → one result per input in order, with per-item `invalid` status and error code (413 above the limit) |
| `GET /analytics/summary` | Dataset statistics, splits, model comparison, from saved reports (503 `report_unavailable` if untrained) |
| `GET /model-metrics` | The full saved evaluation report |

```bash
curl -s -X POST localhost:8000/api/predict -H 'content-type: application/json' \
     -d '{"url":"http://secure-login.example.xyz/verify.php?id=1"}'
```

`phishing_score` is the model's `P(class 0)`. It is **not** a calibrated real-world probability (test Brier score 0.0023, ECE 0.0003 on the dataset's own distribution only).

## Docker

```bash
cp .env.example .env
docker compose up --build
# UI  http://localhost:8080     API http://localhost:8000/docs
```

Backend and frontend are separate images with health checks. The backend image contains only code and `backend/artifacts`; the dataset and reports are excluded via `.dockerignore`. The frontend is static files served by nginx; `VITE_API_BASE_URL` is baked in at build time and must be the API address **as seen from the browser**. **The Docker files were not built or run in the environment where this project was produced** (no Docker daemon was available), so treat them as unverified until you run the command above.

## How it works

1. **Extraction** (`backend/app/ml/feature_extraction.py`): one deterministic function, 39 numeric features, imported by training and by the API. No network access. Input without a scheme is analysed as `http://<input>` (and the UI says so); only http/https are supported; maximum length 2048 characters.
2. **Cleaning** (`preprocessing.py`): 235,795 rows in → 234,198 out. 425 exact-duplicate URLs, 1,164 same-label near-duplicates (case / trailing slash), 8 URLs over the length limit. No conflicting-label duplicates exist (0). 108 registrable domains contain both labels; they are kept at URL level and never split across partitions in Experiment B.
3. **Splits:** A = stratified 70/15/15; B = `StratifiedGroupKFold` by registrable domain (Public Suffix List). Both verified to have zero URL overlap; B has zero domain overlap (asserted in code and tested).
4. **Models:** Logistic Regression (scaled, C tuned), Random Forest (150 trees, `min_samples_leaf` tuned), XGBoost (`max_depth` tuned, early stopping on the validation set). No class weights: the classes are 1.34:1, which does not justify them.
5. **Explanations:** SHAP `TreeExplainer` on the real model for each request (Logistic Regression would use exact coefficient contributions). Contributions are in log-odds toward phishing and describe the model, not the URL's intent.

### Feature dictionary

| Name | Label | Definition |
|---|---|---|
| `url_length` | URL length | Characters in the normalised URL, scheme included. |
| `hostname_length` | Hostname length | Characters in the ASCII (punycode) hostname. |
| `path_length` | Path length | Characters in the URL path. |
| `query_length` | Query length | Characters in the query string, without '?'. |
| `fragment_length` | Fragment length | Characters in the fragment, without '#'. |
| `path_segment_count` | Path segments | Non-empty segments separated by '/' in the path. |
| `path_depth_has_extension` | File extension in path | 1 if the last path segment looks like a file name (contains a '.'). |
| `query_param_count` | Query parameters | Number of key=value pairs in the query string. |
| `subdomain_count` | Subdomain levels | Hostname labels left of the registrable domain (0 for IP hosts). |
| `hostname_label_count` | Hostname labels | Dot-separated labels in the hostname. |
| `longest_label_length` | Longest hostname label | Length of the longest hostname label. |
| `registrable_domain_length` | Registrable domain length | Length of the registrable domain (public suffix + one label). |
| `tld_length` | Public suffix length | Length of the public suffix, e.g. 'co.uk' = 5 (0 for IP hosts). |
| `is_https` | Uses HTTPS | 1 if the scheme is https. A weak signal; HTTPS does not prove legitimacy. |
| `is_ip_host` | IP address as host | 1 if the hostname is an IPv4 or IPv6 literal. |
| `has_nonstandard_port` | Non-standard port | 1 if an explicit port other than 80/443 is present. |
| `has_userinfo` | Embedded username | 1 if the URL contains a 'user[:pass]@' component. |
| `has_punycode` | Punycode hostname | 1 if any hostname label is IDNA/punycode encoded ('xn--'). |
| `letter_count` | Letters | ASCII letters in the whole URL. |
| `digit_count` | Digits | ASCII digits in the whole URL. |
| `digit_ratio` | Digit share | Digits divided by URL length. |
| `letter_ratio` | Letter share | ASCII letters divided by URL length. |
| `digit_to_letter_ratio` | Digits per letter | Digits divided by max(letters, 1). |
| `hyphen_count` | Hyphens | '-' characters in the whole URL. |
| `dot_count` | Dots | '.' characters in the whole URL. |
| `underscore_count` | Underscores | '_' characters in the whole URL. |
| `at_count` | '@' characters | '@' characters in the whole URL. |
| `qmark_count` | '?' characters | '?' characters in the whole URL. |
| `equals_count` | '=' characters | '=' characters in the whole URL. |
| `ampersand_count` | '&' characters | '&' characters in the whole URL. |
| `slash_count` | Slashes | '/' characters in the whole URL (scheme '//' included). |
| `percent_encoded_count` | Percent-encoded bytes | Number of %XX sequences. |
| `other_special_count` | Other special characters | Non-alphanumeric characters outside . - _ @ ? = & % / : # (non-ASCII included). |
| `url_entropy` | URL character entropy | Shannon entropy (bits per character) of the whole URL. |
| `hostname_entropy` | Hostname character entropy | Shannon entropy (bits per character) of the hostname. |
| `hostname_digit_count` | Digits in hostname | ASCII digits in the hostname. |
| `hostname_hyphen_count` | Hyphens in hostname | '-' characters in the hostname. |
| `suspicious_token_count` | Suspicious keywords | Distinct entries from the documented keyword list found in the URL. |
| `has_suspicious_token` | Any suspicious keyword | 1 if at least one keyword from the list is present. |

Suspicious-keyword list: `login`, `logon`, `signin`, `sign-in`, `verify`, `verification`, `secure`, `security`, `account`, `update`, `confirm`, `password`, `passwd`, `banking`, `wallet`, `webscr`, `paypal`, `support`, `billing`, `invoice`, `recover`, `unlock`, `suspend`, `authenticate`, `credential` (substring match, weak signal).

Original dataset columns such as `URLSimilarityIndex`, `LineOfCode` or `HasPasswordField` need page content or dataset-wide tables, and the stored URL-count columns could not be reproduced from the URL (e.g. `URLLength` equals `len(URL)` for only 20.6% of rows). I did not guess at the original generation conventions; all of these columns are excluded.

## Privacy and safety

* Submitted URLs are parsed as strings only. A test blocks socket access and verifies predictions still work.
* The server never logs URLs, bodies or query strings (a test checks this). Nothing is persisted. The Overview page keeps recent results in tab memory only (registered domain + verdict).
* `model.joblib` is a pickle-based file: only load artifacts you trained yourself. The loader never accepts a user-supplied path and verifies a SHA-256, which detects accidental corruption but is not protection against someone who can edit both files.

## Limitations

* URL text only: no page content, live reputation, WHOIS/DNS, or threat intelligence.
* **Dataset collection pattern (above) is the dominant limitation.** Results do not transfer to real-world URL distributions.
* The dataset is a snapshot from one collection period; phishing tactics change.
* Scores are uncalibrated estimates. The tool does not guarantee safety, find all phishing, or detect malware files.
* HTTPS and keywords are weak signals, never proof.
* Scheme-less input is assumed `http`, which the model treats as riskier than https.
* A single dark theme is provided; there is no theme switch.
* Not tested: Docker builds; browsers other than headless Chromium; screen readers (keyboard operation and ARIA roles were tested, but no assistive technology was).

## Troubleshooting

| Symptom | Fix |
|---|---|
| UI shows "API unreachable" | Start the backend; check `VITE_API_BASE_URL`; the page origin must be in `PHISHGUARD_CORS_ORIGINS` |
| API health says `degraded` | Artifacts missing or failed a check; read `detail` in `/api/health`, or retrain |
| "Artifact was trained with extractor X" | You changed the extractor; retrain |
| "checksum does not match" | `model.joblib` was modified or partially copied; retrain or restore it |
| XGBoost import error (`libgomp`) | `apt install libgomp1` (Linux) |
| Training is slow | One CPU core takes ~5 min; lower `--rf-trees` or use `--sample 30000` for development |
| Model Lab shows "Not evaluated yet" | `evaluation_report.json` is missing; run the training script |

## Citation and license

Dataset: Prasad, A. & Chandra, S. (2024). *PhiUSIIL: A diverse security profile empowered phishing URL detection framework based on similarity index and incremental learning.* Computers & Security, 136, 103545. https://doi.org/10.1016/j.cose.2023.103545. Licensed CC BY 4.0 (UCI ML Repository, dataset 967). The dataset file is not redistributed in this zip.
