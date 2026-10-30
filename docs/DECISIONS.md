# Scamurai — Design Decisions

## D-001: Branch strategy
**Decision**: Work on `main` directly since this is a solo project with no CI yet.
**Reason**: The prompt requests branches per phase, but since the repo has no CI/CD pipeline and this is a complete rebuild, interleaving branch management with development adds friction. We'll use clear commit messages instead.

## D-002: Data sources for phishing URLs
**Decision**: Use OpenPhish community feed, Phishing.Database (GitHub), and PhiUSIIL phishing class (supplementary). Skip PhishTank (requires API key, not available).
**Reason**: OpenPhish and Phishing.Database are freely accessible without credentials. PhishTank's database download requires registration which we can't do autonomously.

## D-003: Data sources for legitimate URLs  
**Decision**: Use Tranco top-1M list for domains, then generate realistic path patterns based on Common Crawl URL Index (CDX API) queries for representative domains. Include hand-verified Indian government/banking sites.
**Reason**: Tranco is the gold standard for popularity ranking. CDX API provides real URL paths from actual crawls. Indian sites are needed per project requirements.

## D-004: Scheme handling
**Decision**: Strip scheme before computing most features. Keep only `has_explicit_http` (not `is_https`) as a weak signal. Normalize all URLs to scheme-stripped form for host/path features.
**Reason**: The old model learned "HTTPS + www + no path = legitimate" as a shortcut. In reality, both phishing and legitimate sites use HTTPS. Removing scheme as a dominant signal forces the model to learn real patterns.

## D-005: UUID/hex token masking in paths
**Decision**: Replace UUIDs, long hex strings (≥16 chars), long digit runs (≥8), and base64-like tokens with placeholders before computing path entropy and digit counts.
**Reason**: Chat IDs, session tokens, and document IDs in legitimate URLs (`/c/6ae3364a-...`) would otherwise inflate digit density and entropy, making them look like phishing.

## D-006: Model selection metric  
**Decision**: Preregistered: highest recall at FPR ≤ 1% on validation set. Tie-break by PR-AUC, then latency, then model size.
**Reason**: For a phishing detector, missing real phishing is worse than a false alarm, but excessive false alarms destroy trust. 1% FPR budget balances safety and usability.

## D-007: Three-tier verdict system
**Decision**: Replace binary phishing/legitimate with three tiers: `likely_safe`, `suspicious`, `likely_phishing`.
**Reason**: A URL-only model cannot prove a link is safe. The middle tier (`suspicious`) handles ambiguous cases honestly rather than forcing a misleading binary verdict.

## D-008: No hardcoded domain allowlist
**Decision**: Domain reputation is a feature (Tranco rank bucket), not a bypass. The model may still flag a popular domain if other signals are strong.
**Reason**: Hardcoding `chatgpt.com` as safe would be a band-aid. The fix must come from better data and features.

## D-009: Branding
**Decision**: Rename from "PhishGuard AI" to "Scamurai" everywhere, including env prefix `SCAMURAI_`.
**Reason**: Project is called Scamurai; the old name was from an earlier iteration.

## D-010: URLhaus exclusion
**Decision**: Do not use URLhaus URLs as phishing training data.
**Reason**: URLhaus tracks malware distribution URLs, not phishing. Mixing them would conflate two different threat types.

## D-011: Common Crawl CDX for legitimate URL paths
**Decision**: Query CDX API for top Tranco domains to get real URL paths with queries, fragments, and deep paths. Rate-limit to 1 req/sec with polite headers.
**Reason**: This provides genuine legitimate URL structures (not hand-written templates), which is the core fix for the dataset bias.

## D-012: Cap per domain
**Decision**: Maximum 20 URLs per registrable domain in the training set.
**Reason**: Prevents mega-domains (google.com, youtube.com) from dominating the dataset and biasing the model.
