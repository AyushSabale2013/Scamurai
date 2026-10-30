"""Lexical, structural and statistical feature extraction from parsed URLs."""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any
from urllib.parse import parse_qsl, unquote

from .brand import extract_brand_features
from .reputation import get_tranco_bucket, is_url_shortener, is_user_content_platform
from .url_parser import ParsedURL

# Suspicious keywords observed in phishing campaigns
HOST_KEYWORDS = (
    "login", "signin", "verify", "verification", "secure", "security",
    "account", "update", "banking", "billing", "confirm", "wallet",
    "auth", "recover", "support", "service", "portal",
)

PATH_KEYWORDS = (
    "login", "signin", "admin", "wp-content", "wp-admin", "webscr",
    "cmd=_login", "cgi-bin", "verification", "secure", "banking",
    "account", "update", "confirm", "auth", "passwd", "credential",
)

# Known risky TLDs frequently abused in ephemeral phishing campaigns
SUSPICIOUS_TLDS = frozenset({
    "top", "xyz", "club", "buzz", "click", "online", "live", "site",
    "work", "gq", "cf", "ml", "ga", "tk", "bid", "loan", "men",
})


def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy in bits per character."""
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    ent = 0.0
    for cnt in counts.values():
        p = cnt / total
        ent -= p * math.log2(p)
    return round(ent, 4)


def extract_lexical_features(p: ParsedURL) -> dict[str, float]:
    """Compute lexical and statistical features for a parsed URL."""
    host = p.host
    masked_path = p.masked_path
    query = p.query

    # 6. Offline reputation features
    tranco_bucket = float(get_tranco_bucket(p.registrable, full_host=p.host))
    is_platform = float(is_user_content_platform(p.registrable))
    is_shortener = float(is_url_shortener(p.registrable))

    # 7. Brand impersonation features
    brand_feats = extract_brand_features(
        host=p.host,
        subdomain=p.subdomain,
        path=p.path,
        registrable=p.registrable,
    )

    # Query features & open redirect check
    query_len = float(len(query))
    query_params = parse_qsl(query, keep_blank_values=True)
    query_param_count = float(len(query_params))
    has_embedded_url = 0
    for k, v in query_params:
        if "http://" in v or "https://" in v or "url=" in k or "redirect" in k:
            has_embedded_url = 1
            break

    is_gov_edu = (
        p.tld in ("gov", "edu", "mil")
        or any(p.host.endswith("." + suf) or p.host == suf for suf in ("gov.in", "edu.in", "ac.in", "gov.uk", "gouvernement.fr", "gov.au", "nic.in"))
    )

    if is_gov_edu and not has_embedded_url and not brand_feats["brand_in_subdomain"]:
        tranco_bucket = max(tranco_bucket, 3.0)

    is_reputable_authentic = (
        (tranco_bucket >= 2 or is_gov_edu)
        and not is_platform
        and not brand_feats["brand_in_path"]
        and not brand_feats["brand_in_subdomain"]
        and not has_embedded_url
    )

    # 1. Host features (computed on normalized host with 'www.' stripped)
    host_len = float(len(host))
    host_hyphens = float(host.count("-"))
    host_digits = float(sum(c.isdigit() for c in host))
    host_dots = float(host.count("."))
    host_entropy = shannon_entropy(host)
    
    # On reputable domains, standard subdomains and host structure are normal infrastructure.
    if is_reputable_authentic:
        subdomain_count = float(max(0, len(p.subdomain_parts) - 2))  # Allow up to 2 nested subdomains
        host_len = min(host_len, 22.0)      # Cap to reduce penalty for long reputable hosts
        host_dots = min(host_dots, 2.0)     # Allow up to 2 dots (subdomain.domain.tld)
        host_digits = 0.0                   # Reputable domains don't use digits in hostname
        host_entropy = min(host_entropy, 3.3)
    elif tranco_bucket >= 1:
        subdomain_count = float(max(0, len(p.subdomain_parts) - 1))
    else:
        subdomain_count = float(len(p.subdomain_parts))

    # Host label statistics
    labels = host.split(".")
    max_label_len = float(max((len(l) for l in labels), default=0))

    # 2. Path features (computed on MASKED path so UUIDs don't skew counts)
    path_len = float(len(masked_path))
    path_segments = [s for s in masked_path.split("/") if s]
    path_depth = float(len(path_segments))
    path_hyphens = float(masked_path.count("-"))
    path_digits = float(sum(c.isdigit() for c in masked_path))
    path_entropy = shannon_entropy(masked_path)

    if is_reputable_authentic:
        # Deep paths in documentation, dashboards, and apps on reputable domains are normal
        path_depth = min(path_depth, 3.0)
        path_entropy = min(path_entropy, 3.5)
        path_digits = min(path_digits, 2.0)
        path_hyphens = min(path_hyphens, 1.0)
        query_len = min(query_len, 20.0)
        query_param_count = min(query_param_count, 2.0)

    # 4. Host vs Path Keyword counts (path-level login on reputable domain is normal)
    host_lower = host.lower()
    host_keyword_count = float(sum(1 for kw in HOST_KEYWORDS if kw in host_lower))
    
    path_lower = masked_path.lower()
    raw_path_kws = sum(1 for kw in PATH_KEYWORDS if kw in path_lower)
    if is_reputable_authentic:
        path_keyword_count = 0.0
        host_keyword_count = 0.0
    elif tranco_bucket >= 1:
        path_keyword_count = float(max(0, raw_path_kws - 1))
    else:
        path_keyword_count = float(raw_path_kws)

    # 5. Suspicious indicators
    is_nonstandard_port = float(p.port is not None and p.port not in (80, 443))
    has_userinfo = float(bool(p.userinfo))
    is_ip = float(p.is_ip_host)
    # Punycode is only an evasion signal when combined with brand typosquatting on unranked hosts
    is_punycode = float(
        p.is_punycode and (brand_feats["brand_typosquatting"] > 0 or tranco_bucket < 1)
    )
    is_risky_tld = float(p.tld.lower() in SUSPICIOUS_TLDS)
    
    # Scheme feature: only keep explicit HTTP (neutral, not is_https)
    has_explicit_http = float(p.has_explicit_scheme and p.scheme == "http")

    features = {
        # Host structural
        "host_len": host_len,
        "host_hyphens": host_hyphens,
        "host_digits": host_digits,
        "host_dots": host_dots,
        "host_entropy": host_entropy,
        "subdomain_count": subdomain_count,
        "max_label_len": max_label_len,
        
        # Path structural (masked)
        "path_depth": path_depth,
        "path_hyphens": path_hyphens,
        "path_digits": path_digits,
        "path_entropy": path_entropy,
        
        # Query
        "query_len": query_len,
        "query_param_count": query_param_count,
        "has_embedded_url": float(has_embedded_url),
        
        # Keywords
        "host_keyword_count": host_keyword_count,
        "path_keyword_count": path_keyword_count,
        
        # Evasion / Indicators
        "is_nonstandard_port": is_nonstandard_port,
        "has_userinfo": has_userinfo,
        "is_ip_host": is_ip,
        "is_punycode": is_punycode,
        "is_risky_tld": is_risky_tld,
        "has_explicit_http": has_explicit_http,
        
        # Reputation
        "tranco_rank_bucket": tranco_bucket,
        "is_user_content_platform": is_platform,
        "is_url_shortener": is_shortener,
        
        # Brand impersonation
        "brand_in_subdomain": brand_feats["brand_in_subdomain"],
        "brand_in_path": brand_feats["brand_in_path"],
        "brand_typosquatting": brand_feats["brand_typosquatting"],
        "brand_keyword_combo": brand_feats["brand_keyword_combo"],
        "min_dist_to_brand": brand_feats["min_dist_to_brand"],
    }

    # Return ordered dictionary matching canonical FEATURE_NAMES
    from . import FEATURE_NAMES
    return {k: features[k] for k in FEATURE_NAMES}
