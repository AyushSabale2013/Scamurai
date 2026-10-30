"""Brand impersonation and typosquatting detection.

Detects when a known brand name is used in subdomains, paths, or lookalike
domains where the registrable domain does NOT match the legitimate brand owner.
"""

from __future__ import annotations

import re
from typing import NamedTuple

# Canonical mapping of target brand -> authentic registrable domains
BRAND_DOMAINS: dict[str, set[str]] = {
    # Global Tech & Cloud
    "google": {"google.com", "google.co.in", "google.co.uk", "google.de", "google.fr", "googleapis.com", "gstatic.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "office365.com", "outlook.com", "azure.com", "microsoftonline.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "aws.amazon.com"},
    "netflix": {"netflix.com"},
    "spotify": {"spotify.com"},
    "paypal": {"paypal.com", "paypal.me"},
    "meta": {"meta.com", "facebook.com", "instagram.com", "whatsapp.com"},
    "openai": {"openai.com", "chatgpt.com"},
    "anthropic": {"anthropic.com", "claude.ai"},
    
    # Financial & Banking (Global)
    "chase": {"chase.com", "jpmorganchase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com", "bofa.com"},
    "citibank": {"citibank.com", "citi.com"},
    "barclays": {"barclays.co.uk", "barclays.com"},
    "hsbc": {"hsbc.com", "hsbc.co.uk"},
    
    # Indian Banking, Finance & Payments
    "sbi": {"onlinesbi.sbi", "sbi.co.in", "statebankofindia.com"},
    "hdfc": {"hdfcbank.com", "hdfc.com"},
    "icici": {"icicibank.com", "icicidirect.com"},
    "axisbank": {"axisbank.com"},
    "kotak": {"kotak.com"},
    "paytm": {"paytm.com"},
    "phonepe": {"phonepe.com"},
    "googlepay": {"google.com", "pay.google.com"},
    "bhim": {"npci.org.in"},
    
    # Indian Government & Public Services
    "aadhaar": {"uidai.gov.in", "myaadhaar.uidai.gov.in"},
    "uidai": {"uidai.gov.in", "myaadhaar.uidai.gov.in"},
    "irctc": {"irctc.co.in"},
    "indiapost": {"indiapost.gov.in", "epost.gov.in"},
    "incometax": {"incometax.gov.in", "incometaxindia.gov.in", "incometaxindiaefiling.gov.in"},
    "digilocker": {"digilocker.gov.in", "meripehchaan.gov.in"},
    "fastag": {"ihmcl.co.in", "fastag.ihmcl.com", "npci.org.in", "parivahan.gov.in"},
    
    # Telecom & E-Commerce (India)
    "jio": {"jio.com", "jiomart.com"},
    "airtel": {"airtel.in", "airtel.com"},
    "flipkart": {"flipkart.com"},
}

SUSPICIOUS_KEYWORD_COMBOS = frozenset({
    "login", "signin", "verify", "security", "update", "account",
    "banking", "secure", "support", "billing", "recovery", "confirm",
    "password", "wallet", "portal", "helpdesk",
})


KNOWN_CODE_CONTENT_DOMAINS = frozenset({
    "github.com", "gitlab.com", "bitbucket.org", "wikipedia.org", "wikimedia.org",
    "npmjs.com", "pypi.org", "mozilla.org", "python.org", "stackoverflow.com",
    "medium.com", "huggingface.co", "crates.io", "docker.com", "golang.org",
})


def _levenshtein(s1: str, s2: str) -> int:
    """Compute standard Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev[j + 1] + 1
            deletions = curr[j] + 1
            substitutions = prev[j] + (c1 != c2)
            curr.append(min(insertions, deletions, substitutions))
        prev = curr
    return prev[-1]


def extract_brand_features(
    host: str,
    subdomain: str,
    path: str,
    registrable: str,
) -> dict[str, float]:
    """Compute brand impersonation and typosquatting features."""
    host_clean = (host or "").lower()
    sub_clean = (subdomain or "").lower()
    path_clean = (path or "").lower()
    rd_clean = (registrable or "").lower()
    is_code_repo_host = rd_clean in KNOWN_CODE_CONTENT_DOMAINS
    
    # Strip TLD from registrable domain to get the domain stem
    rd_stem = rd_clean.split(".")[0] if "." in rd_clean else rd_clean

    brand_in_subdomain = 0
    brand_in_path = 0
    brand_typosquatting = 0
    brand_keyword_combo = 0
    min_dist_to_brand = 99

    for brand, authentic_domains in BRAND_DOMAINS.items():
        is_authentic = any(rd_clean == ad or rd_clean.endswith("." + ad) for ad in authentic_domains)
        
        # 1. Brand in subdomain on non-authentic domain (e.g., paypal.com.evil.xyz)
        if not is_authentic:
            if re.search(r'(^|\.)' + re.escape(brand) + r'(\.|$)', sub_clean):
                brand_in_subdomain = 1
            
            # 2. Brand in path on non-authentic domain (e.g., evil.com/login/paypal)
            if not is_code_repo_host and re.search(r'(/|_|-|^)' + re.escape(brand) + r'(/|_|-|$)', path_clean):
                brand_in_path = 1
                
            # 3. Typosquatting on domain stem (e.g., paypa1.com, go0gle.com, wellsfarg0.com)
            if rd_stem:
                dist = _levenshtein(brand, rd_stem)
                min_dist_to_brand = min(min_dist_to_brand, dist)
                # If length >= 4 and edit distance is 1, or length >= 7 and dist <= 2
                if (len(brand) >= 4 and dist == 1) or (len(brand) >= 7 and dist == 2):
                    brand_typosquatting = 1
                    
            # 4. Brand + suspicious keyword in host or path (non-authentic domain)
            if not is_code_repo_host and (brand in host_clean or brand in path_clean):
                for kw in SUSPICIOUS_KEYWORD_COMBOS:
                    if kw in host_clean or kw in path_clean:
                        brand_keyword_combo = 1
                        break

    return {
        "brand_in_subdomain": float(brand_in_subdomain),
        "brand_in_path": float(brand_in_path),
        "brand_typosquatting": float(brand_typosquatting),
        "brand_keyword_combo": float(brand_keyword_combo),
        "min_dist_to_brand": float(min(min_dist_to_brand, 10)),
    }
