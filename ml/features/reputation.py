"""Offline domain reputation and platform classification.

Zero network access at runtime. All data is loaded from bundled static lookup tables.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

# Versioned user-content platforms where legitimate and phishing URLs coexist
USER_CONTENT_PLATFORMS = frozenset({
    "github.io", "pages.dev", "weebly.com", "wixsite.com", "firebaseapp.com",
    "blogspot.com", "wordpress.com", "herokuapp.com", "netlify.app", "vercel.app",
    "web.app", "appspot.com", "azurewebsites.net", "000webhostapp.com",
    "sites.google.com", "docs.google.com", "forms.gle", "glitch.me", "surveymonkey.com",
    "cdn77.org", "s3.amazonaws.com", "storage.googleapis.com", "blob.core.windows.net",
})

# Well-known URL shorteners
URL_SHORTENERS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly", "is.gd",
    "rebrand.ly", "cutt.ly", "shorturl.at", "bl.ink", "tiny.cc", "rb.gy",
})

# Default top domains if lookup file not yet built (safely bundled fallback)
TOP_DOMAINS_SAMPLE = {
    # Top 1k - Tier 4
    "google.com": 4, "youtube.com": 4, "facebook.com": 4, "microsoft.com": 4,
    "apple.com": 4, "amazon.com": 4, "chatgpt.com": 4, "claude.ai": 4,
    "openai.com": 4, "wikipedia.org": 4, "github.com": 4, "twitter.com": 4,
    "linkedin.com": 4, "instagram.com": 4, "reddit.com": 4, "netflix.com": 4,
    "zoom.us": 4, "slack.com": 4, "spotify.com": 4, "dropbox.com": 4,
    "stackoverflow.com": 4, "mozilla.org": 4, "archive.org": 4,
    "amazon.in": 4, "live.com": 4, "outlook.com": 4, "microsoftonline.com": 4,

    # Top 10k - Tier 3
    "irctc.co.in": 3, "onlinesbi.sbi": 3, "incometax.gov.in": 3, "digilocker.gov.in": 3,
    "npci.org.in": 3, "paytm.com": 3, "phonepe.com": 3, "hdfcbank.com": 3,
    "icicibank.com": 3, "axisbank.com": 3, "uidai.gov.in": 3, "flipkart.com": 3,
    "stripe.com": 3, "netlify.com": 3, "netlify.app": 3, "heroku.com": 3,
    "gitlab.com": 3, "bitbucket.org": 3, "npmjs.com": 3, "pypi.org": 3,
    "python.org": 3, "developer.mozilla.org": 3, "developer.apple.com": 3,
    "aws.amazon.com": 3, "cloud.google.com": 3, "azure.microsoft.com": 3,
    "console.aws.amazon.com": 3, "console.cloud.google.com": 3,
    "docs.google.com": 3, "drive.google.com": 3, "mail.google.com": 3,
    "calendar.google.com": 3, "translate.google.com": 3, "maps.google.com": 3,
    "apps.google.com": 3, "accounts.google.com": 3,
    "vodafone.in": 3, "airtel.in": 3, "jio.com": 3,
    "timesofindia.indiatimes.com": 3, "thehindu.com": 3, "ndtv.com": 3,
    "bharatpe.com": 3, "meripehchaan.gov.in": 3, "parivahan.gov.in": 3,
    "epost.gov.in": 3, "eprocure.gov.in": 3, "incometaxindiaefiling.gov.in": 3,
    "myaadhaar.uidai.gov.in": 3, "vahan.parivahan.gov.in": 3,
    "web.archive.org": 3,

    # Top 100k - Tier 2
    "jsonplaceholder.typicode.com": 2, "fonts.google.com": 2, "fonts.googleapis.com": 2,
    "reactjs.org": 2, "vuejs.org": 2, "angular.io": 2, "nextjs.org": 2,
    "dashboard.stripe.com": 2, "app.netlify.com": 2, "dashboard.heroku.com": 2,
    "news.ycombinator.com": 2, "huggingface.co": 2,
}

_TRANCO_BUCKETS: Optional[dict[str, int]] = None
_RAW_TO_MONOTONIC = {1: 4, 2: 3, 3: 2, 4: 1, 0: 0}


def load_tranco_buckets(table_path: Optional[Path] = None) -> dict[str, int]:
    """Load the offline Tranco rank bucket lookup table."""
    global _TRANCO_BUCKETS
    if _TRANCO_BUCKETS is not None:
        return _TRANCO_BUCKETS

    if table_path is None:
        table_path = Path(__file__).resolve().parent / "data" / "tranco_buckets.json"

    if table_path.exists():
        try:
            with open(table_path, "r", encoding="utf-8") as f:
                _TRANCO_BUCKETS = json.load(f)
                return _TRANCO_BUCKETS
        except Exception:
            pass

    _TRANCO_BUCKETS = dict(TOP_DOMAINS_SAMPLE)
    return _TRANCO_BUCKETS


def get_tranco_bucket(registrable_domain: str, full_host: str = "") -> int:
    """Return monotonic Tranco rank bucket:
    4 = Top 1k (highest reputation)
    3 = Top 10k
    2 = Top 100k
    1 = Top 1M
    0 = Unranked / Unknown (lowest reputation)
    Checks full hostname first (e.g. console.aws.amazon.com), then registrable domain.
    """
    if not registrable_domain:
        return 0
    buckets = load_tranco_buckets()
    # Try full host first (subdomains like console.aws.amazon.com may have their own entry)
    if full_host:
        raw = buckets.get(full_host.lower())
        if raw is not None:
            return _RAW_TO_MONOTONIC.get(raw, 0)
    raw = buckets.get(registrable_domain.lower(), 0)
    # Convert raw (where 1 was top 1k) to monotonic (where 4 is top 1k)
    return _RAW_TO_MONOTONIC.get(raw, 0)


def is_user_content_platform(registrable_domain: str) -> int:
    """Flag if host is on a free/shared hosting or user-content platform."""
    if not registrable_domain:
        return 0
    rd = registrable_domain.lower()
    return int(any(rd == p or rd.endswith("." + p) for p in USER_CONTENT_PLATFORMS))


def is_url_shortener(registrable_domain: str) -> int:
    """Flag if host is a known URL shortening service."""
    if not registrable_domain:
        return 0
    return int(registrable_domain.lower() in URL_SHORTENERS)
