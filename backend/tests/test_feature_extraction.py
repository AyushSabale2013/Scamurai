"""Unit tests for Scamurai v2.0 feature extraction.

Verifies:
- Stable feature ordering
- Masking of UUIDs, hex tokens, digit runs
- Brand impersonation & typosquatting detection
- Offline Tranco rank lookups
- Handling of edge cases, punycode, IP hosts, non-standard ports
- Zero network I/O
"""

import socket
import pytest

from ml.features import (
    EXTRACTOR_VERSION, FEATURE_NAMES, URLValidationError,
    extract_features, features_to_vector, mask_path_tokens, parse_url,
)


def f(url: str):
    return extract_features(url)


def test_extractor_version_and_stable_names():
    assert EXTRACTOR_VERSION == "2.0.0"
    feats = f("https://example.com/test")
    assert tuple(feats.keys()) == FEATURE_NAMES
    assert len(set(FEATURE_NAMES)) == len(FEATURE_NAMES)
    vec = features_to_vector(feats)
    assert len(vec) == len(FEATURE_NAMES)


def test_uuid_and_token_masking():
    # ChatGPT chat UUID route
    url1 = "https://chatgpt.com/c/6ae3364a-1440-83e8-be31-1e5aefa525c5"
    p1 = parse_url(url1)
    assert p1.masked_path == "/c/<uuid>"
    f1 = f(url1)
    assert f1["tranco_rank_bucket"] >= 1
    assert f1["brand_in_path"] == 0.0

    # Claude chat UUID route
    url2 = "https://claude.ai/chat/305c187a-fc1f-4d9a-9063-3f0b53b47a2a"
    p2 = parse_url(url2)
    assert p2.masked_path == "/chat/<uuid>"

    # Hex token masking
    masked_hex = mask_path_tokens("/session/0123456789abcdef0123456789abcdef/view")
    assert masked_hex == "/session/<hex>/view"


def test_brand_impersonation_detection():
    # Brand in subdomain on attacker domain
    phish1 = f("http://paypal.com.verify-account-security.xyz/login")
    assert phish1["brand_in_subdomain"] == 1.0 or phish1["brand_keyword_combo"] == 1.0
    assert phish1["is_risky_tld"] == 1.0

    # Authentic brand domain should NOT be flagged as brand_in_subdomain
    auth1 = f("https://www.paypal.com/signin")
    assert auth1["brand_in_subdomain"] == 0.0
    assert auth1["brand_typosquatting"] == 0.0

    # Typosquatting domain
    typo = f("http://paypa1.com/login")
    assert typo["brand_typosquatting"] == 1.0 or typo["brand_keyword_combo"] == 1.0


def test_indian_banking_and_gov_reputation():
    sbi = f("https://onlinesbi.sbi/sbijava/retail/login.htm")
    assert sbi["tranco_rank_bucket"] >= 1
    assert sbi["brand_in_subdomain"] == 0.0

    irctc = f("https://irctc.co.in/nget/train-search")
    assert irctc["tranco_rank_bucket"] >= 1


def test_ip_and_port_indicators():
    ip_url = f("http://192.168.1.100:8080/admin")
    assert ip_url["is_ip_host"] == 1.0
    assert ip_url["is_nonstandard_port"] == 1.0

    std_url = f("https://example.com/test")
    assert std_url["is_ip_host"] == 0.0
    assert std_url["is_nonstandard_port"] == 0.0


def test_punycode_and_userinfo():
    puny = f("http://xn--pypal-4ve.com/account")
    assert puny["is_punycode"] == 1.0

    userinfo = f("http://paypal.com@evil-site.com/verify")
    assert userinfo["has_userinfo"] == 1.0


def test_malformed_url_rejections():
    with pytest.raises(URLValidationError):
        f("")
    with pytest.raises(URLValidationError):
        f("javascript:alert(1)")
    with pytest.raises(URLValidationError):
        f("data:text/html,<h1>test</h1>")
    with pytest.raises(URLValidationError):
        f(None)


def test_extractor_never_touches_network(monkeypatch):
    """Confirm extractor makes zero network calls."""
    def guarded(*args, **kwargs):
        raise AssertionError("Network socket called during feature extraction!")

    monkeypatch.setattr(socket, "socket", guarded)
    f("https://chatgpt.com/c/6ae3364a-1440-83e8-be31-1e5aefa525c5")
    f("https://claude.ai/chat/305c187a-fc1f-4d9a-9063-3f0b53b47a2a")
    f("http://192.168.1.1:8080/login")
