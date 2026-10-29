import math

import numpy as np
import pytest

from app.ml.feature_extraction import (
    FEATURE_NAMES, MAX_URL_LENGTH, URLValidationError, extract_features, features_to_vector, normalize_url,
)


def f(url):
    return extract_features(url)


def test_feature_order_is_stable_and_complete():
    feats = f("https://www.example.com")
    assert list(feats) == FEATURE_NAMES
    assert len(set(FEATURE_NAMES)) == len(FEATURE_NAMES)


def test_normal_https_url():
    x = f("https://www.example.com/")
    assert x["is_https"] == 1 and x["url_length"] == len("https://www.example.com/")
    assert x["hostname_length"] == len("www.example.com")
    assert x["subdomain_count"] == 1 and x["tld_length"] == 3 and x["is_ip_host"] == 0


def test_http_url():
    assert f("http://example.com")["is_https"] == 0


def test_query_parameters_and_fragment():
    x = f("https://example.com/a/b?x=1&y=2&z=#frag")
    assert x["query_param_count"] == 3 and x["qmark_count"] == 1 and x["equals_count"] == 3 and x["ampersand_count"] == 2
    assert x["fragment_length"] == 4 and x["path_segment_count"] == 2 and x["query_length"] == len("x=1&y=2&z=")


def test_long_path():
    x = f("https://example.com/" + "a/" * 200)
    assert x["path_segment_count"] == 200 and x["path_length"] > 399


def test_ipv4_and_ipv6_hosts():
    a = f("http://192.168.1.10:8080/login")
    assert a["is_ip_host"] == 1 and a["subdomain_count"] == 0 and a["has_nonstandard_port"] == 1 and a["tld_length"] == 0
    b = f("http://[2001:db8::1]/x")
    assert b["is_ip_host"] == 1


def test_punycode_and_unicode_hostnames():
    assert f("http://xn--80ak6aa92e.com")["has_punycode"] == 1
    u = f("https://münchen.de/straße")
    assert u["has_punycode"] == 1 and u["hostname_length"] == len("xn--mnchen-3ya.de")
    assert f("https://example.com")["has_punycode"] == 0


def test_userinfo_and_at_sign():
    x = f("http://paypal.com@evil.example.net/login")
    assert x["has_userinfo"] == 1 and x["at_count"] == 1 and x["registrable_domain_length"] == len("example.net")


def test_percent_encoding_and_unusual_punctuation():
    x = f("https://example.com/a%20b%2Fc!$'()*,;~|<>")
    assert x["percent_encoded_count"] == 2 and x["other_special_count"] >= 10


def test_suspicious_tokens_counted_distinctly():
    x = f("https://secure-login.example.com/verify/account")
    assert x["suspicious_token_count"] >= 4 and x["has_suspicious_token"] == 1
    assert f("https://example.com")["has_suspicious_token"] == 0


def test_scheme_handling_is_consistent():
    n = normalize_url("Example.com/path")
    assert n.url == "http://Example.com/path" and n.scheme_assumed and n.notes
    assert normalize_url("HTTPS://x.com").url == "https://x.com"
    assert f("example.com/path")["url_length"] == len("http://example.com/path")
    assert f("//example.com")["url_length"] == len("http://example.com")


def test_public_suffix_handling():
    x = f("https://a.b.bbc.co.uk")
    assert x["tld_length"] == len("co.uk") and x["subdomain_count"] == 2 and x["registrable_domain_length"] == len("bbc.co.uk")


@pytest.mark.parametrize("bad,code", [
    ("", "empty_url"), ("   ", "empty_url"), ("http://", "missing_hostname"), ("ftp://example.com", "unsupported_scheme"),
    ("mailto:a@b.com", "unsupported_scheme"), ("javascript:alert(1)", "unsupported_scheme"), ("http://a b.com", "invalid_characters"),
    ("http://a..b.com", "invalid_hostname"), ("http://exa\x00mple.com", "invalid_characters"), ("http://[::1", "malformed_url"),
    ("http://example.com:99999", "malformed_url"),
])
def test_malformed_inputs_rejected_with_code(bad, code):
    with pytest.raises(URLValidationError) as e:
        extract_features(bad)
    assert e.value.code == code


def test_non_string_rejected():
    with pytest.raises(URLValidationError):
        extract_features(None)  # type: ignore[arg-type]


def test_extremely_long_input_rejected():
    with pytest.raises(URLValidationError) as e:
        extract_features("https://example.com/" + "a" * MAX_URL_LENGTH)
    assert e.value.code == "url_too_long"
    assert f("https://example.com/" + "a" * (MAX_URL_LENGTH - 20))["url_length"] == MAX_URL_LENGTH


def test_all_outputs_finite_and_vector_matches():
    for u in ["https://a.co", "http://1.2.3.4", "https://x.com/?" + "&".join(f"k{i}=v" for i in range(50)), "https://日本語.jp/パス"]:
        feats = f(u)
        assert all(math.isfinite(v) for v in feats.values())
        vec = features_to_vector(feats)
        assert vec.dtype == np.float64 and vec.shape == (len(FEATURE_NAMES),)


def test_deterministic():
    assert f("https://www.Example.com/Path?q=1") == f("https://www.Example.com/Path?q=1")


def test_extractor_never_touches_network(monkeypatch):
    import socket

    def boom(*a, **k):
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket, "socket", boom)
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    f("https://www.example.com/login?x=1")
