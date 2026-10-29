"""URL-only feature extraction for PhishGuard AI.

This single module is imported by BOTH the training pipeline and the inference
API. It never touches the network: every feature is computed from the URL
string (plus the bundled Public Suffix List snapshot shipped inside the
``publicsuffix2`` package).

Counting conventions (applies to every feature below)
-----------------------------------------------------
* ``normalize_url`` strips surrounding whitespace, lower-cases the scheme and,
  when the input has no scheme, prepends ``http://``. All "whole URL" counts
  are taken over this normalised string (scheme included).
* Hostname features use the lower-cased hostname in its ASCII/IDNA (punycode)
  form, without port, userinfo, or a single trailing dot.
* Letters / digits are ASCII only (``A-Za-z`` / ``0-9``). Non-ASCII characters
  and anything that is not ASCII alphanumeric or one of ``.-_@?=&%/:#`` are
  counted in ``other_special_count``.
* Ratios divide by a guarded denominator (never zero) and are always finite.

If anything in this file changes in a way that affects feature values, bump
``EXTRACTOR_VERSION``: the model loader refuses artifacts trained with another
extractor version, which forces retraining.
"""

from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlsplit

import numpy as np
from publicsuffix2 import get_sld, get_tld

EXTRACTOR_VERSION = "1.0.0"
MAX_URL_LENGTH = 2048

# Weak lexical signal only: substring match on the lower-cased URL. Matches such
# as "account" inside "accounting" are expected, which is why this is a model
# input and never presented as proof.
SUSPICIOUS_TOKENS: tuple[str, ...] = (
    "login", "logon", "signin", "sign-in", "verify", "verification", "secure",
    "security", "account", "update", "confirm", "password", "passwd", "banking",
    "wallet", "webscr", "paypal", "support", "billing", "invoice", "recover",
    "unlock", "suspend", "authenticate", "credential",
)

_SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*)://")
_OPAQUE_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*:(?!//)(?!\d)")
_PCT_RE = re.compile(r"%[0-9A-Fa-f]{2}")
_NORMAL_PUNCT = set(".-_@?=&%/:#")


class URLValidationError(ValueError):
    """Raised when an input cannot be analysed. ``code`` is machine readable."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class FeatureDef:
    label: str
    description: str


# Order here IS the model's feature order.
FEATURE_DEFINITIONS: dict[str, FeatureDef] = {
    "url_length": FeatureDef("URL length", "Characters in the normalised URL, scheme included."),
    "hostname_length": FeatureDef("Hostname length", "Characters in the ASCII (punycode) hostname."),
    "path_length": FeatureDef("Path length", "Characters in the URL path."),
    "query_length": FeatureDef("Query length", "Characters in the query string, without '?'."),
    "fragment_length": FeatureDef("Fragment length", "Characters in the fragment, without '#'."),
    "path_segment_count": FeatureDef("Path segments", "Non-empty segments separated by '/' in the path."),
    "path_depth_has_extension": FeatureDef("File extension in path", "1 if the last path segment looks like a file name (contains a '.')."),
    "query_param_count": FeatureDef("Query parameters", "Number of key=value pairs in the query string."),
    "subdomain_count": FeatureDef("Subdomain levels", "Hostname labels left of the registrable domain (0 for IP hosts)."),
    "hostname_label_count": FeatureDef("Hostname labels", "Dot-separated labels in the hostname."),
    "longest_label_length": FeatureDef("Longest hostname label", "Length of the longest hostname label."),
    "registrable_domain_length": FeatureDef("Registrable domain length", "Length of the registrable domain (public suffix + one label)."),
    "tld_length": FeatureDef("Public suffix length", "Length of the public suffix, e.g. 'co.uk' = 5 (0 for IP hosts)."),
    "is_https": FeatureDef("Uses HTTPS", "1 if the scheme is https. A weak signal; HTTPS does not prove legitimacy."),
    "is_ip_host": FeatureDef("IP address as host", "1 if the hostname is an IPv4 or IPv6 literal."),
    "has_nonstandard_port": FeatureDef("Non-standard port", "1 if an explicit port other than 80/443 is present."),
    "has_userinfo": FeatureDef("Embedded username", "1 if the URL contains a 'user[:pass]@' component."),
    "has_punycode": FeatureDef("Punycode hostname", "1 if any hostname label is IDNA/punycode encoded ('xn--')."),
    "letter_count": FeatureDef("Letters", "ASCII letters in the whole URL."),
    "digit_count": FeatureDef("Digits", "ASCII digits in the whole URL."),
    "digit_ratio": FeatureDef("Digit share", "Digits divided by URL length."),
    "letter_ratio": FeatureDef("Letter share", "ASCII letters divided by URL length."),
    "digit_to_letter_ratio": FeatureDef("Digits per letter", "Digits divided by max(letters, 1)."),
    "hyphen_count": FeatureDef("Hyphens", "'-' characters in the whole URL."),
    "dot_count": FeatureDef("Dots", "'.' characters in the whole URL."),
    "underscore_count": FeatureDef("Underscores", "'_' characters in the whole URL."),
    "at_count": FeatureDef("'@' characters", "'@' characters in the whole URL."),
    "qmark_count": FeatureDef("'?' characters", "'?' characters in the whole URL."),
    "equals_count": FeatureDef("'=' characters", "'=' characters in the whole URL."),
    "ampersand_count": FeatureDef("'&' characters", "'&' characters in the whole URL."),
    "slash_count": FeatureDef("Slashes", "'/' characters in the whole URL (scheme '//' included)."),
    "percent_encoded_count": FeatureDef("Percent-encoded bytes", "Number of %XX sequences."),
    "other_special_count": FeatureDef("Other special characters", "Non-alphanumeric characters outside . - _ @ ? = & % / : # (non-ASCII included)."),
    "url_entropy": FeatureDef("URL character entropy", "Shannon entropy (bits per character) of the whole URL."),
    "hostname_entropy": FeatureDef("Hostname character entropy", "Shannon entropy (bits per character) of the hostname."),
    "hostname_digit_count": FeatureDef("Digits in hostname", "ASCII digits in the hostname."),
    "hostname_hyphen_count": FeatureDef("Hyphens in hostname", "'-' characters in the hostname."),
    "suspicious_token_count": FeatureDef("Suspicious keywords", "Distinct entries from the documented keyword list found in the URL."),
    "has_suspicious_token": FeatureDef("Any suspicious keyword", "1 if at least one keyword from the list is present."),
}

FEATURE_NAMES: list[str] = list(FEATURE_DEFINITIONS)
N_FEATURES = len(FEATURE_NAMES)


@dataclass
class NormalizedURL:
    url: str
    scheme_assumed: bool
    notes: list[str] = field(default_factory=list)


def normalize_url(raw: str) -> NormalizedURL:
    """Deterministic normalisation. Raises URLValidationError on unsupported input."""
    if not isinstance(raw, str):
        raise URLValidationError("invalid_type", "URL must be a string.")
    url = raw.strip()
    if not url:
        raise URLValidationError("empty_url", "URL is empty.")
    if len(url) > MAX_URL_LENGTH:
        raise URLValidationError(
            "url_too_long", f"URL is longer than the supported maximum of {MAX_URL_LENGTH} characters."
        )
    if any(ch.isspace() or not ch.isprintable() for ch in url):
        raise URLValidationError("invalid_characters", "URL contains whitespace or control characters.")

    m = _SCHEME_RE.match(url)
    if m:
        scheme = m.group(1).lower()
        if scheme not in ("http", "https"):
            raise URLValidationError("unsupported_scheme", f"Only http and https URLs are supported (got '{scheme}').")
        return NormalizedURL(scheme + url[m.end() - 3:], False)
    if url.startswith("//"):
        return NormalizedURL("http:" + url, True, ["No scheme given; 'http' was assumed."])
    if _OPAQUE_SCHEME_RE.match(url):
        raise URLValidationError("unsupported_scheme", "Only http and https URLs are supported.")
    return NormalizedURL("http://" + url, True, ["No scheme given; 'http' was assumed."])


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    n = len(text)
    return float(-sum((c / n) * math.log2(c / n) for c in Counter(text).values()))


@dataclass
class ParsedURL:
    normalized: NormalizedURL
    host: str          # ASCII hostname, lower-case, no trailing dot
    is_ip: bool
    registrable: str
    public_suffix: str
    path: str
    query: str
    fragment: str
    scheme: str
    port: int | None
    has_userinfo: bool


def parse_url(raw: str) -> ParsedURL:
    norm = normalize_url(raw)
    try:
        sp = urlsplit(norm.url)
        port = sp.port
        hostname = sp.hostname
    except ValueError as exc:
        raise URLValidationError("malformed_url", "URL could not be parsed.") from exc
    if not hostname:
        raise URLValidationError("missing_hostname", "URL has no hostname.")

    host = hostname.lower()
    if host.endswith("."):
        host = host[:-1]
    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        pass
    if not is_ip:
        if not host.isascii():
            try:
                host = host.encode("idna").decode("ascii")
            except UnicodeError as exc:
                raise URLValidationError("invalid_hostname", "Hostname could not be IDNA-encoded.") from exc
        labels = host.split(".")
        if not host or any(label == "" for label in labels):
            raise URLValidationError("invalid_hostname", "Hostname contains an empty label.")
        if len(host) > 253 or any(len(label) > 63 for label in labels):
            raise URLValidationError("invalid_hostname", "Hostname exceeds DNS length limits.")

    if is_ip:
        registrable, suffix = host, ""
    else:
        labels = host.split(".")
        suffix = get_tld(host) or labels[-1]
        sld = get_sld(host)
        if not sld or "." not in sld:
            sld = ".".join(labels[-2:]) if len(labels) >= 2 else host
        registrable = sld
    return ParsedURL(
        normalized=norm, host=host, is_ip=is_ip, registrable=registrable, public_suffix=suffix,
        path=sp.path, query=sp.query, fragment=sp.fragment, scheme=sp.scheme, port=port,
        has_userinfo=("@" in sp.netloc),
    )


def extract_features_from_parsed(p: ParsedURL) -> dict[str, float]:
    url = p.normalized.url
    n = len(url)
    letters = sum(1 for c in url if c.isascii() and c.isalpha())
    digits = sum(1 for c in url if "0" <= c <= "9")
    other = sum(1 for c in url if not (c.isascii() and c.isalnum()) and c not in _NORMAL_PUNCT)
    labels = p.host.split(".") if not p.is_ip else [p.host]
    reg_labels = p.registrable.count(".") + 1
    low = url.lower()
    tokens = sum(1 for t in SUSPICIOUS_TOKENS if t in low)
    segments = [s for s in p.path.split("/") if s]
    last = segments[-1] if segments else ""
    try:
        n_params = len(parse_qsl(p.query, keep_blank_values=True, max_num_fields=1000)) if p.query else 0
    except ValueError:
        n_params = p.query.count("&") + 1
    host_for_count = p.host

    feats: dict[str, float] = {
        "url_length": n,
        "hostname_length": len(host_for_count),
        "path_length": len(p.path),
        "query_length": len(p.query),
        "fragment_length": len(p.fragment),
        "path_segment_count": len(segments),
        "path_depth_has_extension": int("." in last),
        "query_param_count": n_params,
        "subdomain_count": 0 if p.is_ip else max(0, len(labels) - reg_labels),
        "hostname_label_count": len(labels),
        "longest_label_length": max(len(x) for x in labels),
        "registrable_domain_length": len(p.registrable),
        "tld_length": len(p.public_suffix),
        "is_https": int(p.scheme == "https"),
        "is_ip_host": int(p.is_ip),
        "has_nonstandard_port": int(p.port is not None and p.port not in (80, 443)),
        "has_userinfo": int(p.has_userinfo),
        "has_punycode": int(any(x.startswith("xn--") for x in labels)),
        "letter_count": letters,
        "digit_count": digits,
        "digit_ratio": digits / n,
        "letter_ratio": letters / n,
        "digit_to_letter_ratio": digits / max(letters, 1),
        "hyphen_count": url.count("-"),
        "dot_count": url.count("."),
        "underscore_count": url.count("_"),
        "at_count": url.count("@"),
        "qmark_count": url.count("?"),
        "equals_count": url.count("="),
        "ampersand_count": url.count("&"),
        "slash_count": url.count("/"),
        "percent_encoded_count": len(_PCT_RE.findall(url)),
        "other_special_count": other,
        "url_entropy": _entropy(url),
        "hostname_entropy": _entropy(p.host),
        "hostname_digit_count": sum(1 for c in p.host if "0" <= c <= "9"),
        "hostname_hyphen_count": p.host.count("-"),
        "suspicious_token_count": tokens,
        "has_suspicious_token": int(tokens > 0),
    }
    # Stable order + finiteness guarantee.
    out = {k: feats[k] for k in FEATURE_NAMES}
    for k, v in out.items():
        if not math.isfinite(float(v)):
            raise URLValidationError("non_finite_feature", f"Feature '{k}' is not finite.")
    return out


def extract_features(raw: str) -> dict[str, float]:
    """Raw URL string -> ordered feature dict. Raises URLValidationError."""
    return extract_features_from_parsed(parse_url(raw))


def features_to_vector(features: dict[str, float]) -> np.ndarray:
    """Feature dict -> float64 vector in the canonical order."""
    return np.asarray([float(features[k]) for k in FEATURE_NAMES], dtype=np.float64)
