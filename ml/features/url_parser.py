"""Deterministic URL parsing, token masking and structural decomposition.

Ensures that chat session IDs, UUIDs, hex strings and numeric paths
are masked into canonical tokens before feature calculation so legitimate
app routes are not mistaken for high-entropy phishing evasion.
"""

from __future__ import annotations

import ipaddress
import re
from typing import NamedTuple
from urllib.parse import unquote, urlparse

import publicsuffix2

EXTRACTOR_VERSION = "2.0.0"

# Regular expressions for sensitive ID and date masking in paths
RE_UUID = re.compile(r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b')
RE_HEX = re.compile(r'\b[0-9a-fA-F]{16,}\b')
RE_DATE = re.compile(r'/\d{4}/\d{1,2}/\d{1,2}/')
RE_DIGITS = re.compile(r'\b\d{8,}\b')
RE_BASE64 = re.compile(r'(?<=/)[A-Za-z0-9+_-]{24,}={0,2}(?=(/|$))')


class URLValidationError(ValueError):
    """Raised when an input cannot be parsed as an HTTP/HTTPS URL."""
    def __init__(self, message: str, code: str):
        super().__init__(message)
        self.code = code


class ParsedURL(NamedTuple):
    raw_url: str
    scheme: str
    has_explicit_scheme: bool
    userinfo: str
    host: str             # Normalized host with 'www.' stripped
    raw_host: str         # Original parsed host
    port: int | None
    path: str             # Raw path
    masked_path: str      # Path with UUIDs/hex/numbers masked
    query: str
    fragment: str
    tld: str              # Public suffix (e.g. 'com', 'co.uk')
    registrable: str      # e.g. 'google.com', 'chatgpt.com'
    subdomain: str        # e.g. 'mail', 'support'
    subdomain_parts: list[str]
    is_ip_host: bool
    is_punycode: bool


def mask_path_tokens(path: str) -> str:
    """Replace UUIDs, dates, long hex strings, long digit runs with placeholders."""
    if not path:
        return ""
    p = RE_UUID.sub("<uuid>", path)
    p = RE_HEX.sub("<hex>", p)
    p = RE_DATE.sub("/<date>/", p)
    p = RE_DIGITS.sub("<num>", p)
    p = RE_BASE64.sub("<b64>", p)
    return p


def parse_url(raw: str) -> ParsedURL:
    """Strictly parse and normalize a URL string without network calls."""
    if not isinstance(raw, str):
        raise URLValidationError(f"Expected str, got {type(raw).__name__}", "non_string_input")

    s = raw.strip()
    if not s:
        raise URLValidationError("Empty URL string", "empty_url")
    if len(s) > 4096:
        raise URLValidationError("URL exceeds 4096 characters", "url_too_long")

    # Reject dangerous or non-web schemes
    s_low = s.lower()
    if s_low.startswith(("javascript:", "data:", "file:", "vbscript:", "blob:")):
        raise URLValidationError("Unsupported non-HTTP URI scheme", "unsupported_scheme")

    has_explicit_scheme = bool(re.match(r'^[a-zA-Z][a-zA-Z0-9+.\-]*://', s))
    if not has_explicit_scheme:
        # Prepend http:// for consistent parsing
        s_parse = "http://" + s
    else:
        s_parse = s

    try:
        parsed = urlparse(s_parse)
    except Exception as exc:
        raise URLValidationError(f"Malformed URL: {exc}", "malformed_url") from exc

    scheme = (parsed.scheme or "http").lower()
    if scheme not in ("http", "https"):
        raise URLValidationError(f"Unsupported scheme {scheme!r}", "unsupported_scheme")

    netloc = parsed.netloc or ""
    userinfo = ""
    host_port = netloc
    if "@" in netloc:
        userinfo, host_port = netloc.split("@", 1)

    raw_host = host_port.split(":")[0].strip().lower().rstrip(".")
    if not raw_host:
        raise URLValidationError("Missing hostname", "missing_hostname")

    port = parsed.port

    # Check for IP address host
    is_ip = False
    try:
        ipaddress.ip_address(raw_host.strip("[]"))
        is_ip = True
    except ValueError:
        is_ip = False

    # Check punycode / IDN
    is_punycode = "xn--" in raw_host or any(ord(c) > 127 for c in raw_host)

    # Normalize host: strip leading www. for feature extraction
    host = raw_host[4:] if raw_host.startswith("www.") else raw_host

    # Extract public suffix and registrable domain
    if is_ip:
        tld = ""
        registrable = raw_host
        subdomain = ""
        subdomain_parts = []
    else:
        tld = publicsuffix2.get_tld(host) or ""
        # Registrable domain
        registrable = publicsuffix2.get_sld(host) or host
        # Subdomain is everything before registrable
        if host == registrable or not host.endswith("." + registrable):
            subdomain = ""
            subdomain_parts = []
        else:
            subdomain = host[: -(len(registrable) + 1)]
            subdomain_parts = [p for p in subdomain.split(".") if p]

    path = parsed.path or ""
    masked_path = mask_path_tokens(unquote(path))
    query = parsed.query or ""
    fragment = parsed.fragment or ""

    return ParsedURL(
        raw_url=raw,
        scheme=scheme,
        has_explicit_scheme=has_explicit_scheme,
        userinfo=userinfo,
        host=host,
        raw_host=raw_host,
        port=port,
        path=path,
        masked_path=masked_path,
        query=query,
        fragment=fragment,
        tld=tld,
        registrable=registrable,
        subdomain=subdomain,
        subdomain_parts=subdomain_parts,
        is_ip_host=is_ip,
        is_punycode=is_punycode,
    )
