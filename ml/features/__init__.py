"""Unified, shared feature extraction package for Scamurai.

Zero network calls, deterministic, versioned with EXTRACTOR_VERSION = '2.0.0'.
Used identically by offline training and online inference.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from .lexical import extract_lexical_features, shannon_entropy
from .url_parser import (
    EXTRACTOR_VERSION,
    ParsedURL,
    URLValidationError,
    mask_path_tokens,
    parse_url,
)

# Canonical, stable feature ordering for vectorization
FEATURE_NAMES: tuple[str, ...] = (
    "brand_in_path",
    "brand_in_subdomain",
    "brand_keyword_combo",
    "brand_typosquatting",
    "has_embedded_url",
    "has_explicit_http",
    "has_userinfo",
    "host_digits",
    "host_dots",
    "host_entropy",
    "host_hyphens",
    "host_keyword_count",
    "host_len",
    "is_ip_host",
    "is_nonstandard_port",
    "is_punycode",
    "is_risky_tld",
    "is_url_shortener",
    "is_user_content_platform",
    "max_label_len",
    "min_dist_to_brand",
    "path_digits",
    "path_depth",
    "path_entropy",
    "path_hyphens",
    "path_keyword_count",
    "query_len",
    "query_param_count",
    "subdomain_count",
    "tranco_rank_bucket",
)


# Simple feature definition structure for explainability UI
@dataclass(frozen=True)
class FeatureDefinition:
    label: str
    description: str


# Human-readable labels & descriptions
FEATURE_DEFINITIONS: dict[str, FeatureDefinition] = {
    name: FeatureDefinition(
        label=name.replace("_", " ").title(),
        description="Feature representing " + name.replace("_", " "),
    )
    for name in FEATURE_NAMES
}


def extract_features(url: str) -> dict[str, float]:
    """Extract full feature dictionary from a raw URL string."""
    parsed = parse_url(url)
    return extract_features_from_parsed(parsed)


def extract_features_from_parsed(parsed: ParsedURL) -> dict[str, float]:
    """Extract features from an already-parsed URL."""
    return extract_lexical_features(parsed)


def features_to_vector(features: dict[str, float]) -> np.ndarray:
    """Convert feature dictionary to a 1D float64 numpy array in canonical order."""
    return np.asarray([float(features[name]) for name in FEATURE_NAMES], dtype=np.float64)


__all__ = [
    "EXTRACTOR_VERSION",
    "FEATURE_DEFINITIONS",
    "FEATURE_NAMES",
    "FeatureDefinition",
    "ParsedURL",
    "URLValidationError",
    "extract_features",
    "extract_features_from_parsed",
    "features_to_vector",
    "mask_path_tokens",
    "parse_url",
    "shannon_entropy",
]
