"""Compatibility bridge for backend inference.

Directly imports the canonical shared feature extraction logic from ml.features.
Ensures zero duplication between offline training and online serving.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure repo root is on sys.path for ml.features
_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from ml.features import (
    EXTRACTOR_VERSION,
    FEATURE_DEFINITIONS,
    FEATURE_NAMES,
    FeatureDefinition,
    ParsedURL,
    URLValidationError,
    extract_features,
    extract_features_from_parsed,
    features_to_vector,
    mask_path_tokens,
    parse_url,
    shannon_entropy,
)

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
