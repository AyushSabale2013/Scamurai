"""Safe, one-time loading of the trained artifact.

Only the fixed file names inside the configured artifact directory are ever
loaded (never a user-supplied path). ``model.joblib`` is a pickle-based format,
so it must come from a trusted training run: the loader verifies the SHA-256
recorded in the metadata and refuses artifacts built with a different feature
extractor version or feature order.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib

from .explainability import ModelExplainer
from .feature_extraction import EXTRACTOR_VERSION, FEATURE_NAMES
from .preprocessing import sha256_file

log = logging.getLogger("phishguard.model")
MODEL_FILE = "model.joblib"
METADATA_FILE = "model_metadata.json"
REPORT_FILE = "evaluation_report.json"
AUDIT_FILE = "dataset_audit.json"


class ModelUnavailableError(RuntimeError):
    pass


@dataclass
class LoadedModel:
    pipeline: Any
    metadata: dict[str, Any]
    explainer: ModelExplainer | None

    @property
    def version(self) -> str:
        return self.metadata["model_version"]

    @property
    def threshold(self) -> float:
        return float(self.metadata["decision_threshold"])


def load_json(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def load_model(artifact_dir: Path) -> LoadedModel:
    meta_path, model_path = artifact_dir / METADATA_FILE, artifact_dir / MODEL_FILE
    if not meta_path.is_file() or not model_path.is_file():
        raise ModelUnavailableError(f"Model artifacts not found in {artifact_dir}. Run the training script first.")
    metadata = json.loads(meta_path.read_text(encoding="utf-8"))
    if metadata.get("artifact_file") != MODEL_FILE:
        raise ModelUnavailableError("Metadata points to an unexpected artifact file name.")
    if metadata.get("extractor_version") != EXTRACTOR_VERSION:
        raise ModelUnavailableError(
            f"Artifact was trained with extractor {metadata.get('extractor_version')} but this code is {EXTRACTOR_VERSION}. Retrain the model.")
    if metadata.get("feature_names") != FEATURE_NAMES:
        raise ModelUnavailableError("Artifact feature schema differs from the current extractor. Retrain the model.")
    if sha256_file(model_path) != metadata.get("artifact_sha256"):
        raise ModelUnavailableError("Model file checksum does not match its metadata; refusing to load.")
    pipeline = joblib.load(model_path)
    if list(pipeline.classes_) != [0, 1]:
        raise ModelUnavailableError(f"Unexpected class ordering {list(pipeline.classes_)}; expected [0, 1].")
    try:
        explainer: ModelExplainer | None = ModelExplainer(pipeline)
    except Exception:  # explanations are optional; predictions still work
        log.warning("Explainer unavailable", exc_info=True)
        explainer = None
    log.info("Model loaded", extra={"fields": {"model_version": metadata["model_version"]}})
    return LoadedModel(pipeline=pipeline, metadata=metadata, explainer=explainer)
