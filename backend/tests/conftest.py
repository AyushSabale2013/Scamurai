"""Shared fixtures. A tiny synthetic dataset is used so the whole pipeline
(audit -> clean -> split -> train -> artifacts) is exercised in seconds without
needing the real CSV."""

from __future__ import annotations

import random
import string
import sys
from pathlib import Path

import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def _word(rng: random.Random, n: int) -> str:
    return "".join(rng.choice(string.ascii_lowercase) for _ in range(n))


def make_synthetic_csv(path: Path, n: int = 1400, seed: int = 0) -> Path:
    rng = random.Random(seed)
    rows = []
    for i in range(n):
        if i % 2:  # legitimate: short https://www.<word>.com
            rows.append((f"https://www.{_word(rng, rng.randint(5, 10))}.{rng.choice(['com', 'org', 'co.uk'])}", 1))
        else:      # phishing: varied, longer, digits, paths
            host = f"{_word(rng, 6)}-{rng.choice(['login', 'secure', 'verify'])}{rng.randint(1, 999)}.{rng.choice(['xyz', 'top', 'com'])}"
            rows.append((f"{rng.choice(['http', 'https'])}://{host}/{_word(rng, 8)}/{_word(rng, 5)}.php?id={rng.randint(1, 10**6)}", 0))
    rows.append(rows[0])  # one exact duplicate
    df = pd.DataFrame(rows, columns=["URL", "label"])
    df.to_csv(path, index=False, encoding="utf-8-sig")
    return path


@pytest.fixture(scope="session")
def synthetic_csv(tmp_path_factory) -> Path:
    return make_synthetic_csv(tmp_path_factory.mktemp("data") / "synthetic.csv")


@pytest.fixture(scope="session")
def trained_dir(tmp_path_factory, synthetic_csv) -> Path:
    from app.ml import train

    out = tmp_path_factory.mktemp("artifacts")
    rep = tmp_path_factory.mktemp("reports")
    rc = train.main(["--csv", str(synthetic_csv), "--artifacts", str(out), "--reports", str(rep), "--rf-trees", "15"])
    assert rc == 0
    return out


@pytest.fixture()
def client(trained_dir, monkeypatch):
    from fastapi.testclient import TestClient

    from app.core import config

    monkeypatch.setenv("PHISHGUARD_ARTIFACT_DIR", str(trained_dir))
    config.get_settings.cache_clear()
    from app.main import create_app

    with TestClient(create_app()) as c:
        yield c
    config.get_settings.cache_clear()
