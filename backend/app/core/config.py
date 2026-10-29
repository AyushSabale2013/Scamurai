"""Runtime configuration (environment variables, see .env.example)."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PHISHGUARD_", env_file=".env", extra="ignore")

    artifact_dir: Path = Field(default=BACKEND_DIR / "artifacts")
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173,http://localhost:4173,http://localhost:8080"
    max_batch_size: int = 100
    max_request_bytes: int = 1_000_000
    log_level: str = "INFO"
    explain_by_default: bool = True

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
