from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]


def _as_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True, slots=True)
class Settings:
    app_name: str = os.getenv("CTI_APP_NAME", "AI-Based CTI Platform")
    app_env: str = os.getenv("CTI_APP_ENV", "development")
    api_prefix: str = "/api/v1"
    database_url: str | None = os.getenv("DATABASE_URL")
    database_host: str | None = os.getenv("POSTGRES_HOST")
    database_port: int = int(os.getenv("POSTGRES_PORT", "5432"))
    database_name: str = os.getenv("POSTGRES_DB", "cti_platform")
    database_user: str = os.getenv("POSTGRES_USER", "cti")
    database_password: str | None = os.getenv("POSTGRES_PASSWORD")
    jwt_secret: str = os.getenv("JWT_SECRET", "development-only-change-me")
    jwt_algorithm: str = "HS256"
    access_token_minutes: int = int(os.getenv("ACCESS_TOKEN_MINUTES", "480"))
    bootstrap_admin_username: str | None = os.getenv("BOOTSTRAP_ADMIN_USERNAME")
    bootstrap_admin_password: str | None = os.getenv("BOOTSTRAP_ADMIN_PASSWORD")
    max_upload_bytes: int = int(os.getenv("MAX_UPLOAD_BYTES", str(10 * 1024 * 1024)))
    upload_dir: Path = Path(os.getenv("UPLOAD_DIR", str(PROJECT_ROOT / "data" / "uploads")))
    dionaea_json_log_path: Path = Path(
        os.getenv("DIONAEA_JSON_LOG_PATH", str(PROJECT_ROOT / "data" / "dionaea" / "dionaea.json"))
    )
    dionaea_max_log_bytes: int = int(os.getenv("DIONAEA_MAX_LOG_BYTES", str(50 * 1024 * 1024)))
    nvd_api_key: str | None = os.getenv("NVD_API_KEY")
    misp_url: str | None = os.getenv("MISP_URL")
    misp_api_key: str | None = os.getenv("MISP_API_KEY")
    misp_verify_tls: bool = _as_bool(os.getenv("MISP_VERIFY_TLS"), True)
    misp_timeout_seconds: int = int(os.getenv("MISP_TIMEOUT_SECONDS", "30"))

    @property
    def is_production(self) -> bool:
        return self.app_env.lower() == "production"

    @property
    def misp_configured(self) -> bool:
        return bool(self.misp_url and self.misp_api_key)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
