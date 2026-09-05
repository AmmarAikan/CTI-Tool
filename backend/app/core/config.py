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
    misp_allow_http: bool = _as_bool(os.getenv("MISP_ALLOW_HTTP"), False)
    misp_timeout_seconds: int = int(os.getenv("MISP_TIMEOUT_SECONDS", "30"))
    external_feed_url: str | None = os.getenv("EXTERNAL_FEED_URL")
    external_feed_token: str | None = os.getenv("EXTERNAL_FEED_TOKEN")
    external_feed_hmac_secret: str | None = os.getenv("EXTERNAL_FEED_HMAC_SECRET")
    external_feed_verify_tls: bool = _as_bool(os.getenv("EXTERNAL_FEED_VERIFY_TLS"), True)
    external_feed_allow_http: bool = _as_bool(os.getenv("EXTERNAL_FEED_ALLOW_HTTP"), False)
    external_feed_require_contract: bool = _as_bool(os.getenv("EXTERNAL_FEED_REQUIRE_CONTRACT"), True)
    external_feed_connect_timeout_seconds: int = int(os.getenv("EXTERNAL_FEED_CONNECT_TIMEOUT_SECONDS", "5"))
    external_feed_read_timeout_seconds: int = int(os.getenv("EXTERNAL_FEED_READ_TIMEOUT_SECONDS", "60"))
    external_feed_max_bytes: int = int(os.getenv("EXTERNAL_FEED_MAX_BYTES", str(20 * 1024 * 1024)))
    external_feed_max_pages: int = int(os.getenv("EXTERNAL_FEED_MAX_PAGES", "20"))
    external_feed_page_size: int = int(os.getenv("EXTERNAL_FEED_PAGE_SIZE", "250"))
    external_control_api_url: str | None = os.getenv("EXTERNAL_CONTROL_API_URL")
    external_control_api_token: str | None = os.getenv("EXTERNAL_CONTROL_API_TOKEN")
    external_control_verify_tls: bool = _as_bool(os.getenv("EXTERNAL_CONTROL_VERIFY_TLS"), True)
    external_control_allow_http: bool = _as_bool(os.getenv("EXTERNAL_CONTROL_ALLOW_HTTP"), False)
    external_control_timeout_seconds: int = int(os.getenv("EXTERNAL_CONTROL_TIMEOUT_SECONDS", "30"))
    external_control_max_bytes: int = int(
        os.getenv("EXTERNAL_CONTROL_MAX_BYTES", str(2 * 1024 * 1024))
    )
    wazuh_indexer_url: str | None = os.getenv("WAZUH_INDEXER_URL")
    wazuh_indexer_username: str | None = os.getenv("WAZUH_INDEXER_USERNAME")
    wazuh_indexer_password: str | None = os.getenv("WAZUH_INDEXER_PASSWORD")
    wazuh_indexer_token: str | None = os.getenv("WAZUH_INDEXER_TOKEN")
    wazuh_indexer_verify_tls: bool = _as_bool(os.getenv("WAZUH_INDEXER_VERIFY_TLS"), True)
    wazuh_indexer_allow_http: bool = _as_bool(os.getenv("WAZUH_INDEXER_ALLOW_HTTP"), False)
    wazuh_indexer_timeout_seconds: int = int(os.getenv("WAZUH_INDEXER_TIMEOUT_SECONDS", "30"))
    wazuh_indexer_batch_size: int = int(os.getenv("WAZUH_INDEXER_BATCH_SIZE", "500"))
    wazuh_indexer_name: str = os.getenv("WAZUH_INDEXER_NAME", "Wazuh VPS")
    wazuh_index_pattern: str = os.getenv("WAZUH_INDEX_PATTERN", "wazuh-alerts*")
    wazuh_timestamp_field: str = os.getenv("WAZUH_TIMESTAMP_FIELD", "timestamp")
    wazuh_tiebreaker_field: str = os.getenv("WAZUH_TIEBREAKER_FIELD", "id")
    wazuh_initial_since: str | None = os.getenv("WAZUH_INITIAL_SINCE")
    dionaea_api_url: str | None = os.getenv("DIONAEA_API_URL")
    dionaea_api_token: str | None = os.getenv("DIONAEA_API_TOKEN")
    dionaea_api_hmac_secret: str | None = os.getenv("DIONAEA_API_HMAC_SECRET")
    dionaea_api_verify_tls: bool = _as_bool(os.getenv("DIONAEA_API_VERIFY_TLS"), True)
    dionaea_api_allow_http: bool = _as_bool(os.getenv("DIONAEA_API_ALLOW_HTTP"), False)
    dionaea_api_timeout_seconds: int = int(os.getenv("DIONAEA_API_TIMEOUT_SECONDS", "30"))
    dionaea_api_max_bytes: int = int(
        os.getenv("DIONAEA_API_MAX_BYTES", str(20 * 1024 * 1024))
    )
    dionaea_api_max_pages: int = int(os.getenv("DIONAEA_API_MAX_PAGES", "20"))
    dionaea_api_page_size: int = int(os.getenv("DIONAEA_API_PAGE_SIZE", "500"))
    dionaea_sensor_name: str = os.getenv("DIONAEA_SENSOR_NAME", "Dionaea VPS")
    internal_sensor_api_token: str | None = os.getenv("INTERNAL_SENSOR_API_TOKEN")
    internal_sensor_api_hmac_secret: str | None = os.getenv("INTERNAL_SENSOR_API_HMAC_SECRET")
    internal_sensor_verify_tls: bool = _as_bool(os.getenv("INTERNAL_SENSOR_VERIFY_TLS"), True)
    internal_sensor_allow_http: bool = _as_bool(os.getenv("INTERNAL_SENSOR_ALLOW_HTTP"), False)
    internal_sensor_timeout_seconds: int = int(os.getenv("INTERNAL_SENSOR_TIMEOUT_SECONDS", "30"))
    internal_sensor_max_bytes: int = int(
        os.getenv("INTERNAL_SENSOR_MAX_BYTES", str(20 * 1024 * 1024))
    )
    internal_sensor_max_pages: int = int(os.getenv("INTERNAL_SENSOR_MAX_PAGES", "20"))
    internal_sensor_page_size: int = int(os.getenv("INTERNAL_SENSOR_PAGE_SIZE", "500"))
    host_auth_api_url: str | None = os.getenv("HOST_AUTH_API_URL")
    host_auth_sensor_name: str = os.getenv("HOST_AUTH_SENSOR_NAME", "VPS SSH Authentication")
    web_access_api_url: str | None = os.getenv("WEB_ACCESS_API_URL")
    web_access_sensor_name: str = os.getenv("WEB_ACCESS_SENSOR_NAME", "VPS Gateway Access")
    ner_min_confidence: float = float(os.getenv("NER_MIN_CONFIDENCE", "0.50"))
    ner_chunk_chars: int = int(os.getenv("NER_CHUNK_CHARS", "600"))
    ner_chunk_overlap_chars: int = int(os.getenv("NER_CHUNK_OVERLAP_CHARS", "100"))
    ner_inference_batch_size: int = int(os.getenv("NER_INFERENCE_BATCH_SIZE", "8"))
    ner_cache_size: int = int(os.getenv("NER_CACHE_SIZE", "4096"))

    @property
    def is_production(self) -> bool:
        return self.app_env.lower() == "production"

    @property
    def misp_configured(self) -> bool:
        return bool(self.misp_url and self.misp_api_key)

    @property
    def external_feed_configured(self) -> bool:
        return bool(self.external_feed_url and self.external_feed_token)

    @property
    def external_control_configured(self) -> bool:
        return bool(self.external_control_api_url and self.external_control_api_token)

    @property
    def wazuh_indexer_configured(self) -> bool:
        has_auth = bool(self.wazuh_indexer_token or (self.wazuh_indexer_username and self.wazuh_indexer_password))
        return bool(self.wazuh_indexer_url and has_auth)

    @property
    def dionaea_api_configured(self) -> bool:
        return bool(self.dionaea_api_url and self.dionaea_api_token)

    @property
    def host_auth_api_configured(self) -> bool:
        return bool(self.host_auth_api_url and self.internal_sensor_api_token)

    @property
    def web_access_api_configured(self) -> bool:
        return bool(self.web_access_api_url and self.internal_sensor_api_token)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
