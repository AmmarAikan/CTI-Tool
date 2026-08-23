from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class ConfigurationError(ValueError):
    pass


def load_config(path: str | Path, *, required_version: str = "1.0") -> dict[str, Any]:
    target = Path(path)
    try:
        with target.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
    except FileNotFoundError as exc:
        raise ConfigurationError(f"configuration file not found: {target}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigurationError(f"invalid JSON configuration: {target}") from exc
    if not isinstance(value, dict):
        raise ConfigurationError(f"configuration root must be an object: {target}")
    if value.get("schema_version") != required_version:
        raise ConfigurationError(f"configuration schema_version must be {required_version}: {target}")
    return value


def validate_collection_settings(value: dict[str, Any]) -> dict[str, Any]:
    http = value.get("http")
    collection = value.get("collection")
    if not isinstance(http, dict) or not isinstance(collection, dict):
        raise ConfigurationError("collection settings require http and collection objects")
    positive_http = ("connect_timeout_seconds", "read_timeout_seconds", "max_response_bytes", "retry_total")
    for key in positive_http:
        number = http.get(key)
        if not isinstance(number, (int, float)) or number <= 0:
            raise ConfigurationError(f"http.{key} must be positive")
    if not isinstance(http.get("max_redirects"), int) or http["max_redirects"] < 0:
        raise ConfigurationError("http.max_redirects must be a non-negative integer")
    if not isinstance(http.get("user_agent"), str) or not http["user_agent"].strip():
        raise ConfigurationError("http.user_agent is required")
    if not isinstance(collection.get("max_items_per_source"), int) or collection["max_items_per_source"] <= 0:
        raise ConfigurationError("collection.max_items_per_source must be positive")
    return value
