from __future__ import annotations

import logging
import re
from typing import Any


SENSITIVE_KEY = re.compile(r"token|secret|password|authorization|api[_-]?key|cookie", re.IGNORECASE)


def redact_mapping(value: dict[str, Any]) -> dict[str, Any]:
    """Recursively redact values whose keys identify credentials or secrets."""
    result: dict[str, Any] = {}
    for key, item in value.items():
        if SENSITIVE_KEY.search(str(key)):
            result[key] = "[REDACTED]"
        elif isinstance(item, dict):
            result[key] = redact_mapping(item)
        elif isinstance(item, list):
            result[key] = [redact_mapping(entry) if isinstance(entry, dict) else entry for entry in item]
        else:
            result[key] = item
    return result


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
