from __future__ import annotations

import logging
import re
from pathlib import Path
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


def configure_file_logging(path: str | Path, *, level: int = logging.INFO) -> Path:
    """Attach one canonical UTF-8 file handler at the active repository log path."""
    target = Path(path).resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    root = logging.getLogger()
    for handler in root.handlers:
        if isinstance(handler, logging.FileHandler) and Path(handler.baseFilename).resolve() == target:
            return target
    handler = logging.FileHandler(target, encoding="utf-8")
    handler.setLevel(level)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    root.addHandler(handler)
    if root.level > level:
        root.setLevel(level)
    return target
