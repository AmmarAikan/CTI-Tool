from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def timestamped_filename(prefix: str, extension: str = "json", *, now: datetime | None = None) -> str:
    moment = now or datetime.now(timezone.utc)
    stamp = moment.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{prefix}_{stamp}.{extension.lstrip('.')}"


def atomic_replace(path: str | Path, data: bytes) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temp_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=target.parent)
    temp_path = Path(temp_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, target)
    except BaseException:
        temp_path.unlink(missing_ok=True)
        raise
    return target


def save_json(value: Any, path: str | Path) -> Path:
    payload = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n"
    return atomic_replace(path, payload.encode("utf-8"))


def load_json(path: str | Path, *, default: Any = None) -> Any:
    target = Path(path)
    if not target.exists():
        return default
    with target.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def latest_file(directory: str | Path, prefix: str, extension: str = "json") -> Path | None:
    candidates = [path for path in Path(directory).glob(f"{prefix}_*.{extension.lstrip('.')}") if path.is_file()]
    return max(candidates, key=lambda path: (path.stat().st_mtime_ns, path.name)) if candidates else None
