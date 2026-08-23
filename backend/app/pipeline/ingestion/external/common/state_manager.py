from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.app.pipeline.ingestion.external.common.json_storage import load_json, save_json


EMPTY_STATE: dict[str, Any] = {"schema_version": "1.0", "sources": {}, "urls": {}, "items": {}, "runs": {}}


class StateCorruptionError(RuntimeError):
    pass


class JsonStateManager:
    """Atomic JSON state with recoverable corrupt-file quarantine."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def load(self, *, recover_corrupt: bool = True) -> dict[str, Any]:
        try:
            value = load_json(self.path, default=deepcopy(EMPTY_STATE))
        except (OSError, ValueError) as exc:
            if not recover_corrupt:
                raise StateCorruptionError(f"invalid state file: {self.path}") from exc
            self._quarantine_corrupt_file()
            return deepcopy(EMPTY_STATE)
        if not isinstance(value, dict) or value.get("schema_version") != "1.0":
            if not recover_corrupt:
                raise StateCorruptionError(f"unsupported state file: {self.path}")
            self._quarantine_corrupt_file()
            return deepcopy(EMPTY_STATE)
        return value

    def save(self, state: dict[str, Any]) -> Path:
        if state.get("schema_version") != "1.0":
            raise ValueError("state schema_version must be 1.0")
        return save_json(state, self.path)

    def _quarantine_corrupt_file(self) -> Path | None:
        if not self.path.exists():
            return None
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        backup = self.path.with_name(f"{self.path.name}.corrupt-{stamp}")
        self.path.replace(backup)
        return backup
