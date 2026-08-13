from __future__ import annotations

import hashlib
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

from backend.app.pipeline.common.cti_schema import RawRecord, utc_now_iso
from backend.app.pipeline.ingestion.internal.base_internal_connector import (
    InternalConnector,
)
from backend.app.pipeline.ingestion.internal.json_file_reader import read_json_records


def nested_value(payload: dict[str, Any], *paths: str) -> Any:
    for path in paths:
        current: Any = payload
        for part in path.split("."):
            if not isinstance(current, dict) or part not in current:
                current = None
                break
            current = current[part]
        if current not in (None, "", [], {}):
            return current
    return None


class WazuhFileConnector(InternalConnector):
    """Read Wazuh ``alerts.json`` in JSON-array, wrapper-object, or JSONL form."""

    def __init__(self, paths: Sequence[str | Path], source_name: str = "Wazuh") -> None:
        self.paths = [Path(path) for path in paths]
        self.source_name = source_name

    def collect(self) -> Iterable[RawRecord]:
        for path in self.paths:
            for item in self._read_items(path):
                yield self._normalize_item(item, path)

    def _read_items(self, path: Path) -> Iterable[dict[str, Any]]:
        yield from read_json_records(
            path,
            wrapper_keys=("alerts", "items", "data", "results"),
            format_name="Wazuh",
        )

    def _normalize_item(self, item: dict[str, Any], path: Path) -> RawRecord:
        timestamp = nested_value(item, "timestamp", "@timestamp", "data.timestamp")
        rule_description = nested_value(item, "rule.description", "description", "decoder.name")
        full_log = nested_value(item, "full_log", "data.message", "message", "predecoder.program_name")
        title = str(rule_description or "Wazuh security alert")
        content = str(full_log or title)
        external_id = str(
            nested_value(item, "id", "alert_id", "event.id")
            or self._stable_id(path, timestamp, title, content)
        )
        return RawRecord(
            external_id=external_id,
            source_name=self.source_name,
            source_type="wazuh",
            title=title,
            content=content,
            published_at=str(timestamp) if timestamp else None,
            collected_at=utc_now_iso(),
            raw_data=item,
            trusted_cybersecurity_source=True,
            source_pipeline="internal",
        )

    def _stable_id(self, path: Path, timestamp: Any, title: str, content: str) -> str:
        basis = f"{path.name}\n{timestamp}\n{title}\n{content}"
        return f"wazuh:{hashlib.sha256(basis.encode('utf-8')).hexdigest()[:24]}"
