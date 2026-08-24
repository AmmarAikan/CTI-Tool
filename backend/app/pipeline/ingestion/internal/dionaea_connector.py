from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

from backend.app.pipeline.common.cti_schema import RawRecord, utc_now_iso
from backend.app.pipeline.ingestion.internal.base_internal_connector import (
    InternalConnector,
)
from backend.app.pipeline.ingestion.internal.json_file_reader import read_json_records
from backend.app.pipeline.ingestion.internal.wazuh_connector import nested_value


def _collection_size(value: Any) -> int:
    if isinstance(value, list):
        return len(value)
    if isinstance(value, dict):
        lengths = [len(item) for item in value.values() if isinstance(item, list)]
        return max(lengths, default=1 if value else 0)
    return 0


class DionaeaFileConnector(InternalConnector):
    """Read the official Dionaea ``log_json`` JSONL output."""

    def __init__(
        self,
        paths: Sequence[str | Path],
        source_name: str = "Dionaea Honeypot",
    ) -> None:
        self.paths = [Path(path) for path in paths]
        self.source_name = source_name

    def collect(self) -> Iterable[RawRecord]:
        for path in self.paths:
            for item in read_json_records(
                path,
                wrapper_keys=("events", "items", "data", "results"),
                format_name="Dionaea",
            ):
                yield self.normalize_item(item)

    def normalize_item(self, item: dict[str, Any], _path: Path | None = None) -> RawRecord:
        timestamp = nested_value(item, "timestamp", "@timestamp")
        protocol = str(nested_value(item, "connection.protocol", "protocol") or "unknown")
        transport = str(nested_value(item, "connection.transport", "transport") or "unknown")
        connection_type = str(nested_value(item, "connection.type", "type") or "interaction")
        src_ip = str(nested_value(item, "src_ip", "source.ip") or "unknown")
        dst_ip = str(nested_value(item, "dst_ip", "destination.ip") or "honeypot")
        src_port = nested_value(item, "src_port", "source.port")
        dst_port = nested_value(item, "dst_port", "destination.port")
        credentials = _collection_size(nested_value(item, "credentials"))
        commands = _collection_size(nested_value(item, "ftp.commands", "commands"))

        title = f"Dionaea {protocol} {connection_type} interaction from {src_ip}"
        content_parts = [
            f"Dionaea observed a {connection_type} {protocol}/{transport} connection",
            f"from {src_ip}:{src_port or 'unknown'}",
            f"to {dst_ip}:{dst_port or 'unknown'}",
        ]
        if credentials:
            content_parts.append(f"with {credentials} credential attempt(s)")
        if commands:
            content_parts.append(f"and {commands} captured command(s)")
        content = " ".join(content_parts) + "."

        canonical = json.dumps(item, sort_keys=True, separators=(",", ":"), default=str)
        external_id = f"dionaea:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()[:24]}"
        return RawRecord(
            external_id=external_id,
            source_name=self.source_name,
            source_type="dionaea",
            title=title,
            content=content,
            published_at=str(timestamp) if timestamp else None,
            collected_at=utc_now_iso(),
            raw_data=item,
            trusted_cybersecurity_source=True,
            source_pipeline="internal",
        )
