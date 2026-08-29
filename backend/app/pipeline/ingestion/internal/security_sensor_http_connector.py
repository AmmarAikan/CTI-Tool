from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from backend.app.pipeline.common.cti_schema import RawRecord, utc_now_iso
from backend.app.pipeline.ingestion.internal.dionaea_http_connector import (
    DionaeaAPIConnector,
)
from backend.app.pipeline.ingestion.internal.wazuh_connector import nested_value


class StructuredSecurityEventNormalizer:
    """Map lightweight VPS sensor events to the shared internal RawRecord contract."""

    def __init__(self, *, source_name: str, source_type: str) -> None:
        self.source_name = source_name
        self.source_type = source_type

    def normalize_item(self, item: dict[str, Any], _path: Path | None = None) -> RawRecord:
        timestamp = nested_value(item, "timestamp", "@timestamp", "event.created")
        event_id = nested_value(item, "id", "event.id")
        action = str(nested_value(item, "event.action", "action") or "security_event")
        outcome = str(nested_value(item, "event.outcome", "outcome") or "unknown")
        source_ip = str(nested_value(item, "source.ip", "src_ip", "remote_addr") or "unknown")
        message = str(nested_value(item, "message", "log.original") or "").strip()

        if self.source_type == "web_access":
            method = str(nested_value(item, "http.request.method", "method") or "UNKNOWN")
            path = str(nested_value(item, "url.original", "path") or "/")
            status = nested_value(item, "http.response.status_code", "status")
            title = f"Web {method} request from {source_ip}"
            content = message or f"{method} {path} returned HTTP {status or 'unknown'} for {source_ip}."
        else:
            title = f"Host authentication {outcome} from {source_ip}"
            content = message or f"Host authentication action {action} had outcome {outcome} from {source_ip}."

        canonical = json.dumps(item, sort_keys=True, separators=(",", ":"), default=str)
        stable_id = str(event_id or f"{self.source_type}:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()[:24]}")
        return RawRecord(
            external_id=stable_id,
            source_name=self.source_name,
            source_type=self.source_type,
            title=title,
            content=content,
            published_at=str(timestamp) if timestamp else None,
            collected_at=utc_now_iso(),
            raw_data=item,
            trusted_cybersecurity_source=True,
            source_pipeline="internal",
        )


class SecuritySensorAPIConnector(DionaeaAPIConnector):
    """Pull host-auth or web-access JSON from the bounded VPS sensor gateway."""

    def __init__(self, *args, source_type: str, **kwargs) -> None:
        if source_type not in {"linux_auth", "web_access"}:
            raise ValueError("source_type must be linux_auth or web_access")
        self.source_type = source_type
        super().__init__(*args, **kwargs)

    def _normalizer(self) -> StructuredSecurityEventNormalizer:
        return StructuredSecurityEventNormalizer(
            source_name=self.source_name,
            source_type=self.source_type,
        )

    def _transport_name(self) -> str:
        return f"{self.source_type}_https_json_api"
