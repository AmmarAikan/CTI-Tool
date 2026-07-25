from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

from backend.app.pipeline.common.cti_schema import RawRecord, utc_now_iso
from backend.app.pipeline.ingestion.base_connector import ExternalConnector


TRUSTED_CYBER_SOURCES = {
    "cisa",
    "cert-at",
    "cert-eu",
    "mitre cve",
    "nvd",
}


class ExternalJsonFileConnector(ExternalConnector):
    """Load prepared external-source JSON records from data/external_samples/*.json."""

    def __init__(self, paths: Sequence[str | Path], source_name: str = "external_json_file") -> None:
        self.paths = [Path(path) for path in paths]
        self.source_name = source_name

    @classmethod
    def from_directory(cls, directory: str | Path) -> "ExternalJsonFileConnector":
        return cls(sorted(Path(directory).glob("*.json")))

    def collect(self) -> Iterable[RawRecord]:
        for path in self.paths:
            with path.open("r", encoding="utf-8") as file:
                payload = json.load(file)
            records = payload if isinstance(payload, list) else payload.get("items", [])
            if not isinstance(records, list):
                continue
            for item in records:
                if isinstance(item, dict):
                    yield self._normalize_item(item, path)

    def _normalize_item(self, item: dict[str, Any], path: Path) -> RawRecord:
        metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
        source_name = str(item.get("source") or path.stem)
        category = str(item.get("category") or "").lower()
        title = str(item.get("title") or metadata.get("cve_id") or "Untitled external record")
        content = str(item.get("content") or item.get("summary") or title)
        link = item.get("link") or item.get("url")
        external_id = str(metadata.get("cve_id") or link or self._stable_id(source_name, title, content))

        return RawRecord(
            external_id=external_id,
            source_name=source_name,
            source_type=self._infer_source_type(item, path),
            title=title,
            content=content,
            url=str(link) if link else None,
            published_at=str(item.get("published")) if item.get("published") else None,
            collected_at=str(item.get("collected_at") or utc_now_iso()),
            raw_data=item,
            trusted_cybersecurity_source=self._is_trusted_cyber_source(source_name, category),
        )

    def _infer_source_type(self, item: dict[str, Any], path: Path) -> str:
        metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
        source_name = str(item.get("source") or "").lower()
        category = str(item.get("category") or "").lower()
        file_name = path.name.lower()

        if source_name in {"nvd", "mitre cve"} or metadata.get("cve_id") or "vulnerabilities" in file_name:
            return "nvd"
        if category == "social":
            return "api"
        if metadata.get("feed_id"):
            return "rss"
        if metadata.get("collection_method") == "scrape":
            return "crawler"
        return "file"

    def _is_trusted_cyber_source(self, source_name: str, category: str) -> bool:
        normalized_source = source_name.strip().lower()
        return normalized_source in TRUSTED_CYBER_SOURCES and category in {"advisory", "vulnerability"}

    def _stable_id(self, source_name: str, title: str, content: str) -> str:
        digest = hashlib.sha256(f"{source_name}\n{title}\n{content}".encode("utf-8")).hexdigest()
        return f"external:{digest[:24]}"
