from __future__ import annotations

import hashlib

from backend.app.pipeline.common.cti_schema import RawRecord


class RecordDeduplicator:
    """Track duplicate external records by URL, external id, or normalized text fingerprint."""

    def __init__(self) -> None:
        self._seen: set[str] = set()

    def is_duplicate(self, record: RawRecord, normalized_text: str) -> bool:
        fingerprint = self.fingerprint(record, normalized_text)
        if fingerprint in self._seen:
            return True
        self._seen.add(fingerprint)
        return False

    def fingerprint(self, record: RawRecord, normalized_text: str) -> str:
        stable_reference = record.url or record.external_id
        if stable_reference:
            return f"ref:{stable_reference.strip().lower()}"
        digest = hashlib.sha256(
            f"{record.source_name}\n{record.title}\n{normalized_text}".lower().encode("utf-8")
        ).hexdigest()
        return f"text:{digest}"
