from __future__ import annotations

import secrets
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def generate_run_id(now: datetime | None = None) -> str:
    moment = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    return f"ext-{moment.strftime('%Y%m%dT%H%M%SZ')}-{secrets.token_hex(6)}"


@dataclass(slots=True)
class RunManifest:
    run_id: str = field(default_factory=generate_run_id)
    started_at: str = field(default_factory=utc_now_iso)
    completed_at: str | None = None
    status: str = "running"
    sources: dict[str, Any] = field(default_factory=dict)
    failed_sources: list[dict[str, Any]] = field(default_factory=list)
    total_records: int = 0
    accepted_records: int = 0
    review_records: int = 0
    invalid_records: int = 0
    duplicates_removed: int = 0
    dataset_file: str | None = None
    dataset_sha256: str | None = None
    classifier_model_version: str | None = None
    classifier_model_sha256: str | None = None
    schema_version: str = "1.0"
    producer: str = "external-sources-team"

    def record_failure(self, source_id: str, category: str, *, retryable: bool = False) -> None:
        self.failed_sources.append({"source_id": source_id, "category": category, "retryable": retryable})

    def finish(self, status: str) -> None:
        if status not in {"completed", "partial", "failed", "cancelled"}:
            raise ValueError("invalid terminal run status")
        self.status = status
        self.completed_at = utc_now_iso()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
