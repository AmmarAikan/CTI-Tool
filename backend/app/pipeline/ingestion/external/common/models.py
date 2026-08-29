from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

from backend.app.pipeline.common.cti_schema import RawRecord
from backend.app.pipeline.ingestion.external.common.hashing import sha256_text


ClassificationStatus = Literal["not_required", "not_run", "accepted", "rejected", "error"]


@dataclass(frozen=True, slots=True)
class ExternalClassification:
    status: ClassificationStatus = "not_run"
    label: str | None = None
    score: float | None = None
    model_version: str | None = None


@dataclass(frozen=True, slots=True)
class ExternalCTIItem:
    record_id: str
    source: str
    source_type: str
    category: str
    title: str
    link: str | None
    content: str
    summary: str
    collected_at: str
    content_hash: str
    source_item_id: str | None = None
    published: str | None = None
    updated_at: str | None = None
    author: str | None = None
    tags: tuple[str, ...] = ()
    language: str = "en"
    classification: ExternalClassification = field(default_factory=ExternalClassification)
    metadata: dict[str, Any] = field(default_factory=dict)
    schema_version: str = "1.0"

    def __post_init__(self) -> None:
        if self.schema_version != "1.0":
            raise ValueError("unsupported External CTI item schema version")
        if len(self.record_id) < 16 or not self.source or not self.source_type:
            raise ValueError("record_id, source, and source_type are required")
        if self.content_hash != sha256_text(self.content):
            raise ValueError("content_hash does not match content")
        if self.classification.score is not None and not 0 <= self.classification.score <= 1:
            raise ValueError("classification score must be between 0 and 1")

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["tags"] = list(self.tags)
        return result

    def to_raw_record(self) -> RawRecord:
        """Map the External-owned handoff model to the approved shared runtime contract."""
        raw_data = self.to_dict()
        return RawRecord(
            external_id=self.source_item_id or self.record_id,
            source_name=self.source,
            source_type=self.source_type,
            title=self.title,
            content=self.content,
            url=self.link,
            published_at=self.published,
            collected_at=self.collected_at,
            raw_data=raw_data,
            trusted_cybersecurity_source=self.classification.status == "not_required",
        )


@dataclass(frozen=True, slots=True)
class IntegrationError:
    code: str
    message: str
    retryable: bool = False
    details: dict[str, Any] = field(default_factory=dict)
    schema_version: str = "1.0"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
