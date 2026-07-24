from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal


ClassificationLabel = Literal["cti_related", "cybersecurity_related", "not_cybersecurity"]
PipelineName = Literal["external", "internal"]
ProcessingStatus = Literal[
    "collected",
    "normalized",
    "classified",
    "ignored",
    "extracted",
    "transformed",
    "stored",
    "failed",
]


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(slots=True)
class RawRecord:
    external_id: str
    source_name: str
    source_type: str
    title: str
    content: str
    url: str | None = None
    published_at: str | None = None
    collected_at: str = field(default_factory=utc_now_iso)
    raw_data: dict[str, Any] = field(default_factory=dict)
    trusted_cybersecurity_source: bool = False
    source_pipeline: PipelineName = "external"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ClassificationResult:
    label: ClassificationLabel
    confidence: float
    backend: str
    model_version: str
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Entity:
    text: str
    type: str
    confidence: float
    extractor: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Indicator:
    value: str
    type: str
    confidence: float
    extractor: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Relationship:
    subject: str
    relation: str
    object: str
    confidence: float
    extraction_method: str
    source_record_id: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ProcessingError:
    stage: str
    message: str
    connector_name: str | None = None
    source_record_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class CTIObject:
    object_id: str
    source_id: str
    source_type: str
    source_pipeline: PipelineName
    title: str
    original_text: str
    normalized_text: str
    classification_label: str | None
    classification_confidence: float | None
    classification_backend: str | None
    indicators: list[Indicator] = field(default_factory=list)
    entities: list[Entity] = field(default_factory=list)
    relationships: list[Relationship] = field(default_factory=list)
    first_seen: str | None = None
    last_seen: str | None = None
    confidence: float = 0.0
    severity: str | None = None
    tags: list[str] = field(default_factory=list)
    raw_reference: dict[str, Any] = field(default_factory=dict)
    processing_status: ProcessingStatus = "collected"
    processing_errors: list[ProcessingError] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["indicators"] = [indicator.to_dict() for indicator in self.indicators]
        payload["entities"] = [entity.to_dict() for entity in self.entities]
        payload["relationships"] = [relationship.to_dict() for relationship in self.relationships]
        payload["processing_errors"] = [error.to_dict() for error in self.processing_errors]
        return payload
