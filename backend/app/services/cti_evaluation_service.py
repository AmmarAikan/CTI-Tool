"""Read-only live CTI sampling shared by authorized maintenance adapters."""

from __future__ import annotations

import inspect
from collections import Counter
from pathlib import Path
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.orm import Session, selectinload

from backend.app.db.models import ThreatEvent
from backend.app.pipeline.extraction.ner_extractor import NERExtractor
from ml.evaluation.cti_sampling import (
    Candidate,
    canonical_json,
    digest,
    select_sample,
    write_package,
)


class CTIEvaluationService:
    MAX_EVENTS = 50_000
    MAX_TEXT_CHARS = 250_000

    def __init__(self, session: Session) -> None:
        self.session = session

    def export(
        self, destination: Path, *, size: int = 400, seed: str = "cti-live-v1"
    ) -> dict[str, Any]:
        if destination.exists():
            raise FileExistsError(
                "Evaluation output already exists; refusing to replace annotations"
            )
        if self.session.in_transaction():
            raise ValueError("Evaluation export requires a fresh read-only transaction")
        if self.session.get_bind().dialect.name == "postgresql":
            self.session.execute(
                text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            )
            self.session.execute(text("SET LOCAL statement_timeout = '120s'"))
            self.session.execute(text("SET LOCAL lock_timeout = '5s'"))
        exclusions: Counter[str] = Counter()
        candidates = []
        query = (
            select(
                ThreatEvent.id,
                ThreatEvent.source_id,
                ThreatEvent.source_type,
                ThreatEvent.classification_label,
                ThreatEvent.normalized_text,
            )
            .where(ThreatEvent.source_pipeline == "external")
            .order_by(ThreatEvent.id)
        )
        scanned = 0
        try:
            for (
                event_id,
                source_id,
                source_type,
                label,
                document_text,
            ) in self.session.execute(query).yield_per(100):
                scanned += 1
                if scanned > self.MAX_EVENTS:
                    raise ValueError(
                        "Population exceeds bounded scan; partition explicitly before export"
                    )
                if not document_text or not document_text.strip():
                    exclusions["empty_text"] += 1
                    continue
                if len(document_text) > self.MAX_TEXT_CHARS:
                    exclusions["text_over_250000_characters"] += 1
                    continue
                candidates.append(
                    Candidate(
                        event_id=event_id,
                        source_key=digest(source_id or "missing-source"),
                        source_type=source_type,
                        classification=label or "unclassified",
                        text_sha256=digest(document_text),
                        dedup_sha256=digest(" ".join(document_text.split()).casefold()),
                        characters=len(document_text),
                    )
                )
            selected, manifest = select_sample(candidates, size=size, seed=seed)
            loaded = self.session.scalars(
                select(ThreatEvent)
                .where(ThreatEvent.id.in_([item.event_id for item in selected]))
                .options(
                    selectinload(ThreatEvent.entities),
                    selectinload(ThreatEvent.indicators),
                    selectinload(ThreatEvent.relationships),
                )
            ).all()
            by_id = {event.id: event for event in loaded}
            documents, references = [], []
            type_coverage: Counter[str] = Counter()
            for candidate in selected:
                event = by_id[candidate.event_id]
                if digest(event.normalized_text) != candidate.text_sha256:
                    raise ValueError("Document changed during sampling")
                documents.append(
                    {
                        "sample_id": candidate.sample_id,
                        "text_sha256": candidate.text_sha256,
                        "text": event.normalized_text,
                    }
                )
                entities = sorted(
                    [
                        {
                            "type": item.entity_type,
                            "value": item.value,
                            "confidence": item.confidence,
                            "extractor": item.extractor,
                        }
                        for item in event.entities
                    ],
                    key=canonical_json,
                )
                policy_entities = [
                    item
                    for item in entities
                    if (
                        not item["extractor"].startswith("dnrti_")
                        or NERExtractor._passes_quality_policy(item)
                    )
                ]
                type_coverage.update({item["type"] for item in entities})
                references.append(
                    {
                        "sample_id": candidate.sample_id,
                        "event_id": event.id,
                        "source_key": candidate.source_key,
                        "source_type": candidate.source_type,
                        "stratum": candidate.stratum,
                        "weight": manifest["strata"][candidate.stratum]["weight"],
                        "classification": event.classification_label,
                        "entities": entities,
                        "policy_entities": policy_entities,
                        "observables": sorted(
                            [
                                {
                                    "type": item.indicator_type,
                                    "value": item.value,
                                    "extractor": item.extractor,
                                }
                                for item in event.indicators
                            ],
                            key=canonical_json,
                        ),
                        "relationships": sorted(
                            [
                                {
                                    "subject": item.subject,
                                    "relation": item.relation,
                                    "object": item.object_value,
                                }
                                for item in event.relationships
                                if item.relation in {"USES", "TARGETS", "EXPLOITS"}
                            ],
                            key=canonical_json,
                        ),
                    }
                )
            manifest.update(
                {
                    "scanned_external_events": scanned,
                    "exclusions": dict(sorted(exclusions.items())),
                    "sample_source_type_counts": dict(
                        sorted(Counter(item.source_type for item in selected).items())
                    ),
                    "sample_predicted_entity_type_document_counts": dict(
                        sorted(type_coverage.items())
                    ),
                    "max_text_characters": self.MAX_TEXT_CHARS,
                    "ner_policy_source_sha256": digest(
                        Path(inspect.getfile(NERExtractor)).read_text(encoding="utf-8")
                    ),
                }
            )
        finally:
            # End the snapshot before file IO. No application audit/commit/write.
            self.session.rollback()
        return write_package(destination, documents, references, manifest)
