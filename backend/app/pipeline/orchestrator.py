from __future__ import annotations

import argparse
import hashlib
import json
import logging
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from backend.app.pipeline.classification.relevance_classifier import RelevanceClassifier
from backend.app.pipeline.common.cti_schema import (
    CTIObject,
    ClassificationResult,
    Entity,
    ProcessingError,
    RawRecord,
)
from backend.app.pipeline.extraction.ioc_extractor import IoCExtractor
from backend.app.pipeline.extraction.ner_extractor import NERExtractor
from backend.app.pipeline.extraction.relation_extractor import RelationExtractor
from backend.app.pipeline.ingestion.external.file_connector import ExternalJsonFileConnector
from backend.app.pipeline.preprocessing.deduplicator import RecordDeduplicator
from backend.app.pipeline.preprocessing.normalizer import RecordNormalizer


LOGGER = logging.getLogger(__name__)


class ExternalCTIPipeline:
    """External runtime pipeline: normalize, classify, extract, transform."""

    def __init__(
        self,
        normalizer: RecordNormalizer | None = None,
        deduplicator: RecordDeduplicator | None = None,
        classifier: RelevanceClassifier | None = None,
        ner_extractor: NERExtractor | None = None,
        ioc_extractor: IoCExtractor | None = None,
        relation_extractor: RelationExtractor | None = None,
    ) -> None:
        self.normalizer = normalizer or RecordNormalizer()
        self.deduplicator = deduplicator or RecordDeduplicator()
        self.classifier = classifier or RelevanceClassifier()
        self.ner_extractor = ner_extractor or NERExtractor()
        self.ioc_extractor = ioc_extractor or IoCExtractor()
        self.relation_extractor = relation_extractor or RelationExtractor()

    def process_batch(self, records: Iterable[RawRecord]) -> list[CTIObject]:
        objects: list[CTIObject] = []
        for record in records:
            try:
                cti_object = self.process_record(record)
            except Exception as exc:
                LOGGER.exception(
                    "external_pipeline_record_failed",
                    extra={
                        "source_record_id": getattr(record, "external_id", None),
                        "connector_name": getattr(record, "source_name", None),
                        "stage": "batch",
                    },
                )
                cti_object = self._failed_object(record, "batch", str(exc))
            objects.append(cti_object)
        return objects

    def process_record(self, record: RawRecord) -> CTIObject:
        normalized_text = self.normalizer.normalize_text(record)
        cti_object = self._base_object(record, normalized_text)

        if self.deduplicator.is_duplicate(record, normalized_text):
            cti_object.processing_status = "ignored"
            cti_object.processing_errors.append(
                ProcessingError(
                    stage="deduplication",
                    message="duplicate external record",
                    connector_name=record.source_name,
                    source_record_id=record.external_id,
                )
            )
            return cti_object

        cti_object.processing_status = "normalized"
        classification = self.classifier.classify(record, normalized_text)
        self._apply_classification(cti_object, classification)

        if classification.label == "not_cybersecurity":
            cti_object.processing_status = "ignored"
            return cti_object

        indicators = self.ioc_extractor.extract(normalized_text)
        entities = []
        if classification.label == "cti_related":
            entities = self._extract_entities(normalized_text)
            cti_object.processing_status = "extracted"
        else:
            cti_object.processing_status = "classified"

        cti_object.indicators = indicators
        cti_object.entities = entities
        cti_object.relationships = self.relation_extractor.extract(
            normalized_text,
            entities,
            indicators,
            record.external_id,
        )
        cti_object.confidence = self._object_confidence(classification, entities, indicators)
        cti_object.severity = self._infer_severity(record)
        cti_object.tags = self._tags(record, classification)
        cti_object.processing_status = "transformed"
        return cti_object

    def _extract_entities(self, normalized_text: str) -> list[Entity]:
        raw_entities = self.ner_extractor.extract_entities(normalized_text)
        entities = []
        for item in raw_entities:
            text = str(item.get("text") or item.get("value") or "").strip()
            entity_type = str(item.get("type") or "unknown")
            if not text:
                continue
            confidence = float(item.get("confidence", 0.0))
            if confidence > 1:
                confidence = confidence / 100
            entities.append(
                Entity(
                    text=text,
                    type=entity_type,
                    confidence=round(confidence, 4),
                    extractor=str(item.get("extractor") or item.get("source") or self.ner_extractor.backend),
                )
            )
        return self._deduplicate_entities(entities)

    def _base_object(self, record: RawRecord, normalized_text: str) -> CTIObject:
        return CTIObject(
            object_id=self._object_id(record),
            source_id=record.external_id,
            source_type=record.source_type,
            source_pipeline="external",
            title=record.title,
            original_text=record.content,
            normalized_text=normalized_text,
            classification_label=None,
            classification_confidence=None,
            classification_backend=None,
            first_seen=record.published_at or record.collected_at,
            last_seen=record.collected_at,
            raw_reference=record.to_dict(),
            processing_status="collected",
        )

    def _failed_object(self, record: RawRecord, stage: str, message: str) -> CTIObject:
        cti_object = self._base_object(record, "")
        cti_object.processing_status = "failed"
        cti_object.processing_errors.append(
            ProcessingError(
                stage=stage,
                message=message,
                connector_name=record.source_name,
                source_record_id=record.external_id,
            )
        )
        return cti_object

    def _apply_classification(self, cti_object: CTIObject, classification: ClassificationResult) -> None:
        cti_object.classification_label = classification.label
        cti_object.classification_confidence = classification.confidence
        cti_object.classification_backend = classification.backend
        cti_object.raw_reference["classification"] = classification.to_dict()
        cti_object.processing_status = "classified"

    def _object_id(self, record: RawRecord) -> str:
        digest = hashlib.sha256(f"{record.source_pipeline}:{record.external_id}".encode("utf-8")).hexdigest()
        return f"cti-{digest[:24]}"

    def _object_confidence(
        self,
        classification: ClassificationResult,
        entities: list[Entity],
        indicators: list[Any],
    ) -> float:
        extraction_bonus = 0.05 if entities or indicators else 0.0
        return round(min(1.0, classification.confidence + extraction_bonus), 4)

    def _infer_severity(self, record: RawRecord) -> str | None:
        cvss = record.raw_data.get("metadata", {}).get("cvss") if isinstance(record.raw_data, dict) else None
        if isinstance(cvss, dict) and cvss.get("base_severity"):
            return str(cvss["base_severity"]).lower()
        return None

    def _tags(self, record: RawRecord, classification: ClassificationResult) -> list[str]:
        tags = [record.source_pipeline, record.source_type, classification.label]
        raw_tags = record.raw_data.get("tags", []) if isinstance(record.raw_data, dict) else []
        if isinstance(raw_tags, list):
            tags.extend(str(tag) for tag in raw_tags if tag)
        return sorted(set(tags))

    def _deduplicate_entities(self, entities: list[Entity]) -> list[Entity]:
        seen = set()
        unique = []
        for entity in entities:
            key = (entity.type, entity.text.lower())
            if key in seen:
                continue
            seen.add(key)
            unique.append(entity)
        return unique


def run_external_files(paths: list[Path]) -> list[dict[str, Any]]:
    connector = ExternalJsonFileConnector(paths)
    pipeline = ExternalCTIPipeline()
    return [item.to_dict() for item in pipeline.process_batch(connector.collect())]


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the external CTI pipeline over prepared JSON files.")
    parser.add_argument("paths", nargs="+", type=Path, help="External JSON file(s), such as p2/*.json")
    parser.add_argument("--limit", type=int, default=0, help="Optional maximum records to print")
    args = parser.parse_args()

    connector = ExternalJsonFileConnector(args.paths)
    records = connector.collect()
    if args.limit:
        records = list(records)[: args.limit]
    objects = ExternalCTIPipeline().process_batch(records)
    print(json.dumps([item.to_dict() for item in objects], indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
