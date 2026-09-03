from __future__ import annotations

from collections import Counter
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from backend.app.db.models import (
    EntityRecord,
    IndicatorRecord,
    RelationshipRecord,
    ThreatEvent,
)
from backend.app.pipeline.common.cti_schema import Entity, Indicator
from backend.app.pipeline.extraction.ioc_extractor import IoCExtractor
from backend.app.pipeline.extraction.ner_extractor import NERExtractor
from backend.app.pipeline.extraction.relation_extractor import RelationExtractor


def _key(value_type: str, value: str) -> tuple[str, str]:
    return value_type, value.casefold()


def _relationship_key(record: RelationshipRecord) -> tuple[str, str, str, str]:
    return (
        record.subject.casefold(),
        record.relation,
        record.object_value.casefold(),
        record.extraction_method,
    )


class CTIQualityService:
    """Preview or apply deterministic quality policies to stored CTI results.

    This service never reruns classification or BERT. It adds newly supported
    observables, flags DNRTI entities rejected by the runtime quality policy,
    and rebuilds only external ``rule_based`` relationships. Deleting flagged
    legacy entities requires a separate explicit opt-in.
    """

    def __init__(
        self,
        session: Session,
        *,
        ioc_extractor: IoCExtractor | None = None,
        relation_extractor: RelationExtractor | None = None,
    ) -> None:
        self.session = session
        self.ioc_extractor = ioc_extractor or IoCExtractor()
        self.relation_extractor = relation_extractor or RelationExtractor()

    def run(
        self,
        *,
        apply: bool = False,
        remove_rejected_entities: bool = False,
    ) -> dict[str, Any]:
        events = self.session.scalars(
            select(ThreatEvent)
            .where(ThreatEvent.source_pipeline == "external")
            .options(
                selectinload(ThreatEvent.indicators),
                selectinload(ThreatEvent.entities),
                selectinload(ThreatEvent.relationships),
            )
            .order_by(ThreatEvent.id)
        ).all()

        added_observable_types: Counter[str] = Counter()
        flagged_entity_types: Counter[str] = Counter()
        removed_entity_types: Counter[str] = Counter()
        old_relation_types: Counter[str] = Counter()
        new_relation_types: Counter[str] = Counter()
        changed_events = 0
        events_with_flagged_entities = 0

        for event in events:
            event_changed = False
            existing_indicator_keys = {
                _key(record.indicator_type, record.value) for record in event.indicators
            }
            extracted = self.ioc_extractor.extract(event.normalized_text)
            additions = [
                item
                for item in extracted
                if _key(item.type, item.value) not in existing_indicator_keys
            ]
            for item in additions:
                added_observable_types[item.type] += 1
                existing_indicator_keys.add(_key(item.type, item.value))
                event_changed = True
                if apply:
                    event.indicators.append(
                        IndicatorRecord(
                            indicator_type=item.type,
                            value=item.value,
                            confidence=item.confidence,
                            extractor=item.extractor,
                            first_seen=event.first_seen,
                            last_seen=event.last_seen,
                        )
                    )

            retained_entities: list[EntityRecord] = []
            event_has_flagged_entities = False
            for record in list(event.entities):
                candidate = {
                    "type": record.entity_type,
                    "value": record.value,
                    "confidence": record.confidence * 100.0,
                }
                managed = record.extractor.startswith("dnrti_")
                if managed and not NERExtractor._passes_quality_policy(candidate):
                    flagged_entity_types[record.entity_type] += 1
                    event_has_flagged_entities = True
                    if apply and remove_rejected_entities:
                        removed_entity_types[record.entity_type] += 1
                        event_changed = True
                        event.entities.remove(record)
                    continue
                retained_entities.append(record)
            if event_has_flagged_entities:
                events_with_flagged_entities += 1

            existing_rule_relationships = [
                record
                for record in event.relationships
                if record.extraction_method == "rule_based"
            ]
            old_relation_types.update(record.relation for record in existing_rule_relationships)

            relation_entities = [
                Entity(
                    text=record.value,
                    type=record.entity_type,
                    confidence=record.confidence,
                    extractor=record.extractor,
                )
                for record in retained_entities
            ]
            relation_indicators = [
                Indicator(
                    value=record.value,
                    type=record.indicator_type,
                    confidence=record.confidence,
                    extractor=record.extractor,
                )
                for record in event.indicators
            ]
            if not apply:
                relation_indicators.extend(additions)
            desired_relationships = self.relation_extractor.extract(
                event.normalized_text,
                relation_entities,
                relation_indicators,
                event.source_record_id,
            )
            new_relation_types.update(item.relation for item in desired_relationships)
            current_keys = {_relationship_key(record) for record in existing_rule_relationships}
            desired_keys = {
                (
                    item.subject.casefold(),
                    item.relation,
                    item.object.casefold(),
                    item.extraction_method,
                )
                for item in desired_relationships
            }
            if current_keys != desired_keys:
                event_changed = True

            if apply and current_keys != desired_keys:
                for record in existing_rule_relationships:
                    event.relationships.remove(record)
                for item in desired_relationships:
                    event.relationships.append(
                        RelationshipRecord(
                            subject=item.subject,
                            relation=item.relation,
                            object_value=item.object,
                            confidence=item.confidence,
                            extraction_method=item.extraction_method,
                        )
                    )

            if event_changed:
                changed_events += 1

        old_total = sum(old_relation_types.values())
        new_total = sum(new_relation_types.values())
        return {
            "mode": "apply" if apply else "preview",
            "scope": "external events only; BERT and classification are not rerun",
            "events_scanned": len(events),
            "events_changed": changed_events,
            "events_with_flagged_entities": events_with_flagged_entities,
            "observables_added": sum(added_observable_types.values()),
            "observables_added_by_type": dict(sorted(added_observable_types.items())),
            "dnrti_entities_flagged_for_review": sum(flagged_entity_types.values()),
            "dnrti_entities_flagged_for_review_by_type": dict(sorted(flagged_entity_types.items())),
            "dnrti_entities_removed": sum(removed_entity_types.values()),
            "dnrti_entities_removed_by_type": dict(sorted(removed_entity_types.items())),
            "old_rule_relationships": old_total,
            "new_rule_relationships": new_total,
            "rule_relationship_reduction": old_total - new_total,
            "rule_relationship_reduction_percent": round(
                ((old_total - new_total) / old_total * 100.0) if old_total else 0.0,
                2,
            ),
            "old_rule_relationships_by_type": dict(sorted(old_relation_types.items())),
            "new_rule_relationships_by_type": dict(sorted(new_relation_types.items())),
        }
