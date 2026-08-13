from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from backend.app.db.models import (
    AuditLog,
    CorrelationRecord,
    EnrichmentRecord,
    EntityRecord,
    IndicatorRecord,
    OutlierSessionRecord,
    PipelineRun,
    RawItem,
    RelationshipRecord,
    Source,
    ThreatEvent,
)
from backend.app.pipeline.common.cti_schema import CTIObject, RawRecord


def parse_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not value:
        return None
    text = str(value).strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


class CTIRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def get_or_create_source(
        self,
        name: str,
        source_type: str,
        source_pipeline: str,
        config: dict[str, Any] | None = None,
    ) -> Source:
        source = self.session.scalar(select(Source).where(Source.name == name))
        if source is None:
            source = Source(
                name=name,
                source_type=source_type,
                source_pipeline=source_pipeline,
                config=config or {},
            )
            self.session.add(source)
            self.session.flush()
        else:
            source.source_type = source_type
            source.source_pipeline = source_pipeline
            if config:
                source.config = {**source.config, **config}
        return source

    def create_run(self, pipeline: str, source: Source | None = None, details: dict[str, Any] | None = None) -> PipelineRun:
        run = PipelineRun(
            pipeline=pipeline,
            source_id=source.id if source else None,
            status="running",
            details=details or {},
        )
        self.session.add(run)
        self.session.flush()
        return run

    def finish_run(
        self,
        run: PipelineRun,
        *,
        status: str,
        collected: int,
        processed: int,
        stored: int,
        failed: int,
        error_message: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> PipelineRun:
        run.status = status
        run.collected_count = collected
        run.processed_count = processed
        run.stored_count = stored
        run.failed_count = failed
        run.error_message = error_message
        run.completed_at = datetime.now(timezone.utc)
        if details:
            run.details = {**run.details, **details}
        self.session.flush()
        return run

    def upsert_raw_record(self, source: Source, record: RawRecord) -> RawItem:
        raw_item = self.session.scalar(
            select(RawItem).where(
                RawItem.source_id == source.id,
                RawItem.external_id == record.external_id,
            )
        )
        if raw_item is None:
            raw_item = RawItem(source_id=source.id, external_id=record.external_id)
            self.session.add(raw_item)
        raw_item.source_pipeline = record.source_pipeline
        raw_item.title = record.title
        raw_item.content = record.content
        raw_item.raw_data = record.raw_data
        raw_item.observed_at = parse_datetime(record.published_at or record.collected_at)
        self.session.flush()
        return raw_item

    def upsert_cti_object(
        self,
        source: Source,
        cti_object: CTIObject,
        raw_item: RawItem | None = None,
        risk_score: float = 0.0,
    ) -> ThreatEvent:
        event = self.session.get(ThreatEvent, cti_object.object_id)
        if event is None:
            event = ThreatEvent(
                id=cti_object.object_id,
                source_record_id=cti_object.source_id,
                source_type=cti_object.source_type,
                source_pipeline=cti_object.source_pipeline,
                title=cti_object.title,
                processing_status=cti_object.processing_status,
            )
            self.session.add(event)
        event.raw_item_id = raw_item.id if raw_item else None
        event.source_id = source.id
        event.source_record_id = cti_object.source_id
        event.source_type = cti_object.source_type
        event.source_pipeline = cti_object.source_pipeline
        event.title = cti_object.title
        event.description = cti_object.original_text
        event.normalized_text = cti_object.normalized_text
        event.classification_label = cti_object.classification_label
        event.classification_confidence = cti_object.classification_confidence
        event.classification_backend = cti_object.classification_backend
        event.severity = cti_object.severity
        event.risk_score = round(max(0.0, min(100.0, risk_score)), 2)
        event.confidence = cti_object.confidence
        event.tags = cti_object.tags
        event.first_seen = parse_datetime(cti_object.first_seen)
        event.last_seen = parse_datetime(cti_object.last_seen)
        event.processing_status = cti_object.processing_status
        event.raw_reference = cti_object.raw_reference
        self._sync_indicators(event, cti_object)
        self._sync_entities(event, cti_object)
        self._sync_relationships(event, cti_object)
        self.session.flush()
        return event

    def _sync_indicators(self, event: ThreatEvent, cti_object: CTIObject) -> None:
        existing = {(item.indicator_type, item.value): item for item in event.indicators}
        desired_keys: set[tuple[str, str]] = set()
        for item in cti_object.indicators:
            key = (item.type, item.value)
            if key in desired_keys:
                continue
            desired_keys.add(key)
            record = existing.pop(key, None)
            if record is None:
                record = IndicatorRecord(indicator_type=item.type, value=item.value)
                event.indicators.append(record)
            record.confidence = item.confidence
            record.extractor = item.extractor
            record.first_seen = event.first_seen
            record.last_seen = event.last_seen
        for stale in existing.values():
            event.indicators.remove(stale)

    def _sync_entities(self, event: ThreatEvent, cti_object: CTIObject) -> None:
        existing = {(item.entity_type, item.value): item for item in event.entities}
        desired_keys: set[tuple[str, str]] = set()
        for item in cti_object.entities:
            key = (item.type, item.text)
            if key in desired_keys:
                continue
            desired_keys.add(key)
            record = existing.pop(key, None)
            if record is None:
                record = EntityRecord(entity_type=item.type, value=item.text)
                event.entities.append(record)
            record.confidence = item.confidence
            record.extractor = item.extractor
        for stale in existing.values():
            event.entities.remove(stale)

    def _sync_relationships(self, event: ThreatEvent, cti_object: CTIObject) -> None:
        existing: dict[tuple[str, str, str, str], list[RelationshipRecord]] = {}
        for item in event.relationships:
            key = (item.subject, item.relation, item.object_value, item.extraction_method)
            existing.setdefault(key, []).append(item)

        desired_keys: set[tuple[str, str, str, str]] = set()
        for item in cti_object.relationships:
            key = (item.subject, item.relation, item.object, item.extraction_method)
            if key in desired_keys:
                continue
            desired_keys.add(key)
            matches = existing.get(key, [])
            if matches:
                record = matches.pop()
            else:
                record = RelationshipRecord(
                    subject=item.subject,
                    relation=item.relation,
                    object_value=item.object,
                    extraction_method=item.extraction_method,
                )
                event.relationships.append(record)
            record.confidence = item.confidence

        for stale_records in existing.values():
            for stale in stale_records:
                event.relationships.remove(stale)

    def store_outlier_session(
        self,
        *,
        session_id: str,
        source: Source,
        source_ip: str,
        started_at: datetime,
        ended_at: datetime,
        features: dict[str, Any],
        is_outlier: bool,
        anomaly_score: float,
        detector_backend: str,
        alerts: list[dict[str, Any]],
        event_id: str | None,
    ) -> OutlierSessionRecord:
        record = self.session.get(OutlierSessionRecord, session_id)
        if record is None:
            record = OutlierSessionRecord(
                id=session_id,
                source_ip=source_ip,
                started_at=started_at,
                ended_at=ended_at,
                alert_count=len(alerts),
                is_outlier=is_outlier,
                anomaly_score=anomaly_score,
                detector_backend=detector_backend,
            )
            self.session.add(record)
        record.source_id = source.id
        record.event_id = event_id
        record.source_ip = source_ip
        record.started_at = started_at
        record.ended_at = ended_at
        record.alert_count = len(alerts)
        record.features = features
        record.is_outlier = is_outlier
        record.anomaly_score = anomaly_score
        record.detector_backend = detector_backend
        record.alerts = alerts
        self.session.flush()
        return record

    def upsert_correlation(
        self,
        event_a_id: str,
        event_b_id: str,
        correlation_type: str,
        score: float,
        reason: str,
        evidence: dict[str, Any] | None = None,
    ) -> CorrelationRecord:
        event_a_id, event_b_id = sorted((event_a_id, event_b_id))
        correlation = self.session.scalar(
            select(CorrelationRecord).where(
                CorrelationRecord.event_a_id == event_a_id,
                CorrelationRecord.event_b_id == event_b_id,
                CorrelationRecord.correlation_type == correlation_type,
                CorrelationRecord.reason == reason,
            )
        )
        if correlation is None:
            correlation = CorrelationRecord(
                event_a_id=event_a_id,
                event_b_id=event_b_id,
                correlation_type=correlation_type,
                reason=reason,
                score=score,
                evidence=evidence or {},
            )
            self.session.add(correlation)
        else:
            correlation.score = score
            correlation.evidence = evidence or correlation.evidence
        self.session.flush()
        return correlation

    def upsert_enrichment(
        self,
        indicator: IndicatorRecord,
        provider: str,
        data: dict[str, Any],
        status: str = "completed",
    ) -> EnrichmentRecord:
        enrichment = self.session.scalar(
            select(EnrichmentRecord).where(
                EnrichmentRecord.indicator_id == indicator.id,
                EnrichmentRecord.provider == provider,
            )
        )
        if enrichment is None:
            enrichment = EnrichmentRecord(indicator_id=indicator.id, provider=provider)
            self.session.add(enrichment)
        enrichment.data = data
        enrichment.status = status
        enrichment.enriched_at = datetime.now(timezone.utc)
        self.session.flush()
        return enrichment

    def get_event(self, event_id: str) -> ThreatEvent | None:
        return self.session.scalar(
            select(ThreatEvent)
            .where(ThreatEvent.id == event_id)
            .options(
                selectinload(ThreatEvent.indicators).selectinload(IndicatorRecord.enrichments),
                selectinload(ThreatEvent.entities),
                selectinload(ThreatEvent.relationships),
            )
        )

    def audit(
        self,
        action: str,
        resource_type: str,
        resource_id: str | None = None,
        *,
        user_id: str | None = None,
        username: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> AuditLog:
        log = AuditLog(
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            user_id=user_id,
            username=username,
            details=details or {},
        )
        self.session.add(log)
        self.session.flush()
        return log
