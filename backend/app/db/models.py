from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.db.database import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def new_uuid() -> str:
    return str(uuid.uuid4())


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    username: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(30), default="analyst", index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class Source(Base):
    __tablename__ = "sources"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    name: Mapped[str] = mapped_column(String(200), unique=True, index=True)
    source_type: Mapped[str] = mapped_column(String(50), index=True)
    source_pipeline: Mapped[str] = mapped_column(String(20), index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    config: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    raw_items: Mapped[list[RawItem]] = relationship(back_populates="source", cascade="all, delete-orphan")
    runs: Mapped[list[PipelineRun]] = relationship(back_populates="source")


class RawItem(Base):
    __tablename__ = "raw_items"
    __table_args__ = (UniqueConstraint("source_id", "external_id", name="uq_raw_source_external"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    source_id: Mapped[str] = mapped_column(ForeignKey("sources.id", ondelete="CASCADE"), index=True)
    external_id: Mapped[str] = mapped_column(String(500), index=True)
    source_pipeline: Mapped[str] = mapped_column(String(20), index=True)
    title: Mapped[str] = mapped_column(String(500), default="")
    content: Mapped[str] = mapped_column(Text, default="")
    raw_data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    source: Mapped[Source] = relationship(back_populates="raw_items")
    events: Mapped[list[ThreatEvent]] = relationship(back_populates="raw_item")


class PipelineRun(Base):
    __tablename__ = "pipeline_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    source_id: Mapped[str | None] = mapped_column(ForeignKey("sources.id", ondelete="SET NULL"), nullable=True)
    pipeline: Mapped[str] = mapped_column(String(20), index=True)
    status: Mapped[str] = mapped_column(String(30), default="running", index=True)
    collected_count: Mapped[int] = mapped_column(Integer, default=0)
    processed_count: Mapped[int] = mapped_column(Integer, default=0)
    stored_count: Mapped[int] = mapped_column(Integer, default=0)
    failed_count: Mapped[int] = mapped_column(Integer, default=0)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    source: Mapped[Source | None] = relationship(back_populates="runs")


class ExternalIngestionOperation(Base):
    __tablename__ = "external_ingestion_operations"
    __table_args__ = (
        UniqueConstraint("external_job_id", "export_run_id", "dataset_sha256",
                         name="uq_external_ingestion_identity"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    operation_type: Mapped[str] = mapped_column(String(40), default="external_ingestion")
    state: Mapped[str] = mapped_column(String(30), default="queued", index=True)
    stage: Mapped[str] = mapped_column(String(40), default="export_ready", index=True)
    retryable: Mapped[bool] = mapped_column(Boolean, default=True)
    attempt_count: Mapped[int] = mapped_column(Integer, default=0)
    priority: Mapped[int] = mapped_column(Integer, default=100, index=True)
    external_job_id: Mapped[str] = mapped_column(String(200), index=True)
    export_run_id: Mapped[str] = mapped_column(String(200), index=True)
    dataset_sha256: Mapped[str] = mapped_column(String(64), index=True)
    gateway_checkpoint: Mapped[str | None] = mapped_column(String(200), nullable=True)
    pipeline_run_id: Mapped[str | None] = mapped_column(ForeignKey("pipeline_runs.id", ondelete="SET NULL"), nullable=True)
    collected_count: Mapped[int] = mapped_column(Integer, default=0)
    exported_count: Mapped[int] = mapped_column(Integer, default=0)
    imported_count: Mapped[int] = mapped_column(Integer, default=0)
    created_count: Mapped[int] = mapped_column(Integer, default=0)
    updated_count: Mapped[int] = mapped_column(Integer, default=0)
    unchanged_count: Mapped[int] = mapped_column(Integer, default=0)
    failed_count: Mapped[int] = mapped_column(Integer, default=0)
    acknowledged_count: Mapped[int] = mapped_column(Integer, default=0)
    processed_offset: Mapped[int] = mapped_column(Integer, default=0)
    fairness_skips: Mapped[int] = mapped_column(Integer, default=0)
    error_code: Mapped[str | None] = mapped_column(String(100), nullable=True)
    error_category: Mapped[str | None] = mapped_column(String(100), nullable=True)
    claim_token: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, index=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ThreatEvent(Base):
    __tablename__ = "threat_events"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    raw_item_id: Mapped[str | None] = mapped_column(ForeignKey("raw_items.id", ondelete="SET NULL"), nullable=True)
    source_id: Mapped[str | None] = mapped_column(ForeignKey("sources.id", ondelete="SET NULL"), nullable=True, index=True)
    source_record_id: Mapped[str] = mapped_column(String(500), index=True)
    source_type: Mapped[str] = mapped_column(String(50), index=True)
    source_pipeline: Mapped[str] = mapped_column(String(20), index=True)
    title: Mapped[str] = mapped_column(String(500))
    description: Mapped[str] = mapped_column(Text, default="")
    normalized_text: Mapped[str] = mapped_column(Text, default="")
    classification_label: Mapped[str | None] = mapped_column(String(50), nullable=True, index=True)
    classification_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    classification_backend: Mapped[str | None] = mapped_column(String(100), nullable=True)
    severity: Mapped[str | None] = mapped_column(String(30), nullable=True, index=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    processing_status: Mapped[str] = mapped_column(String(30), index=True)
    raw_reference: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    raw_item: Mapped[RawItem | None] = relationship(back_populates="events")
    indicators: Mapped[list[IndicatorRecord]] = relationship(back_populates="event", cascade="all, delete-orphan")
    entities: Mapped[list[EntityRecord]] = relationship(back_populates="event", cascade="all, delete-orphan")
    relationships: Mapped[list[RelationshipRecord]] = relationship(back_populates="event", cascade="all, delete-orphan")


class IndicatorRecord(Base):
    __tablename__ = "indicators"
    __table_args__ = (UniqueConstraint("event_id", "indicator_type", "value", name="uq_event_indicator"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    event_id: Mapped[str] = mapped_column(ForeignKey("threat_events.id", ondelete="CASCADE"), index=True)
    indicator_type: Mapped[str] = mapped_column(String(50), index=True)
    value: Mapped[str] = mapped_column(String(2048), index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    extractor: Mapped[str] = mapped_column(String(100), default="unknown")
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    event: Mapped[ThreatEvent] = relationship(back_populates="indicators")
    enrichments: Mapped[list[EnrichmentRecord]] = relationship(back_populates="indicator", cascade="all, delete-orphan")


class EntityRecord(Base):
    __tablename__ = "entities"
    __table_args__ = (UniqueConstraint("event_id", "entity_type", "value", name="uq_event_entity"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    event_id: Mapped[str] = mapped_column(ForeignKey("threat_events.id", ondelete="CASCADE"), index=True)
    entity_type: Mapped[str] = mapped_column(String(100), index=True)
    value: Mapped[str] = mapped_column(String(1000), index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    extractor: Mapped[str] = mapped_column(String(100), default="unknown")

    event: Mapped[ThreatEvent] = relationship(back_populates="entities")


class RelationshipRecord(Base):
    __tablename__ = "extracted_relationships"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    event_id: Mapped[str] = mapped_column(ForeignKey("threat_events.id", ondelete="CASCADE"), index=True)
    subject: Mapped[str] = mapped_column(String(1000))
    relation: Mapped[str] = mapped_column(String(100))
    object_value: Mapped[str] = mapped_column(String(1000))
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    extraction_method: Mapped[str] = mapped_column(String(100), default="unknown")

    event: Mapped[ThreatEvent] = relationship(back_populates="relationships")


class EnrichmentRecord(Base):
    __tablename__ = "enrichments"
    __table_args__ = (UniqueConstraint("indicator_id", "provider", name="uq_indicator_provider"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    indicator_id: Mapped[str] = mapped_column(ForeignKey("indicators.id", ondelete="CASCADE"), index=True)
    provider: Mapped[str] = mapped_column(String(100), index=True)
    status: Mapped[str] = mapped_column(String(30), default="completed")
    data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    enriched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    indicator: Mapped[IndicatorRecord] = relationship(back_populates="enrichments")


class CorrelationRecord(Base):
    __tablename__ = "correlations"
    __table_args__ = (UniqueConstraint("event_a_id", "event_b_id", "correlation_type", "reason", name="uq_correlation"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    event_a_id: Mapped[str] = mapped_column(ForeignKey("threat_events.id", ondelete="CASCADE"), index=True)
    event_b_id: Mapped[str] = mapped_column(ForeignKey("threat_events.id", ondelete="CASCADE"), index=True)
    correlation_type: Mapped[str] = mapped_column(String(50), index=True)
    score: Mapped[float] = mapped_column(Float)
    reason: Mapped[str] = mapped_column(String(500))
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class OutlierSessionRecord(Base):
    __tablename__ = "outlier_sessions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    source_id: Mapped[str | None] = mapped_column(ForeignKey("sources.id", ondelete="SET NULL"), nullable=True, index=True)
    event_id: Mapped[str | None] = mapped_column(ForeignKey("threat_events.id", ondelete="SET NULL"), nullable=True, index=True)
    source_ip: Mapped[str] = mapped_column(String(100), index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    ended_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    alert_count: Mapped[int] = mapped_column(Integer)
    features: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    is_outlier: Mapped[bool] = mapped_column(Boolean, index=True)
    anomaly_score: Mapped[float] = mapped_column(Float)
    detector_backend: Mapped[str] = mapped_column(String(100))
    alerts: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    username: Mapped[str | None] = mapped_column(String(100), nullable=True)
    action: Mapped[str] = mapped_column(String(100), index=True)
    resource_type: Mapped[str] = mapped_column(String(100), index=True)
    resource_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
