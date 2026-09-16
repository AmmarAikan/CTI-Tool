"""Deterministic, synthetic ACTIT demo records in a disposable SQLite database.

This module never uses SessionLocal, the configured database URL, or live MISP.
It seeds projections for a presentation; it does not simulate pipeline or ML output.
"""
from __future__ import annotations

import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from backend.app.db.database import Base
from backend.app.db.models import (
    CorrelationRecord, EntityRecord, IndicatorRecord, RelationshipRecord, Source, ThreatEvent,
)

DEMO_EVENTS = {
    "external": "demo-external-0001",
    "internal": "demo-internal-0001",
    "internal_followup": "demo-internal-0002",
}
WHEN = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)


def seed_demo(session: Session) -> None:
    """Seed only a fresh database; fail closed if any CTI event already exists."""
    if session.scalar(select(ThreatEvent.id).limit(1)) is not None:
        raise ValueError("Demo seed requires an empty isolated database")
    session.add_all([
        Source(id="00000000-0000-4000-8000-000000000101", name="[DEMO] Public advisory", source_type="rss", source_pipeline="external", enabled=False, config={"synthetic": True}, created_at=WHEN, updated_at=WHEN),
        Source(id="00000000-0000-4000-8000-000000000102", name="[DEMO] Host authentication", source_type="host-auth", source_pipeline="internal", enabled=False, config={"synthetic": True}, created_at=WHEN, updated_at=WHEN),
    ])
    session.add_all([
        ThreatEvent(id=DEMO_EVENTS["external"], source_id="00000000-0000-4000-8000-000000000101", source_record_id="demo-advisory-1", source_type="rss", source_pipeline="external", title="[DEMO] Public advisory mentions T1059.001", description="Synthetic advisory about PowerShell activity and CVE-2026-1234.", normalized_text="PowerShell T1059.001 CVE-2026-1234 command.example", classification_label="cti_related", classification_confidence=0.92, classification_backend="demo_fixture_not_model", severity="high", risk_score=72, confidence=0.9, tags=["demo", "synthetic"], first_seen=WHEN, last_seen=WHEN, processing_status="transformed", raw_reference={"synthetic": True, "risk_factors": {"base_severity_or_cvss": 40, "indicators": 20, "confidence": 12}, "risk_context": {"source_count": 2, "correlation_count": 1}}, created_at=WHEN, updated_at=WHEN),
        ThreatEvent(id=DEMO_EVENTS["internal"], source_id="00000000-0000-4000-8000-000000000102", source_record_id="demo-auth-1", source_type="host-auth", source_pipeline="internal", title="[DEMO] Host auth observation", description="Synthetic host observation sharing a reserved test domain.", normalized_text="Observed command.example; no raw credentials or source IP stored.", classification_label="cti_related", classification_confidence=0.8, classification_backend="demo_fixture_not_model", severity="medium", risk_score=48, confidence=0.8, tags=["demo", "synthetic"], first_seen=WHEN, last_seen=WHEN, processing_status="transformed", raw_reference={"synthetic": True}, created_at=WHEN, updated_at=WHEN),
        ThreatEvent(id=DEMO_EVENTS["internal_followup"], source_id="00000000-0000-4000-8000-000000000102", source_record_id="demo-auth-2", source_type="host-auth", source_pipeline="internal", title="[DEMO] Follow-up host observation", description="Second synthetic internal observation.", normalized_text="Observed command.example again.", classification_label="cti_related", classification_confidence=0.7, classification_backend="demo_fixture_not_model", severity="low", risk_score=28, confidence=0.7, tags=["demo", "synthetic"], first_seen=WHEN, last_seen=WHEN, processing_status="transformed", raw_reference={"synthetic": True}, created_at=WHEN, updated_at=WHEN),
    ])
    session.add_all([
        IndicatorRecord(id="00000000-0000-4000-8000-000000000201", event_id=DEMO_EVENTS["external"], indicator_type="domain", value="command.example", confidence=0.95, extractor="demo_fixture", first_seen=WHEN, last_seen=WHEN),
        IndicatorRecord(id="00000000-0000-4000-8000-000000000202", event_id=DEMO_EVENTS["external"], indicator_type="cve", value="CVE-2026-1234", confidence=0.9, extractor="demo_fixture", first_seen=WHEN, last_seen=WHEN),
        IndicatorRecord(id="00000000-0000-4000-8000-000000000203", event_id=DEMO_EVENTS["internal"], indicator_type="domain", value="command.example", confidence=0.85, extractor="demo_fixture", first_seen=WHEN, last_seen=WHEN),
        IndicatorRecord(id="00000000-0000-4000-8000-000000000204", event_id=DEMO_EVENTS["internal_followup"], indicator_type="domain", value="command.example", confidence=0.75, extractor="demo_fixture", first_seen=WHEN, last_seen=WHEN),
        EntityRecord(id="00000000-0000-4000-8000-000000000301", event_id=DEMO_EVENTS["external"], entity_type="technique", value="T1059.001", confidence=0.98, extractor="demo_fixture"),
        RelationshipRecord(id="00000000-0000-4000-8000-000000000401", event_id=DEMO_EVENTS["external"], subject="T1059.001", relation="mentioned_in", object_value="CVE-2026-1234", confidence=0.8, extraction_method="demo_fixture"),
        CorrelationRecord(id="00000000-0000-4000-8000-000000000501", event_a_id=DEMO_EVENTS["external"], event_b_id=DEMO_EVENTS["internal"], correlation_type="shared_indicator", score=0.9, reason="Shared synthetic domain command.example", evidence={"indicator_type": "domain", "value": "command.example", "synthetic": True}, created_at=WHEN),
        CorrelationRecord(id="00000000-0000-4000-8000-000000000502", event_a_id=DEMO_EVENTS["internal"], event_b_id=DEMO_EVENTS["internal_followup"], correlation_type="shared_indicator", score=0.75, reason="Second synthetic observation of command.example", evidence={"indicator_type": "domain", "value": "command.example", "synthetic": True}, created_at=WHEN),
    ])
    session.commit()


def create_disposable_demo() -> Path:
    """Return a new private SQLite path, never a configured production database."""
    directory = Path(tempfile.mkdtemp(prefix="actit-demo-"))
    path = directory / "demo.sqlite3"
    engine = create_engine(f"sqlite+pysqlite:///{path}", future=True)
    try:
        Base.metadata.create_all(engine)
        with Session(engine) as session:
            seed_demo(session)
        os.chmod(path, 0o600)
    finally:
        engine.dispose()
    return path


if __name__ == "__main__":
    print(create_disposable_demo())
