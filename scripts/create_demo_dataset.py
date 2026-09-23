"""Deterministic ACTIT demo records for disposable SQLite or PostgreSQL databases.

This module never uses SessionLocal, the configured database URL, or live MISP.
It seeds projections for a presentation; it does not simulate pipeline or ML output.
"""
from __future__ import annotations

import argparse
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from backend.app.db.database import Base
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
    User,
)
from backend.app.core.security import hash_password

DEMO_EVENTS = {
    "external": "demo-external-0001",
    "internal": "demo-internal-0001",
    "internal_followup": "demo-internal-0002",
    "attack_candidate": "demo-external-attack-candidate",
    "web_access": "demo-internal-web-access",
    "dionaea": "demo-internal-dionaea",
}
DEMO_ACCOUNTS = {
    "viewer": ("demo-viewer", "ViewerDemo!2026"),
    "analyst": ("demo-analyst", "AnalystDemo!2026"),
    "admin": ("demo-admin", "AdminDemo!2026"),
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
    session.flush()
    session.add_all([
        ThreatEvent(id=DEMO_EVENTS["external"], source_id="00000000-0000-4000-8000-000000000101", source_record_id="demo-advisory-1", source_type="rss", source_pipeline="external", title="[DEMO] Public advisory mentions T1059.001", description="Synthetic advisory about PowerShell activity and CVE-2026-1234.", normalized_text="PowerShell T1059.001 CVE-2026-1234 command.example", classification_label="cti_related", classification_confidence=0.92, classification_backend="demo_fixture_not_model", severity="high", risk_score=72, confidence=0.9, tags=["demo", "synthetic"], first_seen=WHEN, last_seen=WHEN, processing_status="transformed", raw_reference={"synthetic": True, "risk_factors": {"base_severity_or_cvss": 40, "indicators": 20, "confidence": 12}, "risk_context": {"source_count": 2, "correlation_count": 1}}, created_at=WHEN, updated_at=WHEN),
        ThreatEvent(id=DEMO_EVENTS["internal"], source_id="00000000-0000-4000-8000-000000000102", source_record_id="demo-auth-1", source_type="host-auth", source_pipeline="internal", title="[DEMO] Host auth observation", description="Synthetic host observation sharing a reserved test domain.", normalized_text="Observed command.example; no raw credentials or source IP stored.", classification_label="cti_related", classification_confidence=0.8, classification_backend="demo_fixture_not_model", severity="medium", risk_score=48, confidence=0.8, tags=["demo", "synthetic"], first_seen=WHEN, last_seen=WHEN, processing_status="transformed", raw_reference={"synthetic": True}, created_at=WHEN, updated_at=WHEN),
        ThreatEvent(id=DEMO_EVENTS["internal_followup"], source_id="00000000-0000-4000-8000-000000000102", source_record_id="demo-auth-2", source_type="host-auth", source_pipeline="internal", title="[DEMO] Follow-up host observation", description="Second synthetic internal observation.", normalized_text="Observed command.example again.", classification_label="cti_related", classification_confidence=0.7, classification_backend="demo_fixture_not_model", severity="low", risk_score=28, confidence=0.7, tags=["demo", "synthetic"], first_seen=WHEN, last_seen=WHEN, processing_status="transformed", raw_reference={"synthetic": True}, created_at=WHEN, updated_at=WHEN),
    ])
    session.flush()
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


def seed_defense_demo(session: Session) -> None:
    """Seed the complete browser defense scenario in a fresh isolated database."""
    seed_demo(session)

    users = []
    for index, (role, (username, password)) in enumerate(DEMO_ACCOUNTS.items(), start=1):
        users.append(User(
            id=f"00000000-0000-4000-8000-{index:012d}",
            username=username,
            password_hash=hash_password(password),
            role=role,
            is_active=True,
            created_at=WHEN,
        ))
    session.add_all(users)

    extra_sources = [
        Source(id="00000000-0000-4000-8000-000000000103", name="[DEMO] Web access sensor", source_type="web_access", source_pipeline="internal", enabled=False, config={"synthetic": True}, created_at=WHEN, updated_at=WHEN),
        Source(id="00000000-0000-4000-8000-000000000104", name="[DEMO] Dionaea sensor", source_type="dionaea", source_pipeline="internal", enabled=False, config={"synthetic": True}, created_at=WHEN, updated_at=WHEN),
        Source(id="00000000-0000-4000-8000-000000000105", name="[DEMO] Analyst-reviewed advisory", source_type="rss", source_pipeline="external", enabled=False, config={"synthetic": True}, created_at=WHEN, updated_at=WHEN),
    ]
    session.add_all(extra_sources)
    session.flush()

    raw_item = RawItem(
        id="00000000-0000-4000-8000-000000000601",
        source_id="00000000-0000-4000-8000-000000000101",
        external_id="demo-advisory-1",
        source_pipeline="external",
        title="[DEMO] Public advisory mentions T1059.001",
        content="Synthetic advisory content for the isolated defense environment.",
        raw_data={
            "synthetic": True,
            "record_id": "demo-defense-record-0001",
            "source": "[DEMO] Public advisory",
            "source_type": "rss",
            "category": "vulnerability",
            "summary": "Synthetic accepted record with stored offline enrichment.",
            "privacy_status": "reviewed",
            "classification": {"label": "cti_related"},
        },
        observed_at=WHEN,
        ingested_at=WHEN,
    )
    session.add(raw_item)
    session.flush()
    external_event = session.get(ThreatEvent, DEMO_EVENTS["external"])
    if external_event is None:
        raise RuntimeError("Base demo event was not seeded")
    external_event.raw_item_id = raw_item.id

    session.add_all([
        ThreatEvent(
            id=DEMO_EVENTS["attack_candidate"], source_id=extra_sources[2].id,
            source_record_id="demo-attack-candidate-1", source_type="rss", source_pipeline="external",
            title="[DEMO] Scheduled task persistence behavior", description="Synthetic advisory describing a scheduled task without asserting an ATT&CK identifier.",
            normalized_text="The observed campaign used a scheduled task for persistence.", classification_label="cti_related",
            classification_confidence=0.86, classification_backend="demo_fixture_not_model", severity="medium",
            risk_score=54, confidence=0.86, tags=["demo", "synthetic", "analyst-review-candidate"],
            first_seen=WHEN, last_seen=WHEN, processing_status="transformed",
            raw_reference={"synthetic": True, "risk_factors": {"base_severity_or_cvss": 24, "indicators": 10, "confidence": 10}, "risk_context": {"source_count": 1, "correlation_count": 0}},
            created_at=WHEN, updated_at=WHEN,
        ),
        ThreatEvent(
            id=DEMO_EVENTS["web_access"], source_id=extra_sources[0].id,
            source_record_id="demo-web-access-1", source_type="web_access_session", source_pipeline="internal",
            title="[DEMO] Web access observation", description="Synthetic safe web-access projection.",
            normalized_text="Repeated web requests were observed in the isolated fixture.", classification_label="web_activity",
            classification_confidence=0.91, classification_backend="deterministic_demo_fixture", severity="medium",
            risk_score=61, confidence=0.91, tags=["demo", "synthetic", "outlier"], first_seen=WHEN,
            last_seen=WHEN, processing_status="transformed",
            raw_reference={"synthetic": True, "risk_factors": {"base_severity_or_cvss": 24, "indicators": 15, "confidence": 10, "internal_outlier": 12}, "risk_context": {"source_count": 1, "correlation_count": 0}},
            created_at=WHEN, updated_at=WHEN,
        ),
        ThreatEvent(
            id=DEMO_EVENTS["dionaea"], source_id=extra_sources[1].id,
            source_record_id="demo-dionaea-1", source_type="dionaea_session", source_pipeline="internal",
            title="[DEMO] Dionaea observation", description="Synthetic safe honeypot projection.",
            normalized_text="A bounded synthetic honeypot session.", classification_label="honeypot_session",
            classification_confidence=0.78, classification_backend="deterministic_demo_fixture", severity="low",
            risk_score=31, confidence=0.78, tags=["demo", "synthetic"], first_seen=WHEN,
            last_seen=WHEN, processing_status="transformed", raw_reference={"synthetic": True},
            created_at=WHEN, updated_at=WHEN,
        ),
    ])
    session.flush()

    session.add(EnrichmentRecord(
        id="00000000-0000-4000-8000-000000000701",
        indicator_id="00000000-0000-4000-8000-000000000202",
        provider="NVD",
        status="completed",
        data={
            "found": True,
            "cvss_score": 9.8,
            "cvss_version": "3.1",
            "severity": "critical",
            "description": "Synthetic offline NVD-like evidence for the isolated defense demo.",
            "cwes": ["CWE-78", "CWE-20"],
            "provenance": "synthetic_offline_nvd_like_fixture",
        },
        enriched_at=WHEN,
    ))

    session.add(OutlierSessionRecord(
        id="demo-outlier-web-session-0001",
        source_id=extra_sources[0].id,
        event_id=DEMO_EVENTS["web_access"],
        source_ip="192.0.2.44",
        started_at=WHEN,
        ended_at=WHEN.replace(minute=18),
        alert_count=18,
        features={"alerts_count": 18.0, "max_rule_level": 13.0, "distinct_rules": 6.0, "failed_actions": 9.0, "credential_attempts": 7.0},
        is_outlier=True,
        anomaly_score=0.82,
        detector_backend="documented_small_batch_heuristic",
        alerts=[],
        created_at=WHEN,
    ))

    session.add_all([
        PipelineRun(id="00000000-0000-4000-8000-000000000801", source_id="00000000-0000-4000-8000-000000000101", pipeline="external", status="completed", collected_count=2, processed_count=2, stored_count=2, failed_count=0, details={"synthetic": True, "event_ids": [DEMO_EVENTS["external"], DEMO_EVENTS["attack_candidate"]], "review_count": 1, "rejected_count": 0}, started_at=WHEN, completed_at=WHEN.replace(minute=2)),
        PipelineRun(id="00000000-0000-4000-8000-000000000802", source_id="00000000-0000-4000-8000-000000000103", pipeline="internal", status="completed", collected_count=3, processed_count=3, stored_count=3, failed_count=0, details={"synthetic": True, "event_ids": [DEMO_EVENTS["internal"], DEMO_EVENTS["web_access"], DEMO_EVENTS["dionaea"]]}, started_at=WHEN.replace(minute=3), completed_at=WHEN.replace(minute=5)),
    ])
    session.add(AuditLog(
        id="00000000-0000-4000-8000-000000000901",
        user_id=users[2].id,
        username=users[2].username,
        action="demo_seed_verified",
        resource_type="isolated_demo",
        resource_id="actit-defense-demo",
        details={"synthetic": True, "live_delivery": False},
        created_at=WHEN,
    ))
    session.commit()


def seed_configured_defense_demo() -> None:
    """Seed only the explicitly named isolated Compose database."""
    from backend.app.core.config import get_settings
    from backend.app.db.database import SessionLocal, initialize_database

    settings = get_settings()
    if os.getenv("ACTIT_DEMO_SEED") != "confirmed":
        raise RuntimeError("ACTIT_DEMO_SEED=confirmed is required")
    if settings.app_env != "demo" or settings.database_host != "demo-db" or settings.database_name != "actit_demo":
        raise RuntimeError("Refusing to seed a database outside the isolated ACTIT defense demo")
    initialize_database()
    with SessionLocal() as session:
        seed_defense_demo(session)


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
    parser = argparse.ArgumentParser()
    parser.add_argument("--configured-defense-demo", action="store_true")
    arguments = parser.parse_args()
    if arguments.configured_defense_demo:
        seed_configured_defense_demo()
        print("isolated defense demo seeded")
    else:
        print(create_disposable_demo())
