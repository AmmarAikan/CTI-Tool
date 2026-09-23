from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from backend.app.api.v1.router import accepted_records
from backend.app.db.database import Base
from backend.app.db.models import Source, ThreatEvent


def temporary_database_engine():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return engine


def accepted_event(event_id: str, source_id: str, *, created_at: datetime,
                   updated_at: datetime) -> ThreatEvent:
    return ThreatEvent(
        id=event_id,
        source_id=source_id,
        source_record_id=f"record-{event_id}",
        source_type="rss",
        source_pipeline="external",
        title=f"Record {event_id}",
        processing_status="processed",
        created_at=created_at,
        updated_at=updated_at,
    )


def page(session: Session, *, limit: int = 25, offset: int = 0):
    return accepted_records(
        session,
        SimpleNamespace(),
        search=None,
        source=None,
        source_type=None,
        processing_state=None,
        limit=limit,
        offset=offset,
    )


class AcceptedRecordsOrderingTests(unittest.TestCase):
    def test_latest_central_acceptance_version_is_first(self) -> None:
        engine = temporary_database_engine()
        first_import = datetime(2026, 9, 20, 10, 0, tzinfo=timezone.utc)
        latest_import = first_import + timedelta(hours=1)
        with Session(engine) as session:
            source = Source(name="Accepted ordering", source_type="rss", source_pipeline="external")
            session.add(source)
            session.flush()
            session.add_all([
                accepted_event("event-old-version", source.id, created_at=first_import,
                               updated_at=latest_import),
                accepted_event("event-newer-created", source.id,
                               created_at=first_import + timedelta(minutes=30),
                               updated_at=first_import + timedelta(minutes=30)),
            ])
            session.commit()
            result = page(session)

        self.assertEqual(
            [item["id"] for item in result["items"]],
            ["event-old-version", "event-newer-created"],
        )
        self.assertEqual(result["items"][0]["accepted_at"], "2026-09-20T11:00:00Z")

    def test_equal_timestamps_use_descending_id_without_page_overlap(self) -> None:
        engine = temporary_database_engine()
        accepted_at = datetime(2026, 9, 20, 12, 0, tzinfo=timezone.utc)
        with Session(engine) as session:
            source = Source(name="Accepted pagination", source_type="rss", source_pipeline="external")
            session.add(source)
            session.flush()
            session.add_all([
                accepted_event(f"event-{suffix}", source.id,
                               created_at=accepted_at, updated_at=accepted_at)
                for suffix in ("a", "b", "c")
            ])
            session.commit()
            first = page(session, limit=2, offset=0)
            second = page(session, limit=2, offset=2)

        ids = [item["id"] for item in [*first["items"], *second["items"]]]
        self.assertEqual(ids, ["event-c", "event-b", "event-a"])
        self.assertEqual(len(ids), len(set(ids)))


if __name__ == "__main__":
    unittest.main()
