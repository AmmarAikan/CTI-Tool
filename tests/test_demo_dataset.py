"""Focused regression for the isolated graduation demonstration fixture."""
from __future__ import annotations

from tempfile import TemporaryDirectory
from pathlib import Path
import unittest

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from backend.app.api.v1.router import intelligence_event_storyline
from backend.app.db.database import Base
from backend.app.db.models import CorrelationRecord, Source, ThreatEvent
from backend.app.integrations.misp_client import MISPClient
from backend.app.integrations.stix_exporter import STIXExporter
from backend.app.schemas.api import IntelligenceStorylineResponse
from scripts.create_demo_dataset import DEMO_EVENTS, create_disposable_demo, seed_demo

from scripts.demo_walkthrough import walkthrough

class DemoDatasetTests(unittest.TestCase):
    def test_isolated_seed_and_existing_projections(self) -> None:
        with TemporaryDirectory(prefix="actit-demo-test-") as directory:
            path = Path(directory) / "demo.sqlite3"
            engine = create_engine(f"sqlite+pysqlite:///{path}", future=True)
            try:
                Base.metadata.create_all(engine)
                with Session(engine) as session:
                    seed_demo(session)
                    self.assertEqual(session.scalar(select(func.count()).select_from(Source)), 2)
                    self.assertEqual(session.scalar(select(func.count()).select_from(ThreatEvent)), 3)
                    self.assertEqual(session.scalar(select(func.count()).select_from(CorrelationRecord)), 2)
                    with self.assertRaisesRegex(ValueError, "empty isolated database"):
                        seed_demo(session)

                    storyline = intelligence_event_storyline(DEMO_EVENTS["external"], session, None)
                    IntelligenceStorylineResponse.model_validate(storyline)
                    self.assertTrue(any(item["cross_source"] for item in storyline["correlations"]))
                    self.assertTrue(any(item["kind"] == "correlated" for item in storyline["milestones"]))
                    self.assertTrue(any(item["technique_id"] == "T1059.001" and item["mapping_source"] == "explicit_id" for item in storyline["attack"]["techniques"]))
                    self.assertEqual(storyline["risk_method"], "deterministic_rule_score")
                    self.assertEqual([factor["key"] for factor in storyline["risk_factors"]], ["base_severity_or_cvss", "indicators", "confidence"])

                    event = session.get(ThreatEvent, DEMO_EVENTS["external"])
                    assert event is not None
                    bundle = STIXExporter().export_event(event)
                    self.assertEqual(bundle["type"], "bundle")
                    self.assertTrue(any(item.get("type") == "vulnerability" for item in bundle["objects"]))
                    payload = MISPClient(base_url="http://localhost:8443", api_key="demo-only", allow_http=True).event_payload(event)
                    self.assertFalse(payload["Event"]["published"])
                    self.assertEqual(payload["Event"]["distribution"], 0)
                    self.assertTrue(any(item["type"] == "vulnerability" for item in payload["Event"]["Attribute"]))
                    self.assertFalse(any(item["value"] == "command.example" for item in payload["Event"]["Attribute"]))
            finally:
                engine.dispose()

    def test_cli_creator_uses_private_temporary_sqlite(self) -> None:
        path = create_disposable_demo()
        self.assertEqual(path.name, "demo.sqlite3")
        self.assertTrue(path.parent.name.startswith("actit-demo-"))
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        engine = create_engine(f"sqlite+pysqlite:///{path}", future=True)
        try:
            with Session(engine) as session:
                self.assertEqual(session.scalar(select(func.count()).select_from(ThreatEvent)), 3)
        finally:
            engine.dispose()
            path.unlink()
            path.parent.rmdir()

    def test_walkthrough_is_deterministic(self) -> None:
        path = create_disposable_demo()
        try:
            self.assertEqual(walkthrough(path), walkthrough(path))
            self.assertTrue(walkthrough(path)["cross_source_evidence"][0]["cross_source"])
        finally:
            path.unlink()
            path.parent.rmdir()


if __name__ == "__main__":
    unittest.main()
