"""Print a deterministic, read-only graduation walkthrough from synthetic SQLite data.

No HTTP requests, configured database sessions, or MISP sends are performed.
"""
from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from backend.app.api.v1.router import intelligence_event_storyline
from backend.app.db.models import ThreatEvent
from backend.app.integrations.misp_client import MISPClient
from backend.app.integrations.stix_exporter import STIXExporter
from scripts.create_demo_dataset import DEMO_EVENTS, create_disposable_demo


def walkthrough(path: Path) -> dict:
    engine = create_engine(f"sqlite+pysqlite:///{path}", future=True)
    try:
        with Session(engine) as session:
            event = session.get(ThreatEvent, DEMO_EVENTS["external"])
            if event is None:
                raise ValueError("The isolated demo event is missing")
            story = intelligence_event_storyline(event.id, session, None)
            stix = STIXExporter().export_event(event)
            misp = MISPClient(base_url="http://localhost:8443", api_key="demo-only", allow_http=True).event_payload(event)
            return {
                "mode": "synthetic_disposable_sqlite_no_live_sharing",
                "events": DEMO_EVENTS,
                "cross_source_evidence": [
                    {"source_event_id": item["source_event_id"], "target_event_id": item["target_event_id"], "cross_source": item["cross_source"], "reason": item["reason"]}
                    for item in story["correlations"]
                ],
                "storyline_milestone_kinds": [item["kind"] for item in story["milestones"]],
                "risk": {"score": story["event"]["risk_score"], "method": story["risk_method"], "factors": story["risk_factors"]},
                "attack": [{"technique_id": item["technique_id"], "mapping_source": item["mapping_source"]} for item in story["attack"]["techniques"]],
                "stix": {"type": stix["type"], "object_types": sorted(item["type"] for item in stix["objects"])},
                "misp_preview": {"published": misp["Event"]["published"], "distribution": misp["Event"]["distribution"], "included": misp["cti_filtering"]["included"], "omitted": misp["cti_filtering"]["omitted"], "sent": False},
            }
    finally:
        engine.dispose()


if __name__ == "__main__":
    path = create_disposable_demo()
    try:
        print(json.dumps(walkthrough(path), indent=2, sort_keys=True, ensure_ascii=False))
    finally:
        path.unlink()
        path.parent.rmdir()
