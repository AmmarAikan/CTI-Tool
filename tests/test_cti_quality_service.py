from __future__ import annotations

import unittest

from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from backend.app.db.database import Base
from backend.app.db.models import (
    EntityRecord,
    IndicatorRecord,
    RelationshipRecord,
    ThreatEvent,
)
from backend.app.services.cti_quality_service import CTIQualityService


class CTIQualityServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = create_engine(
            "sqlite+pysqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(self.engine)

    def tearDown(self) -> None:
        self.engine.dispose()

    def test_preview_is_read_only_and_apply_is_idempotent(self) -> None:
        text = (
            "attacker reviewed WordPress. "
            "APT29 used Cobalt Strike to exploit CVE-2026-1234. "
            "Mimikatz appears in an appendix. "
            "Callback hxxps://evil[.]example[.]com via 2001:db8::5."
        )
        with Session(self.engine) as session:
            event = ThreatEvent(
                id="cti-quality-test",
                source_record_id="record-1",
                source_type="rss",
                source_pipeline="external",
                title="Quality test",
                description=text,
                normalized_text=text,
                classification_label="cti_related",
                classification_confidence=0.9,
                classification_backend="test",
                processing_status="transformed",
                raw_reference={},
            )
            event.entities.extend(
                [
                    EntityRecord(entity_type="threat_actor", value="attacker", confidence=0.99, extractor="dnrti_bert_ner"),
                    EntityRecord(entity_type="sample_file", value="WordPress", confidence=0.99, extractor="dnrti_bert_ner"),
                    EntityRecord(entity_type="threat_actor", value="APT29", confidence=0.9, extractor="dnrti_bert_ner"),
                    EntityRecord(entity_type="tool_or_malware", value="Cobalt Strike", confidence=0.9, extractor="dnrti_bert_ner"),
                    EntityRecord(entity_type="tool_or_malware", value="Mimikatz", confidence=0.9, extractor="dnrti_bert_ner"),
                ]
            )
            event.indicators.append(
                IndicatorRecord(indicator_type="cve", value="CVE-2026-1234", confidence=1.0, extractor="regex")
            )
            event.relationships.append(
                RelationshipRecord(
                    subject="APT29",
                    relation="USES",
                    object_value="Mimikatz",
                    confidence=0.65,
                    extraction_method="rule_based",
                )
            )
            session.add(event)
            session.commit()

            preview = CTIQualityService(session).run(apply=False)
            session.rollback()
            self.assertEqual(preview["events_scanned"], 1)
            self.assertEqual(preview["dnrti_entities_flagged_for_review"], 2)
            self.assertEqual(preview["dnrti_entities_removed"], 0)
            self.assertGreaterEqual(preview["observables_added"], 2)
            self.assertEqual(len(event.entities), 5)

            applied = CTIQualityService(session).run(
                apply=True,
                remove_rejected_entities=True,
            )
            session.commit()
            self.assertEqual(applied["dnrti_entities_removed"], 2)
            self.assertEqual(
                {(item.entity_type, item.value) for item in event.entities},
                {
                    ("threat_actor", "APT29"),
                    ("tool_or_malware", "Cobalt Strike"),
                    ("tool_or_malware", "Mimikatz"),
                },
            )
            relation_keys = {
                (item.subject, item.relation, item.object_value)
                for item in event.relationships
                if item.extraction_method == "rule_based"
            }
            self.assertIn(("APT29", "USES", "Cobalt Strike"), relation_keys)
            self.assertIn(("Cobalt Strike", "EXPLOITS", "CVE-2026-1234"), relation_keys)
            self.assertNotIn(("APT29", "USES", "Mimikatz"), relation_keys)

            repeated = CTIQualityService(session).run(apply=False)
            session.rollback()
            self.assertEqual(repeated["events_changed"], 0)
            self.assertEqual(repeated["observables_added"], 0)


if __name__ == "__main__":
    unittest.main()
