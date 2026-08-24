from __future__ import annotations

import hashlib
import hmac
import json
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch

import requests
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from backend.app.db.database import Base
from backend.app.db.models import OutlierSessionRecord, RawItem, Source, ThreatEvent
from backend.app.integrations.misp_client import MISPClient
from backend.app.pipeline.extraction.ner_extractor import NERExtractor
from backend.app.pipeline.ingestion.external.http_connector import (
    ExternalFeedAPIConnector,
    ExternalFeedContractError,
)
from backend.app.pipeline.ingestion.internal.dionaea_http_connector import (
    DionaeaAPIConnector,
)
from backend.app.pipeline.ingestion.internal.wazuh_indexer_connector import (
    WazuhIndexerConnector,
)
from backend.app.pipeline.scoring.risk_scorer import RiskScorer
from backend.app.services.model_evidence_service import ModelEvidenceService
from backend.app.services.pipeline_service import PipelineService


class FakeResponse:
    def __init__(
        self,
        payload: object,
        *,
        status_code: int = 200,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.status_code = status_code
        self.content = json.dumps(payload).encode("utf-8")
        self.headers = {"Content-Type": "application/json", **(headers or {})}

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}")

    def json(self):
        return json.loads(self.content.decode("utf-8"))


class FakeSession:
    def __init__(self, responses: list[FakeResponse]) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, str, dict[str, object]]] = []

    def get(self, url: str, **kwargs):
        self.calls.append(("GET", url, kwargs))
        return self.responses.pop(0)

    def post(self, url: str, **kwargs):
        self.calls.append(("POST", url, kwargs))
        return self.responses.pop(0)


def signed_response(payload: object, secret: str) -> FakeResponse:
    response = FakeResponse(payload)
    signature = hmac.new(secret.encode(), response.content, hashlib.sha256).hexdigest()
    response.headers["X-CTI-Signature"] = f"sha256={signature}"
    return response


def temporary_database_engine():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return engine


class BackendEnhancementTests(unittest.TestCase):
    def test_external_feed_validates_hmac_paginates_and_deduplicates(self) -> None:
        secret = "shared-test-secret"
        first = {
            "schema_version": "1.0",
            "feed_id": "friend-external",
            "generated_at": "2026-08-24T00:00:00Z",
            "items": [{"external_id": "item-1", "title": "CVE report"}],
            "has_more": True,
            "next_cursor": "page-2",
            "checkpoint": "page-2",
        }
        second = {
            "schema_version": "1.0",
            "feed_id": "friend-external",
            "generated_at": "2026-08-24T00:01:00Z",
            "items": [
                {"external_id": "item-1", "title": "duplicate"},
                {"external_id": "item-2", "content": "APT28 used malware"},
            ],
            "has_more": False,
            "checkpoint": "complete-2",
        }
        session = FakeSession([signed_response(first, secret), signed_response(second, secret)])
        connector = ExternalFeedAPIConnector(
            "https://feeds.example.test/v1/cti",
            "token",
            hmac_secret=secret,
            session=session,
        )

        result = connector.fetch()

        self.assertEqual([item.external_id for item in result.records], ["item-1", "item-2"])
        self.assertEqual(result.pages, 2)
        self.assertEqual(result.duplicate_items, 1)
        self.assertEqual(result.checkpoint, "complete-2")
        self.assertEqual(session.calls[1][2]["params"]["cursor"], "page-2")

    def test_external_feed_rejects_invalid_hmac_and_unstable_items(self) -> None:
        payload = {
            "schema_version": "1.0",
            "feed_id": "friend-external",
            "generated_at": "2026-08-24T00:00:00Z",
            "items": [{"title": "missing stable id"}],
        }
        bad_signature = FakeResponse(payload, headers={"X-CTI-Signature": "sha256=bad"})
        connector = ExternalFeedAPIConnector(
            "https://feeds.example.test/v1/cti",
            "token",
            hmac_secret="expected-secret",
            session=FakeSession([bad_signature]),
        )
        with self.assertRaises(ExternalFeedContractError):
            connector.fetch()

        unsigned_connector = ExternalFeedAPIConnector(
            "https://feeds.example.test/v1/cti",
            "token",
            session=FakeSession([FakeResponse(payload)]),
        )
        with self.assertRaisesRegex(ExternalFeedContractError, "stable external_id"):
            unsigned_connector.fetch()

    def test_external_feed_full_service_is_idempotent_in_temporary_database(self) -> None:
        payload = {
            "schema_version": "1.0",
            "feed_id": "integration-test-feed",
            "generated_at": "2026-08-24T00:00:00Z",
            "items": [
                {
                    "external_id": "integration:CVE-2026-12345",
                    "source": "Integration Test Source",
                    "source_type": "api",
                    "title": "CVE-2026-12345 malware report",
                    "content": "Malware exploited CVE-2026-12345 and contacted 203.0.113.25.",
                    "published_at": "2026-08-24T00:00:00Z",
                }
            ],
            "has_more": False,
            "checkpoint": "checkpoint-1",
        }
        engine = temporary_database_engine()
        fake_ner = SimpleNamespace(backend="fake", extract_entities=lambda _text: [])
        with Session(engine) as session, patch(
            "backend.app.pipeline.orchestrator.get_runtime_ner_extractor",
            return_value=fake_ner,
        ):
            first_connector = ExternalFeedAPIConnector(
                "https://feed.example.test/v1/cti",
                "token",
                session=FakeSession([FakeResponse(payload)]),
            )
            second_connector = ExternalFeedAPIConnector(
                "https://feed.example.test/v1/cti",
                "token",
                session=FakeSession([FakeResponse(payload)]),
            )

            first = PipelineService(session).run_external_feed(first_connector)
            second = PipelineService(session).run_external_feed(second_connector)
            raw_count = session.scalar(select(func.count()).select_from(RawItem))
            event_count = session.scalar(select(func.count()).select_from(ThreatEvent))

        self.assertEqual(first["collected_count"], 1)
        self.assertEqual(second["collected_count"], 1)
        self.assertEqual(raw_count, 1)
        self.assertEqual(event_count, 1)

    def test_remote_connectors_require_https_by_default(self) -> None:
        with self.assertRaisesRegex(ValueError, "must use HTTPS"):
            ExternalFeedAPIConnector("http://example.test/feed", "token")
        with self.assertRaisesRegex(ValueError, "must use HTTPS"):
            WazuhIndexerConnector(
                "http://example.test:9200",
                username="reader",
                password="password",
            )

    def test_wazuh_indexer_uses_search_after_and_normalizes_hits(self) -> None:
        payload = {
            "hits": {
                "total": {"value": 2, "relation": "eq"},
                "hits": [
                    {
                        "_id": "alert-2",
                        "_index": "wazuh-alerts-4.x-2026.08.24",
                        "sort": [1787529600000, "alert-2"],
                        "_source": {
                            "timestamp": "2026-08-24T00:00:00Z",
                            "rule": {"description": "Malware detected"},
                            "full_log": "APT28 connected to 8.8.8.8",
                        },
                    }
                ],
            }
        }
        session = FakeSession([FakeResponse(payload)])
        connector = WazuhIndexerConnector(
            "https://wazuh.internal:9200",
            token="indexer-token",
            since="2026-08-23T00:00:00Z",
            search_after=[1787443200000, "alert-1"],
            session=session,
        )

        result = connector.fetch()

        self.assertEqual(result.records[0].external_id, "alert-2")
        self.assertEqual(result.records[0].source_pipeline, "internal")
        self.assertEqual(result.last_sort, [1787529600000, "alert-2"])
        request_json = session.calls[0][2]["json"]
        self.assertEqual(request_json["search_after"], [1787443200000, "alert-1"])
        self.assertIn("range", request_json["query"])

    def test_wazuh_indexer_full_service_is_idempotent(self) -> None:
        payload = {
            "hits": {
                "total": {"value": 1, "relation": "eq"},
                "hits": [
                    {
                        "_id": "critical-alert-1",
                        "_index": "wazuh-alerts-4.x-2026.08.24",
                        "sort": [1787529600000, "critical-alert-1"],
                        "_source": {
                            "id": "critical-alert-1",
                            "timestamp": "2026-08-24T00:00:00Z",
                            "agent": {"id": "001", "ip": "192.0.2.40"},
                            "rule": {"id": "100001", "level": 12, "description": "Test critical alert"},
                            "full_log": "Malware contacted 203.0.113.40",
                        },
                    }
                ],
            }
        }
        engine = temporary_database_engine()
        with Session(engine) as session:
            for _ in range(2):
                connector = WazuhIndexerConnector(
                    "https://wazuh.internal:9200",
                    token="indexer-token",
                    session=FakeSession([FakeResponse(payload)]),
                )
                result = PipelineService(session).run_wazuh_indexer(connector)
                self.assertEqual(result["collected_count"], 1)
            raw_count = session.scalar(select(func.count()).select_from(RawItem))
            event_count = session.scalar(select(func.count()).select_from(ThreatEvent))
            session_count = session.scalar(
                select(func.count()).select_from(OutlierSessionRecord)
            )
            source = session.scalar(select(Source).where(Source.name == "Wazuh VPS"))

        self.assertEqual((raw_count, event_count, session_count), (1, 1, 1))
        self.assertEqual(source.config["last_sort"], [1787529600000, "critical-alert-1"])

    def test_dionaea_sensor_api_preserves_raw_json_and_checkpoint(self) -> None:
        secret = "dionaea-shared-secret"
        payload = {
            "schema_version": "1.0",
            "sensor_id": "dionaea-vps-1",
            "generated_at": "2026-08-24T00:00:00Z",
            "events": [
                {
                    "timestamp": "2026-08-24T00:00:00Z",
                    "connection": {
                        "protocol": "httpd",
                        "transport": "tcp",
                        "type": "accept",
                    },
                    "src_ip": "192.0.2.25",
                    "src_port": 50000,
                    "dst_ip": "172.30.0.2",
                    "dst_port": 80,
                }
            ],
            "has_more": False,
            "checkpoint": "sensor-offset-101",
        }
        connector = DionaeaAPIConnector(
            "https://sensor.internal/api/v1/events",
            "sensor-token",
            hmac_secret=secret,
            session=FakeSession([signed_response(payload, secret)]),
        )

        result = connector.fetch()

        self.assertEqual(result.sensor_id, "dionaea-vps-1")
        self.assertEqual(result.checkpoint, "sensor-offset-101")
        self.assertEqual(result.records[0].raw_data["src_ip"], "192.0.2.25")
        self.assertEqual(result.records[0].source_pipeline, "internal")

    def test_dionaea_sensor_full_service_is_idempotent_and_redacts_cti_copy(self) -> None:
        event = {
            "timestamp": "2026-08-24T00:00:00Z",
            "connection": {"protocol": "ftpd", "transport": "tcp", "type": "accept"},
            "src_ip": "192.0.2.77",
            "src_port": 50000,
            "dst_ip": "172.30.0.2",
            "dst_port": 21,
            "credentials": [
                {"username": f"user-{index}", "password": f"secret-{index}"}
                for index in range(6)
            ],
        }
        payload = {
            "schema_version": "1.0",
            "sensor_id": "dionaea-vps-1",
            "generated_at": "2026-08-24T00:00:00Z",
            "events": [event],
            "has_more": False,
            "checkpoint": "sensor-offset-202",
        }
        engine = temporary_database_engine()
        with Session(engine) as session:
            for _ in range(2):
                connector = DionaeaAPIConnector(
                    "https://sensor.internal/api/v1/events",
                    "sensor-token",
                    session=FakeSession([FakeResponse(payload)]),
                )
                result = PipelineService(session).run_dionaea_api(connector)
                self.assertEqual(result["collected_count"], 1)
            raw_count = session.scalar(select(func.count()).select_from(RawItem))
            event_record = session.scalar(select(ThreatEvent))
            session_count = session.scalar(
                select(func.count()).select_from(OutlierSessionRecord)
            )
            source = session.scalar(select(Source).where(Source.name == "Dionaea VPS"))

        self.assertEqual(raw_count, 1)
        self.assertEqual(session_count, 1)
        self.assertEqual(source.config["checkpoint"], "sensor-offset-202")
        promoted_credentials = event_record.raw_reference["alerts"][0]["credentials"]
        self.assertTrue(
            all(item["password"] == "[REDACTED]" for item in promoted_credentials)
        )

    def test_ner_chunks_long_text_filters_confidence_and_keeps_best_duplicate(self) -> None:
        extractor = NERExtractor(
            transformer_model_path="missing",
            sklearn_model_path="missing.joblib",
            min_confidence=0.50,
            chunk_chars=100,
            chunk_overlap_chars=20,
        )

        class FakeNERPipeline:
            def __init__(self) -> None:
                self.calls = 0

            def __call__(self, text: str):
                self.calls += 1
                items = []
                if "APT28" in text:
                    start = text.index("APT28")
                    items.append(
                        {
                            "entity_group": "HackOrg",
                            "word": "APT28",
                            "score": 0.8 + min(self.calls, 1) * 0.1,
                            "start": start,
                            "end": start + 5,
                        }
                    )
                items.append(
                    {
                        "entity_group": "Tool",
                        "word": "noise",
                        "score": 0.2,
                    }
                )
                return items

        fake_pipeline = FakeNERPipeline()
        extractor.backend = "transformer"
        extractor.ner_pipeline = fake_pipeline
        text = "APT28 " + ("ordinary words " * 15) + "APT28"

        entities = extractor.extract_entities(text)

        self.assertGreater(extractor.last_chunk_count, 1)
        self.assertEqual([(item["type"], item["value"]) for item in entities], [("threat_actor", "APT28")])
        self.assertGreaterEqual(float(entities[0]["confidence"]), 90.0)

    def test_risk_score_is_explainable_and_does_not_compound_derived_severity(self) -> None:
        event = SimpleNamespace(
            severity="critical",
            raw_reference={"source_severity": "low"},
            indicators=[object(), object()],
            confidence=0.8,
            tags=["outlier"],
        )

        result = RiskScorer().score(event, source_count=3, correlation_count=2)

        self.assertEqual(result.factors["base_severity_or_cvss"], 8.0)
        self.assertEqual(result.factors["source_diversity"], 6.0)
        self.assertEqual(result.factors["correlations"], 4.0)
        self.assertEqual(result.factors["internal_outlier"], 12.0)
        self.assertEqual(result.score, sum(result.factors.values()))

    def test_misp_mapping_is_stable_unpublished_and_time_aware(self) -> None:
        seen = datetime(2026, 8, 24, tzinfo=timezone.utc)
        indicator = SimpleNamespace(
            indicator_type="sha256",
            value="a" * 64,
            extractor="regex",
            confidence=0.95,
            first_seen=seen,
            last_seen=seen,
        )
        event = SimpleNamespace(
            id="cti-stable-event",
            title="Stable MISP mapping",
            indicators=[indicator],
            severity="high",
            tags=["external"],
            source_pipeline="external",
            first_seen=seen,
        )

        first = MISPClient().event_payload(event)
        second = MISPClient().event_payload(event)

        self.assertEqual(first["Event"]["uuid"], second["Event"]["uuid"])
        self.assertEqual(
            first["Event"]["Attribute"][0]["uuid"],
            second["Event"]["Attribute"][0]["uuid"],
        )
        self.assertFalse(first["Event"]["published"])
        self.assertEqual(first["Event"]["Attribute"][0]["category"], "Payload delivery")
        self.assertEqual(first["Event"]["Attribute"][0]["first_seen"], seen.isoformat())

    def test_model_evidence_quality_gates_use_saved_test_reports(self) -> None:
        fake_runtime = SimpleNamespace(diagnostics=lambda: {"backend": "transformer"})
        with patch(
            "backend.app.services.model_evidence_service.get_runtime_ner_extractor",
            return_value=fake_runtime,
        ):
            status = ModelEvidenceService.status()

        self.assertEqual(status["runtime"]["backend"], "transformer")
        self.assertGreater(status["held_out_test"]["bert"]["f1"], 0.75)
        self.assertTrue(status["quality_gates"]["bert_test_f1_at_least_0_75"])
        self.assertTrue(status["quality_gates"]["primary_outperforms_secondary_entity_f1"])


if __name__ == "__main__":
    unittest.main()
