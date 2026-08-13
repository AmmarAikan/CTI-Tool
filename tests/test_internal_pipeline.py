from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from backend.app.pipeline.ingestion.internal.dionaea_connector import (
    DionaeaFileConnector,
)
from backend.app.pipeline.ingestion.internal.wazuh_connector import WazuhFileConnector
from backend.app.pipeline.internal_orchestrator import InternalCTIPipeline
from backend.app.pipeline.outlier.detector import InternalOutlierDetector
from backend.app.pipeline.outlier.feature_extractor import SessionFeatureExtractor
from backend.app.pipeline.outlier.sessionizer import WazuhSessionizer

SAMPLE_PATH = Path(__file__).resolve().parents[1] / "data" / "internal_samples" / "wazuh_alerts_sample.json"
DIONAEA_SAMPLE_PATH = (
    Path(__file__).resolve().parents[1] / "data" / "internal_samples" / "dionaea_events_sample.jsonl"
)


class InternalPipelineTests(unittest.TestCase):
    def test_dionaea_connector_supports_official_json_log_shape(self) -> None:
        records = list(DionaeaFileConnector([DIONAEA_SAMPLE_PATH]).collect())

        self.assertEqual(len(records), 5)
        self.assertTrue(all(record.source_type == "dionaea" for record in records))
        self.assertTrue(all(record.source_pipeline == "internal" for record in records))
        self.assertNotIn("sample-six", records[-1].content)

    def test_dionaea_pipeline_detects_credential_outlier_and_redacts_cti_copy(self) -> None:
        records = list(DionaeaFileConnector([DIONAEA_SAMPLE_PATH]).collect())
        result = InternalCTIPipeline().process(records)

        self.assertEqual(len(result.detections), 5)
        self.assertEqual(len(result.cti_objects), 1)
        detection = next(item for item in result.detections if item.is_outlier)
        event = result.cti_objects[0]
        self.assertEqual(detection.session.source_ip, "198.51.100.77")
        self.assertEqual(detection.features["credential_attempts"], 6.0)
        self.assertEqual(event.source_type, "dionaea_session")
        self.assertIn("honeypot", event.tags)
        self.assertEqual(
            event.raw_reference["alerts"][0]["credentials"][0]["password"],
            "[REDACTED]",
        )

    def test_wazuh_connector_supports_json_array(self) -> None:
        records = list(WazuhFileConnector([SAMPLE_PATH]).collect())

        self.assertEqual(len(records), 8)
        self.assertTrue(all(record.source_pipeline == "internal" for record in records))
        self.assertTrue(all(record.source_type == "wazuh" for record in records))

    def test_wazuh_connector_supports_jsonl(self) -> None:
        items = json.loads(SAMPLE_PATH.read_text(encoding="utf-8"))[:2]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "alerts.json"
            path.write_text("\n".join(json.dumps(item) for item in items), encoding="utf-8")
            records = list(WazuhFileConnector([path]).collect())

        self.assertEqual([record.external_id for record in records], ["sample-001", "sample-002"])

    def test_sessionizer_splits_after_thirty_minutes_idle(self) -> None:
        records = list(WazuhFileConnector([SAMPLE_PATH]).collect())[:2]
        later = records[1]
        later.published_at = "2026-08-10T11:00:01Z"

        sessions = WazuhSessionizer(idle_minutes=30).build_sessions(records)

        self.assertEqual(len(sessions), 2)

    def test_session_id_remains_stable_when_append_only_log_grows(self) -> None:
        records = list(WazuhFileConnector([SAMPLE_PATH]).collect())[:2]
        first_session = WazuhSessionizer().build_sessions(records[:1])[0]
        expanded_session = WazuhSessionizer().build_sessions(records)[0]

        self.assertEqual(first_session.session_id, expanded_session.session_id)
        self.assertEqual(len(expanded_session.records), 2)

    def test_feature_extraction_captures_structured_and_ioc_counts(self) -> None:
        records = list(WazuhFileConnector([SAMPLE_PATH]).collect())
        sessions = WazuhSessionizer().build_sessions(records)
        malicious = next(session for session in sessions if session.source_ip == "198.51.100.99")

        features = SessionFeatureExtractor().extract(malicious)

        self.assertEqual(features["alerts_count"], 3.0)
        self.assertEqual(features["max_rule_level"], 14.0)
        self.assertGreaterEqual(features["cve_count"], 1.0)
        self.assertGreaterEqual(features["domain_count"], 1.0)

    def test_full_internal_pipeline_creates_cti_only_for_outliers(self) -> None:
        records = list(WazuhFileConnector([SAMPLE_PATH]).collect())
        result = InternalCTIPipeline().process(records)

        self.assertEqual(len(result.detections), 4)
        self.assertGreaterEqual(len(result.cti_objects), 1)
        self.assertTrue(all(item.source_pipeline == "internal" for item in result.cti_objects))
        self.assertTrue(all("outlier" in item.tags for item in result.cti_objects))

    def test_small_batch_fallback_is_labeled_as_non_ml_heuristic(self) -> None:
        records = list(WazuhFileConnector([SAMPLE_PATH]).collect())[:2]
        sessions = WazuhSessionizer().build_sessions(records)
        features = [SessionFeatureExtractor().extract(item) for item in sessions]

        detections = InternalOutlierDetector().detect(sessions, features)

        self.assertTrue(all(item.backend == "documented_small_batch_heuristic" for item in detections))


if __name__ == "__main__":
    unittest.main()
