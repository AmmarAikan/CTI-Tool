from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from backend.app.pipeline.classification.relevance_classifier import RelevanceClassifier
from backend.app.pipeline.common.cti_schema import RawRecord
from backend.app.pipeline.extraction.ioc_extractor import IoCExtractor
from backend.app.pipeline.extraction.ner_extractor import NERExtractor
from backend.app.pipeline.ingestion.external.file_connector import ExternalJsonFileConnector
from backend.app.pipeline.orchestrator import ExternalCTIPipeline
from backend.app.pipeline.preprocessing.normalizer import RecordNormalizer


class FakeNERExtractor:
    backend = "fake"

    def __init__(self) -> None:
        self.calls = 0

    def extract_entities(self, text: str):
        self.calls += 1
        return [
            {
                "value": "APT28",
                "type": "threat_actor",
                "confidence": 95.0,
                "source": "fake_dnrti",
            }
        ]


class FailingNormalizer(RecordNormalizer):
    def normalize_text(self, record: RawRecord) -> str:
        if record.external_id == "bad-record":
            raise RuntimeError("normalizer failed")
        return super().normalize_text(record)


def raw_record(**overrides) -> RawRecord:
    values = {
        "external_id": "record-1",
        "source_name": "Example Source",
        "source_type": "rss",
        "title": "Example",
        "content": "APT28 used X-Agent malware against government targets via CVE-2026-12345.",
        "url": "https://example.test/report",
        "published_at": "2026-07-22T00:00:00Z",
        "collected_at": "2026-07-24T00:00:00Z",
        "raw_data": {"category": "news"},
        "trusted_cybersecurity_source": False,
    }
    values.update(overrides)
    return RawRecord(**values)


class ExternalPipelineTests(unittest.TestCase):
    def test_file_connector_normalizes_prepared_external_sample_shape(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "vulnerabilities.json"
            path.write_text(
                json.dumps(
                    [
                        {
                            "title": "CVE-2026-12345",
                            "link": "https://nvd.nist.gov/vuln/detail/CVE-2026-12345",
                            "source": "NVD",
                            "category": "vulnerability",
                            "content": "A vulnerability allows code execution.",
                            "published": "2026-07-22T00:00:00.000",
                            "metadata": {"cve_id": "CVE-2026-12345"},
                        }
                    ]
                ),
                encoding="utf-8",
            )

            records = list(ExternalJsonFileConnector([path]).collect())

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].external_id, "CVE-2026-12345")
        self.assertEqual(records[0].source_type, "nvd")
        self.assertTrue(records[0].trusted_cybersecurity_source)

    def test_classifier_runs_before_ner_for_external_text(self) -> None:
        fake_ner = FakeNERExtractor()
        pipeline = ExternalCTIPipeline(ner_extractor=fake_ner)

        result = pipeline.process_record(raw_record())

        self.assertEqual(result.classification_label, "cti_related")
        self.assertEqual(fake_ner.calls, 1)
        self.assertEqual(result.entities[0].text, "APT28")

    def test_not_cybersecurity_record_stops_before_ner(self) -> None:
        fake_ner = FakeNERExtractor()
        pipeline = ExternalCTIPipeline(ner_extractor=fake_ner)

        result = pipeline.process_record(
            raw_record(
                external_id="not-cyber",
                content="The office cafeteria menu changed for the weekend.",
                title="Cafeteria update",
            )
        )

        self.assertEqual(result.classification_label, "not_cybersecurity")
        self.assertEqual(result.processing_status, "ignored")
        self.assertEqual(fake_ner.calls, 0)

    def test_trusted_structured_source_uses_documented_bypass(self) -> None:
        classifier = RelevanceClassifier()
        record = raw_record(
            source_name="NVD",
            source_type="nvd",
            trusted_cybersecurity_source=True,
            raw_data={"category": "vulnerability"},
        )

        result = classifier.classify(record, "short structured CVE description")

        self.assertEqual(result.label, "cti_related")
        self.assertEqual(result.backend, "trusted_source_bypass")

    def test_ner_extractor_returns_empty_when_models_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing"
            extractor = NERExtractor(transformer_model_path=missing, sklearn_model_path=missing / "model.joblib")

        self.assertEqual(extractor.backend, "none")
        self.assertEqual(extractor.extract_entities("APT28 used malware."), [])

    def test_regex_ioc_extraction_and_deduplication(self) -> None:
        text = (
            "CVE-2026-12345 appeared twice: CVE-2026-12345. "
            "Callback was https://evil.example/a and IP 8.8.8.8. "
            "Hash d41d8cd98f00b204e9800998ecf8427e and email ops@example.com."
        )

        indicators = IoCExtractor().extract(text)
        keys = {(indicator.type, indicator.value.lower()) for indicator in indicators}

        self.assertIn(("cve", "cve-2026-12345"), keys)
        self.assertIn(("url", "https://evil.example/a"), keys)
        self.assertIn(("ipv4", "8.8.8.8"), keys)
        self.assertIn(("md5", "d41d8cd98f00b204e9800998ecf8427e"), keys)
        self.assertIn(("email", "ops@example.com"), keys)
        self.assertEqual(sum(1 for indicator in indicators if indicator.type == "cve"), 1)

    def test_external_cti_object_creation(self) -> None:
        result = ExternalCTIPipeline(ner_extractor=FakeNERExtractor()).process_record(raw_record())

        self.assertEqual(result.source_pipeline, "external")
        self.assertEqual(result.processing_status, "transformed")
        self.assertEqual(result.classification_label, "cti_related")
        self.assertTrue(result.indicators)
        self.assertTrue(result.entities)
        self.assertTrue(result.relationships)

    def test_batch_processing_continues_after_one_record_fails(self) -> None:
        pipeline = ExternalCTIPipeline(
            normalizer=FailingNormalizer(),
            ner_extractor=FakeNERExtractor(),
        )
        records = [
            raw_record(external_id="bad-record"),
            raw_record(external_id="good-record", url="https://example.test/good"),
        ]

        with self.assertLogs("backend.app.pipeline.orchestrator", level="ERROR"):
            results = pipeline.process_batch(records)

        self.assertEqual(results[0].processing_status, "failed")
        self.assertEqual(results[1].processing_status, "transformed")


if __name__ == "__main__":
    unittest.main()
