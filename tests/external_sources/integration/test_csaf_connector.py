from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from jsonschema import Draft202012Validator

from backend.app.pipeline.ingestion.external.common.http_client import HttpClientSettings, HttpResponse
from backend.app.pipeline.ingestion.external.csaf_connector import CSAFConnector, CSAFSource
from backend.app.pipeline.ingestion.external.preprocessing.content_processor import ExternalContentProcessor
from backend.app.pipeline.ingestion.external.preprocessing.text_preprocessor import TextPreprocessor
from backend.app.pipeline.ingestion.external.privacy.privacy_filter import PrivacyFilter


ROOT = Path(__file__).resolve().parents[3]


class FakeClient:
    settings = HttpClientSettings(max_response_bytes=100_000)
    def __init__(self, responses, content_type="application/json"): self.responses, self.calls, self.content_type = list(responses), [], content_type
    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        value = self.responses.pop(0)
        if isinstance(value, Exception): raise value
        return HttpResponse(url, 200, {"content-type": self.content_type}, json.dumps(value).encode())


def advisory(identifier="ICSA-26-001-01", title="Safe advisory"):
    return {"document": {"category": "csaf_security_advisory", "csaf_version": "2.0", "title": title,
        "tracking": {"id": identifier, "initial_release_date": "2026-01-01T00:00:00Z", "current_release_date": "2026-01-02T00:00:00Z"},
        "aggregate_severity": {"text": "HIGH"}, "notes": [{"category": "summary", "text": "Security advisory details for testing."}],
        "references": [{"category": "self", "url": "https://www.cisa.gov/advisory/test"}]},
        "vulnerabilities": [{"cve": "CVE-2026-0001", "remediations": [{"details": "Apply the vendor update."}]}],
        "product_tree": {"branches": [{"product": {"name": "Example product", "product_id": "p1"}}]}}


class CSAFConnectorTests(unittest.TestCase):
    def build(self, catalog, documents, state=None):
        source = CSAFSource("cisa-advisories", "CISA", "https://api.github.test/catalog", "https://raw.github.test/base/", max_advisories=2)
        processor = ExternalContentProcessor(TextPreprocessor(ROOT / "config/preprocessing_rules.json"), PrivacyFilter(ROOT / "config/privacy_rules.json"))
        return CSAFConnector(source, catalog_client=FakeClient([catalog]), document_client=FakeClient(documents),
                             content_processor=processor, state=state, clock=lambda: datetime(2026, 9, 17, tzinfo=timezone.utc))

    def test_bounded_catalog_maps_one_advisory_and_deduplicates(self):
        catalog = {"tree": [{"path": "csaf_files/OT/white/2026/a.json"}, {"path": "README.md"}]}
        state = {}
        first = self.build(catalog, [advisory()], state).collect_result()
        second = self.build(catalog, [advisory()], state).collect_result()
        self.assertEqual((first.status, len(first.accepted_items), first.accepted_items[0].source_item_id), ("completed", 1, "ICSA-26-001-01"))
        self.assertEqual(first.accepted_items[0].metadata["cves"], ["CVE-2026-0001"])
        self.assertEqual(second.skipped_items, 1)

    def test_malformed_advisory_isolated_and_partial(self):
        catalog = {"tree": [{"path": "csaf_files/a.json"}, {"path": "csaf_files/b.json"}]}
        result = self.build(catalog, [advisory(), {"document": {}}]).collect_result()
        self.assertEqual((result.status, len(result.accepted_items), len(result.errors)), ("partial", 1, 1))
        self.assertEqual(result.errors[0].category, "csaf_mapping_invalid")

    def test_live_shape_from_trusted_raw_host_accepts_text_plain_without_weakening_generic_json(self):
        catalog = {"tree": [{"path": "csaf_files/OT/white/2026/live.json"}]}
        document = json.loads((ROOT / "tests/external_sources/fixtures/cisa_csaf_live_shape.json").read_text())
        connector = self.build(catalog, [])
        connector.document_client = FakeClient([document], content_type="text/plain; charset=utf-8")
        result = connector.collect_result()
        self.assertEqual((result.status, len(result.accepted_items), result.errors), ("completed", 1, []))
        item = result.accepted_items[0]
        self.assertEqual((item.source_item_id, item.metadata["products"], item.metadata["cves"]),
                         ("ICSA-26-260-01", ["Example Controller 1.0"], ["CVE-2026-12345"]))
        schema = json.loads((ROOT / "contracts/external_cti_item.schema.json").read_text())
        Draft202012Validator(schema).validate(item.to_dict())

    def test_document_failures_have_safe_stage_categories(self):
        catalog = {"tree": [{"path": "csaf_files/a.json"}]}
        connector = self.build(catalog, [])
        connector.document_client = FakeClient([advisory()], content_type="text/html")
        result = connector.collect_result()
        self.assertEqual(result.errors[0].category, "csaf_document_media_type")

    def test_empty_and_failed_catalog_are_bounded(self):
        for catalog in ({"tree": []}, {"unexpected": []}, {"tree": [], "truncated": True}):
            result = self.build(catalog, []).collect_result()
            self.assertEqual((result.status, result.errors[0].category), ("failed", "csaf_catalog_failed"))


if __name__ == "__main__":
    unittest.main()
