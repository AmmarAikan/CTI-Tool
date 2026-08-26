from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock

from jsonschema import Draft202012Validator
import json

from backend.app.pipeline.ingestion.external.application.manual_source_service import AdapterResult, CanonicalManualSourceService
from backend.app.pipeline.ingestion.external.classification.classification_service import ClassifiedItemResult
from backend.app.pipeline.ingestion.external.common.hashing import sha256_text
from backend.app.pipeline.ingestion.external.common.models import ExternalCTIItem, ExternalClassification
from backend.app.pipeline.ingestion.external.common.state_manager import JsonStateManager
from backend.app.pipeline.ingestion.external.common.json_storage import save_json
from backend.app.pipeline.ingestion.external.crawler.web_crawler import CrawlResult
from backend.app.pipeline.ingestion.external.manual_source.url_policy import ManualURLPolicy
from backend.app.pipeline.ingestion.external.manual_source.url_router import ManualURLRouter


NOW = datetime(2026, 8, 23, tzinfo=timezone.utc)
PUBLIC = lambda _host, port: [(2, 1, 6, "", ("93.184.216.34", port))]


def crawl(url, *, page_type="article", links=(), text="A substantial cybersecurity report describes malware execution, persistence, credential theft, and defensive mitigations."):
    return CrawlResult(url, url, "success", "Sanitized report", text, page_type, .9, tuple(links), {},
                       {"etag": '"v1"', "last_modified": "Wed, 01 Jan 2025 00:00:00 GMT"}, sha256_text("raw:" + url), sha256_text(text))


class FakeCrawler:
    def __init__(self, values): self.values, self.calls = list(values), []
    def crawl(self, url, **kwargs): self.calls.append((url, kwargs)); return self.values.pop(0)


class AcceptClassification:
    classifier = type("Classifier", (), {"model_version": "test-model"})()
    def classify_item(self, item):
        value = replace(item, classification=ExternalClassification(status="accepted", label="cti", score=.9, model_version="test-model"))
        return ClassifiedItemResult(value, "accepted", None)


class ManualSourceServiceTests(unittest.TestCase):
    def service(self, crawler, manager, **kwargs):
        return CanonicalManualSourceService(policy=kwargs.pop("policy", ManualURLPolicy(resolver=PUBLIC)), crawler=crawler,
            state_manager=manager, classification_service=kwargs.pop("classification_service", AcceptClassification()),
            clock=lambda: NOW, **kwargs)

    def test_router_prefers_structured_adapters(self):
        router = ManualURLRouter()
        cases = {
            "https://github.com/advisories/GHSA-2345-6789-cfgh": "github_advisory",
            "https://github.com/org/repo/releases/tag/v1": "github_public",
            "https://nvd.nist.gov/vuln/detail/CVE-2025-1234": "vulnerability",
            "https://example.test/feed.xml": "rss",
            "http://example-not-a-real-service.onion/advisories/one": "dark_web",
            "https://example.test/report": "generic_web",
        }
        for url, expected in cases.items(): self.assertEqual(router.route(url).kind, expected)

    def test_structured_route_invokes_adapter_and_never_crawler(self):
        with tempfile.TemporaryDirectory() as folder:
            manager = JsonStateManager(Path(folder) / "state.json")
            adapter = Mock(); adapter.collect_url.return_value = AdapterResult("stored", (), "official API processed")
            crawler = FakeCrawler([])
            result = self.service(crawler, manager, adapters={"github_advisory": adapter}).add_manual_source(
                "https://github.com/advisories/GHSA-2345-6789-cfgh", requested_by="tester")
        self.assertEqual(result.status, "stored"); self.assertEqual(crawler.calls, [])
        self.assertEqual(adapter.collect_url.call_args.kwargs["identifier"], "GHSA-2345-6789-CFGH")

    def test_unconfigured_structured_route_fails_closed_without_crawler(self):
        crawler = FakeCrawler([])
        with tempfile.TemporaryDirectory() as folder:
            result = self.service(crawler, JsonStateManager(Path(folder) / "state.json")).add_manual_source(
                "https://t.me/s/not-configured", requested_by="tester")
        self.assertEqual(result.status, "ignored")
        self.assertEqual(result.message, "telegram adapter is not configured")
        self.assertEqual(crawler.calls, [])

    def test_feed_content_type_routes_to_rss_adapter_without_html_scraping(self):
        url = "https://example.test/updates"
        rejected_as_html = CrawlResult(url, url, "error", response_metadata={"content_type": "application/atom+xml"})
        adapter = Mock(); adapter.collect_url.return_value = AdapterResult("stored", (), "feed adapter processed")
        with tempfile.TemporaryDirectory() as folder:
            result = self.service(FakeCrawler([rejected_as_html]), JsonStateManager(Path(folder) / "state.json"),
                                  adapters={"rss": adapter}).add_manual_source(url, requested_by="tester")
        self.assertEqual(result.status, "stored"); adapter.collect_url.assert_called_once()

    def test_article_pipeline_stores_contract_and_skips_unchanged(self):
        stored = []
        url = "https://example.test/report"
        crawler = FakeCrawler([crawl(url), CrawlResult(url, url, "unchanged")])
        with tempfile.TemporaryDirectory() as folder:
            manager = JsonStateManager(Path(folder) / "state.json")
            service = self.service(crawler, manager, record_sink=lambda item, disposition: stored.append((item, disposition)))
            first = service.add_manual_source(url, requested_by="tester")
            second = service.add_manual_source(url, requested_by="tester")
            state = manager.load()
        self.assertEqual((first.status, first.records_created), ("stored", 1)); self.assertEqual(second.status, "unchanged")
        self.assertEqual(stored[0][1], "accepted"); self.assertIn("stages", state["urls"][url])
        schema = json.loads((Path(__file__).resolve().parents[3] / "contracts" / "external_cti_item.schema.json").read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(stored[0][0].to_dict())
        self.assertEqual(crawler.calls[1][1]["etag"], '"v1"')

    def test_explicit_submission_registers_stable_safe_active_root(self):
        url = "https://example.test/report"
        with tempfile.TemporaryDirectory() as folder:
            manager = JsonStateManager(Path(folder) / "state.json")
            service = self.service(FakeCrawler([crawl(url)]), manager)
            service.add_manual_source(url, requested_by="tester")
            roots = service.list_tracked_roots()
            state = manager.load()
        self.assertEqual(len(roots), 1)
        self.assertTrue(roots[0].root_id.startswith("manual-root-"))
        self.assertEqual(roots[0].canonical_url, url)
        self.assertNotIn(url, str(roots[0].safe_dict()))
        self.assertEqual(state["tracked_roots"][roots[0].root_id]["origin"], "explicit")

    def test_listing_children_are_not_registered_as_roots(self):
        listing = "https://example.test/index"
        children = ("https://example.test/article-one", "https://example.test/article-two")
        crawler = FakeCrawler([crawl(listing, page_type="listing", links=children), crawl(children[0]), crawl(children[1])])
        with tempfile.TemporaryDirectory() as folder:
            manager = JsonStateManager(Path(folder) / "state.json")
            service = self.service(crawler, manager)
            service.add_manual_source(listing, requested_by="tester")
            roots = service.list_tracked_roots()
        self.assertEqual([root.canonical_url for root in roots], [listing])

    def test_legacy_root_migration_excludes_children_and_inactive_roots_idempotently(self):
        listing = "https://example.test/index"
        child = "https://example.test/article-one"
        standalone = "https://example.test/standalone"
        inactive = "https://example.test/retired"
        historical = {"custom_history": {"first_seen": "2024-01-01T00:00:00Z"}}
        legacy = {"schema_version": "1.0", "sources": {}, "items": {}, "runs": {}, "urls": {
            listing: {"known_sub_links": [child], "last_checked": "2025-01-01T00:00:00Z"},
            child: {"active": True, "last_checked": "2025-01-02T00:00:00Z"},
            standalone: {"active": True, **historical},
            inactive: {"active": False, "retired_at": "2025-01-03T00:00:00Z"},
        }}
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "state.json"; save_json(legacy, path)
            service = self.service(FakeCrawler([]), JsonStateManager(path))
            first = service.list_tracked_roots(); migrated = JsonStateManager(path).load()
            second = service.list_tracked_roots(); repeated = JsonStateManager(path).load()
        self.assertEqual({root.canonical_url for root in first}, {listing, standalone})
        self.assertEqual(first, second)
        self.assertEqual(migrated, repeated)
        self.assertEqual(migrated["urls"][standalone]["custom_history"], historical["custom_history"])
        indexed = migrated["tracked_roots"]
        self.assertFalse(indexed[service._root_id(inactive)]["active"])
        self.assertNotIn(service._root_id(child), indexed)

    def test_rule_fingerprint_change_forces_downstream_rerun_without_conditionals(self):
        url = "https://example.test/report"
        crawler = FakeCrawler([crawl(url), crawl(url)])
        with tempfile.TemporaryDirectory() as folder:
            manager = JsonStateManager(Path(folder) / "state.json")
            first = self.service(crawler, manager); first.add_manual_source(url, requested_by="tester")
            second = self.service(crawler, manager)
            second.content_processor.preprocessor.rules_hash = "sha256:changed"
            second.add_manual_source(url, requested_by="tester")
        self.assertIsNone(crawler.calls[1][1]["etag"]); self.assertIsNone(crawler.calls[1][1]["last_modified"])

    def test_listing_is_bounded_one_level_and_marks_disappeared_links(self):
        listing = "https://example.test/index"
        children = [f"https://example.test/article-{number}" for number in range(1, 4)]
        first_values = [crawl(listing, page_type="listing", links=children), crawl(children[0]), crawl(children[1])]
        second_values = [crawl(listing, page_type="listing", links=(children[1],)), crawl(children[1])]
        stored = []
        with tempfile.TemporaryDirectory() as folder:
            manager = JsonStateManager(Path(folder) / "state.json")
            first = self.service(FakeCrawler(first_values), manager, max_listing_links=2, record_sink=lambda i, d: stored.append(i))
            result = first.add_manual_source(listing, requested_by="tester")
            second = self.service(FakeCrawler(second_values), manager, max_listing_links=2)
            second.add_manual_source(listing, requested_by="tester")
            state = manager.load()
        self.assertEqual((result.status, result.records_created), ("listing_processed", 2))
        self.assertIn("missing_from_source", state["urls"][children[0]])
        self.assertEqual(len(state["urls"][listing]["known_sub_links"]), 1)

    def test_privacy_or_classification_failure_routes_review(self):
        classification = Mock()
        classification.classifier = type("Classifier", (), {"model_version": "test"})()
        classification.classify_item.side_effect = lambda item: ClassifiedItemResult(
            replace(item, classification=ExternalClassification(status="error")), "review", None, "prediction_failed")
        stored = []
        url = "https://example.test/report"
        with tempfile.TemporaryDirectory() as folder:
            result = self.service(FakeCrawler([crawl(url)]), JsonStateManager(Path(folder) / "state.json"),
                                  classification_service=classification, record_sink=lambda i, d: stored.append(d)).add_manual_source(url, requested_by="tester")
        self.assertEqual(result.status, "review_required"); self.assertEqual(stored, ["review"])

    def test_short_and_utility_content_are_gated_before_model_inference(self):
        classification = Mock(); classification.classifier = type("Classifier", (), {"model_version": "test"})()
        stored = []
        with tempfile.TemporaryDirectory() as folder:
            manager = JsonStateManager(Path(folder) / "state.json")
            short = self.service(FakeCrawler([crawl("https://example.test/report", text="Brief ambiguous security update.")]), manager,
                                 classification_service=classification, record_sink=lambda item, disposition: stored.append((item, disposition)))
            short_result = short.add_manual_source("https://example.test/report", requested_by="tester")
            utility = self.service(FakeCrawler([crawl("https://example.test/contact/", text="Contact sales to get started and request a demo for our products.")]), manager,
                                   classification_service=classification, record_sink=lambda item, disposition: stored.append((item, disposition)))
            utility_result = utility.add_manual_source("https://example.test/contact/", requested_by="tester")
        self.assertEqual((short_result.status, stored[0][1], stored[0][0].classification.status), ("review_required", "review", "not_run"))
        self.assertEqual((utility_result.status, stored[1][1], stored[1][0].classification.label), ("ignored", "rejected", "utility_page"))
        classification.classify_item.assert_not_called()


if __name__ == "__main__": unittest.main()
