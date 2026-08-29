from __future__ import annotations

import unittest
import json
from datetime import datetime, timezone
from pathlib import Path

from jsonschema import Draft202012Validator

from backend.app.pipeline.ingestion.external.common.http_client import HttpResponse
from backend.app.pipeline.ingestion.external.crawler.web_crawler import CrawlError, CrawlResult
from backend.app.pipeline.ingestion.external.rss_connector import ConfiguredRSSCollector, RSSCollectionResult, RSSConnector, RSSSource


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
NOW = datetime(2026, 8, 23, 12, 0, tzinfo=timezone.utc)


class StubHttpClient:
    def __init__(self, response=None, error=None) -> None:
        self.response, self.error, self.calls = response, error, []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if self.error:
            raise self.error
        return self.response


class StubCrawler:
    def __init__(self) -> None:
        self.calls = []

    def crawl(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if url.endswith("advisory-002"):
            return CrawlResult(url, url, "error", errors=(CrawlError("request_failed", "RequestException", True),))
        return CrawlResult(
            url, url, "success", title="Full advisory", page_type="article", confidence=0.9,
            extracted_text="Full sanitized advisory content describing CVE-2026-12345 and remediation guidance.",
            response_metadata={"etag": '"article-v1"', "last_modified": "Sat, 22 Aug 2026 10:00:00 GMT"},
            raw_content_hash="sha256:" + "a" * 64, extracted_content_hash="sha256:" + "b" * 64,
        )


def feed_response(*, not_modified=False):
    return HttpResponse(
        "https://example.test/feed.xml", 304 if not_modified else 200,
        {"Content-Type": "application/rss+xml", "ETag": '"feed-v1"', "Last-Modified": "Sat, 22 Aug 2026 11:00:00 GMT"},
        b"" if not_modified else (FIXTURES / "rss_feed.xml").read_bytes(), not_modified=not_modified,
    )


class RSSConnectorTests(unittest.TestCase):
    def test_enriches_full_articles_and_routes_summary_only_to_review(self) -> None:
        state = {"sources": {}, "items": {}}
        client, crawler = StubHttpClient(feed_response()), StubCrawler()
        connector = RSSConnector(
            "https://example.test/feed.xml", "Sanitized Security Feed", source_id="sanitized-feed",
            category="advisory", lookback_days=7, http_client=client, crawler=crawler,
            state=state, clock=lambda: NOW,
        )
        result = connector.collect_result()

        self.assertEqual(result.status, "completed")
        self.assertEqual(len(result.accepted_items), 1)
        self.assertEqual(len(result.review_items), 1)
        self.assertEqual(result.skipped_items, 1)
        accepted = result.accepted_items[0]
        self.assertEqual(accepted.source_item_id, "advisory-001")
        self.assertEqual(accepted.link, "https://example.test/articles/advisory-001")
        self.assertEqual(accepted.metadata["content_status"], "full_text")
        self.assertEqual(accepted.classification.status, "not_required")
        self.assertIn("vulnerability", accepted.tags)
        self.assertEqual(result.review_items[0].metadata["content_status"], "summary_only")
        self.assertIn("raw_content_hash", state["sources"]["sanitized-feed"])
        self.assertEqual(len(state["items"]), 2)

        schema = json.loads((FIXTURES.parents[2] / "contracts" / "external_cti_item.schema.json").read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(accepted.to_dict())

        raw_record = accepted.to_raw_record()
        self.assertTrue(raw_record.trusted_cybersecurity_source)
        self.assertEqual(raw_record.source_pipeline, "external")

    def test_unchanged_item_is_skipped_when_feed_was_refetched(self) -> None:
        state = {"sources": {}, "items": {}}
        connector = RSSConnector(
            "https://example.test/feed.xml", "Sanitized", source_id="sanitized-feed", max_items=1,
            lookback_days=0, http_client=StubHttpClient(feed_response()), crawler=StubCrawler(), state=state, clock=lambda: NOW,
        )
        self.assertEqual(len(connector.collect_result().accepted_items), 1)
        second = connector.collect_result()
        self.assertEqual(second.all_items, [])
        self.assertEqual(second.skipped_items, 1)

    def test_conditional_feed_request_returns_unchanged_and_updates_check(self) -> None:
        state = {"sources": {"sanitized-feed": {"etag": '"old"', "last_modified": "yesterday"}}, "items": {}}
        client = StubHttpClient(feed_response(not_modified=True))
        connector = RSSConnector(
            "https://example.test/feed.xml", "Sanitized", source_id="sanitized-feed",
            http_client=client, crawler=StubCrawler(), state=state, clock=lambda: NOW,
        )
        result = connector.collect_result()
        self.assertEqual(result.status, "unchanged")
        self.assertEqual(client.calls[0][1]["etag"], '"old"')
        self.assertEqual(state["sources"]["sanitized-feed"]["etag"], '"feed-v1"')
        self.assertEqual(state["sources"]["sanitized-feed"]["last_checked"], "2026-08-23T12:00:00Z")

    def test_max_items_is_enforced(self) -> None:
        connector = RSSConnector(
            "https://example.test/feed.xml", "Sanitized", source_id="sanitized-feed", max_items=1,
            lookback_days=0, http_client=StubHttpClient(feed_response()), crawler=StubCrawler(), clock=lambda: NOW,
        )
        result = connector.collect_result()
        self.assertEqual(len(result.all_items), 1)

    def test_configured_collector_isolates_feed_failure_and_skips_disabled(self) -> None:
        good = RSSSource("good", "Good", "https://example.test/good.xml", "news")
        bad = RSSSource("bad", "Bad", "https://example.test/bad.xml", "news")
        disabled = RSSSource("disabled", "Disabled", "https://example.test/off.xml", "news", enabled=False)

        class Connector:
            def __init__(self, source): self.source = source
            def collect_result(self):
                if self.source.source_id == "bad": raise RuntimeError("safe simulated failure")
                return RSSCollectionResult(self.source.source_id)

        results = ConfiguredRSSCollector([good, bad, disabled], connector_factory=Connector).collect_results()
        self.assertEqual([item.source_id for item in results], ["good", "bad"])
        self.assertEqual(results[1].status, "failed")
        self.assertEqual(results[1].errors[0].category, "source_failed")


if __name__ == "__main__":
    unittest.main()
