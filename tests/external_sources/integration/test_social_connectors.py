from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone
from pathlib import Path

from jsonschema import Draft202012Validator

from backend.app.pipeline.ingestion.external.classification.classification_service import ClassificationService
from backend.app.pipeline.ingestion.external.classification.classifier import ClassificationResult, MODEL_SHA256, MODEL_VERSION
from backend.app.pipeline.ingestion.external.common.http_client import HttpResponse
from backend.app.pipeline.ingestion.external.crawler.web_crawler import CrawlResult
from backend.app.pipeline.ingestion.external.hackernews_connector import HackerNewsConnector, HackerNewsSource
from backend.app.pipeline.ingestion.external.reddit_connector import RedditConnector, RedditSource
from backend.app.pipeline.ingestion.external.social_common import ConfiguredSocialCollector, SocialCollectionResult, SocialItemProcessor
from backend.app.pipeline.ingestion.external.telegram_connector import TelegramConnector, TelegramSource


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
ROOT = FIXTURES.parents[2]
NOW = datetime(2026, 8, 23, 12, 0, tzinfo=timezone.utc)


class StubClassifier:
    def __init__(self, status="accepted") -> None: self.status = status
    def classify(self, text):
        label = "cti_related" if self.status == "accepted" else None
        error = "prediction_failed" if self.status == "error" else None
        return ClassificationResult(self.status, label, None, MODEL_VERSION, MODEL_SHA256, error)


class StubCrawler:
    def __init__(self) -> None: self.calls = []
    def crawl(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return CrawlResult(url, url, "success", title="Full article", page_type="article", confidence=0.9,
            extracted_text="A full sanitized external article describes malware behavior, technical indicators, and remediation guidance for defenders.",
            response_metadata={"etag": '"article-v1"'}, raw_content_hash="sha256:" + "a" * 64, extracted_content_hash="sha256:" + "b" * 64)


class StubHttpClient:
    def __init__(self, fixture): self.fixture, self.calls = fixture, []
    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        content_type = "application/json" if self.fixture.endswith(".json") else "text/html"
        return HttpResponse(url, 200, {"Content-Type": content_type}, (FIXTURES / self.fixture).read_bytes())


class StubRedditApi:
    configured = True
    def __init__(self, error=None): self.error, self.calls = error, []
    def listing(self, subreddit, **kwargs):
        self.calls.append((subreddit, kwargs))
        if self.error: raise self.error
        return json.loads((FIXTURES / "reddit_listing.json").read_text(encoding="utf-8"))


def processor(*, state=None, classification="accepted"):
    return SocialItemProcessor(crawler=StubCrawler(), classification_service=ClassificationService(StubClassifier(classification)), state=state, clock=lambda: NOW)


class SocialConnectorTests(unittest.TestCase):
    def test_reddit_uses_bounded_official_api_shape_and_enriches_link_posts(self) -> None:
        source = RedditSource("reddit-netsec", "Reddit - r/netsec", "netsec", True, 30)
        api, state = StubRedditApi(), {"sources": {}, "items": {}}
        result = RedditConnector(source, api_client=api, processor=processor(state=state)).collect_result()
        self.assertEqual(result.status, "completed")
        self.assertEqual(len(result.accepted_items), 2)
        self.assertEqual(api.calls[0], ("netsec", {"limit": 30, "after": None}))
        self.assertEqual(result.accepted_items[0].source_item_id, "t3_example1")
        self.assertEqual(result.accepted_items[1].metadata["content_status"], "full_text")
        self.assertNotIn("utm_source", result.accepted_items[1].metadata["external_url"])

    def test_hackernews_uses_algolia_window_and_skips_unchanged_hashes(self) -> None:
        state = {"sources": {"hackernews-cve": {"checkpoint_created_at_i": 1787300000}}, "items": {}}
        client = StubHttpClient("hackernews_search.json")
        connector = HackerNewsConnector(HackerNewsSource("hackernews-cve", "HN CVE", "CVE", limit=30, max_pages=1), http_client=client, processor=processor(state=state))
        first, second = connector.collect_result(), connector.collect_result()
        self.assertEqual(len(first.accepted_items), 2)
        self.assertEqual(second.all_items, [])
        self.assertEqual(second.skipped_items, 2)
        self.assertIn("numericFilters=created_at_i%3E1787300000", client.calls[0][0])
        self.assertEqual(state["sources"]["hackernews-cve"]["checkpoint_created_at_i"], 1787392800)

    def test_telegram_parses_only_public_channel_posts_and_tracks_message_ids(self) -> None:
        state = {"sources": {}, "items": {}}
        client = StubHttpClient("telegram_public_preview.html")
        connector = TelegramConnector(TelegramSource("telegram-thn", "Telegram THN", "thehackernews", max_pages=1), http_client=client, processor=processor(state=state))
        first, second = connector.collect_result(), connector.collect_result()
        self.assertEqual(len(first.accepted_items), 2)
        self.assertEqual(second.all_items, [])
        self.assertEqual(first.accepted_items[0].source_item_id, "12001")
        self.assertEqual(first.accepted_items[1].link, "https://t.me/thehackernews/12002")
        self.assertEqual(state["sources"]["telegram-thn"]["checkpoint_message_id"], 12002)
        self.assertTrue(client.calls[0][0].startswith("https://t.me/s/"))

    def test_classification_failure_routes_social_item_to_review(self) -> None:
        result = HackerNewsConnector(HackerNewsSource("hn", "HN", "CVE", limit=1, max_pages=1), http_client=StubHttpClient("hackernews_search.json"), processor=processor(classification="error")).collect_result()
        self.assertEqual(len(result.review_items), 2)
        self.assertEqual(result.review_items[0].classification.status, "error")
        self.assertEqual(result.review_items[0].metadata["classification_stage"]["error_category"], "prediction_failed")

    def test_source_failure_isolation_and_configured_methods(self) -> None:
        class Good:
            source = type("Source", (), {"source_id": "good"})()
            def collect_result(self): return SocialCollectionResult("good")
        class Bad:
            source = type("Source", (), {"source_id": "bad"})()
            def collect_result(self): raise RuntimeError("safe outage")
        results = ConfiguredSocialCollector([Bad(), Good()]).collect_results()
        self.assertEqual([(r.source_id, r.status) for r in results], [("bad", "failed"), ("good", "completed")])

        config = json.loads((ROOT / "config" / "sources.json").read_text(encoding="utf-8"))
        self.assertTrue(all(value["method"] == "oauth_api" and not value["enabled"] for value in config["social_media_sources"]))
        self.assertTrue(all(value["method"] == "public_preview" for value in config["telegram_sources"]))

    def test_social_item_validates_contract_and_is_not_trusted(self) -> None:
        result = RedditConnector(RedditSource("reddit-netsec", "Reddit", "netsec", True), api_client=StubRedditApi(), processor=processor()).collect_result()
        item = result.accepted_items[0]
        schema = json.loads((ROOT / "contracts" / "external_cti_item.schema.json").read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(item.to_dict())
        self.assertFalse(item.to_raw_record().trusted_cybersecurity_source)


if __name__ == "__main__": unittest.main()
