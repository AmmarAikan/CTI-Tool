from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone
from pathlib import Path

from jsonschema import Draft202012Validator

from backend.app.pipeline.ingestion.external.cert_connector import (
    CERTCollectionResult,
    CERTConnector,
    CERTSource,
    ConfiguredCERTCollector,
)
from backend.app.pipeline.ingestion.external.common.http_client import HttpResponse
from backend.app.pipeline.ingestion.external.crawler.web_crawler import CrawlError, CrawlResult


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
NOW = datetime(2026, 8, 23, 12, 0, tzinfo=timezone.utc)


class StubHttpClient:
    def __init__(self, response: HttpResponse) -> None:
        self.response = response
        self.calls: list[tuple[str, dict]] = []

    def get(self, url: str, **kwargs):
        self.calls.append((url, kwargs))
        return self.response


class StubCrawler:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    def crawl(self, url: str, **kwargs):
        self.calls.append((url, kwargs))
        if url.endswith("example-vulnerability-advisory"):
            return CrawlResult(
                url,
                url,
                "error",
                errors=(CrawlError("request_failed", "safe fixture failure", True),),
            )
        return CrawlResult(
            url,
            url,
            "success",
            title="Official advisory",
            extracted_text="Official CERT advisory for CVE-2026-12345 with mitigation guidance.",
            page_type="article",
            confidence=0.95,
            response_metadata={"etag": '"detail-v1"'},
            raw_content_hash="sha256:" + "a" * 64,
            extracted_content_hash="sha256:" + "b" * 64,
        )


def listing_response(*, not_modified: bool = False) -> HttpResponse:
    return HttpResponse(
        "https://www.cisa.gov/news-events/cybersecurity-advisories",
        304 if not_modified else 200,
        {"Content-Type": "text/html", "ETag": '"listing-v1"'},
        b"" if not_modified else (FIXTURES / "cisa_advisory_listing.html").read_bytes(),
        not_modified=not_modified,
    )


def cisa_source(**overrides) -> CERTSource:
    values = {
        "source_id": "cisa-advisories",
        "name": "CISA",
        "url": "https://www.cisa.gov/news-events/cybersecurity-advisories",
        "method": "official_listing",
        "detail_path_pattern": r"^/news-events/cybersecurity-advisories/[a-z0-9][a-z0-9-]+$",
    }
    values.update(overrides)
    return CERTSource.from_mapping(values)


class CERTConnectorTests(unittest.TestCase):
    def test_listing_extracts_full_text_and_routes_unavailable_detail_to_review(self) -> None:
        state = {"sources": {}, "items": {}}
        connector = CERTConnector(
            cisa_source(),
            http_client=StubHttpClient(listing_response()),
            crawler=StubCrawler(),
            state=state,
            clock=lambda: NOW,
        )
        result = connector.collect_result()

        self.assertEqual(result.status, "completed")
        self.assertEqual(len(result.accepted_items), 1)
        self.assertEqual(len(result.review_items), 1)
        accepted = result.accepted_items[0]
        self.assertEqual(accepted.source_type, "cert")
        self.assertEqual(accepted.classification.status, "not_required")
        self.assertEqual(accepted.metadata["delivery_method"], "official_listing")
        self.assertEqual(accepted.metadata["content_status"], "full_text")
        self.assertEqual(result.review_items[0].metadata["content_status"], "unavailable")
        self.assertEqual(len(state["items"]), 2)

        schema = json.loads(
            (FIXTURES.parents[2] / "contracts" / "external_cti_item.schema.json").read_text(encoding="utf-8")
        )
        Draft202012Validator(schema).validate(accepted.to_dict())
        self.assertTrue(accepted.to_raw_record().trusted_cybersecurity_source)

    def test_listing_items_are_skipped_when_hashes_are_unchanged(self) -> None:
        state = {"sources": {}, "items": {}}
        connector = CERTConnector(
            cisa_source(max_items=1),
            http_client=StubHttpClient(listing_response()),
            crawler=StubCrawler(),
            state=state,
            clock=lambda: NOW,
        )
        self.assertEqual(len(connector.collect_result().accepted_items), 1)
        second = connector.collect_result()
        self.assertEqual(second.all_items, [])
        self.assertEqual(second.skipped_items, 1)

    def test_listing_uses_conditional_source_state(self) -> None:
        state = {"sources": {"cisa-advisories": {"etag": '"old"'}}, "items": {}}
        client = StubHttpClient(listing_response(not_modified=True))
        result = CERTConnector(
            cisa_source(), http_client=client, crawler=StubCrawler(), state=state, clock=lambda: NOW
        ).collect_result()
        self.assertEqual(result.status, "unchanged")
        self.assertEqual(client.calls[0][1]["etag"], '"old"')
        self.assertEqual(state["sources"]["cisa-advisories"]["last_checked"], "2026-08-23T12:00:00Z")

    def test_rss_delivery_reuses_rss_connector_and_marks_items_as_cert(self) -> None:
        source = CERTSource(
            "cert-at-warnings",
            "CERT.at",
            "https://example.test/feed.xml",
            "rss",
            max_items=1,
            lookback_days=0,
        )
        response = HttpResponse(
            source.url,
            200,
            {"Content-Type": "application/rss+xml"},
            (FIXTURES / "rss_feed.xml").read_bytes(),
        )
        result = CERTConnector(
            source,
            http_client=StubHttpClient(response),
            crawler=StubCrawler(),
            clock=lambda: NOW,
        ).collect_result()
        self.assertEqual(len(result.accepted_items), 1)
        item = result.accepted_items[0]
        self.assertEqual(item.source_type, "cert")
        self.assertEqual(item.metadata["delivery_method"], "official_rss")
        self.assertEqual(item.metadata["cert_source_id"], "cert-at-warnings")
        self.assertEqual(item.classification.status, "not_required")

    def test_configured_sources_match_verified_methods_and_fail_independently(self) -> None:
        configured = json.loads((FIXTURES.parents[2] / "config" / "sources.json").read_text(encoding="utf-8"))
        sources = [CERTSource.from_mapping(item) for item in configured["cert_sources"]]
        self.assertEqual(
            {source.source_id: source.method for source in sources},
            {
                "cisa-advisories": "official_listing",
                "cert-eu-advisories": "rss",
                "cert-at-warnings": "rss",
            },
        )

        class Connector:
            def __init__(self, source):
                self.source = source

            def collect_result(self):
                if self.source.source_id == "cert-eu-advisories":
                    raise RuntimeError("safe simulated outage")
                return CERTCollectionResult(self.source.source_id)

        results = ConfiguredCERTCollector(sources, connector_factory=Connector).collect_results()
        self.assertEqual(len(results), 3)
        self.assertEqual(results[1].status, "failed")
        self.assertEqual(results[2].status, "completed")


if __name__ == "__main__":
    unittest.main()
