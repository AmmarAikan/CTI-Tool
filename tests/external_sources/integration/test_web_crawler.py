from __future__ import annotations

import unittest
from pathlib import Path

import requests

from backend.app.pipeline.ingestion.external.common.hashing import sha256_bytes, sha256_text
from backend.app.pipeline.ingestion.external.common.http_client import HttpResponse, ResponseTooLargeError
from backend.app.pipeline.ingestion.external.crawler.web_crawler import WebCrawler


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


class StubHttpClient:
    def __init__(self, response=None, error=None) -> None:
        self.response = response
        self.error = error
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if self.error:
            raise self.error
        return self.response


def response_for(name: str, *, content_type: str = "text/html; charset=utf-8", final_url=None) -> HttpResponse:
    body = (FIXTURES / name).read_bytes()
    return HttpResponse(
        url=final_url or "https://example.test/advisory",
        status_code=200,
        headers={"Content-Type": content_type, "ETag": '"fixture-v1"', "Last-Modified": "Wed, 20 Aug 2026 10:00:00 GMT"},
        body=body,
    )


class WebCrawlerTests(unittest.TestCase):
    def test_extracts_clean_article_and_structured_metadata(self) -> None:
        response = response_for("article_page.html", final_url="https://EXAMPLE.test:443/advisory?utm_source=test#fragment")
        client = StubHttpClient(response=response)
        result = WebCrawler(http_client=client).crawl("https://example.test/advisory")

        self.assertEqual(result.status, "success")
        self.assertEqual(result.canonical_url, "https://example.test/advisory")
        self.assertEqual(result.page_type, "article")
        self.assertIn("Security researchers identified", result.extracted_text)
        self.assertNotIn("secretTrackingValue", result.extracted_text)
        self.assertNotIn("Buy unrelated product", result.extracted_text)
        self.assertEqual(result.raw_content_hash, sha256_bytes(response.body))
        self.assertEqual(result.extracted_content_hash, sha256_text(result.extracted_text))
        self.assertEqual(result.response_metadata["etag"], '"fixture-v1"')

    def test_listing_exposes_candidate_links_and_signals(self) -> None:
        client = StubHttpClient(response=response_for("listing_page.html", final_url="https://example.test/reports/"))
        result = WebCrawler(http_client=client).crawl("https://example.test/reports/")
        self.assertEqual(result.status, "success")
        self.assertEqual(result.page_type, "listing")
        self.assertEqual(len(result.candidate_links), 4)
        self.assertIn("listing_score", result.signals)

    def test_conditional_request_can_return_unchanged(self) -> None:
        response = HttpResponse("https://example.test/feed", 304, {"ETag": '"v2"'}, b"", not_modified=True)
        client = StubHttpClient(response=response)
        result = WebCrawler(http_client=client).crawl("https://example.test/feed", etag='"v1"')
        self.assertEqual(result.status, "unchanged")
        self.assertFalse(result.errors)
        self.assertEqual(client.calls[0][1]["etag"], '"v1"')

    def test_non_html_response_is_rejected_without_extraction(self) -> None:
        response = HttpResponse("https://example.test/file.pdf", 200, {"Content-Type": "application/pdf"}, b"%PDF")
        result = WebCrawler(http_client=StubHttpClient(response=response)).crawl("https://example.test/file.pdf")
        self.assertEqual(result.status, "error")
        self.assertEqual(result.errors[0].category, "unsupported_content_type")
        self.assertIsNone(result.raw_content_hash)

    def test_size_timeout_and_invalid_url_are_structured_errors(self) -> None:
        too_large = WebCrawler(http_client=StubHttpClient(error=ResponseTooLargeError("too large"))).crawl("https://example.test/")
        timeout = WebCrawler(http_client=StubHttpClient(error=requests.Timeout())).crawl("https://example.test/")
        invalid = WebCrawler(http_client=StubHttpClient()).crawl("file:///tmp/test")
        self.assertEqual(too_large.errors[0].category, "response_too_large")
        self.assertEqual(timeout.errors[0].category, "timeout")
        self.assertTrue(timeout.errors[0].retryable)
        self.assertEqual(invalid.errors[0].category, "invalid_url")


if __name__ == "__main__":
    unittest.main()
