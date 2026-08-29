from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import patch

import requests

from backend.app.pipeline.ingestion.external.common.hashing import sha256_bytes, sha256_text
from backend.app.pipeline.ingestion.external.common.http_client import HttpResponse, ResponseTooLargeError
from backend.app.pipeline.ingestion.external.crawler.web_crawler import EXTRACTION_IMPLEMENTATION_VERSION, WebCrawler
from backend.app.pipeline.ingestion.external.preprocessing.content_processor import ExternalContentProcessor
from backend.app.pipeline.ingestion.external.preprocessing.text_preprocessor import TextPreprocessor
from backend.app.pipeline.ingestion.external.privacy.privacy_filter import PrivacyFilter


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

    def test_complete_multisection_article_metadata_tables_and_boilerplate(self) -> None:
        response = response_for("multisection_cti_article.html")
        result = WebCrawler(http_client=StubHttpClient(response=response)).crawl("https://example.test/advisory")

        self.assertEqual(result.status, "success")
        self.assertEqual(result.title, "Going with the Flow(s): Distinct Sanitized Clusters")
        self.assertEqual(result.author, "Avery Analyst, Riley Researcher")
        self.assertEqual(result.published, "2026-08-20")
        self.assertEqual(result.extraction_version, EXTRACTION_IMPLEMENTATION_VERSION)
        for marker in ("Overview", "Cluster Alpha", "OAuth activity", "Cluster Charlie",
                       "Network Indicators", "File Indicators", "Defensive considerations"):
            self.assertIn(marker, result.extracted_text)
        for indicator in ("control-example[.]test", "198.51.100[.]42", "RIVERSTONE",
                          "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"):
            self.assertIn(indicator, result.extracted_text)
        self.assertNotIn("Unrelated marketing article", result.extracted_text)
        self.assertNotIn("trackingSecret", result.extracted_text)

    def test_label_only_byline_uses_bounded_sibling_and_rejects_punctuation(self) -> None:
        html = b"""<html><main><article><h1>Sanitized security report</h1>
        <div class='byline'>Written by:</div><div itemprop='author'>Avery Analyst and Riley Researcher</div>
        <p>A substantial technical analysis describes malicious infrastructure, defensive evidence, and remediation guidance for responders.</p>
        </article></main></html>"""
        response = HttpResponse("https://example.test/report", 200, {"Content-Type": "text/html"}, html)
        result = WebCrawler(http_client=StubHttpClient(response=response)).crawl("https://example.test/report")
        self.assertEqual(result.author, "Avery Analyst and Riley Researcher")
        self.assertNotEqual(result.author, ":")

    def test_semantic_article_wins_when_readability_returns_middle_fragment(self) -> None:
        class FragmentedDocument:
            def __init__(self, _html): pass
            def short_title(self): return "Distinct Sanitized Clusters"
            def summary(self, *, html_partial):
                self.assert_partial = html_partial
                return ("<div><h3>Cluster Charlie</h3><p>After authenticating, the target was redirected to an "
                        "attacker-controlled application that collected an authorization token. This deliberately "
                        "fragmented readability candidate omits every earlier section and both indicator tables.</p></div>")

        with patch("backend.app.pipeline.ingestion.external.crawler.web_crawler.Document", FragmentedDocument):
            result = WebCrawler(http_client=StubHttpClient(response=response_for("multisection_cti_article.html"))).crawl(
                "https://example.test/advisory")
        self.assertIn("Overview", result.extracted_text)
        self.assertIn("Cluster Alpha", result.extracted_text)
        self.assertIn("Network Indicators", result.extracted_text)
        self.assertIn("HEADWIND", result.extracted_text)

    def test_cti_indicators_survive_canonical_preprocessing_and_privacy(self) -> None:
        result = WebCrawler(http_client=StubHttpClient(response=response_for("multisection_cti_article.html"))).crawl(
            "https://example.test/advisory")
        project_root = Path(__file__).resolve().parents[3]
        processor = ExternalContentProcessor(
            TextPreprocessor(project_root / "config" / "preprocessing_rules.json"),
            PrivacyFilter(project_root / "config" / "privacy_rules.json"),
        )
        processed = processor.process(result.extracted_text)
        for indicator in ("control-example[.]test", "198.51.100[.]42", "RIVERSTONE",
                          "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"):
            self.assertIn(indicator, processed.export_content)

    def test_listing_exposes_candidate_links_and_signals(self) -> None:
        client = StubHttpClient(response=response_for("listing_page.html", final_url="https://example.test/reports/"))
        result = WebCrawler(http_client=client).crawl("https://example.test/reports/")
        self.assertEqual(result.status, "success")
        self.assertEqual(result.page_type, "listing")
        self.assertEqual(len(result.candidate_links), 4)
        self.assertIn("listing_score", result.signals)

    def test_dense_listing_is_structurally_locked_before_complete_content_extraction(self) -> None:
        response = response_for("dense_structural_listing.html", final_url="https://example.test/research/")
        result = WebCrawler(http_client=StubHttpClient(response=response)).crawl("https://example.test/research/")
        self.assertEqual(result.page_type, "listing")
        self.assertTrue(result.signals["strong_structural_listing"])
        self.assertGreater(len(result.extracted_text), 300)
        self.assertEqual(len(result.candidate_links), 5)
        self.assertTrue(all(value.startswith("https://example.test/research/") for value in result.candidate_links))

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
