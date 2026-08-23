from __future__ import annotations

import unittest
from pathlib import Path

from backend.app.pipeline.ingestion.external.crawler.page_type_detector import PageTypeDetector


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


class PageTypeDetectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.detector = PageTypeDetector()

    def test_article_uses_metadata_heading_density_and_yield(self) -> None:
        html = (FIXTURES / "article_page.html").read_text(encoding="utf-8")
        extracted = "x" * 500
        result = self.detector.detect(html, "https://example.test/advisory", extracted)
        self.assertEqual(result.page_type, "article")
        self.assertGreaterEqual(result.confidence, 0.5)
        self.assertTrue(result.signals["article_metadata"])
        self.assertEqual(result.signals["h1_count"], 1)

    def test_listing_returns_only_canonical_same_host_headlines(self) -> None:
        html = (FIXTURES / "listing_page.html").read_text(encoding="utf-8")
        result = self.detector.detect(html, "https://example.test/reports/", "Recent reports")
        self.assertEqual(result.page_type, "listing")
        self.assertGreaterEqual(result.confidence, 0.5)
        self.assertEqual(len(result.candidate_links), 4)
        self.assertEqual(result.candidate_links[0], "https://example.test/reports/alpha")
        self.assertTrue(all("outside.example" not in link for link in result.candidate_links))
        self.assertGreaterEqual(result.signals["repeated_card_elements"], 4)

    def test_weak_page_remains_unknown(self) -> None:
        html = (FIXTURES / "unknown_page.html").read_text(encoding="utf-8")
        result = self.detector.detect(html, "https://example.test/", "Welcome.")
        self.assertEqual(result.page_type, "unknown")
        self.assertLess(result.confidence, 0.5)


if __name__ == "__main__":
    unittest.main()
