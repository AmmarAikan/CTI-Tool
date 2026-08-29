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

    def test_navigation_heavy_listing_ranks_real_articles_before_limit(self) -> None:
        html = (FIXTURES / "navigation_heavy_threat_listing.html").read_text(encoding="utf-8")
        detector = PageTypeDetector(max_candidate_links=2)
        result = detector.detect(html, "https://cloud.google.com/blog/topics/threat-intelligence/", "Latest research")
        self.assertEqual(result.page_type, "listing")
        self.assertEqual(len(result.candidate_links), 2)
        self.assertTrue(all("/blog/topics/threat-intelligence/" in value for value in result.candidate_links))
        self.assertTrue(any("fictional-ransomware-disruption" in value for value in result.candidate_links))
        self.assertNotIn("https://cloud.google.com/contact/", result.candidate_links)
        self.assertNotIn("https://cloud.google.com/blog/products/media-entertainment", result.candidate_links)

    def test_relative_urls_are_canonicalized_and_duplicates_use_best_context(self) -> None:
        html = """
        <main><a href='/reports/alpha?utm_source=menu'>A duplicate security research report</a>
        <section class='post-card'><h2><a href='https://example.test/reports/alpha'>Detailed Alpha campaign investigation report</a></h2></section>
        <section class='post-card'><h2><a href='../reports/bravo'>Detailed Bravo malware investigation report</a></h2></section></main>
        """
        result = self.detector.detect(html, "https://example.test/reports/", "Recent reports")
        self.assertEqual(result.candidate_links, (
            "https://example.test/reports/alpha", "https://example.test/reports/bravo",
        ))

    def test_insufficient_candidates_do_not_force_listing_classification(self) -> None:
        html = "<main><p>Short directory introduction.</p><a href='/reports/one'>One ordinary report link</a></main>"
        result = self.detector.detect(html, "https://example.test/reports/", "Short directory introduction.")
        self.assertEqual(result.page_type, "unknown")
        self.assertLessEqual(len(result.candidate_links), 1)

    def test_article_page_does_not_promote_utility_links(self) -> None:
        html = (FIXTURES / "article_page.html").read_text(encoding="utf-8")
        result = self.detector.detect(html, "https://example.test/advisory", "x" * 500)
        self.assertEqual(result.page_type, "article")
        self.assertEqual(result.candidate_links, ())

    def test_strong_structural_listing_cannot_be_overridden_by_dense_extracted_text(self) -> None:
        html = (FIXTURES / "dense_structural_listing.html").read_text(encoding="utf-8")
        result = self.detector.detect(html, "https://example.test/research/", "x" * 1800)
        self.assertEqual(result.page_type, "listing")
        self.assertTrue(result.signals["strong_structural_listing"])
        self.assertFalse(result.signals["article_metadata"])
        self.assertFalse(result.signals["semantic_article_container"])
        self.assertGreaterEqual(len(result.candidate_links), 4)
        self.assertEqual(result.signals["repeated_card_elements"], 0)

    def test_summary_large_image_is_not_independent_article_metadata(self) -> None:
        html = "<html><head><meta name='twitter:card' content='summary_large_image'></head><body><h1>Directory</h1></body></html>"
        result = self.detector.detect(html, "https://example.test/research/", "A short directory introduction.")
        self.assertFalse(result.signals["article_metadata"])
        self.assertEqual(result.page_type, "unknown")


if __name__ == "__main__":
    unittest.main()
