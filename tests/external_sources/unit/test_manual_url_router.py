from __future__ import annotations

import unittest

from backend.app.pipeline.ingestion.external.application.collection_service import RegisteredSource
from backend.app.pipeline.ingestion.external.manual_source.url_policy import ManualURLPolicy, URLPolicyError
from backend.app.pipeline.ingestion.external.manual_source.url_router import ManualURLRouter


PUBLIC = lambda _host, port: [(2, 1, 6, "", ("93.184.216.34", port))]
PRIVATE = lambda _host, port: [(2, 1, 6, "", ("127.0.0.1", port))]


class ManualURLRouterTests(unittest.TestCase):
    def setUp(self) -> None:
        registry = {
            "nvd-cve-api": RegisteredSource("nvd-cve-api", "vulnerability", True, {"type": "nvd", "base_url": "https://services.nvd.nist.gov/rest/json/cves/2.0"}),
            "cve-program-records": RegisteredSource("cve-program-records", "vulnerability", True, {"type": "cve", "base_url": "https://cveawg.mitre.org/api/cve"}),
            "github-global-advisories": RegisteredSource("github-global-advisories", "vulnerability", True, {"type": "github_advisories", "base_url": "https://api.github.com/advisories"}),
            "the-hacker-news": RegisteredSource("the-hacker-news", "rss", True, {"url": "https://feeds.feedburner.com/TheHackersNews"}),
            "bleepingcomputer": RegisteredSource("bleepingcomputer", "rss", True, {"url": "https://www.bleepingcomputer.com/feed/"}),
            "cert-eu-advisories": RegisteredSource("cert-eu-advisories", "cert", True, {"method": "rss", "url": "https://cert.europa.eu/publications/security-advisories-rss"}),
            "cisa-advisories": RegisteredSource("cisa-advisories", "cert", True, {"method": "official_listing", "url": "https://www.cisa.gov/news-events/cybersecurity-advisories"}),
            "cisa-kev": RegisteredSource("cisa-kev", "vulnerability", True, {"type": "cisa_kev", "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"}),
            "telegram-thehackernews": RegisteredSource("telegram-thehackernews", "telegram", True, {"channel": "thehackernews"}),
            "reddit-netsec": RegisteredSource("reddit-netsec", "reddit", False, {"url": "https://www.reddit.com/r/netsec/"}),
        }
        self.router = ManualURLRouter(registry)

    def assert_route(self, url: str, kind: str, source_id: str | None = None) -> None:
        route = self.router.route(url)
        self.assertEqual((route.kind, route.source_id), (kind, source_id))

    def test_every_explicit_route_type_and_matched_source_ids(self):
        self.assert_route("http://approved-source.onion/CVE-2026-1234", "dark_web")
        self.assert_route("https://nvd.nist.gov/vuln/detail/CVE-2026-1234", "vulnerability", "nvd-cve-api")
        self.assert_route("https://cve.mitre.org/cgi-bin/cvename.cgi/CVE-2026-1234", "vulnerability", "cve-program-records")
        self.assert_route("https://github.com/advisories/GHSA-2345-6789-CFGH", "github_advisory", "github-global-advisories")
        self.assert_route("https://github.com/example/project/releases/tag/v1", "github_public")
        self.assert_route("https://feeds.feedburner.com/TheHackersNews", "rss", "the-hacker-news")
        self.assert_route("https://cert.europa.eu/publications/security-advisories-rss", "rss", "cert-eu-advisories")
        self.assert_route("https://www.cisa.gov/news-events/cybersecurity-advisories/example-advisory", "cert", "cisa-advisories")
        self.assert_route("https://t.me/s/thehackernews", "telegram", "telegram-thehackernews")
        self.assert_route("https://www.reddit.com/r/netsec/", "reddit", "reddit-netsec")
        self.assert_route("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "registered_source", "cisa-kev")
        self.assert_route("https://example.test/security-article", "generic_web")

    def test_precedence_is_stable(self):
        self.assertEqual(self.router.route("http://hidden.onion/github.com/CVE-2026-1234/feed").kind, "dark_web")
        self.assertEqual(self.router.route("https://nvd.nist.gov/feed/CVE-2026-1234").kind, "vulnerability")
        self.assertEqual(self.router.route("https://github.com/example/feed").kind, "github_public")
        self.assertEqual(self.router.route("https://t.me/feed/channel").kind, "rss")

    def test_canonical_equivalence_and_non_substring_feed_detection(self):
        route = self.router.route("https://WWW.BLEEPINGCOMPUTER.COM:443/feed?utm_source=test")
        self.assertEqual((route.kind, route.source_id), ("rss", "bleepingcomputer"))
        self.assertEqual(self.router.route("https://example.test/newsfeed/archive").kind, "generic_web")
        self.assertEqual(self.router.route("https://example.test/security.atom").kind, "rss")
        self.assertEqual(self.router.route("https://example.test/updates", detected_feed=True).kind, "rss")

    def test_unconfigured_structured_hosts_are_explicit_without_false_registration(self):
        self.assert_route("https://t.me/s/not-configured-channel", "telegram")
        self.assert_route("https://www.reddit.com/r/notconfigured/comments/abc/report", "reddit")

    def test_unsafe_urls_are_rejected_before_routing(self):
        policy = ManualURLPolicy(resolver=PUBLIC)
        with self.assertRaises(URLPolicyError): policy.validate("https://user:password@example.test/report")
        with self.assertRaises(URLPolicyError): ManualURLPolicy(resolver=PRIVATE).validate("https://example.test/report")
        with self.assertRaises(URLPolicyError): policy.validate("http://unapproved.onion/report")


if __name__ == "__main__":
    unittest.main()
