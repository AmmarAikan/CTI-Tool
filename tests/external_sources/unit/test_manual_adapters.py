from __future__ import annotations

import unittest
from types import SimpleNamespace

from backend.app.pipeline.ingestion.external.application.collection_service import RegisteredSource
from backend.app.pipeline.ingestion.external.common.hashing import sha256_text
from backend.app.pipeline.ingestion.external.common.models import ExternalCTIItem, ExternalClassification
from backend.app.pipeline.ingestion.external.dark_web_connector import DarkWebSource
from backend.app.pipeline.ingestion.external.manual_source.adapters import (
    DarkWebManualAdapter, RegisteredConnectorManualAdapter, UnsupportedManualAdapter,
)


def item(identity="structured-1") -> ExternalCTIItem:
    content = "A sanitized structured cybersecurity advisory with detection and remediation guidance."
    return ExternalCTIItem(record_id="adapter-" + sha256_text(identity).split(":", 1)[1][:32], source_item_id=identity,
        source="Structured Source", source_type="rss", category="cti", title="Structured advisory",
        link="https://example.test/advisory", content=content, summary=content, collected_at="2026-08-25T12:00:00Z",
        content_hash=sha256_text(content), classification=ExternalClassification(status="not_required"))


class StubConnector:
    def __init__(self, result=None, error=None): self.result, self.error, self.identifiers = result, error, []
    def collect_result(self):
        if self.error: raise self.error
        return self.result
    def collect_identifier(self, source, identifier):
        self.identifiers.append((source.source_id, identifier))
        if self.error: raise self.error
        return self.result


class ManualAdapterTests(unittest.TestCase):
    def source(self, source_id="feed-one", source_type="rss", enabled=True, **configuration):
        raw = {"source_id": source_id, "name": source_id, "enabled": enabled, **configuration}
        return RegisteredSource(source_id, source_type, enabled, raw)

    def test_successful_and_unchanged_registered_connector_results(self):
        source = self.source(url="https://example.test/feed.xml", category="news")
        success = SimpleNamespace(status="completed", accepted_items=[item()], review_items=[], errors=[], skipped_items=0)
        adapter = RegisteredConnectorManualAdapter({source.source_id: source}, "rss", lambda _source, _state: StubConnector(success))
        result = adapter.collect_url(source.configuration["url"], identifier=None, source_id=source.source_id, state={})
        self.assertEqual((result.status, result.items), ("stored", (item(),)))

        unchanged = SimpleNamespace(status="unchanged", accepted_items=[], review_items=[], errors=[], skipped_items=1)
        adapter = RegisteredConnectorManualAdapter({source.source_id: source}, "rss", lambda _source, _state: StubConnector(unchanged))
        self.assertEqual(adapter.collect_url(source.configuration["url"], identifier=None, source_id=source.source_id, state={}).status, "unchanged")

    def test_missing_reddit_credentials_fail_closed(self):
        source = self.source("reddit-one", "reddit", subreddit="netsec", limit=10)
        failed = SimpleNamespace(status="failed", accepted_items=[], review_items=[], rejected_items=[],
                                 errors=[SimpleNamespace(category="credentials_missing")], skipped_items=0)
        adapter = RegisteredConnectorManualAdapter({source.source_id: source}, "reddit", lambda _source, _state: StubConnector(failed))
        result = adapter.collect_url("https://www.reddit.com/r/netsec/", identifier=None, source_id=source.source_id, state={})
        self.assertEqual((result.status, result.message), ("ignored", "credentials are not configured"))

    def test_connector_exception_is_safe_error(self):
        source = self.source(url="https://example.test/feed.xml", category="news")
        adapter = RegisteredConnectorManualAdapter({source.source_id: source}, "rss",
            lambda _source, _state: StubConnector(error=RuntimeError("token=must-not-escape")))
        result = adapter.collect_url(source.configuration["url"], identifier=None, source_id=source.source_id, state={})
        self.assertEqual(result.status, "error"); self.assertNotIn("must-not-escape", result.message)

    def test_specific_identifier_uses_bounded_vulnerability_method(self):
        source = self.source("nvd", "vulnerability", type="nvd", base_url="https://services.nvd.nist.gov/rest/json/cves/2.0",
                             results_per_page=10, max_pages=1, lookback_days=1)
        connector = StubConnector(SimpleNamespace(status="completed", accepted_items=[item("CVE-2026-1234")], review_items=[], errors=[], skipped_items=0))
        adapter = RegisteredConnectorManualAdapter({source.source_id: source}, "vulnerability", lambda _source, _state: connector)
        result = adapter.collect_url("https://nvd.nist.gov/vuln/detail/CVE-2026-1234", identifier="CVE-2026-1234",
                                     source_id=source.source_id, state={})
        self.assertEqual(result.status, "stored")
        self.assertEqual(connector.identifiers, [("nvd", "CVE-2026-1234")])

    def test_specific_cert_item_and_public_github_are_explicitly_unsupported(self):
        source = self.source("cert-one", "cert", method="official_listing", url="https://cert.example.test/advisories",
                             detail_path_pattern="^/advisories/[a-z-]+$")
        called = []
        adapter = RegisteredConnectorManualAdapter({source.source_id: source}, "cert", lambda *_args: called.append(True))
        result = adapter.collect_url("https://cert.example.test/advisories/item-one", identifier=None,
                                     source_id=source.source_id, state={})
        self.assertEqual(result.status, "ignored"); self.assertEqual(called, [])
        github = UnsupportedManualAdapter("public GitHub").collect_url("https://github.com/org/repo", identifier=None, source_id=None, state={})
        self.assertEqual(github.status, "ignored"); self.assertIn("not safely supported", github.message)

    def test_unavailable_tor_is_isolated(self):
        source = DarkWebSource("dark-one", "Dark One", "http://exampleplaceholder.onion/advisories/",
                               ("/advisories/",), True)
        connector = StubConnector(SimpleNamespace(status="unavailable", accepted_items=[], review_items=[], rejected_items=[],
                                                   errors=["tor_proxy_unavailable"], skipped_items=0))
        connector.state = {}
        connector.collect_url = lambda _source, _url: connector.result
        adapter = DarkWebManualAdapter((source,), connector)
        result = adapter.collect_url(source.url, identifier=None, source_id=None, state={"sources": {}, "urls": {}, "items": {}})
        self.assertEqual((result.status, result.message), ("ignored", "structured source is unavailable"))


if __name__ == "__main__":
    unittest.main()
