from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock

import requests
from jsonschema import Draft202012Validator

from backend.app.pipeline.ingestion.external.classification.classification_service import ClassifiedItemResult
from backend.app.pipeline.ingestion.external.common.models import ExternalClassification
from backend.app.pipeline.ingestion.external.dark_web_connector import (
    DarkWebConfigurationError, DarkWebConnector, DarkWebRequestError, DarkWebSource,
    TorHttpClient, TorProxy, TorResponse, load_dark_web_config,
)


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
FAKE_HOST = "a" * 56 + ".onion"
BASE_URL = f"http://{FAKE_HOST}/advisories/"


def source(**changes):
    values = dict(source_id="curated-test", name="Sanitized source", url=BASE_URL,
                  allowed_paths=("/advisories/",), enabled=True, max_items=10,
                  rate_limit_seconds=0, trusted_curated=True)
    values.update(changes)
    return DarkWebSource(**values)


def response(status: int, body: bytes = b"", *, headers=None):
    result = Mock()
    result.status_code = status
    result.headers = headers or {"Content-Type": "text/html; charset=utf-8"}
    result.iter_content.return_value = [body]
    return result


class TorPolicyTests(unittest.TestCase):
    def test_local_config_requires_explicit_proxy_and_enforces_policy(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "dark_web_sources.local.json"
            path.write_text(json.dumps({"schema_version": "1.0", "proxy": {"host": "127.0.0.1", "port": 9999},
                "sources": [{"id": "curated-test", "name": "Test", "url": BASE_URL, "enabled": True,
                             "allowed_paths": ["/advisories/"], "max_items": 2}]}), encoding="utf-8")
            proxy, sources = load_dark_web_config(path, environ={})
        self.assertEqual(proxy.port, 9999)
        self.assertTrue(sources[0].allows(BASE_URL + "one"))
        self.assertFalse(sources[0].allows(f"http://{FAKE_HOST}/outside/one"))
        self.assertFalse(sources[0].allows("https://public.example/report"))

    def test_missing_proxy_has_no_assumed_default_port(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "local.json"
            path.write_text('{"schema_version":"1.0","sources":[]}', encoding="utf-8")
            with self.assertRaises(DarkWebConfigurationError):
                load_dark_web_config(path, environ={})

    def test_environment_explicitly_overrides_local_proxy(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "dark_web_sources.local.json"
            path.write_text(json.dumps({"schema_version": "1.0", "proxy": {"host": "127.0.0.1", "port": 9999},
                "sources": [{"id": "curated-test", "name": "Test", "url": BASE_URL, "enabled": False,
                             "allowed_paths": ["/advisories/"]}]}), encoding="utf-8")
            proxy, _ = load_dark_web_config(path, environ={"TOR_PROXY_HOST": "192.0.2.1", "TOR_PROXY_PORT": "9150"})
        self.assertEqual(proxy, TorProxy("192.0.2.1", 9150))

    def test_enabled_invalid_v3_source_fails_with_source_id_only(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "dark_web_sources.local.json"
            sensitive_host = "c" * 55 + ".onion"
            path.write_text(json.dumps({"schema_version": "1.0", "proxy": {"host": "127.0.0.1", "port": 9999},
                "sources": [{"id": "invalid-length-test", "name": "Test",
                             "url": f"http://{sensitive_host}/advisories/", "enabled": True,
                             "allowed_paths": ["/advisories/"]}]}), encoding="utf-8")
            with self.assertRaises(DarkWebConfigurationError) as raised:
                load_dark_web_config(path, environ={})
        message = str(raised.exception)
        self.assertEqual(message, "invalid dark-web source source_id=invalid-length-test reason=invalid_v3_onion_length")
        self.assertNotIn(".onion", message); self.assertNotIn("c" * 20, message)

    def test_invalid_disabled_placeholder_does_not_block_startup(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "dark_web_sources.local.json"
            path.write_text(json.dumps({"schema_version": "1.0", "proxy": {"host": "127.0.0.1", "port": 9999},
                "sources": [{"id": "disabled-placeholder", "name": "Disabled", "url": "http://placeholder.onion/",
                             "enabled": False, "allowed_paths": ["/"]}]}), encoding="utf-8")
            _proxy, sources = load_dark_web_config(path, environ={})
        self.assertEqual(sources, ())

    def test_client_uses_socks5h_and_manual_safe_redirects(self):
        session = Mock(spec=requests.Session)
        session.get.side_effect = [
            response(302, headers={"Location": "/advisories/one", "Content-Type": "text/html"}),
            response(200, b"<html>ok</html>"),
        ]
        client = TorHttpClient(TorProxy("127.0.0.1", 9999), session=session, retries=0)
        result = client.get(source(), BASE_URL)
        self.assertEqual(result.status_code, 200)
        kwargs = session.get.call_args_list[0].kwargs
        self.assertEqual(session.method_calls[0][0], "get")
        self.assertEqual(kwargs["proxies"]["http"], "socks5h://127.0.0.1:9999")
        self.assertFalse(kwargs["allow_redirects"])

    def test_redirect_outside_policy_and_non_html_are_blocked(self):
        session = Mock(spec=requests.Session)
        session.get.return_value = response(302, headers={"Location": "https://public.example/", "Content-Type": "text/html"})
        client = TorHttpClient(TorProxy("127.0.0.1", 9999), session=session, retries=0)
        with self.assertRaises(DarkWebRequestError): client.get(source(), BASE_URL)
        session.get.return_value = response(200, b"binary", headers={"Content-Type": "application/octet-stream"})
        with self.assertRaises(DarkWebRequestError): client.get(source(), BASE_URL)

    def test_response_size_is_bounded(self):
        session = Mock(spec=requests.Session)
        session.get.return_value = response(200, b"12345")
        client = TorHttpClient(TorProxy("127.0.0.1", 9999), session=session, retries=0, max_response_bytes=4)
        with self.assertRaises(DarkWebRequestError): client.get(source(), BASE_URL)


class FakeClient:
    def __init__(self, pages, available=True): self.pages, self.available, self.calls, self.requests = pages, available, [], []
    def tor_available(self): return self.available
    def get(self, source, url, **kwargs):
        self.calls.append(url)
        self.requests.append((url, kwargs))
        value = self.pages[url]
        if isinstance(value, Exception): raise value
        return TorResponse(200, value.encode(), "text/html", '"test"', "Wed, 01 Jan 2025 00:00:00 GMT")


class DarkWebConnectorTests(unittest.TestCase):
    def setUp(self):
        self.listing = (FIXTURES / "dark_web_listing.html").read_text(encoding="utf-8")
        self.article = (FIXTURES / "dark_web_article.html").read_text(encoding="utf-8")
        self.clock = lambda: datetime(2026, 8, 23, tzinfo=timezone.utc)

    def test_listing_is_one_level_bounded_and_each_child_has_state(self):
        pages = {BASE_URL: self.listing, BASE_URL + "one": self.article, BASE_URL + "two": self.article.replace("phishing", "malware")}
        client, state = FakeClient(pages), {"schema_version": "1.0", "sources": {}, "urls": {}, "items": {}, "runs": {}}
        result = DarkWebConnector([source()], client, state=state, clock=self.clock, sleeper=lambda _: None).collect_result()
        self.assertEqual(len(result.accepted_items), 2)
        self.assertEqual(client.calls, [BASE_URL, BASE_URL + "one", BASE_URL + "two"])
        self.assertEqual(len(state["urls"]), 3)
        self.assertEqual(len(state["items"]), 2)
        self.assertIn("privacy_output_hash", next(iter(state["items"].values())))
        self.assertEqual(set(next(iter(state["items"].values()))["stages"]), {"extraction", "cleaning", "privacy", "classification"})
        self.assertEqual(next(iter(state["items"].values()))["stages"]["privacy"]["status"], "reviewed")
        self.assertEqual(result.accepted_items[0].classification.status, "not_required")
        schema = json.loads((Path(__file__).resolve().parents[3] / "contracts" / "external_cti_item.schema.json").read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(result.accepted_items[0].to_dict())

    def test_unchanged_hashes_are_skipped_incrementally(self):
        client, state = FakeClient({BASE_URL: self.article}), {"schema_version": "1.0", "sources": {}, "urls": {}, "items": {}, "runs": {}}
        connector = DarkWebConnector([source()], client, state=state, clock=self.clock)
        self.assertEqual(len(connector.collect_result().accepted_items), 1)
        second = connector.collect_result()
        self.assertEqual(second.skipped_items, 1)
        self.assertEqual(second.accepted_items, [])

    def test_force_reprocesses_unchanged_hash_without_changing_identity_or_collected_at(self):
        client, state = FakeClient({BASE_URL: self.article}), {"schema_version": "1.0", "sources": {}, "urls": {}, "items": {}, "runs": {}}
        connector = DarkWebConnector([source()], client, state=state, clock=self.clock)
        first = connector.collect_result().accepted_items[0]
        state["items"][first.record_id].pop("collected_at")  # legacy checkpoint compatibility
        forced = connector.collect_result(force=True)
        self.assertEqual((forced.skipped_items, len(forced.accepted_items)), (0, 1))
        again = forced.accepted_items[0]
        self.assertEqual((again.record_id, again.collected_at), (first.record_id, first.collected_at))
        self.assertIsNone(client.requests[-1][1]["etag"])
        self.assertIsNone(client.requests[-1][1]["last_modified"])
        item_state = state["items"][first.record_id]
        self.assertEqual(item_state["collected_at"], first.collected_at)
        self.assertIn("external_privacy_filter_v2", item_state["stages"]["privacy"]["version"])
        self.assertIn("external_text_preprocessor_v2", item_state["stages"]["cleaning"]["version"])

    def test_classification_error_routes_general_source_to_review(self):
        service = Mock()
        def classify(item):
            changed = item.__class__(**{**item.to_dict(), "tags": tuple(item.tags), "classification": ExternalClassification(status="error")})
            return ClassifiedItemResult(changed, "review", None, "prediction_failed")
        service.classify_item.side_effect = classify
        result = DarkWebConnector([source(trusted_curated=False)], FakeClient({BASE_URL: self.article}),
                                  classification_service=service, clock=self.clock).collect_result()
        self.assertEqual(len(result.review_items), 1)

    def test_tor_unavailable_affects_only_dark_web_phase(self):
        result = DarkWebConnector([source()], FakeClient({}, available=False), clock=self.clock).collect_result()
        self.assertEqual(result.status, "unavailable")
        self.assertEqual(result.errors, ["tor_proxy_unavailable"])

    def test_source_and_item_failures_are_redacted_and_isolated(self):
        broken = source(source_id="broken", url=f"http://{FAKE_HOST}/advisories/broken")
        good = source(source_id="good")
        client = FakeClient({broken.url: RuntimeError("secret"), BASE_URL: self.article})
        result = DarkWebConnector([broken, good], client, clock=self.clock).collect_result(check_proxy=False)
        self.assertEqual(len(result.accepted_items), 1)
        self.assertEqual(result.errors, ["broken:source_failed"])
        self.assertNotIn(FAKE_HOST, repr(result.errors))


if __name__ == "__main__":
    unittest.main()
