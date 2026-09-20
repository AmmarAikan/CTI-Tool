from __future__ import annotations

import unittest
from unittest.mock import MagicMock, Mock, patch

import requests

from backend.app.pipeline.ingestion.external.common.http_client import HttpClientSettings, ResponseTooLargeError
from backend.app.pipeline.ingestion.external.manual_source.safe_http_client import SSRFProtectedHttpClient, _PinnedHTTPAdapter
from backend.app.pipeline.ingestion.external.manual_source.url_policy import ManualURLPolicy, URLPolicyError


def resolver(_host, port):
    return [(2, 1, 6, "", ("93.184.216.34", port))]


def response(status=200, *, location=None, body=b"ok", content_type="text/html"):
    value = Mock()
    value.__enter__ = Mock(return_value=value); value.__exit__ = Mock(return_value=False)
    value.status_code = status; value.url = "https://example.test/article"
    value.headers = {"Content-Type": content_type}
    if location: value.headers["Location"] = location
    value.iter_content.return_value = [body]; value.raise_for_status.return_value = None
    return value


class ManualURLSecurityTests(unittest.TestCase):
    def test_rejects_credentials_local_and_every_non_public_ip_class(self):
        policy = ManualURLPolicy(resolver=resolver)
        with self.assertRaises(URLPolicyError): policy.validate("https://user:pass@example.test/")
        for address in ("127.0.0.1", "10.0.0.1", "169.254.1.1", "224.0.0.1", "0.0.0.0", "192.0.2.1"):
            blocked = ManualURLPolicy(resolver=lambda _h, port, ip=address: [(2, 1, 6, "", (ip, port))])
            with self.subTest(address=address), self.assertRaises(URLPolicyError): blocked.validate("https://example.test/")

    def test_onion_requires_explicit_approval_and_never_uses_public_client(self):
        url = "http://example-not-a-real-service.onion/advisories/one"
        with self.assertRaises(URLPolicyError): ManualURLPolicy(resolver=resolver).validate(url)
        approved = ManualURLPolicy(resolver=resolver, approved_onion=lambda value: value == url)
        self.assertTrue(approved.validate(url).is_onion)
        with self.assertRaises(URLPolicyError): approved.validate(url, allow_onion=False)

    def test_get_only_client_revalidates_redirects_and_strips_credentials(self):
        policy = ManualURLPolicy(resolver=resolver)
        with patch.object(requests.Session, "get", autospec=True, side_effect=[
            response(302, location="https://other.test/next"), response()
        ]) as fetch:
            client = SSRFProtectedHttpClient(policy, HttpClientSettings(max_redirects=2))
            result = client.get("https://example.test/start", headers={"Authorization": "secret", "Cookie": "secret", "Host": "private.test", "X-Test": "ok"})
        self.assertEqual(result.status_code, 200)
        self.assertEqual(fetch.call_count, 2)
        kwargs = fetch.call_args_list[0].kwargs
        self.assertFalse(kwargs["allow_redirects"]); self.assertTrue(kwargs["stream"])
        self.assertNotIn("Authorization", kwargs["headers"]); self.assertNotIn("Cookie", kwargs["headers"]); self.assertNotIn("Host", kwargs["headers"])
        self.assertEqual(kwargs["headers"]["X-Test"], "ok")

    def test_redirect_to_private_destination_is_rejected_before_second_request(self):
        def changing(host, port):
            address = "10.0.0.1" if host == "private.test" else "93.184.216.34"
            return [(2, 1, 6, "", (address, port))]
        with patch.object(requests.Session, "get", autospec=True, return_value=response(302, location="http://private.test/")) as fetch:
            with self.assertRaises(URLPolicyError):
                SSRFProtectedHttpClient(ManualURLPolicy(resolver=changing)).get("https://example.test/")
        self.assertEqual(fetch.call_count, 1)


    def test_policy_returns_deterministic_public_socket_addresses(self):
        def public_answers(_host, port):
            return [
                (10, 1, 6, "", ("2606:4700:4700::1111", port, 0, 0)),
                (2, 1, 6, "", ("1.1.1.1", port)),
                (2, 1, 6, "", ("1.1.1.1", port)),
            ]
        validated = ManualURLPolicy(resolver=public_answers).validate("https://example.test/")
        self.assertEqual(validated.approved_addresses, ("1.1.1.1", "2606:4700:4700::1111"))
        many = ManualURLPolicy(resolver=lambda _host, port: [
            (2, 1, 6, "", (f"1.1.1.{index}", port)) for index in range(1, 12)
        ]).validate("https://example.test/")
        self.assertEqual(len(many.approved_addresses), 8)
        def mixed_answers(_host, port):
            return public_answers(_host, port) + [(2, 1, 6, "", ("127.0.0.1", port))]
        with self.assertRaises(URLPolicyError):
            ManualURLPolicy(resolver=mixed_answers).validate("https://example.test/")

    def test_pinned_socket_tries_only_validated_ips_and_keeps_tls_origin(self):
        adapter = _PinnedHTTPAdapter(("1.1.1.1", "8.8.8.8"))
        for scheme in ("http", "https"):
            with self.subTest(scheme=scheme):
                pool = adapter.poolmanager.connection_from_url(f"{scheme}://example.test/report")
                connection = pool.ConnectionCls("example.test", 443 if scheme == "https" else 80)
                self.assertEqual(connection.host, "example.test")
                socket = object()
                with patch(
                    "backend.app.pipeline.ingestion.external.manual_source.safe_http_client.connection.connection.create_connection",
                    side_effect=[OSError("first address unavailable"), socket],
                ) as dial:
                    self.assertIs(connection._new_conn(), socket)
                self.assertEqual(
                    [call.args[0][0] for call in dial.call_args_list],
                    ["1.1.1.1", "8.8.8.8"],
                )
                self.assertTrue(all(call.args[0][0] != "example.test" for call in dial.call_args_list))
        adapter.close()

    def test_https_pinning_preserves_sni_and_certificate_hostname(self):
        adapter = _PinnedHTTPAdapter(("1.1.1.1",))
        pool = adapter.poolmanager.connection_from_url("https://example.test/report")
        connection = pool.ConnectionCls("example.test", 443, cert_reqs="CERT_REQUIRED")
        wrapped = MagicMock()
        wrapped.socket.selected_alpn_protocol.return_value = "http/1.1"
        wrapped.__iter__.return_value = iter((wrapped.socket, True))
        with patch(
            "backend.app.pipeline.ingestion.external.manual_source.safe_http_client.connection.connection.create_connection",
            return_value=Mock(),
        ), patch("urllib3.connection._ssl_wrap_socket_and_match_hostname", return_value=wrapped) as tls:
            connection.connect()
        self.assertEqual(tls.call_args.kwargs["server_hostname"], "example.test")
        self.assertEqual(tls.call_args.kwargs["cert_reqs"], "CERT_REQUIRED")
        adapter.close()

    def test_pinned_fetch_retains_proxy_and_size_bounds(self):
        policy = ManualURLPolicy(resolver=resolver)
        recorded = []
        def fake_get(session, url, **kwargs):
            recorded.append((session.trust_env, kwargs["timeout"], session.get_adapter(url).max_retries.total))
            return response(body=b"too-large")
        with patch.object(requests.Session, "get", autospec=True, side_effect=fake_get):
            with self.assertRaises(ResponseTooLargeError):
                SSRFProtectedHttpClient(
                    policy, HttpClientSettings(max_response_bytes=4, connect_timeout_seconds=2, read_timeout_seconds=3)
                ).get("https://example.test/")
        self.assertEqual(recorded, [(False, (2, 3), 0)])

    def test_each_redirect_uses_a_fresh_pinned_adapter(self):
        def changing(host, port):
            address = "1.1.1.1" if host == "example.test" else "8.8.8.8"
            return [(2, 1, 6, "", (address, port))]
        observed = []
        def fake_get(session, url, **kwargs):
            adapter = session.get_adapter(url)
            pool = adapter.poolmanager.connection_from_url(url)
            observed.append((url, pool.ConnectionCls._approved_addresses, kwargs["allow_redirects"]))
            return response(302, location="https://other.test/next") if len(observed) == 1 else response()
        with patch.object(requests.Session, "get", autospec=True, side_effect=fake_get):
            result = SSRFProtectedHttpClient(ManualURLPolicy(resolver=changing)).get("https://example.test/start")
        self.assertEqual(result.status_code, 200)
        self.assertEqual(observed, [
            ("https://example.test/start", ("1.1.1.1",), False),
            ("https://other.test/next", ("8.8.8.8",), False),
        ])

if __name__ == "__main__": unittest.main()
