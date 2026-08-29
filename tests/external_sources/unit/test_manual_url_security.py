from __future__ import annotations

import unittest
from unittest.mock import Mock

import requests

from backend.app.pipeline.ingestion.external.common.http_client import HttpClientSettings
from backend.app.pipeline.ingestion.external.manual_source.safe_http_client import SSRFProtectedHttpClient
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
        session = Mock(spec=requests.Session)
        session.get.side_effect = [response(302, location="https://other.test/next"), response()]
        client = SSRFProtectedHttpClient(policy, HttpClientSettings(max_redirects=2), session)
        result = client.get("https://example.test/start", headers={"Authorization": "secret", "Cookie": "secret", "X-Test": "ok"})
        self.assertEqual(result.status_code, 200)
        self.assertEqual(session.get.call_count, 2)
        kwargs = session.get.call_args_list[0].kwargs
        self.assertFalse(kwargs["allow_redirects"]); self.assertTrue(kwargs["stream"])
        self.assertNotIn("Authorization", kwargs["headers"]); self.assertNotIn("Cookie", kwargs["headers"])
        self.assertEqual(kwargs["headers"]["X-Test"], "ok")

    def test_redirect_to_private_destination_is_rejected_before_second_request(self):
        def changing(host, port):
            address = "10.0.0.1" if host == "private.test" else "93.184.216.34"
            return [(2, 1, 6, "", (address, port))]
        session = Mock(spec=requests.Session); session.get.return_value = response(302, location="http://private.test/")
        with self.assertRaises(URLPolicyError): SSRFProtectedHttpClient(ManualURLPolicy(resolver=changing), session=session).get("https://example.test/")
        self.assertEqual(session.get.call_count, 1)


if __name__ == "__main__": unittest.main()
