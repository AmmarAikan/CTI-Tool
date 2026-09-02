from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from dataclasses import replace
from unittest.mock import patch

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
GATEWAY_PATH = ROOT / "infra" / "vps" / "gateway" / "app.py"

for key in (
    "FEED_PUBLISH_TOKEN", "FEED_READ_TOKEN", "FEED_RESPONSE_HMAC_SECRET",
    "SENSOR_READ_TOKEN", "SENSOR_RESPONSE_HMAC_SECRET", "CURSOR_HMAC_SECRET", "JWT_SECRET",
):
    os.environ.setdefault(key, f"test-{key.lower()}-0123456789abcdef")

spec = importlib.util.spec_from_file_location("cti_gateway_external_proxy_test", GATEWAY_PATH)
gateway = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = gateway
assert spec.loader
spec.loader.exec_module(gateway)


def token(role: str, secret: str) -> str:
    def encode(value: dict[str, object]) -> str:
        return base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode()).decode().rstrip("=")

    header = encode({"alg": "HS256", "typ": "JWT"})
    payload = encode({"sub": f"{role}-user", "role": role, "exp": 4102444800})
    signing_input = f"{header}.{payload}"
    signature = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    encoded_signature = base64.urlsafe_b64encode(signature).decode().rstrip("=")
    return f"{signing_input}.{encoded_signature}"


class FakeResponse:
    def __init__(self, status: int, payload: object):
        self.status = status
        self.payload = payload

    def read(self, limit: int = -1) -> bytes:
        value = json.dumps(self.payload).encode()
        return value[:limit] if limit >= 0 else value

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class FakeOpener:
    def __init__(self, response):
        self.response = response

    def open(self, request, timeout):
        self.request = request
        self.timeout = timeout
        return self.response


class GatewayExternalProxyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.jwt_secret = "jwt-secret-for-gateway-tests-0123456789"
        self.service_token = "external-service-token-0123456789"
        self.settings = gateway.GatewaySettings(
            feed_publish_token="publish-token-0123456789abcdef",
            feed_read_token="read-token-0123456789abcdefghi",
            feed_hmac_secret="feed-hmac-0123456789abcdefghij",
            sensor_read_token="sensor-token-0123456789abcdef",
            sensor_hmac_secret="sensor-hmac-0123456789abcdefg",
            cursor_secret="cursor-secret-0123456789abcdefg",
            data_dir=self.root / "data",
            dionaea_path=self.root / "dionaea.json",
            host_auth_path=self.root / "host_auth.jsonl",
            external_control_api_url="http://external-sources:8000/api/v1/external-sources",
            external_control_api_token=self.service_token,
            jwt_secret=self.jwt_secret,
            external_control_timeout_seconds=1,
            external_control_max_bytes=4096,
        )
        self.client = TestClient(gateway.create_app(self.settings))
        self.headers = {"Authorization": f"Bearer {token('analyst', self.jwt_secret)}"}

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def upstream(self, status: int = 200, payload: object | None = None):
        return patch(
            "urllib.request.build_opener",
            return_value=FakeOpener(FakeResponse(status, payload if payload is not None else {"status": "ok"})),
        )

    def test_unauthenticated_and_unauthorized_control_are_rejected(self) -> None:
        self.assertEqual(self.client.get("/api/v1/external-sources/sources").status_code, 401)
        viewer = {"Authorization": f"Bearer {token('viewer', self.jwt_secret)}"}
        response = self.client.post("/api/v1/external-sources/jobs", headers=viewer, json={})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["code"], "authorization_denied")

    def test_read_forwards_service_token_and_redacts_sensitive_values(self) -> None:
        payload = [{"source_id": "dark", "name": "Dark", "source_type": "dark_web", "status": "enabled",
                "metadata": {"url": "http://" + "a" * 56 + ".onion/x", "token": self.service_token}}]
        with self.upstream(payload=payload) as upstream:
            response = self.client.get("/api/v1/external-sources/sources", headers=self.headers)
        request = upstream.return_value.request
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(".onion", response.text)
        self.assertNotIn(self.service_token, response.text)
        self.assertEqual(request.headers["Authorization"], f"Bearer {self.service_token}")

    def test_control_forwards_only_allowlisted_body_and_never_user_token(self) -> None:
        job = {"schema_version": "1.0", "job_id": "job-1234567890", "command_id": "cmd-1234567890", "state": "queued",
               "created_at": "2026-09-02T00:00:00Z", "updated_at": "2026-09-02T00:00:00Z", "progress": {}, "result": None, "error": None}
        with self.upstream(payload=job) as upstream:
            response = self.client.post(
                "/api/v1/external-sources/jobs",
                headers={**self.headers, "Idempotency-Key": "ignored"},
                json={"scope": "all_enabled", "force": True},
            )
        request = upstream.return_value.request
        self.assertEqual(response.status_code, 202)
        self.assertEqual(json.loads(request.data), {"scope": "all_enabled", "force": True})
        self.assertNotIn(self.headers["Authorization"].split()[-1], request.headers["Authorization"])
        self.assertEqual(request.headers["Authorization"], f"Bearer {self.service_token}")

    def test_allowlist_rejects_arbitrary_paths_and_urls_without_upstream_call(self) -> None:
        with patch("urllib.request.urlopen") as upstream:
            path = self.client.get("/api/v1/external-sources/../secrets", headers=self.headers)
            url = self.client.post(
                "/api/v1/external-sources/manual-sources",
                headers=self.headers,
                json={"url": "ftp://example.test/secret"},
            )
        self.assertIn(path.status_code, {404, 422})
        self.assertEqual(url.status_code, 422)
        upstream.assert_not_called()

    def test_upstream_errors_are_stable_and_bounded(self) -> None:
        for upstream_status, expected_status in ((401, 401), (404, 404), (422, 422), (500, 502)):
            with self.subTest(upstream_status=upstream_status), self.upstream(upstream_status, {"detail": "token=" + self.service_token}):
                response = self.client.get("/api/v1/external-sources/sources", headers=self.headers)
            self.assertEqual(response.status_code, expected_status)
            self.assertEqual(set(response.json()), {"schema_version", "code", "message", "retryable", "details"})
            self.assertNotIn(self.service_token, response.text)

    def test_existing_gateway_health_route_remains_unchanged(self) -> None:
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["service"], "cti-vps-gateway")

    def test_cancel_manual_and_recheck_forward_fixed_upstream_paths(self) -> None:
        job = {"schema_version": "1.0", "job_id": "job-1234567890", "command_id": "cmd-1234567890", "state": "queued",
               "created_at": "2026-09-02T00:00:00Z", "updated_at": "2026-09-02T00:00:00Z", "progress": {}, "result": None, "error": None}
        calls = []

        def fake_urlopen(request, timeout):
            calls.append((request.full_url, request.method, json.loads(request.data) if request.data else None, timeout))
            return FakeResponse(200, job)

        with patch("urllib.request.build_opener", side_effect=lambda *_args: type("Opener", (), {"open": lambda _self, request, timeout: fake_urlopen(request, timeout)})()):
            cancelled = self.client.post("/api/v1/external-sources/jobs/job-1234567890/cancel", headers=self.headers)
            manual = self.client.post("/api/v1/external-sources/manual-sources", headers=self.headers,
                                      json={"url": "https://example.test/report"})
            rechecked = self.client.post("/api/v1/external-sources/manual-sources/recheck", headers=self.headers,
                                         json={"url": "https://example.test/report", "force": False})

        self.assertEqual((cancelled.status_code, manual.status_code, rechecked.status_code), (200, 202, 202))
        self.assertEqual([call[0].rsplit("/external-sources", 1)[-1] for call in calls],
                         ["/jobs/job-1234567890/cancel", "/manual-sources", "/manual-sources/recheck"])
        self.assertEqual(calls[1][2], {"url": "https://example.test/report", "force": False})
        self.assertEqual(calls[2][2], {"url": "https://example.test/report", "force": True})
        self.assertTrue(all(call[3] == 1 for call in calls))

    def test_timeout_is_stable_and_token_is_absent_from_gateway_log(self) -> None:
        def timeout(*_args, **_kwargs):
            raise TimeoutError("service token=" + self.service_token)

        with patch("urllib.request.build_opener", side_effect=lambda *_args: type("Opener", (), {"open": timeout})()):
            response = self.client.get("/api/v1/external-sources/sources", headers=self.headers)
        self.assertEqual(response.status_code, 504)
        self.assertNotIn(self.service_token, response.text)
        log_path = self.root / "data" / "web_access.jsonl"
        self.assertTrue(log_path.exists())
        self.assertNotIn(self.service_token, log_path.read_text(encoding="utf-8"))

    def test_startup_requires_jwt_secret(self) -> None:
        environment = {key: "x" * 32 for key in (
            "FEED_PUBLISH_TOKEN", "FEED_READ_TOKEN", "FEED_RESPONSE_HMAC_SECRET",
            "SENSOR_READ_TOKEN", "SENSOR_RESPONSE_HMAC_SECRET", "CURSOR_HMAC_SECRET",
        )}
        environment["JWT_SECRET"] = ""
        with patch.dict(os.environ, environment, clear=True):
            with self.assertRaisesRegex(RuntimeError, "JWT_SECRET"):
                gateway.GatewaySettings.from_env()

    def test_stream_reader_rejects_deceptive_chunked_body_and_accepts_bounded_json(self) -> None:
        class ChunkedRequest:
            headers = {}

            async def stream(self):
                yield b'{"force": '
                yield b"true" + b" " * (64 * 1024)

        with self.assertRaises(gateway.ExternalGatewayError) as failure:
            asyncio.run(gateway._bounded_json_request(ChunkedRequest()))
        self.assertEqual(failure.exception.status_code, 413)

        class ValidRequest:
            headers = {"content-length": "16"}

            async def stream(self):
                yield b'{"force": true}'

        self.assertEqual(asyncio.run(gateway._bounded_json_request(ValidRequest())), {"force": True})

    def test_destination_allowlist_rejects_host_port_credentials_query_fragment_and_traversal(self) -> None:
        for destination in (
            "http://other-service:8000/api/v1/external-sources",
            "http://external-sources:9000/api/v1/external-sources",
            "http://user:pass@external-sources:8000/api/v1/external-sources",
            "http://external-sources:8000/api/v1/external-sources?x=1",
            "http://external-sources:8000/api/v1/external-sources#x",
            "http://external-sources:8000/api/v1/other/../external-sources",
        ):
            with self.subTest(destination=destination):
                with self.assertRaises(ValueError):
                    gateway.create_app(replace(self.settings, external_control_api_url=destination))

    def test_redirect_is_not_followed(self) -> None:
        redirect = gateway.urllib.error.HTTPError(
            "http://external-sources:8000/api/v1/external-sources/sources", 302,
            "redirect", {"Location": "http://other-service:8000/secrets"}, None,
        )
        opener = type("Opener", (), {"open": lambda _self, _request, **_kwargs: (_ for _ in ()).throw(redirect)})()
        with patch("urllib.request.build_opener", return_value=opener):
            response = self.client.get("/api/v1/external-sources/sources", headers=self.headers)
        self.assertEqual(response.status_code, 502)

    def test_unknown_upstream_response_fields_are_rejected(self) -> None:
        payload = [{"source_id": "source", "name": "Source", "source_type": "rss", "status": "enabled",
                    "metadata": {}, "unexpected": "must not pass"}]
        with self.upstream(payload=payload):
            response = self.client.get("/api/v1/external-sources/sources", headers=self.headers)
        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.json()["code"], "external_control_invalid_response")


if __name__ == "__main__":
    unittest.main()
