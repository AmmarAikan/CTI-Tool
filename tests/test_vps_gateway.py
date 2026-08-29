from __future__ import annotations

import hashlib
import hmac
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
GATEWAY_PATH = ROOT / "infra" / "vps" / "gateway" / "app.py"
COLLECTOR_PATH = ROOT / "infra" / "vps" / "collectors" / "ssh_journal_collector.py"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


for key in (
    "FEED_PUBLISH_TOKEN",
    "FEED_READ_TOKEN",
    "FEED_RESPONSE_HMAC_SECRET",
    "SENSOR_READ_TOKEN",
    "SENSOR_RESPONSE_HMAC_SECRET",
    "CURSOR_HMAC_SECRET",
):
    os.environ.setdefault(key, f"test-{key.lower()}-0123456789abcdef")

gateway = load_module("cti_vps_gateway_test_module", GATEWAY_PATH)
collector = load_module("cti_ssh_collector_test_module", COLLECTOR_PATH)


class VPSGatewayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.auth_path = self.root / "host_auth.jsonl"
        self.dionaea_path = self.root / "dionaea.json"
        self.settings = gateway.GatewaySettings(
            feed_publish_token="publish-token-0123456789abcdef",
            feed_read_token="read-token-0123456789abcdefghi",
            feed_hmac_secret="feed-hmac-0123456789abcdefghij",
            sensor_read_token="sensor-token-0123456789abcdef",
            sensor_hmac_secret="sensor-hmac-0123456789abcdefg",
            cursor_secret="cursor-secret-0123456789abcdefg",
            data_dir=self.root / "data",
            dionaea_path=self.dionaea_path,
            host_auth_path=self.auth_path,
        )
        self.client = TestClient(gateway.create_app(self.settings))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_external_publish_pull_hmac_pagination_etag_and_auth(self) -> None:
        dataset = {
            "run_id": "ext-run-1",
            "completed_at": "2026-08-29T00:00:00Z",
            "dataset": [
                {"record_id": "ext-1", "source": "NVD", "source_type": "nvd", "title": "CVE report", "content": "CVE-2026-1234"},
                {"record_id": "ext-2", "source": "CERT", "source_type": "cert", "title": "Advisory", "content": "Malware advisory"},
            ],
        }
        publish = self.client.post(
            "/api/v1/external-feed/publish",
            headers={"Authorization": f"Bearer {self.settings.feed_publish_token}"},
            json=dataset,
        )
        self.assertEqual(publish.status_code, 202)
        denied = self.client.get("/api/v1/external-feed")
        self.assertEqual(denied.status_code, 401)

        first = self.client.get(
            "/api/v1/external-feed?limit=1",
            headers={"Authorization": f"Bearer {self.settings.feed_read_token}"},
        )
        self.assertEqual(first.status_code, 200)
        expected = hmac.new(self.settings.feed_hmac_secret.encode(), first.content, hashlib.sha256).hexdigest()
        self.assertEqual(first.headers["X-CTI-Signature"], f"sha256={expected}")
        payload = first.json()
        self.assertTrue(payload["has_more"])
        self.assertEqual(payload["items"][0]["external_id"], "ext-1")

        second = self.client.get(
            f"/api/v1/external-feed?limit=1&cursor={payload['next_cursor']}",
            headers={"Authorization": f"Bearer {self.settings.feed_read_token}"},
        )
        self.assertEqual(second.json()["items"][0]["external_id"], "ext-2")
        not_modified = self.client.get(
            "/api/v1/external-feed",
            headers={
                "Authorization": f"Bearer {self.settings.feed_read_token}",
                "If-None-Match": first.headers["ETag"],
            },
        )
        self.assertEqual(not_modified.status_code, 304)

    def test_sensor_stream_and_ssh_parser_are_bounded_structured_json(self) -> None:
        record = {
            "MESSAGE": "Failed password for invalid user analyst from 198.51.100.9 port 50123 ssh2",
            "__CURSOR": "cursor-1",
            "__REALTIME_TIMESTAMP": "1787961600000000",
        }
        event = collector.normalize_journal_record(record)
        self.assertIsNotNone(event)
        self.assertEqual(event["event"]["outcome"], "failure")
        self.assertEqual(event["source"]["ip"], "198.51.100.9")
        self.auth_path.write_text(json.dumps(event) + "\n", encoding="utf-8")

        response = self.client.get(
            "/api/v1/sensors/host-auth?limit=1",
            headers={"Authorization": f"Bearer {self.settings.sensor_read_token}"},
        )
        self.assertEqual(response.status_code, 200)
        expected = hmac.new(self.settings.sensor_hmac_secret.encode(), response.content, hashlib.sha256).hexdigest()
        self.assertEqual(response.headers["X-CTI-Signature"], f"sha256={expected}")
        self.assertEqual(response.json()["events"][0]["id"], event["id"])

        tampered = self.client.get(
            "/api/v1/sensors/host-auth?cursor=invalid",
            headers={"Authorization": f"Bearer {self.settings.sensor_read_token}"},
        )
        self.assertEqual(tampered.status_code, 422)


if __name__ == "__main__":
    unittest.main()
