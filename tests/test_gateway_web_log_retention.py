from __future__ import annotations

import json
import hashlib
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from backend.app.db.database import Base
from backend.app.db.models import RawItem, Source
from backend.app.pipeline.ingestion.internal.security_sensor_http_connector import SecuritySensorAPIConnector
from backend.app.services.pipeline_service import PipelineService
import hmac
import tempfile
import unittest
from pathlib import Path
from dataclasses import replace

from fastapi.testclient import TestClient

from tests.test_vps_gateway import gateway


class GatewayWebLogRetentionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.settings = gateway.GatewaySettings(
            feed_publish_token="publish-token-0123456789abcdef",
            feed_read_token="read-token-0123456789abcdefghi",
            feed_hmac_secret="feed-hmac-0123456789abcdefghij",
            sensor_read_token="sensor-token-0123456789abcdef",
            sensor_hmac_secret="sensor-hmac-0123456789abcdefg",
            cursor_secret="cursor-secret-0123456789abcdefg",
            data_dir=self.root,
            dionaea_path=self.root / "dionaea.json",
            host_auth_path=self.root / "host_auth.jsonl",
        )
        self.client = TestClient(gateway.create_app(self.settings))
        self.headers = {"Authorization": f"Bearer {self.settings.sensor_read_token}"}

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_legacy_web_log_over_50_mib_remains_pageable(self) -> None:
        path = self.root / "web_access.jsonl"
        event = {"id": "legacy-web", "timestamp": "2026-09-17T00:00:00Z", "message": "x" * 8192}
        row = (json.dumps(event) + "\n").encode("utf-8")
        with path.open("wb") as handle:
            while handle.tell() <= 50 * 1024 * 1024:
                handle.write(row)
        self.assertGreater(path.stat().st_size, self.settings.max_sensor_bytes)

        first = self.client.get("/api/v1/sensors/web-access?limit=2", headers=self.headers)
        self.assertEqual(first.status_code, 200)
        self.assertEqual(len(first.json()["events"]), 2)
        self.assertTrue(first.json()["has_more"])
        second = self.client.get(
            "/api/v1/sensors/web-access?limit=2",
            params={"cursor": first.json()["next_cursor"], "limit": 2},
            headers=self.headers,
        )
        self.assertEqual(second.status_code, 200)
        self.assertEqual(len(second.json()["events"]), 2)


    def test_acknowledged_compaction_preserves_pending_events_and_absolute_cursors(self) -> None:
        for index in range(4):
            self.assertEqual(self.client.get(f"/probe/{index}").status_code, 404)
        partial = self.client.get("/api/v1/sensors/web-access", params={"limit": 2}, headers=self.headers).json()
        complete = self.client.get("/api/v1/sensors/web-access", params={"limit": 10}, headers=self.headers).json()
        self.assertEqual(len(complete["events"]), 4)
        self.assertEqual(len({item["id"] for item in complete["events"]}), 4)
        path = self.root / "web_access.jsonl"
        original_size = path.stat().st_size
        self.assertEqual(self.client.get("/probe/pending").status_code, 404)
        checkpoint = complete["checkpoint"]
        params = {"cursor": checkpoint, "limit": 10}
        bad = self.client.get(
            "/api/v1/sensors/web-access",
            params=params,
            headers={**self.headers, "X-CTI-Ack-Cursor": checkpoint, "X-CTI-Ack-Signature": "bad"},
        )
        self.assertEqual(bad.status_code, 401)
        self.assertGreater(path.stat().st_size, original_size)
        signature = hmac.new(
            self.settings.sensor_read_token.encode(),
            f"web-access-ack:{checkpoint}".encode(),
            hashlib.sha256,
        ).hexdigest()
        resumed = self.client.get(
            "/api/v1/sensors/web-access",
            params=params,
            headers={**self.headers, "X-CTI-Ack-Cursor": checkpoint, "X-CTI-Ack-Signature": signature},
        )
        self.assertEqual(resumed.status_code, 200)
        self.assertEqual([item["url"]["original"] for item in resumed.json()["events"]], ["/probe/pending"])
        self.assertLess(path.stat().st_size, original_size)
        with path.open("rb") as handle:
            self.assertEqual(json.loads(handle.readline())[gateway.WEB_BASE_KEY], 4)
        stale = self.client.get(
            "/api/v1/sensors/web-access",
            params={"cursor": partial["checkpoint"]},
            headers=self.headers,
        )
        self.assertEqual(stale.status_code, 409)
        restarted = TestClient(gateway.create_app(self.settings))
        after_restart = restarted.get(
            "/api/v1/sensors/web-access",
            params={"cursor": checkpoint},
            headers=self.headers,
        )
        self.assertEqual(after_restart.status_code, 200)
        self.assertEqual(len(after_restart.json()["events"]), 1)

    def test_healthcheck_resumes_after_compaction_without_acknowledging_pending_data(self) -> None:
        for index in range(3):
            self.assertEqual(self.client.get(f"/health/{index}").status_code, 404)
        complete = self.client.get(
            "/api/v1/sensors/web-access",
            params={"limit": 10},
            headers=self.headers,
        ).json()
        checkpoint = complete["checkpoint"]
        self.assertEqual(self.client.get("/health/pending").status_code, 404)
        signature = hmac.new(
            self.settings.sensor_read_token.encode(),
            f"web-access-ack:{checkpoint}".encode(),
            hashlib.sha256,
        ).hexdigest()
        compacted = self.client.get(
            "/api/v1/sensors/web-access",
            params={"cursor": checkpoint, "limit": 10},
            headers={
                **self.headers,
                "X-CTI-Ack-Cursor": checkpoint,
                "X-CTI-Ack-Signature": signature,
            },
        )
        self.assertEqual(compacted.status_code, 200)
        path = self.root / "web_access.jsonl"
        before_health = path.read_bytes()

        class GatewaySession:
            def get(self, _url: str, **kwargs):
                return self_client.get(
                    "/api/v1/sensors/web-access",
                    params=kwargs["params"],
                    headers=kwargs["headers"],
                )

        self_client = self.client
        connector = SecuritySensorAPIConnector(
            "http://gateway.test/api/v1/sensors/web-access",
            self.settings.sensor_read_token,
            source_type="web_access",
            hmac_secret=self.settings.sensor_hmac_secret,
            allow_http=True,
            verify_tls=False,
            checkpoint=checkpoint,
            session=GatewaySession(),
        )
        self.assertTrue(connector.healthcheck()["reachable"])
        self.assertEqual(path.read_bytes(), before_health)
        self.assertEqual(self.client.get("/api/v1/sensors/dionaea", headers=self.headers).status_code, 200)
    def test_capacity_backpressure_keeps_pending_log_and_recovers_after_ack(self) -> None:
        settings = replace(self.settings, max_web_log_bytes=64 * 1024)
        client = TestClient(gateway.create_app(settings))
        for _ in range(200):
            response = client.get("/probe/" + "x" * 512)
            if response.status_code == 503:
                break
            self.assertEqual(response.status_code, 404)
        else:
            self.fail("web-access log never applied backpressure")
        path = self.root / "web_access.jsonl"
        size = path.stat().st_size
        self.assertLessEqual(size, settings.max_web_log_bytes)
        self.assertEqual(client.get("/probe/again").status_code, 503)
        self.assertEqual(path.stat().st_size, size)
        pending = client.get("/api/v1/sensors/web-access", params={"limit": 1000}, headers=self.headers)
        self.assertEqual(pending.status_code, 200)
        self.assertFalse(pending.json()["has_more"])
        self.assertTrue(pending.json()["events"])
        checkpoint = pending.json()["checkpoint"]
        signature = hmac.new(
            settings.sensor_read_token.encode(),
            f"web-access-ack:{checkpoint}".encode(),
            hashlib.sha256,
        ).hexdigest()
        drained = client.get(
            "/api/v1/sensors/web-access",
            params={"cursor": checkpoint},
            headers={**self.headers, "X-CTI-Ack-Cursor": checkpoint, "X-CTI-Ack-Signature": signature},
        )
        self.assertEqual(drained.status_code, 200)
        self.assertEqual(drained.json()["events"], [])
        self.assertLess(path.stat().st_size, settings.max_web_log_bytes // 2)
        self.assertEqual(client.get("/probe/recovered").status_code, 404)

    def test_backend_commits_partial_batches_before_acknowledging(self) -> None:
        for index in range(5):
            self.assertEqual(self.client.get(f"/batch/{index}").status_code, 404)

        class GatewaySession:
            def __init__(self, client: TestClient) -> None:
                self.client = client

            def get(self, _url: str, **kwargs):
                return self.client.get(
                    "/api/v1/sensors/web-access",
                    params=kwargs["params"],
                    headers=kwargs["headers"],
                )

        engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(engine)
        try:
            with Session(engine) as db:
                def connector(checkpoint: str | None) -> SecuritySensorAPIConnector:
                    return SecuritySensorAPIConnector(
                        "http://gateway.test/api/v1/sensors/web-access",
                        self.settings.sensor_read_token,
                        source_type="web_access",
                        hmac_secret=self.settings.sensor_hmac_secret,
                        allow_http=True,
                        verify_tls=False,
                        page_size=2,
                        max_pages=2,
                        checkpoint=checkpoint,
                        session=GatewaySession(self.client),
                    )

                first = connector(None)
                PipelineService(db).run_security_sensor_api("web_access", first)
                self.assertTrue(first.last_result.has_more)
                self.assertEqual(db.scalar(select(func.count()).select_from(RawItem)), 4)
                source = db.scalar(select(Source).where(Source.source_type == "web_access"))
                checkpoint = source.config["checkpoint"]
                path = self.root / "web_access.jsonl"
                with path.open("rb") as handle:
                    self.assertFalse(handle.readline().startswith(b'{"_gateway_web_base_offset"'))

                second = connector(checkpoint)
                PipelineService(db).run_security_sensor_api("web_access", second)
                self.assertFalse(second.last_result.has_more)
                self.assertEqual(db.scalar(select(func.count()).select_from(RawItem)), 5)
                with path.open("rb") as handle:
                    self.assertEqual(json.loads(handle.readline())[gateway.WEB_BASE_KEY], 4)
                source = db.scalar(select(Source).where(Source.source_type == "web_access"))
                third = connector(source.config["checkpoint"])
                PipelineService(db).run_security_sensor_api("web_access", third)
                self.assertEqual(db.scalar(select(func.count()).select_from(RawItem)), 5)
                with path.open("rb") as handle:
                    self.assertEqual(json.loads(handle.readline())[gateway.WEB_BASE_KEY], 5)
        finally:
            engine.dispose()



    def test_operational_gateway_routes_survive_web_log_capacity(self) -> None:
        settings = replace(self.settings, max_web_log_bytes=64 * 1024)
        client = TestClient(gateway.create_app(settings))
        for _ in range(200):
            if client.get("/probe/" + "x" * 512).status_code == 503:
                break
        else:
            self.fail("web-access log never reached capacity")
        for stream in ("dionaea", "host-auth"):
            response = client.get(f"/api/v1/sensors/{stream}", headers=self.headers)
            self.assertEqual(response.status_code, 200)
        feed = client.get(
            "/api/v1/external-feed",
            headers={"Authorization": f"Bearer {settings.feed_read_token}"},
        )
        self.assertEqual(feed.status_code, 404)
        publish = client.post(
            "/api/v1/external-feed/publish",
            headers={"Authorization": f"Bearer {settings.feed_publish_token}"},
            json={},
        )
        self.assertEqual(publish.status_code, 422)
        self.assertEqual(client.get("/probe/still-blocked").status_code, 503)

    def test_token_signed_ack_works_without_optional_response_hmac(self) -> None:
        self.client.get("/probe/no-hmac")
        first = self.client.get("/api/v1/sensors/web-access", headers=self.headers).json()
        checkpoint = first["checkpoint"]

        class GatewaySession:
            def get(self, _url: str, **kwargs):
                return self_client.get(
                    "/api/v1/sensors/web-access",
                    params=kwargs["params"],
                    headers=kwargs["headers"],
                )

        self_client = self.client
        connector = SecuritySensorAPIConnector(
            "http://gateway.test/api/v1/sensors/web-access",
            self.settings.sensor_read_token,
            source_type="web_access",
            hmac_secret=None,
            allow_http=True,
            verify_tls=False,
            checkpoint=checkpoint,
            session=GatewaySession(),
        )
        self.assertEqual(len(connector.fetch().records), 0)
        with (self.root / "web_access.jsonl").open("rb") as handle:
            self.assertEqual(json.loads(handle.readline())[gateway.WEB_BASE_KEY], 1)

    def test_legacy_large_records_stay_within_backend_page_budget(self) -> None:
        path = self.root / "web_access.jsonl"
        event = {"id": "legacy-large", "timestamp": "2026-09-17T00:00:00Z", "message": "x" * (50 * 1024)}
        row = (json.dumps(event) + "\n").encode()
        with path.open("wb") as handle:
            for _ in range(500):
                handle.write(row)
        first = self.client.get("/api/v1/sensors/web-access", params={"limit": 500}, headers=self.headers)
        self.assertEqual(first.status_code, 200)
        self.assertLess(len(first.content), gateway.WEB_PAGE_MAX_BYTES + 2048)
        self.assertTrue(first.json()["has_more"])

        class GatewaySession:
            def get(self, _url: str, **kwargs):
                return self_client.get(
                    "/api/v1/sensors/web-access",
                    params=kwargs["params"],
                    headers=kwargs["headers"],
                )

        self_client = self.client
        connector = SecuritySensorAPIConnector(
            "http://gateway.test/api/v1/sensors/web-access",
            self.settings.sensor_read_token,
            source_type="web_access",
            hmac_secret=self.settings.sensor_hmac_secret,
            allow_http=True,
            verify_tls=False,
            max_pages=1,
            checkpoint=None,
            session=GatewaySession(),
        )
        result = connector.fetch()
        self.assertTrue(result.records)
        self.assertTrue(result.has_more)

    def test_malformed_legacy_line_is_not_pruned_or_silently_skipped(self) -> None:
        path = self.root / "web_access.jsonl"
        original = b'not-json\n{"id":"valid","message":"valid"}\n'
        path.write_bytes(original)
        response = self.client.get("/api/v1/sensors/web-access", headers=self.headers)
        self.assertEqual(response.status_code, 422)
        checkpoint = gateway._encode_cursor(1, "web-access", self.settings.cursor_secret)
        signature = hmac.new(
            self.settings.sensor_read_token.encode(),
            f"web-access-ack:{checkpoint}".encode(),
            hashlib.sha256,
        ).hexdigest()
        acked = self.client.get(
            "/api/v1/sensors/web-access",
            params={"cursor": checkpoint},
            headers={**self.headers, "X-CTI-Ack-Cursor": checkpoint, "X-CTI-Ack-Signature": signature},
        )
        self.assertEqual(acked.status_code, 422)
        self.assertEqual(path.read_bytes(), original)

if __name__ == "__main__":
    unittest.main()
