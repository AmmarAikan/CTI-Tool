from __future__ import annotations

import json
import unittest

from backend.app.integrations.external_control_client import (
    ExternalControlClient,
    ExternalControlRemoteError,
    ExternalControlTransportError,
)


class FakeResponse:
    def __init__(self, payload: object, status_code: int = 200, headers: dict[str, str] | None = None) -> None:
        self.status_code = status_code
        self.content = json.dumps(payload).encode("utf-8")
        self.headers = {"Content-Type": "application/json", **(headers or {})}


class FakeSession:
    def __init__(self, responses: list[FakeResponse]) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, str, dict[str, object]]] = []

    def request(self, method: str, url: str, **kwargs):
        self.calls.append((method, url, kwargs))
        return self.responses.pop(0)


class ExternalControlClientTests(unittest.TestCase):
    token = "external-control-token-that-is-long-enough"

    def client(self, responses: list[FakeResponse], **kwargs) -> ExternalControlClient:
        return ExternalControlClient(
            "http://127.0.0.1:18090/api/v1/external-sources",
            self.token,
            allow_http=True,
            session=FakeSession(responses),
            **kwargs,
        )

    def test_health_and_source_listing_are_bounded_contracts(self) -> None:
        session = FakeSession(
            [
                FakeResponse({"status": "ok", "service": "external-sources", "api_version": "v1"}),
                FakeResponse(
                    [
                        {
                            "source_id": "cisa-kev",
                            "name": "CISA KEV",
                            "source_type": "vulnerability",
                            "status": "enabled",
                            "metadata": {},
                        }
                    ]
                ),
            ]
        )
        client = ExternalControlClient(
            "http://127.0.0.1:18090/api/v1/external-sources",
            self.token,
            allow_http=True,
            session=session,
        )

        health = client.healthcheck()
        sources = client.list_sources()

        self.assertTrue(health["reachable"])
        self.assertEqual(sources[0]["source_id"], "cisa-kev")
        self.assertNotIn("Authorization", session.calls[0][2]["headers"])
        self.assertEqual(session.calls[1][2]["headers"]["Authorization"], f"Bearer {self.token}")

    def test_collection_uses_idempotency_and_rejects_unsafe_ids(self) -> None:
        client = self.client(
            [
                FakeResponse(
                    {
                        "schema_version": "1.0",
                        "job_id": "job-1234567890",
                        "command_id": "cmd-1234567890",
                        "state": "queued",
                        "created_at": "2026-08-29T00:00:00Z",
                        "updated_at": "2026-08-29T00:00:00Z",
                        "progress": {},
                        "result": None,
                        "error": None,
                    },
                    status_code=202,
                )
            ]
        )

        result = client.start_collection(scope="all_enabled")

        self.assertEqual(result["state"], "queued")
        call = client.session.calls[0]
        self.assertEqual(call[0], "POST")
        self.assertTrue(call[2]["headers"]["Idempotency-Key"])
        self.assertEqual(call[2]["json"]["scope"], "all_enabled")
        with self.assertRaises(ValueError):
            client.collect_source("../unsafe")

    def test_remote_errors_and_oversized_responses_are_safe(self) -> None:
        client = self.client(
            [
                FakeResponse(
                    {
                        "schema_version": "1.0",
                        "code": "source_disabled",
                        "message": "selected source is disabled",
                        "retryable": False,
                        "details": {},
                    },
                    status_code=409,
                )
            ]
        )
        with self.assertRaises(ExternalControlRemoteError) as raised:
            client.collect_source("reddit-netsec")
        self.assertEqual(raised.exception.code, "source_disabled")
        self.assertNotIn(self.token, str(raised.exception))

        oversized = self.client(
            [FakeResponse({"sources": []}, headers={"Content-Length": "5000"})],
            max_response_bytes=4096,
        )
        with self.assertRaises(ExternalControlTransportError):
            oversized.list_sources()

    def test_plain_http_and_embedded_credentials_fail_closed(self) -> None:
        with self.assertRaises(ValueError):
            ExternalControlClient("http://example.test/api", self.token)
        client = self.client([])
        with self.assertRaises(ValueError):
            client.add_manual_source("https://user:password@example.test/report")

    def test_latest_export_uses_bounded_summary_route(self) -> None:
        client = self.client(
            [
                FakeResponse(
                    {
                        "run_id": "ext-run-1234567890",
                        "status": "completed",
                        "dataset_sha256": "a" * 64,
                        "accepted_records": 25,
                        "review_records": 2,
                        "completed_at": "2026-08-30T00:00:00Z",
                    }
                )
            ]
        )

        summary = client.latest_export_summary()

        self.assertEqual(summary["accepted_records"], 25)
        self.assertTrue(client.session.calls[0][1].endswith("/exports/latest/summary"))

    def test_manual_preview_proxy_contract_and_decision_idempotency(self) -> None:
        preview = {"schema_version": "1.0", "preview_id": "prv-12345678901234567890", "state": "pending",
            "created_at": "2026-09-06T00:00:00Z", "expires_at": "2026-09-06T00:15:00Z",
            "display_url": "https://example.test/report", "page_type": "article", "title": "Safe",
            "excerpt": "Safe excerpt", "disposition": "accepted", "classification_label": "cti_related",
            "classification_confidence": 0.9, "privacy_status": "reviewed", "review_reasons": [],
            "content_sha256": "sha256:" + "a" * 64,
            "counts": {"items": 1, "accepted": 1, "review": 0, "rejected": 0, "skipped": 0, "errors": 0}}
        queued = {"schema_version": "1.0", "job_id": "job-1234567890", "command_id": "cmd-1234567890",
            "state": "queued", "created_at": "2026-09-06T00:00:00Z", "updated_at": "2026-09-06T00:00:00Z",
            "progress": {}, "result": None, "error": None}
        rejected = {"schema_version": "1.0", "preview_id": preview["preview_id"], "state": "rejected",
                    "decided_at": "2026-09-06T00:01:00Z"}
        client = self.client([FakeResponse(preview), FakeResponse(queued), FakeResponse(rejected)])
        self.assertEqual(client.create_manual_preview("https://example.test/report")["state"], "pending")
        client.approve_manual_preview(preview["preview_id"], preview["content_sha256"], idempotency_key="approve-once")
        client.reject_manual_preview(preview["preview_id"], "duplicate", idempotency_key="reject-once")
        self.assertEqual(client.session.calls[1][2]["headers"]["Idempotency-Key"], "approve-once")
        self.assertEqual(client.session.calls[2][2]["headers"]["Idempotency-Key"], "reject-once")


if __name__ == "__main__":
    unittest.main()
