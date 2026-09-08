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

    def test_reviews_history_and_cancellation_use_bounded_contracts(self) -> None:
        review = {"run_id": "ext-run-1234567890", "records": [{
            "record_id": "rec-123", "canonical_url": "https://private.test/report", "title": "Safe",
            "source_type": "rss", "review_reason": "privacy_review", "review_reasons": ["privacy_review"],
            "stage_status": {"privacy": "review"}, "classification_label": "related",
            "privacy_status": "review_required", "collected_at": "2026-09-07T00:00:00Z", "published": None,
        }]}
        history = {"schema_version": "1.0", "persistence": "process_memory", "jobs": [{
            "schema_version": "1.0", "job_id": "job-1234567890", "source_id": "cisa-kev",
            "state": "running", "created_at": "2026-09-07T00:00:00Z", "updated_at": "2026-09-07T00:00:01Z",
            "counts": {}, "error_code": None, "error_message": None,
        }]}
        queued = {"schema_version": "1.0", "job_id": "job-1234567890", "command_id": "cmd-1234567890",
            "state": "cancellation_requested", "created_at": "2026-09-07T00:00:00Z",
            "updated_at": "2026-09-07T00:00:01Z", "progress": {}, "result": None, "error": None}
        client = self.client([FakeResponse(review), FakeResponse(history), FakeResponse(queued)])
        projected = client.latest_reviews()
        self.assertNotIn("canonical_url", projected["records"][0])
        self.assertNotIn("stage_status", projected["records"][0])
        self.assertEqual(client.list_jobs(limit=50)["persistence"], "process_memory")
        self.assertEqual(client.cancel_job("job-1234567890")["state"], "cancellation_requested")
        self.assertTrue(client.session.calls[1][1].endswith("/jobs?limit=50"))
        self.assertEqual(client.session.calls[2][0], "POST")

    def test_history_rejects_extra_sensitive_fields(self) -> None:
        payload = {"schema_version": "1.0", "persistence": "process_memory", "jobs": [{
            "schema_version": "1.0", "job_id": "job-1234567890", "source_id": None, "state": "failed",
            "created_at": "2026-09-07T00:00:00Z", "updated_at": "2026-09-07T00:00:01Z",
            "counts": {}, "error_code": "job_failed", "error_message": "safe", "submitted_url": "https://private.test",
        }]}
        with self.assertRaises(ExternalControlTransportError):
            self.client([FakeResponse(payload)]).list_jobs()

    def test_job_and_source_projections_reject_unknown_or_sensitive_fields(self) -> None:
        job = {"schema_version": "1.0", "job_id": "job-1234567890", "command_id": "cmd-1234567890",
            "state": "completed", "created_at": "2026-09-07T00:00:00Z", "updated_at": "2026-09-07T00:00:01Z",
            "progress": {}, "result": {"status": "completed", "accepted_records": 1}, "error": None,
            "request_body": {"token": "secret"}}
        with self.assertRaises(ExternalControlTransportError):
            self.client([FakeResponse(job)]).get_job("job-1234567890")
        nested = dict(job); nested.pop("request_body"); nested["result"] = {"status": "completed", "path": "/tmp/private"}
        with self.assertRaises(ExternalControlTransportError):
            self.client([FakeResponse(nested)]).get_job("job-1234567890")
        source = {"source_id": "safe", "name": "Safe", "source_type": "rss", "status": "enabled",
                  "metadata": {"url": "https://private.test"}}
        with self.assertRaises(ExternalControlTransportError):
            self.client([FakeResponse([source])]).list_sources()

        private = dict(job); private.pop("request_body"); private["result"] = {
            "status": "completed", "accepted_records": 1, "canonical_url": "https://private.test/report",
            "message": "private collector detail", "export": {"status": "completed", "run_id": "ext-run-123",
                "dataset_sha256": "a" * 64, "accepted_records": 1, "review_records": 0,
                "dataset_file": "final_dataset.json", "manifest_file": "manifest.json", "review_file": "review.json"}}
        projected = self.client([FakeResponse(private)]).get_job("job-1234567890")
        self.assertNotIn("canonical_url", str(projected))
        self.assertNotIn("dataset_file", str(projected))

    def test_manual_preview_proxy_contract_and_decision_idempotency(self) -> None:
        preview = {"schema_version": "1.0", "preview_id": "prv-12345678901234567890", "state": "pending",
            "created_at": "2026-09-06T00:00:00Z", "expires_at": "2026-09-06T00:15:00Z",
            "display_url": "https://example.test/report", "page_type": "article", "title": "Safe",
            "excerpt": "Safe excerpt", "disposition": "accepted", "classification_label": "cti_related",
            "classification_confidence": 0.9, "privacy_status": "reviewed", "review_reasons": [],
            "content_sha256": "sha256:" + "a" * 64,
            "items_preview": [{"item_index": 1, "title": "Safe", "excerpt": "Safe excerpt", "page_type": "article",
                "disposition": "accepted", "classification_label": "cti_related", "classification_confidence": 0.9,
                "privacy_status": "reviewed", "review_reasons": [], "content_sha256": "sha256:" + "b" * 64}],
            "items_preview_total": 1, "items_preview_truncated": False,
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

    def test_manual_preview_accepts_deployed_exclude_none_response(self) -> None:
        preview = {"schema_version": "1.0", "preview_id": "prv-12345678901234567890", "state": "pending",
            "created_at": "2026-09-07T00:00:00Z", "expires_at": "2026-09-07T00:15:00Z",
            "display_url": "https://example.test/report", "page_type": "article", "title": "Safe",
            "excerpt": "Safe excerpt", "disposition": "accepted", "privacy_status": "reviewed",
            "review_reasons": [], "content_sha256": "sha256:" + "a" * 64,
            "items_preview": [{"item_index": 1, "title": "Safe", "excerpt": "Safe excerpt",
                "page_type": "article", "disposition": "accepted", "privacy_status": "reviewed",
                "review_reasons": [], "content_sha256": "sha256:" + "b" * 64}],
            "items_preview_total": 1, "items_preview_truncated": False,
            "counts": {"items": 1, "accepted": 1, "review": 0, "rejected": 0, "skipped": 0, "errors": 0}}
        result = self.client([FakeResponse(preview)]).create_manual_preview("https://example.test/report")
        self.assertIsNone(result["classification_label"])
        self.assertIsNone(result["classification_confidence"])
        self.assertNotIn("classification_label", result["items_preview"][0])

    def test_manual_preview_proxy_rejects_malformed_or_leaking_item_contract(self) -> None:
        base = {"schema_version": "1.0", "preview_id": "prv-12345678901234567890", "state": "pending",
            "created_at": "2026-09-06T00:00:00Z", "expires_at": "2026-09-06T00:15:00Z",
            "display_url": "https://example.test/report", "page_type": "article", "title": "Safe", "excerpt": "",
            "disposition": "accepted", "classification_label": None, "classification_confidence": None,
            "privacy_status": "reviewed", "review_reasons": [], "content_sha256": "sha256:" + "a" * 64,
            "counts": {"items": 1, "accepted": 1, "review": 0, "rejected": 0, "skipped": 0, "errors": 0},
            "items_preview_total": 1, "items_preview_truncated": False}
        item = {"item_index": 1, "title": "Safe", "excerpt": "", "page_type": "article", "disposition": "accepted",
            "classification_label": None, "classification_confidence": None, "privacy_status": "reviewed",
            "review_reasons": [], "content_sha256": "sha256:" + "b" * 64}
        from backend.app.integrations.external_control_client import ExternalControlTransportError
        for changed in ({**item, "url": "https://private.example/?token=x"},
                        {**item, "title": "x" * 201},
                        {**item, "privacy_status": "review_required", "excerpt": "private"}):
            with self.subTest(changed=changed):
                client = self.client([FakeResponse({**base, "items_preview": [changed]})])
                with self.assertRaises(ExternalControlTransportError):
                    client.create_manual_preview("https://example.test/report")


if __name__ == "__main__":
    unittest.main()
