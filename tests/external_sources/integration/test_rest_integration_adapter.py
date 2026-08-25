from __future__ import annotations

import inspect
import unittest
from unittest.mock import Mock

from fastapi.testclient import TestClient
from jsonschema import Draft202012Validator
import json
from pathlib import Path

from backend.app.pipeline.ingestion.external.application.collection_service import CollectionService, JobAccepted
from backend.app.pipeline.ingestion.external.application.job_service import JobService
from backend.app.pipeline.ingestion.external.application.manual_source_service import ManualSourceService
from backend.app.pipeline.ingestion.external.application.source_management_service import SourceManagementService, SourceView
from backend.app.pipeline.ingestion.external.integration.api import API_PREFIX, AdapterServices, create_app
from backend.app.pipeline.ingestion.external.integration.auth import Principal, RoleAuthorizer
from backend.app.pipeline.ingestion.external.integration.idempotency import InMemoryIdempotencyStore
from backend.app.pipeline.ingestion.external.integration.jobs import IntegrationJob
import backend.app.pipeline.ingestion.external.integration.api as api_module


class TokenAuth:
    def authenticate(self, token):
        roles = {"viewer-token": {"viewer"}, "operator-token": {"operator"}, "dark-token": {"dark_web_approver"}, "admin-token": {"admin"}}
        if token not in roles:
            from backend.app.pipeline.ingestion.external.integration.auth import AuthenticationError
            raise AuthenticationError()
        return Principal(token.removesuffix("-token"), frozenset(roles[token]))


class FakeRunner:
    def __init__(self): self.jobs, self.submissions = {}, []
    def submit(self, command_id, operation):
        job = IntegrationJob(f"job-{len(self.jobs) + 1:024d}", command_id)
        self.jobs[job.job_id] = job; self.submissions.append(operation); return job
    def get(self, job_id): return self.jobs.get(job_id)
    def cancel(self, job_id):
        job = self.jobs.get(job_id)
        if job: job.state = "cancelled"
        return job


class FakeSources:
    def __init__(self):
        self.values = {"rss-one": SourceView("rss-one", "RSS One", "rss", "disabled", {"url": "https://secret.example", "safe": "yes"}),
                       "dark-one": SourceView("dark-one", "Dark One", "dark_web", "disabled", {"url": "onion"})}
    def list_sources(self): return list(self.values.values())
    def get_source_status(self, source_id): return self.values.get(source_id)
    def request_source_enable(self, source_id, *, requested_by):
        old = self.values[source_id]; value = SourceView(old.source_id, old.name, old.source_type, "pending_review", old.metadata); self.values[source_id] = value; return value
    def disable_source(self, source_id, *, requested_by):
        old = self.values[source_id]; value = SourceView(old.source_id, old.name, old.source_type, "disabled", old.metadata); self.values[source_id] = value; return value


class RestIntegrationAdapterTests(unittest.TestCase):
    def setUp(self):
        self.collection = Mock(spec=CollectionService); self.collection.start_collection.return_value = JobAccepted("job-collection-0001"); self.collection.collect_source.return_value = JobAccepted("job-source-00000001")
        self.manual = Mock(spec=ManualSourceService); self.sources = FakeSources(); self.job_service = Mock(spec=JobService); self.runner = FakeRunner()
        self.manual.validate_url.side_effect = lambda value: value
        self.job_service.get_job_status.return_value = None
        self.services = AdapterServices(TokenAuth(), RoleAuthorizer(), self.collection, self.manual, self.sources, self.job_service, self.runner, InMemoryIdempotencyStore())
        self.client = TestClient(create_app(self.services))

    @staticmethod
    def auth(token="operator-token"): return {"Authorization": f"Bearer {token}"}

    def test_health_and_authentication_safe_error(self):
        self.assertEqual(self.client.get(f"{API_PREFIX}/health").json()["status"], "ok")
        response = self.client.get(f"{API_PREFIX}/sources")
        self.assertEqual(response.status_code, 401); self.assertEqual(set(response.json()), {"schema_version", "code", "message", "retryable", "details"})
        error_schema = json.loads((Path(__file__).resolve().parents[3] / "contracts/integration_error.schema.json").read_text(encoding="utf-8"))
        Draft202012Validator(error_schema).validate(response.json())
        self.assertNotIn("trace", response.text.lower())

    def test_swagger_and_openapi_are_disabled_by_default(self):
        self.assertEqual(self.client.get("/docs").status_code, 404)
        self.assertEqual(self.client.get("/openapi.json").status_code, 404)

    def test_enabled_openapi_describes_bearer_auth_without_bypassing_it(self):
        client = TestClient(create_app(self.services, docs_enabled=True))
        self.assertEqual(client.get("/docs").status_code, 200)
        schema_response = client.get("/openapi.json")
        self.assertEqual(schema_response.status_code, 200)
        schema = schema_response.json()
        self.assertEqual(schema["components"]["securitySchemes"]["HTTPBearer"]["scheme"], "bearer")
        protected = schema["paths"][f"{API_PREFIX}/sources"]["get"]
        self.assertEqual(protected["security"], [{"HTTPBearer": []}])
        collection_responses = schema["paths"][f"{API_PREFIX}/jobs"]["post"]["responses"]
        self.assertTrue({"404", "409", "422", "503"}.issubset(collection_responses))
        self.assertIn("IntegrationErrorResponse", str(collection_responses["503"]))
        export_responses = schema["paths"][f"{API_PREFIX}/exports/latest"]["get"]["responses"]
        self.assertIn("404", export_responses)
        self.assertIn("IntegrationErrorResponse", str(export_responses["404"]))
        self.assertEqual(client.get(f"{API_PREFIX}/sources").status_code, 401)

    def test_authorization_boundaries(self):
        response = self.client.post(f"{API_PREFIX}/jobs", json={}, headers=self.auth("viewer-token"))
        self.assertEqual(response.status_code, 403); self.collection.start_collection.assert_not_called()

    def test_collection_job_is_queued_and_idempotent(self):
        headers = {**self.auth(), "Idempotency-Key": "same-command-key"}
        first = self.client.post(f"{API_PREFIX}/jobs", json={"source_ids": ["rss-one"]}, headers=headers)
        second = self.client.post(f"{API_PREFIX}/jobs", json={"source_ids": ["rss-one"]}, headers=headers)
        self.assertEqual((first.status_code, first.json()["state"]), (202, "queued")); self.assertEqual(first.json(), second.json())
        self.collection.start_collection.assert_called_once(); self.assertEqual(self.collection.start_collection.call_args.args[0].requested_by, "operator")
        schema = json.loads((Path(__file__).resolve().parents[3] / "contracts/job_status.schema.json").read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(first.json())

    def test_manual_url_validation_and_job_creation(self):
        invalid = self.client.post(f"{API_PREFIX}/manual-sources", json={"url": "file:///secret"}, headers=self.auth())
        self.assertEqual(invalid.status_code, 422); self.assertEqual(invalid.json()["code"], "request_validation_failed")
        accepted = self.client.post(f"{API_PREFIX}/manual-sources", json={"url": "https://example.test/report"}, headers=self.auth())
        self.assertEqual((accepted.status_code, accepted.json()["state"]), (202, "queued")); self.assertEqual(len(self.runner.submissions), 1)
        self.manual.validate_url.assert_called_once_with("https://example.test/report")

    def test_application_url_policy_rejection_happens_before_job_acceptance(self):
        self.manual.validate_url.side_effect = ValueError("sensitive internal detail")
        response = self.client.post(f"{API_PREFIX}/manual-sources", json={"url": "https://example.test/report"}, headers=self.auth())
        self.assertEqual((response.status_code, response.json()["code"]), (422, "url_policy_rejected"))
        self.assertEqual(self.runner.submissions, []); self.assertNotIn("sensitive", response.text.lower())

    def test_source_review_and_dark_web_explicit_approval(self):
        ordinary = self.client.post(f"{API_PREFIX}/sources/rss-one/enable-requests", headers=self.auth())
        self.assertEqual(ordinary.json()["status"], "pending_review")
        blocked = self.client.post(f"{API_PREFIX}/sources/dark-one/enable-requests", headers=self.auth())
        self.assertEqual((blocked.status_code, blocked.json()["code"]), (403, "dark_web_approval_required"))
        approved = self.client.post(f"{API_PREFIX}/sources/dark-one/enable-requests", headers=self.auth("dark-token"))
        self.assertEqual(approved.json()["status"], "pending_review")

    def test_source_metadata_latest_export_and_errors_are_sanitized(self):
        source = self.client.get(f"{API_PREFIX}/sources/rss-one", headers=self.auth("viewer-token")).json()
        self.assertEqual(source["metadata"], {"safe": "yes"})
        self.job_service.get_latest_export.return_value = {"run_id": "ext-run-0000001", "status": "completed", "dataset_sha256": "sha256:" + "a" * 64,
            "accepted_records": 2, "review_records": 1, "completed_at": "2026-08-24T00:00:00Z", "dataset_file": "C:\\private\\file.json"}
        export = self.client.get(f"{API_PREFIX}/exports/latest", headers=self.auth("viewer-token")).json()
        self.assertNotIn("dataset_file", export); self.assertNotIn("private", str(export).lower())

    def test_cancellation_and_not_found(self):
        created = self.client.post(f"{API_PREFIX}/manual-sources", json={"url": "https://example.test/report"}, headers=self.auth()).json()
        cancelled = self.client.post(f"{API_PREFIX}/jobs/{created['job_id']}/cancel", headers=self.auth())
        self.assertEqual(cancelled.json()["state"], "cancelled")
        missing = self.client.get(f"{API_PREFIX}/jobs/job-missing-0001", headers=self.auth("viewer-token"))
        self.assertEqual((missing.status_code, missing.json()["code"]), (404, "job_not_found"))

    def test_routes_do_not_import_collectors(self):
        source = inspect.getsource(api_module)
        self.assertNotIn("rss_connector", source); self.assertNotIn("dark_web_connector", source); self.assertNotIn("vulnerability_connector", source)
        self.assertNotIn(".collect(", source)

    def test_unexpected_service_error_has_no_exception_or_secret_details(self):
        self.sources.list_sources = Mock(side_effect=RuntimeError("token=do-not-return filesystem=C:\\secret"))
        client = TestClient(create_app(self.services), raise_server_exceptions=False)
        response = client.get(f"{API_PREFIX}/sources", headers=self.auth("viewer-token"))
        self.assertEqual((response.status_code, response.json()["code"]), (500, "internal_adapter_error"))
        self.assertNotIn("secret", response.text.lower()); self.assertNotIn("token", response.text.lower())


if __name__ == "__main__": unittest.main()
