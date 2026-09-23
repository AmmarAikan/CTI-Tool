from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

TEST_DIRECTORY = Path(tempfile.mkdtemp(prefix="cti_backend_test_"))
os.environ["DATABASE_URL"] = f"sqlite:///{(TEST_DIRECTORY / 'test.db').as_posix()}"
os.environ["UPLOAD_DIR"] = str(TEST_DIRECTORY / "uploads")
os.environ["JWT_SECRET"] = "test-only-secret-that-is-long-enough"
os.environ["ACCESS_TOKEN_MINUTES"] = "120"
TEST_DATABASE_URL = os.environ["DATABASE_URL"]

from backend.app.db.database import configure_test_database, dispose_test_database

configure_test_database(TEST_DATABASE_URL)

from fastapi.testclient import TestClient
from fastapi.routing import APIRoute
from stix2 import parse as parse_stix
from backend.app.api.v1.router import router

from backend.app.main import app
from backend.app.core.security import decode_access_token
from backend.app.db.database import SessionLocal
from backend.app.db.models import (
    CorrelationRecord,
    EntityRecord,
    IndicatorRecord,
    RelationshipRecord,
    Source,
    ThreatEvent,
)

SAMPLE_PATH = Path(__file__).resolve().parents[1] / "data" / "internal_samples" / "wazuh_alerts_sample.json"
DIONAEA_SAMPLE_PATH = (
    Path(__file__).resolve().parents[1] / "data" / "internal_samples" / "dionaea_events_sample.jsonl"
)


class BackendAPITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.client_context = TestClient(app)
        cls.client = cls.client_context.__enter__()
        bootstrap = cls.client.post(
            "/api/v1/auth/bootstrap",
            json={"username": "admin", "password": "StrongTestPassword123!"},
        )
        assert bootstrap.status_code == 201, bootstrap.text
        login = cls.client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "StrongTestPassword123!"},
        )
        assert login.status_code == 200, login.text
        cls.headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    @classmethod
    def tearDownClass(cls) -> None:
        try:
            cls.client_context.__exit__(None, None, None)
        finally:
            dispose_test_database(TEST_DATABASE_URL)
            shutil.rmtree(TEST_DIRECTORY, ignore_errors=True)

    def test_health_and_authentication(self) -> None:
        health = self.client.get("/api/v1/health")
        unauthorized = self.client.get("/api/v1/events")
        current = self.client.get("/api/v1/auth/me", headers=self.headers)
        integrations = self.client.get("/api/v1/integrations/status", headers=self.headers)
        model = self.client.get("/api/v1/ml/status", headers=self.headers)

        self.assertEqual(health.status_code, 200)
        self.assertEqual(unauthorized.status_code, 401)
        self.assertEqual(current.json()["role"], "admin")
        self.assertEqual(integrations.status_code, 200)
        self.assertIn("wazuh_indexer", integrations.json())
        self.assertIn("dionaea_sensor_api", integrations.json())
        self.assertIn("external_control_api", integrations.json())
        self.assertEqual(model.status_code, 200)
        self.assertEqual(model.json()["model_priority"]["primary"], "dnrti_bert_ner")
        self.assertGreater(model.json()["held_out_test"]["bert"]["f1"], 0.75)
        token_payload = decode_access_token(self.headers["Authorization"].split()[1])
        self.assertGreater(token_payload["exp"] - token_payload["iat"], 0)
        self.assertLessEqual(token_payload["exp"] - token_payload["iat"], 120 * 60)

    def test_all_mutating_routes_require_roles_and_reject_viewers(self) -> None:
        created = self.client.post(
            "/api/v1/users",
            headers=self.headers,
            json={"username": "rbacdenialviewer", "password": "StrongViewerPassword123!", "role": "viewer"},
        )
        self.assertIn(created.status_code, {201, 409}, created.text)
        login = self.client.post(
            "/api/v1/auth/login",
            json={"username": "rbacdenialviewer", "password": "StrongViewerPassword123!"},
        )
        self.assertEqual(login.status_code, 200, login.text)
        viewer_headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
        public_writes = {
            "/auth/bootstrap", "/auth/register", "/auth/login",
        }
        checked = []
        for route in router.routes:
            if not isinstance(route, APIRoute) or not route.methods.intersection({"POST", "PUT", "PATCH", "DELETE"}):
                continue
            if route.path in public_writes:
                continue
            dependencies = list(route.dependant.dependencies)
            role_guards = [item for item in dependencies if getattr(item.call, "__qualname__", "") == "require_roles.<locals>.dependency"]
            self.assertTrue(role_guards, f"Mutating route has no role guard: {route.path}")
            path = route.path
            for name in ("user_id", "event_id", "job_id", "preview_id", "watch_id", "result_id", "source_id"):
                path = path.replace("{" + name + "}", "missing")
            method = sorted(route.methods.intersection({"POST", "PUT", "PATCH", "DELETE"}))[0]
            unauthenticated = self.client.request(method, f"/api/v1{path}", json={})
            self.assertEqual(unauthenticated.status_code, 401, f"Anonymous mutation: {route.path}")
            response = self.client.request(method, f"/api/v1{path}", headers=viewer_headers, json={})
            self.assertEqual(response.status_code, 403, f"{route.path}: {response.status_code} {response.text[:160]}")
            checked.append(route.path)
        self.assertGreaterEqual(len(checked), 25)

    def test_admin_only_mutations_reject_analysts(self) -> None:
        created = self.client.post(
            "/api/v1/users",
            headers=self.headers,
            json={"username": "rbacdenialanalyst", "password": "StrongAnalystPassword123!", "role": "analyst"},
        )
        self.assertIn(created.status_code, {201, 409}, created.text)
        login = self.client.post(
            "/api/v1/auth/login",
            json={"username": "rbacdenialanalyst", "password": "StrongAnalystPassword123!"},
        )
        self.assertEqual(login.status_code, 200, login.text)
        analyst_headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
        checked = []
        for route in router.routes:
            if not isinstance(route, APIRoute) or not route.methods.intersection({"POST", "PUT", "PATCH", "DELETE"}):
                continue
            role_guards = [item for item in route.dependant.dependencies if getattr(item.call, "__qualname__", "") == "require_roles.<locals>.dependency"]
            if not role_guards:
                continue
            guard = role_guards[0].call
            closure = dict(zip(guard.__code__.co_freevars, (cell.cell_contents for cell in guard.__closure__ or ()), strict=True))
            if closure.get("roles") != ("admin",):
                continue
            path = route.path
            for name in ("user_id", "event_id", "job_id", "preview_id", "watch_id", "result_id", "source_id"):
                path = path.replace("{" + name + "}", "missing")
            method = sorted(route.methods.intersection({"POST", "PUT", "PATCH", "DELETE"}))[0]
            response = self.client.request(method, f"/api/v1{path}", headers=analyst_headers, json={})
            self.assertEqual(response.status_code, 403, f"Analyst mutation: {route.path}")
            checked.append(route.path)
        self.assertGreaterEqual(len(checked), 5)
        with patch("backend.app.api.v1.router.MISPClient.send_event") as send:
            denied = self.client.post(
                "/api/v1/events/missing/misp",
                headers=analyst_headers,
                json={"dry_run": False},
            )
        self.assertEqual(denied.status_code, 403)
        send.assert_not_called()

    def test_public_registration_is_viewer_only_audited_and_login_ready(self) -> None:
        registered = self.client.post(
            "/api/v1/auth/register",
            json={
                "username": "GraduationViewer",
                "password": "GraduationViewerPassword123!",
            },
        )
        self.assertEqual(registered.status_code, 201, registered.text)
        self.assertEqual(registered.json()["username"], "graduationviewer")
        self.assertEqual(registered.json()["role"], "viewer")
        self.assertTrue(registered.json()["is_active"])
        self.assertNotIn("password", registered.text.lower())
        self.assertNotIn("hash", registered.text.lower())

        role_injection = self.client.post(
            "/api/v1/auth/register",
            json={
                "username": "roleinjection",
                "password": "GraduationViewerPassword123!",
                "role": "admin",
            },
        )
        duplicate = self.client.post(
            "/api/v1/auth/register",
            json={
                "username": "GraduationViewer",
                "password": "AnotherGraduationPassword123!",
            },
        )
        self.assertEqual(role_injection.status_code, 422)
        self.assertEqual(duplicate.status_code, 409)

        login = self.client.post(
            "/api/v1/auth/login",
            json={
                "username": "graduationviewer",
                "password": "GraduationViewerPassword123!",
            },
        )
        self.assertEqual(login.status_code, 200, login.text)
        viewer_headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
        denied = self.client.post(
            "/api/v1/users",
            headers=viewer_headers,
            json={"username": "forbidden", "password": "ForbiddenPassword123!"},
        )
        self.assertEqual(denied.status_code, 403)

        audit_page = self.client.get("/api/v1/admin/audit?limit=100", headers=self.headers)
        self.assertTrue(any(item["action"] == "self_register" for item in audit_page.json()["items"]))


    def test_admin_facade_rbac_lifecycle_last_admin_and_safe_audit(self) -> None:
        current = self.client.get("/api/v1/auth/me", headers=self.headers).json()
        protected = self.client.patch(
            f"/api/v1/admin/users/{current['id']}/role",
            headers=self.headers,
            json={"role": "analyst"},
        )
        self.assertEqual(protected.status_code, 409)

        created = self.client.post(
            "/api/v1/admin/users",
            headers=self.headers,
            json={
                "username": "phase3operator",
                "password": "InitialAdminPassword123!",
                "role": "viewer",
            },
        )
        self.assertEqual(created.status_code, 201, created.text)
        user_id = created.json()["id"]
        self.assertNotIn("password", created.json())
        self.assertNotIn("hash", created.json())

        duplicate = self.client.post(
            "/api/v1/admin/users",
            headers=self.headers,
            json={"username": "phase3operator", "password": "AnotherPassword123!", "role": "viewer"},
        )
        self.assertEqual(duplicate.status_code, 409)
        too_many = self.client.get("/api/v1/admin/users?limit=101", headers=self.headers)
        self.assertEqual(too_many.status_code, 422)

        role = self.client.patch(
            f"/api/v1/admin/users/{user_id}/role",
            headers=self.headers,
            json={"role": "analyst"},
        )
        inactive = self.client.patch(
            f"/api/v1/admin/users/{user_id}/active",
            headers=self.headers,
            json={"is_active": False},
        )
        reset = self.client.post(
            f"/api/v1/admin/users/{user_id}/password",
            headers=self.headers,
            json={"password": "ReplacementPassword123!"},
        )
        self.assertEqual(role.json()["role"], "analyst")
        self.assertFalse(inactive.json()["is_active"])
        self.assertNotIn("password", reset.text.lower())

        self.client.post(
            "/api/v1/admin/users", headers=self.headers,
            json={"username": "phase3viewer", "password": "ViewerPassword123!", "role": "viewer"},
        )
        viewer_login = self.client.post(
            "/api/v1/auth/login",
            json={"username": "phase3viewer", "password": "ViewerPassword123!"},
        )
        viewer_headers = {"Authorization": f"Bearer {viewer_login.json()['access_token']}"}
        denied = self.client.get("/api/v1/admin/users", headers=viewer_headers)
        self.assertEqual(denied.status_code, 403)

        audit_page = self.client.get("/api/v1/admin/audit?limit=100", headers=self.headers)
        self.assertEqual(audit_page.status_code, 200, audit_page.text)
        self.assertTrue(any(item["action"] == "admin_reset_user_password" for item in audit_page.json()["items"]))
        for item in audit_page.json()["items"]:
            self.assertEqual(set(item), {"id", "actor", "action", "target_type", "target_id", "outcome", "created_at"})
        self.assertNotIn("ReplacementPassword123!", audit_page.text)

    def test_external_control_routes_are_authenticated_and_frontend_ready(self) -> None:
        sources = [
            {
                "source_id": "cisa-kev",
                "name": "CISA KEV",
                "source_type": "vulnerability",
                "status": "enabled",
                "metadata": {},
            }
        ]
        job = {
            "schema_version": "1.0",
            "job_id": "job-1234567890",
            "command_id": "cmd-1234567890",
            "state": "queued",
            "created_at": "2026-08-29T00:00:00Z",
            "updated_at": "2026-08-29T00:00:00Z",
            "progress": {},
            "result": None,
            "error": None,
        }
        completed = {**job, "job_id": "job-ff5864df424d2bba4a28727b", "state": "completed",
                     "updated_at": "2026-09-16T18:17:21Z", "result": {"status": "completed",
                     "accepted_records": 3, "review_records": 1, "rejected_records": 0,
                     "skipped_records": 2, "error_count": 0}, "error": None}
        with patch("backend.app.api.v1.router.external_control_call", side_effect=[sources, job, completed]):
            unauthorized = self.client.get("/api/v1/integrations/external-control/sources")
            listed = self.client.get(
                "/api/v1/integrations/external-control/sources",
                headers=self.headers,
            )
            started = self.client.post(
                "/api/v1/integrations/external-control/jobs",
                headers=self.headers,
                json={"scope": "all_enabled", "force": False},
            )
            polled = self.client.get(
                "/api/v1/integrations/external-control/jobs/job-ff5864df424d2bba4a28727b",
                headers=self.headers,
            )

        self.assertEqual(unauthorized.status_code, 401)
        self.assertEqual(listed.json()[0]["source_id"], "cisa-kev")
        self.assertEqual(started.status_code, 202)
        self.assertEqual(started.json()["state"], "queued")
        self.assertEqual(polled.status_code, 200)
        self.assertEqual(polled.json()["job_id"], "job-ff5864df424d2bba4a28727b")
        self.assertEqual(polled.json()["result"]["accepted_records"], 3)

    def test_review_decision_imports_only_the_exact_approved_export(self) -> None:
        digest = "sha256:" + "a" * 64
        approved_client = unittest.mock.Mock()
        approved_client.decide_review.return_value = {
            "schema_version": "1.0", "record_id": "record-1234567890", "content_sha256": digest,
            "decision": "approved", "reason": None, "decided_at": "2026-09-20T00:00:00Z",
            "export_run_id": "ext-run-1234567890", "processing_state": "completed", "retryable": False,
        }
        with patch("backend.app.api.v1.router.external_control_client", return_value=approved_client), \
             patch("backend.app.api.v1.router.PipelineService.sync_external_run", return_value={"run_id": "central-run"}) as sync:
            approved = self.client.post("/api/v1/integrations/external-control/reviews/record-1234567890/decision",
                headers=self.headers, json={"expected_content_sha256": digest, "decision": "approved", "reason": None})
        self.assertEqual(approved.status_code, 200, approved.text)
        approved_client.decide_review.assert_called_once_with("record-1234567890", digest, "approved", None)
        sync.assert_called_once_with(approved_client, "ext-run-1234567890")

        rejected_client = unittest.mock.Mock()
        rejected_client.decide_review.return_value = {
            "schema_version": "1.0", "record_id": "record-1234567890", "content_sha256": digest,
            "decision": "rejected", "reason": "duplicate", "decided_at": "2026-09-20T00:00:00Z",
            "export_run_id": None, "processing_state": "completed", "retryable": False,
        }
        with patch("backend.app.api.v1.router.external_control_client", return_value=rejected_client), \
             patch("backend.app.api.v1.router.PipelineService.sync_external_run") as sync:
            rejected = self.client.post("/api/v1/integrations/external-control/reviews/record-1234567890/decision",
                headers=self.headers, json={"expected_content_sha256": digest, "decision": "rejected", "reason": "duplicate"})
        self.assertEqual(rejected.status_code, 200, rejected.text)
        rejected_client.decide_review.assert_called_once_with("record-1234567890", digest, "rejected", "duplicate")
        sync.assert_not_called()

    def test_correlation_projection_explains_safe_cross_source_evidence(self) -> None:
        with SessionLocal() as db:
            external_source = Source(
                id="correlation-external-source",
                name="External Evidence Feed",
                source_type="research",
                source_pipeline="external",
                enabled=True,
            )
            internal_source = Source(
                id="correlation-internal-source",
                name="Internal Honeypot",
                source_type="honeypot",
                source_pipeline="internal",
                enabled=True,
            )
            external_event = ThreatEvent(
                id="correlation-external-event",
                source_id=external_source.id,
                source_record_id="correlation-external-record",
                source_type="research",
                source_pipeline="external",
                title="External campaign evidence",
                description="Safe external context.",
                normalized_text="private external normalized text",
                severity="high",
                risk_score=82,
                confidence=0.9,
                processing_status="transformed",
            )
            internal_event = ThreatEvent(
                id="correlation-internal-event",
                source_id=internal_source.id,
                source_record_id="correlation-internal-record",
                source_type="honeypot",
                source_pipeline="internal",
                title="Private internal sensor title",
                description="private internal description",
                normalized_text="private internal normalized text",
                severity="medium",
                risk_score=64,
                confidence=0.8,
                processing_status="transformed",
            )
            exact_id = "40000000-0000-0000-0000-000000000001"
            similarity_id = "40000000-0000-0000-0000-000000000002"
            db.add_all([
                external_source,
                internal_source,
                external_event,
                internal_event,
                CorrelationRecord(
                    id=exact_id,
                    event_a_id=external_event.id,
                    event_b_id=internal_event.id,
                    correlation_type="simple_indicator_match",
                    score=1.0,
                    reason="same_domain",
                    evidence={
                        "indicator_type": "domain",
                        "values": ["command.example"],
                        "private": "must-not-leak",
                    },
                ),
                CorrelationRecord(
                    id=similarity_id,
                    event_a_id=external_event.id,
                    event_b_id=internal_event.id,
                    correlation_type="text_similarity",
                    score=0.75,
                    reason="similar_text",
                    evidence={
                        "backend": "tfidf_cosine",
                        "threshold": 0.35,
                        "private": "must-not-leak",
                    },
                ),
            ])
            db.commit()

        created = self.client.post(
            "/api/v1/users",
            headers=self.headers,
            json={"username": "correlationviewer", "password": "CorrelationViewerPassword123!", "role": "viewer"},
        )
        self.assertEqual(created.status_code, 201, created.text)
        login = self.client.post(
            "/api/v1/auth/login",
            json={"username": "correlationviewer", "password": "CorrelationViewerPassword123!"},
        )
        viewer_headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
        response = self.client.get("/api/v1/intelligence/correlations?limit=20", headers=viewer_headers)
        self.assertEqual(response.status_code, 200, response.text)
        by_id = {item["id"]: item for item in response.json()["items"]}

        exact = by_id[exact_id]
        self.assertTrue(exact["cross_source"])
        self.assertEqual(exact["score_basis"], "exact_observable_match")
        self.assertEqual(exact["evidence_status"], "available")
        self.assertEqual(exact["source_event"]["source_pipeline"], "external")
        self.assertEqual(exact["target_event"]["source_pipeline"], "internal")
        self.assertEqual(exact["target_event"]["title"], "Internal honeypot event")
        self.assertEqual(exact["factors"], [{"kind": "shared_observable", "label": "domain", "value": "command.example"}])

        similarity = by_id[similarity_id]
        self.assertEqual(similarity["score_basis"], "normalized_text_similarity")
        self.assertEqual(
            {(factor["kind"], factor["value"]) for factor in similarity["factors"]},
            {("algorithm", "tfidf_cosine"), ("threshold", "0.35")},
        )
        for forbidden in ("must-not-leak", "private internal", '"normalized_text":', '"evidence":'):
            self.assertNotIn(forbidden, response.text)


    def test_threat_storyline_is_bounded_chronological_and_private(self) -> None:
        observed_at = datetime(2026, 9, 7, 9, 55, tzinfo=timezone.utc)
        created_at = datetime(2026, 9, 7, 10, 0, tzinfo=timezone.utc)
        last_seen = datetime(2026, 9, 7, 10, 5, tzinfo=timezone.utc)
        with SessionLocal() as db:
            external_source = Source(
                id="storyline-external-source",
                name="Storyline Research Feed",
                source_type="research",
                source_pipeline="external",
                enabled=True,
            )
            internal_source = Source(
                id="storyline-internal-source",
                name="Storyline Honeypot",
                source_type="honeypot",
                source_pipeline="internal",
                enabled=True,
            )
            root_event = ThreatEvent(
                id="storyline-root-event",
                source_id=external_source.id,
                source_record_id="storyline-root-record",
                source_type="research",
                source_pipeline="external",
                title="PowerShell campaign T1059.001",
                description="An external report observed PowerShell infrastructure.",
                normalized_text="PowerShell campaign T1059.001 used command.example.",
                classification_label="cti_related",
                classification_confidence=0.91,
                severity="high",
                risk_score=78,
                confidence=0.9,
                processing_status="transformed",
                first_seen=observed_at,
                last_seen=last_seen,
                created_at=created_at,
                raw_reference={
                    "risk_factors": {
                        "base_severity_or_cvss": 28,
                        "indicators": 3,
                        "confidence": 9,
                        "private_factor": 99,
                    },
                    "risk_context": {
                        "source_count": 2,
                        "correlation_count": 1,
                        "private_context": "must-not-leak",
                    },
                    "secret": "must-not-leak",
                },
            )
            related_event = ThreatEvent(
                id="storyline-related-event",
                source_id=internal_source.id,
                source_record_id="storyline-related-record",
                source_type="honeypot",
                source_pipeline="internal",
                title="Private internal sensor title",
                description="Private internal sensor description",
                normalized_text="PowerShell private internal normalized telemetry",
                severity="medium",
                risk_score=62,
                confidence=0.8,
                processing_status="transformed",
                created_at=last_seen,
            )
            db.add_all([
                external_source,
                internal_source,
                root_event,
                related_event,
                IndicatorRecord(
                    id="50000000-0000-0000-0000-000000000001",
                    event_id=root_event.id,
                    indicator_type="domain",
                    value="command.example",
                    confidence=0.88,
                ),
                EntityRecord(
                    id="50000000-0000-0000-0000-000000000002",
                    event_id=root_event.id,
                    entity_type="threat_actor",
                    value="Nebula",
                    confidence=0.77,
                ),
                RelationshipRecord(
                    id="50000000-0000-0000-0000-000000000003",
                    event_id=root_event.id,
                    subject="Nebula",
                    relation="uses",
                    object_value="command.example",
                    confidence=0.76,
                ),
                CorrelationRecord(
                    id="50000000-0000-0000-0000-000000000004",
                    event_a_id=root_event.id,
                    event_b_id=related_event.id,
                    correlation_type="simple_indicator_match",
                    score=1.0,
                    reason="same_domain",
                    evidence={
                        "indicator_type": "domain",
                        "values": ["command.example"],
                        "private": "must-not-leak",
                    },
                    created_at=last_seen,
                ),
            ])
            db.commit()

        unauthorized = self.client.get(
            "/api/v1/intelligence/events/storyline-root-event/storyline"
        )
        response = self.client.get(
            "/api/v1/intelligence/events/storyline-root-event/storyline",
            headers=self.headers,
        )
        self.assertEqual(unauthorized.status_code, 401)
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(body["event"]["id"], "storyline-root-event")
        self.assertEqual(body["source_name"], "Storyline Research Feed")
        self.assertEqual(body["risk_method"], "deterministic_rule_score")
        self.assertEqual(
            {item["key"] for item in body["risk_factors"]},
            {"base_severity_or_cvss", "indicators", "confidence"},
        )
        self.assertEqual(body["risk_context"], {"source_count": 2, "correlation_count": 1})
        self.assertEqual(body["evidence_counts"]["correlations"], 1)
        self.assertEqual(body["observables"][0]["value"], "command.example")
        self.assertEqual(body["entities"][0]["value"], "Nebula")
        self.assertEqual(body["relationships"][0]["relation"], "uses")
        self.assertTrue(body["correlations"][0]["cross_source"])
        self.assertEqual(body["correlations"][0]["target_event"]["title"], "Internal honeypot event")
        self.assertEqual(body["attack"]["techniques"][0]["technique_id"], "T1059.001")
        internal_attack = self.client.get(
            "/api/v1/intelligence/events/storyline-related-event/attack",
            headers=self.headers,
        )
        internal_layer = self.client.get(
            "/api/v1/intelligence/events/storyline-related-event/attack-navigator",
            headers=self.headers,
        )
        self.assertEqual(internal_attack.status_code, 200, internal_attack.text)
        self.assertEqual(internal_layer.status_code, 200, internal_layer.text)
        self.assertEqual(internal_attack.json()["techniques"][0]["technique_id"], "T1059.001")
        self.assertIn("raw sensor evidence is hidden", internal_attack.json()["techniques"][0]["evidence"])
        self.assertIn("raw sensor evidence is hidden", internal_layer.json()["techniques"][0]["comment"])
        self.assertNotIn("Private internal", internal_attack.text)
        self.assertNotIn("Private internal", internal_layer.text)
        self.assertIn("internal_raw_telemetry_hidden", body["limitations"])
        dated = [item["occurred_at"] for item in body["milestones"] if item["occurred_at"]]
        self.assertEqual(dated, sorted(dated))
        self.assertFalse(body["evidence_truncated"])
        for forbidden in (
            "must-not-leak",
            "Private internal",
            "raw_reference",
            "normalized_text",
            "private_factor",
            "private_context",
        ):
            self.assertNotIn(forbidden, response.text)


    def test_dionaea_upload_persists_sessions_and_outlier_event(self) -> None:
        with DIONAEA_SAMPLE_PATH.open("rb") as handle:
            response = self.client.post(
                "/api/v1/uploads/dionaea",
                headers=self.headers,
                files={"file": ("dionaea.json", handle, "application/x-ndjson")},
            )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["collected_count"], 5)
        self.assertEqual(response.json()["details"]["source_type"], "dionaea")
        self.assertEqual(response.json()["details"]["session_count"], 5)
        self.assertEqual(response.json()["details"]["outlier_count"], 1)

        events = self.client.get("/api/v1/events?source_pipeline=internal", headers=self.headers)
        self.assertTrue(any(item["source_type"] == "dionaea_session" for item in events.json()))

        safe_events = self.client.get(
            "/api/v1/internal/sources/dionaea/events?limit=1&offset=0",
            headers=self.headers,
        )
        self.assertEqual(safe_events.status_code, 200, safe_events.text)
        page = safe_events.json()
        self.assertEqual(page["limit"], 1)
        self.assertGreaterEqual(page["total"], 1)
        self.assertEqual(page["items"][0]["integration"], "dionaea")
        self.assertNotIn("description", page["items"][0])
        self.assertNotIn("source_ip", page["items"][0])

    def test_internal_event_facade_is_bounded_and_viewer_pull_is_forbidden(self) -> None:
        missing = self.client.get(
            "/api/v1/internal/sources/unknown/events", headers=self.headers
        )
        too_large = self.client.get(
            "/api/v1/internal/sources/host-auth/events?limit=101", headers=self.headers
        )
        self.assertEqual(missing.status_code, 404)
        self.assertEqual(too_large.status_code, 422)

        created = self.client.post(
            "/api/v1/users",
            headers=self.headers,
            json={
                "username": "phase1viewer",
                "password": "StrongViewerPassword123!",
                "role": "viewer",
            },
        )
        self.assertIn(created.status_code, {201, 409})
        login = self.client.post(
            "/api/v1/auth/login",
            json={"username": "phase1viewer", "password": "StrongViewerPassword123!"},
        )
        viewer_headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
        listed = self.client.get(
            "/api/v1/internal/sources/web-access/events", headers=viewer_headers
        )
        self.assertEqual(listed.status_code, 200)
        with patch("backend.app.services.pipeline_service.PipelineService.run_security_sensor_api") as pull:
            forbidden = self.client.post(
                "/api/v1/integrations/web-access/pull", headers=viewer_headers
            )
        self.assertEqual(forbidden.status_code, 403)
        pull.assert_not_called()

        private_result = {
            "run_id": "12345678-1234-1234-1234-123456789012",
            "pipeline": "internal",
            "status": "completed",
            "collected_count": 2,
            "processed_count": 2,
            "stored_count": 1,
            "failed_count": 0,
            "details": {"checkpoint": "private", "upstream_path": "/var/log/private"},
        }
        with patch(
            "backend.app.services.pipeline_service.PipelineService.run_security_sensor_api",
            return_value=private_result,
        ):
            pulled = self.client.post(
                "/api/v1/integrations/web-access/pull", headers=self.headers
            )
        self.assertEqual(pulled.status_code, 200, pulled.text)
        self.assertEqual(
            set(pulled.json()),
            {"run_id", "pipeline", "status", "collected_count", "processed_count", "stored_count", "failed_count"},
        )
        self.assertNotIn("private", pulled.text)

    def test_global_intelligence_search_is_bounded_ranked_and_viewer_safe(self) -> None:
        with SessionLocal() as db:
            source = Source(
                id="search-source",
                name="Needle Intelligence Feed",
                source_type="research",
                source_pipeline="external",
                enabled=True,
                config={"private": "must-not-leak"},
            )
            event = ThreatEvent(
                id="search-event",
                source_id=source.id,
                source_record_id="search-record",
                source_type="research",
                source_pipeline="external",
                title="Needle Operation",
                description="Safe investigation context.",
                normalized_text="private normalized text",
                severity="high",
                risk_score=80,
                confidence=0.9,
                processing_status="transformed",
                raw_reference={"private": "must-not-leak"},
            )
            related = ThreatEvent(
                id="search-related-event",
                source_id=source.id,
                source_record_id="search-related-record",
                source_type="research",
                source_pipeline="external",
                title="Related Operation",
                description="Related safe context.",
                normalized_text="private related text",
                severity="medium",
                risk_score=50,
                confidence=0.8,
                processing_status="transformed",
            )
            db.add_all([
                source,
                event,
                related,
                IndicatorRecord(
                    id="10000000-0000-0000-0000-000000000001",
                    event_id=event.id,
                    indicator_type="domain",
                    value="needle.example",
                    confidence=0.95,
                    extractor="test",
                ),
                EntityRecord(
                    id="20000000-0000-0000-0000-000000000001",
                    event_id=event.id,
                    entity_type="malware",
                    value="Needle Malware",
                    confidence=0.88,
                    extractor="test",
                ),
                EntityRecord(
                    id="20000000-0000-0000-0000-000000000002",
                    event_id=event.id,
                    entity_type="source_ip",
                    value="needle-private-source",
                    confidence=0.99,
                    extractor="test",
                ),
                CorrelationRecord(
                    id="30000000-0000-0000-0000-000000000001",
                    event_a_id=event.id,
                    event_b_id=related.id,
                    correlation_type="cross_source",
                    score=0.92,
                    reason="Shared needle evidence",
                    evidence={"private": "must-not-leak"},
                ),
            ])
            db.commit()

        created = self.client.post(
            "/api/v1/users", headers=self.headers,
            json={"username": "searchviewer", "password": "SearchViewerPassword123!", "role": "viewer"},
        )
        self.assertIn(created.status_code, {201, 409})
        login = self.client.post(
            "/api/v1/auth/login",
            json={"username": "searchviewer", "password": "SearchViewerPassword123!"},
        )
        viewer_headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

        self.assertEqual(self.client.get("/api/v1/intelligence/search?q=needle").status_code, 401)
        response = self.client.get(
            "/api/v1/intelligence/search?q=needle&limit_per_type=1", headers=viewer_headers
        )
        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        self.assertEqual(payload["query"], "needle")
        self.assertEqual(payload["returned"], len(payload["items"]))
        self.assertLessEqual(payload["returned"], 5)
        self.assertEqual({item["kind"] for item in payload["items"]}, {"event", "indicator", "entity", "source", "correlation"})
        ranks = {"exact": 0, "prefix": 1, "contains": 2}
        self.assertEqual([ranks[item["match_quality"]] for item in payload["items"]], sorted(ranks[item["match_quality"]] for item in payload["items"]))
        self.assertNotIn("needle-private-source", response.text)
        for forbidden in ('"raw_reference":', '"normalized_text":', '"config":', '"evidence":', "must-not-leak"):
            self.assertNotIn(forbidden, response.text)

        exact = self.client.get(
            "/api/v1/intelligence/search?q=needle.example&limit_per_type=1", headers=viewer_headers
        )
        self.assertEqual(exact.status_code, 200, exact.text)
        self.assertEqual(exact.json()["items"][0]["kind"], "indicator")
        self.assertEqual(exact.json()["items"][0]["match_quality"], "exact")
        self.assertEqual(self.client.get("/api/v1/intelligence/search?q=a", headers=viewer_headers).status_code, 422)
        self.assertEqual(self.client.get("/api/v1/intelligence/search?q=%20%20", headers=viewer_headers).status_code, 422)
        self.assertEqual(self.client.get("/api/v1/intelligence/search?q=needle&limit_per_type=11", headers=viewer_headers).status_code, 422)
        wildcard = self.client.get("/api/v1/intelligence/search?q=%25_", headers=viewer_headers)
        self.assertEqual(wildcard.status_code, 200, wildcard.text)
        self.assertEqual(wildcard.json()["returned"], 0)

    def test_intelligence_facades_are_bounded_typed_and_sanitized(self) -> None:
        events = self.client.get(
            "/api/v1/intelligence/events?source_pipeline=internal&limit=1&offset=0",
            headers=self.headers,
        )
        self.assertEqual(events.status_code, 200, events.text)
        page = events.json()
        self.assertEqual(page["limit"], 1)
        self.assertNotIn("raw_reference", page["items"][0])
        self.assertNotIn("normalized_text", page["items"][0])

        event_id = page["items"][0]["id"]
        detail = self.client.get(
            f"/api/v1/intelligence/events/{event_id}", headers=self.headers
        )
        self.assertEqual(detail.status_code, 200, detail.text)
        self.assertFalse(any(item["type"] == "source_ip" for item in detail.json()["entities"]))
        self.assertEqual(detail.json()["relationships"], [])

        for path in ("indicators", "correlations", "outliers", "runs"):
            response = self.client.get(
                f"/api/v1/intelligence/{path}?limit=101", headers=self.headers
            )
            self.assertEqual(response.status_code, 422, path)
        runs = self.client.get("/api/v1/intelligence/runs?limit=1", headers=self.headers)
        self.assertNotIn("details", runs.json()["items"][0])
        self.assertNotIn("error_message", runs.json()["items"][0])
        indicators = self.client.get("/api/v1/intelligence/indicators?limit=1", headers=self.headers)
        self.assertEqual(indicators.status_code, 200, indicators.text)
        self.assertTrue({"semantic_role", "validation_status", "assessment", "actionable", "reason_code"}.issubset(indicators.json()["items"][0]))
        summary = self.client.get("/api/v1/intelligence/indicators-summary", headers=self.headers)
        self.assertEqual(summary.status_code, 200, summary.text)
        self.assertEqual(summary.json()["total"], sum(summary.json()["by_role"].values()))

        attack = self.client.get(
            f"/api/v1/intelligence/events/{event_id}/attack", headers=self.headers
        )
        self.assertEqual(attack.status_code, 200, attack.text)
        self.assertEqual(attack.json()["source"], "built_in_subset")
        self.assertIn("attack-stix-data", attack.json()["official_dataset_url"])

        ml = self.client.get("/api/v1/intelligence/ml/status", headers=self.headers)
        self.assertEqual(ml.json()["execution_model"], "central_backend")
        self.assertNotIn("load_error", ml.json())
        health = self.client.get("/api/v1/intelligence/misp/health", headers=self.headers)
        self.assertEqual(set(health.json()), {"configured", "reachable"})


    def test_ml_status_projects_runtime_quality_evidence_and_limitations(self) -> None:
        quality_gates = {
            "bert_artifact_present": True,
            "secondary_artifact_present": True,
            "bert_test_f1_at_least_0_75": True,
            "bert_test_accuracy_at_least_0_90": True,
            "primary_outperforms_secondary_entity_f1": True,
            "bert_unique_unseen_f1_at_least_0_73": True,
            "dataset_cross_split_overlap_zero": False,
            "dataset_label_conflicts_zero": True,
            "dataset_malformed_lines_zero": True,
        }
        evidence = {
            "runtime": {
                "last_batch_input_count": 2,
                "last_batch_chunk_count": 3,
                "backend": "transformer",
                "primary_model_loaded": True,
                "secondary_fallback_loaded": False,
            },
            "model_priority": {
                "primary": "dnrti_bert_ner",
                "secondary_fallback": "dnrti_sklearn_ner",
            },
            "held_out_test": {
                "bert": {"f1": 0.8},
                "bert_unique_unseen": {"f1": 0.76},
            },
            "quality_gates": quality_gates,
            "all_quality_gates_passed": False,
        }
        with patch(
            "backend.app.api.v1.router.ModelEvidenceService.status",
            return_value=evidence,
        ):
            response = self.client.get(
                "/api/v1/intelligence/ml/status", headers=self.headers
            )
        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        self.assertEqual(payload["runtime_state"], "primary_active")
        self.assertEqual(
            payload["inference_evidence"],
            {"observed": True, "input_count": 2, "chunk_count": 3},
        )
        self.assertEqual(payload["readiness"], "degraded")
        self.assertEqual(payload["inference_scope"], "named_entity_recognition")
        self.assertEqual(payload["metric_scope"], "saved_offline_evaluation")
        self.assertEqual(payload["unique_unseen_f1"], 0.76)
        self.assertEqual(
            [item["key"] for item in payload["quality_gates"]],
            list(quality_gates),
        )
        self.assertFalse(payload["quality_gates"][6]["passed"])
        self.assertEqual(
            payload["limitations"],
            [
                "saved_metrics_not_live_accuracy",
                "quality_gates_incomplete",
                "fallback_unavailable",
            ],
        )

    def test_ml_status_distinguishes_fallback_and_unavailable_runtime(self) -> None:
        gate_keys = (
            "bert_artifact_present",
            "secondary_artifact_present",
            "bert_test_f1_at_least_0_75",
            "bert_test_accuracy_at_least_0_90",
            "primary_outperforms_secondary_entity_f1",
            "bert_unique_unseen_f1_at_least_0_73",
            "dataset_cross_split_overlap_zero",
            "dataset_label_conflicts_zero",
            "dataset_malformed_lines_zero",
        )
        base_evidence = {
            "model_priority": {
                "primary": "dnrti_bert_ner",
                "secondary_fallback": "dnrti_sklearn_ner",
            },
            "held_out_test": {
                "bert": {"f1": 0.8},
                "bert_unique_unseen": {"f1": 0.76},
            },
            "quality_gates": dict.fromkeys(gate_keys, True),
            "all_quality_gates_passed": True,
        }
        cases = (
            (
                {"backend": "sklearn", "primary_model_loaded": False, "secondary_fallback_loaded": True},
                "secondary_fallback_active",
                "degraded",
                ["saved_metrics_not_live_accuracy", "primary_unavailable"],
            ),
            (
                {"backend": "unavailable", "primary_model_loaded": False, "secondary_fallback_loaded": False},
                "unavailable",
                "unavailable",
                ["saved_metrics_not_live_accuracy", "primary_unavailable", "fallback_unavailable"],
            ),
        )
        for runtime, expected_state, expected_readiness, expected_limitations in cases:
            with self.subTest(runtime_state=expected_state), patch(
                "backend.app.api.v1.router.ModelEvidenceService.status",
                return_value={**base_evidence, "runtime": runtime},
            ):
                response = self.client.get(
                    "/api/v1/intelligence/ml/status", headers=self.headers
                )
                self.assertEqual(response.status_code, 200, response.text)
                payload = response.json()
                self.assertEqual(payload["runtime_state"], expected_state)
                self.assertEqual(payload["readiness"], expected_readiness)
                self.assertEqual(payload["limitations"], expected_limitations)
                self.assertEqual(
                    payload["inference_evidence"],
                    {"observed": False, "input_count": 0, "chunk_count": 0},
                )

    def test_misp_candidates_batch_delivery_and_durable_outcomes(self) -> None:
        ready_id = "misp-batch-ready"
        blocked_id = "misp-batch-blocked"
        with SessionLocal() as db:
            db.add_all(
                [
                    ThreatEvent(
                        id=ready_id,
                        source_record_id="misp-ready-record",
                        source_type="research",
                        source_pipeline="external",
                        title="MISP batch ready candidate",
                        description="Safe sharing candidate.",
                        normalized_text="",
                        severity="high",
                        risk_score=88,
                        confidence=0.9,
                        processing_status="transformed",
                    ),
                    ThreatEvent(
                        id=blocked_id,
                        source_record_id="misp-blocked-record",
                        source_type="research",
                        source_pipeline="external",
                        title="MISP batch blocked candidate",
                        description="No transferable attributes.",
                        normalized_text="",
                        severity="low",
                        risk_score=12,
                        confidence=0.5,
                        processing_status="transformed",
                    ),
                    IndicatorRecord(
                        id="40000000-0000-0000-0000-000000000001",
                        event_id=ready_id,
                        indicator_type="domain",
                        value="batch-security.org",
                        confidence=0.95,
                        extractor="test",
                    ),
                ]
            )
            db.commit()

        send_calls: list[str] = []

        class FakeMISPClient:
            configured = True

            def event_payload(self, event):
                ready = event.id == ready_id
                attributes = (
                    [
                        {
                            "type": "domain",
                            "category": "Network activity",
                            "value": "batch-security.org",
                            "to_ids": False,
                        }
                    ]
                    if ready
                    else []
                )
                omitted = {
                    "external_reference": 0,
                    "invalid": 0,
                    "non_actionable": 0 if ready else 1,
                    "unsupported": 0,
                }
                return {
                    "Event": {"Attribute": attributes, "Tag": []},
                    "cti_filtering": {
                        "included": len(attributes),
                        "omitted": sum(omitted.values()),
                        "omitted_by_reason": omitted,
                    },
                }

            def send_event(self, event, dry_run=True):
                self.assert_false_if_dry_run(dry_run)
                send_calls.append(event.id)
                return {
                    "cti_delivery": {
                        "created": True,
                        "event_id": "42",
                        "event_uuid": "11111111-1111-4111-8111-111111111111",
                        "attributes_requested": 1,
                        "attributes_added": 1,
                        "attributes_verified": 1,
                        "published": False,
                    }
                }

            @staticmethod
            def assert_false_if_dry_run(dry_run):
                if dry_run:
                    raise AssertionError("batch delivery must not be a dry run")

        viewer_created = self.client.post(
            "/api/v1/users",
            headers=self.headers,
            json={
                "username": "mispbatchviewer",
                "password": "MispBatchViewerPassword123!",
                "role": "viewer",
            },
        )
        self.assertEqual(viewer_created.status_code, 201, viewer_created.text)
        viewer_login = self.client.post(
            "/api/v1/auth/login",
            json={
                "username": "mispbatchviewer",
                "password": "MispBatchViewerPassword123!",
            },
        )
        viewer_headers = {
            "Authorization": f"Bearer {viewer_login.json()['access_token']}"
        }

        with patch("backend.app.api.v1.router.MISPClient", return_value=FakeMISPClient()):
            candidates = self.client.get(
                "/api/v1/intelligence/misp/candidates",
                headers=self.headers,
                params={"search": "MISP batch", "limit": 10},
            )
            self.assertEqual(candidates.status_code, 200, candidates.text)
            by_id = {item["event_id"]: item for item in candidates.json()["items"]}
            self.assertTrue(by_id[ready_id]["ready"])
            self.assertEqual(by_id[ready_id]["readiness_reason"], "ready")
            self.assertFalse(by_id[blocked_id]["ready"])
            self.assertEqual(
                by_id[blocked_id]["readiness_reason"],
                "no_transferable_attributes",
            )

            forbidden = self.client.post(
                "/api/v1/intelligence/misp/batch",
                headers=viewer_headers,
                json={"event_ids": [ready_id], "confirm_unpublished": True},
            )
            self.assertEqual(forbidden.status_code, 403)
            self.assertEqual(send_calls, [])
            self.assertEqual(
                self.client.post(
                    "/api/v1/intelligence/misp/batch",
                    headers=self.headers,
                    json={"event_ids": [ready_id], "confirm_unpublished": False},
                ).status_code,
                422,
            )

            delivered = self.client.post(
                "/api/v1/intelligence/misp/batch",
                headers=self.headers,
                json={
                    "event_ids": [
                        ready_id,
                        blocked_id,
                        "misp-batch-missing",
                        ready_id,
                    ],
                    "confirm_unpublished": True,
                },
            )
            self.assertEqual(delivered.status_code, 200, delivered.text)
            payload = delivered.json()
            self.assertEqual(payload["requested"], 3)
            self.assertEqual(payload["delivered"], 1)
            self.assertEqual(payload["skipped"], 2)
            self.assertEqual(payload["failed"], 0)
            self.assertEqual(payload["published"], 0)
            self.assertEqual(send_calls, [ready_id])
            results = {item["event_id"]: item for item in payload["items"]}
            self.assertEqual(results[ready_id]["misp_event_id"], "42")
            self.assertEqual(results[blocked_id]["reason"], "no_transferable_attributes")
            self.assertEqual(results["misp-batch-missing"]["reason"], "event_not_found")

            refreshed = self.client.get(
                "/api/v1/intelligence/misp/candidates",
                headers=self.headers,
                params={"search": "MISP batch", "limit": 10},
            )
            refreshed_by_id = {
                item["event_id"]: item for item in refreshed.json()["items"]
            }
            self.assertEqual(refreshed_by_id[ready_id]["delivery_count"], 1)
            self.assertEqual(refreshed_by_id[ready_id]["last_misp_event_id"], "42")

        history = self.client.get(
            "/api/v1/intelligence/misp/deliveries?limit=100",
            headers=self.headers,
        )
        self.assertEqual(history.status_code, 200, history.text)
        recorded = {
            (item["event_id"], item["status"], item.get("reason"))
            for item in history.json()["items"]
        }
        self.assertIn((ready_id, "delivered", None), recorded)
        self.assertIn(
            (blocked_id, "skipped", "no_transferable_attributes"),
            recorded,
        )
        self.assertIn(("misp-batch-missing", "skipped", "event_not_found"), recorded)

    def test_misp_preview_is_read_only_and_send_remains_admin_only(self) -> None:
        event_id = "misp-single-ready"
        with SessionLocal() as db:
            db.add_all(
                [
                    ThreatEvent(
                        id=event_id,
                        source_record_id="misp-single-record",
                        source_type="research",
                        source_pipeline="external",
                        title="Single MISP delivery candidate",
                        description="Safe sharing candidate.",
                        normalized_text="",
                        severity="medium",
                        risk_score=55,
                        confidence=0.8,
                        processing_status="transformed",
                    ),
                    IndicatorRecord(
                        id="70000000-0000-0000-0000-000000000001",
                        event_id=event_id,
                        indicator_type="domain",
                        value="single-security.org",
                        confidence=0.95,
                        extractor="test",
                    ),
                ]
            )
            db.commit()
        preview = self.client.get(
            f"/api/v1/intelligence/events/{event_id}/misp-preview", headers=self.headers
        )
        self.assertEqual(preview.status_code, 200, preview.text)
        self.assertFalse(preview.json()["published"])
        self.assertEqual(preview.json()["distribution"], 0)
        self.assertEqual(preview.json()["included"], len(preview.json()["attributes"]))
        self.assertIn("omitted_by_reason", preview.json())
        self.assertNotIn("uuid", preview.json())

        viewer_created = self.client.post(
            "/api/v1/users", headers=self.headers,
            json={"username": "phase1viewer", "password": "StrongViewerPassword123!", "role": "viewer"},
        )
        self.assertIn(viewer_created.status_code, {201, 409})
        login = self.client.post(
            "/api/v1/auth/login",
            json={"username": "phase1viewer", "password": "StrongViewerPassword123!"},
        )
        viewer_headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
        with patch("backend.app.api.v1.router.MISPClient.send_event") as send:
            forbidden = self.client.post(
                f"/api/v1/intelligence/events/{event_id}/misp", headers=viewer_headers
            )
        self.assertEqual(forbidden.status_code, 403)
        send.assert_not_called()

        analyst_created = self.client.post(
            "/api/v1/users", headers=self.headers,
            json={"username": "phase2analyst", "password": "StrongAnalystPassword123!", "role": "analyst"},
        )
        self.assertIn(analyst_created.status_code, {201, 409})
        analyst_login = self.client.post(
            "/api/v1/auth/login",
            json={"username": "phase2analyst", "password": "StrongAnalystPassword123!"},
        )
        analyst_headers = {"Authorization": f"Bearer {analyst_login.json()['access_token']}"}
        analyst_preview = self.client.get(
            f"/api/v1/intelligence/events/{event_id}/misp-preview", headers=analyst_headers
        )
        analyst_send = self.client.post(
            f"/api/v1/intelligence/events/{event_id}/misp", headers=analyst_headers
        )
        self.assertEqual(analyst_preview.status_code, 200)
        self.assertEqual(analyst_send.status_code, 403)

        delivery = {"cti_delivery": {"created": True, "attributes_requested": 2, "attributes_added": 2, "attributes_verified": 2, "published": False}}
        with patch("backend.app.api.v1.router.MISPClient.send_event", return_value=delivery):
            sent = self.client.post(
                f"/api/v1/intelligence/events/{event_id}/misp", headers=self.headers
            )
        self.assertEqual(sent.status_code, 200, sent.text)
        self.assertEqual(sent.json()["attributes_verified"], 2)
        self.assertNotIn("Event", sent.json())
        history = self.client.get(
            "/api/v1/intelligence/misp/deliveries", headers=self.headers
        )
        self.assertEqual(history.status_code, 200, history.text)
        self.assertEqual(history.json()["items"][0]["attributes_verified"], 2)

        with patch(
            "backend.app.api.v1.router.MISPClient.send_event",
            side_effect=RuntimeError("token=top-secret http://10.0.0.4/internal"),
        ):
            failed = self.client.post(
                f"/api/v1/events/{event_id}/misp",
                headers=self.headers,
                json={"dry_run": False},
            )
        self.assertEqual(failed.status_code, 502)
        self.assertNotIn("top-secret", failed.text)
        self.assertNotIn("10.0.0.4", failed.text)

    def test_wazuh_upload_dashboard_stix_and_misp_dry_run(self) -> None:
        with SAMPLE_PATH.open("rb") as handle:
            response = self.client.post(
                "/api/v1/uploads/wazuh",
                headers=self.headers,
                files={"file": ("wazuh_alerts.json", handle, "application/json")},
            )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["collected_count"], 8)

        events = self.client.get("/api/v1/events", headers=self.headers)
        dashboard = self.client.get("/api/v1/dashboard/summary", headers=self.headers)
        outliers = self.client.get("/api/v1/outliers?only_outliers=true", headers=self.headers)
        self.assertGreaterEqual(len(events.json()), 1)
        self.assertGreaterEqual(dashboard.json()["outliers"], 1)
        self.assertGreaterEqual(len(outliers.json()), 1)

        counts_before_repeat = {
            "events": dashboard.json()["events"],
            "indicators": dashboard.json()["indicators"],
            "sessions": dashboard.json()["sessions"],
            "outliers": dashboard.json()["outliers"],
        }
        with SAMPLE_PATH.open("rb") as handle:
            repeated = self.client.post(
                "/api/v1/uploads/wazuh",
                headers=self.headers,
                files={"file": ("wazuh_alerts.json", handle, "application/json")},
            )
        repeated_dashboard = self.client.get("/api/v1/dashboard/summary", headers=self.headers)
        self.assertEqual(repeated.status_code, 200, repeated.text)
        self.assertEqual(repeated.json()["collected_count"], 8)
        self.assertEqual(
            {
                "events": repeated_dashboard.json()["events"],
                "indicators": repeated_dashboard.json()["indicators"],
                "sessions": repeated_dashboard.json()["sessions"],
                "outliers": repeated_dashboard.json()["outliers"],
            },
            counts_before_repeat,
        )

        event_id = events.json()[0]["id"]
        stix = self.client.get(f"/api/v1/events/{event_id}/stix", headers=self.headers)
        misp = self.client.post(
            f"/api/v1/events/{event_id}/misp",
            headers=self.headers,
            json={"dry_run": True},
        )
        self.assertEqual(stix.json()["type"], "bundle")
        parsed_bundle = parse_stix(stix.json(), allow_custom=False)
        self.assertGreaterEqual(len(parsed_bundle.objects), 2)
        self.assertTrue(misp.json()["dry_run"])


if __name__ == "__main__":
    unittest.main()
