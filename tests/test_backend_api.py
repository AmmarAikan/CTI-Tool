from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

TEST_DIRECTORY = Path(tempfile.mkdtemp(prefix="cti_backend_test_"))
os.environ["DATABASE_URL"] = f"sqlite:///{(TEST_DIRECTORY / 'test.db').as_posix()}"
os.environ["UPLOAD_DIR"] = str(TEST_DIRECTORY / "uploads")
os.environ["JWT_SECRET"] = "test-only-secret-that-is-long-enough"

from fastapi.testclient import TestClient
from stix2 import parse as parse_stix

from backend.app.main import app

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
        cls.client_context.__exit__(None, None, None)
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
        with patch("backend.app.api.v1.router.external_control_call", side_effect=[sources, job]):
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

        self.assertEqual(unauthorized.status_code, 401)
        self.assertEqual(listed.json()[0]["source_id"], "cisa-kev")
        self.assertEqual(started.status_code, 202)
        self.assertEqual(started.json()["state"], "queued")

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

    def test_misp_preview_is_read_only_and_send_remains_admin_only(self) -> None:
        events = self.client.get("/api/v1/intelligence/events?limit=1", headers=self.headers).json()
        event_id = events["items"][0]["id"]
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
