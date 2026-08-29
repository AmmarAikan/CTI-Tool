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
