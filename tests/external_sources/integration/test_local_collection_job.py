from __future__ import annotations

import importlib
import logging
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.app.pipeline.ingestion.external.application.collection_service import SourceExecutionResult
from backend.app.pipeline.ingestion.external.common.hashing import sha256_text
from backend.app.pipeline.ingestion.external.common.models import ExternalCTIItem, ExternalClassification
from backend.app.pipeline.ingestion.external.integration.api import API_PREFIX


class RecordingExecutor:
    def __init__(self, results=None, error: Exception | None = None) -> None:
        self.results = results or {}
        self.error = error
        self.calls = []

    def execute(self, source, *, force, command_id):
        self.calls.append((source.source_id, force, command_id))
        if self.error:
            raise self.error
        return self.results.get(source.source_id, SourceExecutionResult(source.source_id, "completed", accepted_records=1))


def export_item(identity: str, *, classification="not_required") -> ExternalCTIItem:
    content = f"Sanitized security advisory content for {identity}."
    return ExternalCTIItem(record_id="input-" + sha256_text(identity).split(":", 1)[1][:32], source_item_id=identity,
        source="Test Source", source_type="rss", category="cti", title="Test advisory", link=f"https://example.test/{identity}",
        content=content, summary=content, collected_at="2026-08-25T12:00:00Z", content_hash=sha256_text(content),
        classification=ExternalClassification(status=classification))


class FailingExportCoordinator:
    def export(self, run_id, started_at, results):
        raise OSError("private filesystem path must not escape")


class LocalCollectionJobTests(unittest.TestCase):
    @staticmethod
    def _wait(client: TestClient, job_id: str, headers: dict[str, str]) -> dict:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            value = client.get(f"{API_PREFIX}/jobs/{job_id}", headers=headers).json()
            if value["state"] in {"completed", "partial", "failed", "cancelled"}:
                return value
            time.sleep(0.01)
        raise AssertionError("collection job did not reach a terminal state")

    def _build(self, root: Path, executor: RecordingExecutor):
        environment = {"EXTERNAL_API_TOKEN": "collection-test-token", "EXTERNAL_API_ROLES": "operator", "EXTERNAL_API_DEV_WORKERS": "1"}
        with patch.dict(os.environ, environment):
            local = importlib.import_module("backend.app.pipeline.ingestion.external.integration.local")
            return local.build_local_app(collection_executor=executor, state_directory=root / "state",
                                         dark_web_config_path=root / "missing-dark-web.json",
                                         processed_directory=root / "processed", review_directory=root / "review",
                                         exports_directory=root / "exports", export_state_path=root / "state" / "exports.json",
                                         manual_checkpoint_path=root / "state" / "manual_checkpoints.json",
                                         manual_state_path=root / "state" / "manual.json", log_path=root / "logs" / "cti_tool.log")

    @staticmethod
    def _headers():
        return {"Authorization": "Bearer collection-test-token"}

    def test_multiple_registered_sources_complete_in_one_job(self):
        executor = RecordingExecutor()
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); app = self._build(root, executor); client = TestClient(app)
            accepted = client.post(f"{API_PREFIX}/jobs", json={"source_ids": ["the-hacker-news", "cisco-talos"]}, headers=self._headers())
            self.assertEqual((accepted.status_code, accepted.json()["state"]), (202, "queued"))
            terminal = self._wait(client, accepted.json()["job_id"], self._headers())
            self.assertEqual((terminal["state"], terminal["result"]["source_count"], terminal["result"]["accepted_records"]), ("completed", 2, 2))
            self.assertEqual([call[0] for call in executor.calls], ["the-hacker-news", "cisco-talos"])
            self._close(app, root)

    def test_unknown_source_is_documented_404_before_job_creation(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); app = self._build(root, RecordingExecutor()); client = TestClient(app)
            response = client.post(f"{API_PREFIX}/jobs", json={"source_ids": ["not-registered"]}, headers=self._headers())
            self.assertEqual((response.status_code, response.json()["code"]), (404, "source_not_found"))
            schema = client.get("/openapi.json").json() if client.get("/openapi.json").status_code == 200 else None
            self.assertIsNone(schema)
            self._close(app, root)

    def test_partial_source_failure_keeps_successful_source(self):
        executor = RecordingExecutor({
            "the-hacker-news": SourceExecutionResult("the-hacker-news", "completed", accepted_records=2),
            "cisco-talos": SourceExecutionResult("cisco-talos", "failed", error_count=1),
        })
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); app = self._build(root, executor); client = TestClient(app)
            accepted = client.post(f"{API_PREFIX}/jobs", json={"source_ids": ["the-hacker-news", "cisco-talos"]}, headers=self._headers()).json()
            terminal = self._wait(client, accepted["job_id"], self._headers())
            self.assertEqual((terminal["state"], terminal["result"]["status"]), ("partial", "partial"))
            self.assertEqual(terminal["result"]["accepted_records"], 2)
            self.assertEqual(terminal["result"]["sources"]["cisco-talos"]["status"], "failed")
            self._close(app, root)

    def test_force_mode_is_propagated_to_every_source(self):
        executor = RecordingExecutor()
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); app = self._build(root, executor); client = TestClient(app)
            accepted = client.post(f"{API_PREFIX}/jobs", json={"source_ids": ["the-hacker-news", "cisco-talos"], "force": True}, headers=self._headers()).json()
            terminal = self._wait(client, accepted["job_id"], self._headers())
            self.assertTrue(terminal["result"]["force"])
            self.assertTrue(all(call[1] for call in executor.calls))
            self._close(app, root)

    def test_internal_orchestration_failure_becomes_safe_failed_job(self):
        executor = RecordingExecutor(error=RuntimeError("token=do-not-return content=do-not-return"))
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); app = self._build(root, executor); client = TestClient(app)
            accepted = client.post(f"{API_PREFIX}/jobs", json={"source_ids": ["the-hacker-news"]}, headers=self._headers()).json()
            terminal = self._wait(client, accepted["job_id"], self._headers())
            self.assertEqual((terminal["state"], terminal["error"]["code"]), ("failed", "job_failed"))
            self.assertNotIn("do-not-return", str(terminal))
            self._close(app, root)

    def test_manual_source_identifier_is_rejected_from_collection_command(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); app = self._build(root, RecordingExecutor()); client = TestClient(app)
            response = client.post(f"{API_PREFIX}/jobs", json={"source_ids": ["manual-url"]}, headers=self._headers())
            self.assertEqual((response.status_code, response.json()["code"]), (409, "manual_source_route_required"))
            self._close(app, root)

    def test_successful_run_exports_only_its_records_and_latest_returns_dataset_and_manifest(self):
        first = export_item("guid-run-one")
        executor = RecordingExecutor({"the-hacker-news": SourceExecutionResult(
            "the-hacker-news", "completed", accepted_records=1, accepted=(first,))})
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); app = self._build(root, executor); client = TestClient(app)
            accepted = client.post(f"{API_PREFIX}/jobs", json={"source_ids": ["the-hacker-news"]}, headers=self._headers()).json()
            terminal = self._wait(client, accepted["job_id"], self._headers())
            run_id = terminal["result"]["run_id"]
            self.assertEqual(terminal["result"]["export"]["status"], "completed")
            latest = client.get(f"{API_PREFIX}/exports/latest", headers=self._headers())
            self.assertEqual(latest.status_code, 200)
            self.assertEqual(latest.json()["run_id"], run_id)
            self.assertEqual([value["source_item_id"] for value in latest.json()["dataset"]], ["guid-run-one"])
            self.assertEqual(latest.json()["manifest"]["run_id"], run_id)
            self.assertTrue((root / "exports" / f"final_dataset_{run_id}.json").exists())
            self.assertTrue((root / "exports" / f"external_export_manifest_{run_id}.json").exists())
            self._close(app, root)

    def test_empty_run_produces_valid_empty_export(self):
        executor = RecordingExecutor({"the-hacker-news": SourceExecutionResult("the-hacker-news", "completed")})
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); app = self._build(root, executor); client = TestClient(app)
            queued = client.post(f"{API_PREFIX}/jobs", json={"source_ids": ["the-hacker-news"]}, headers=self._headers()).json()
            terminal = self._wait(client, queued["job_id"], self._headers())
            latest = client.get(f"{API_PREFIX}/exports/latest", headers=self._headers()).json()
            self.assertEqual((terminal["state"], latest["dataset"], latest["accepted_records"]), ("completed", [], 0))
            self._close(app, root)

    def test_review_records_are_preserved_in_run_review_artifact(self):
        review = export_item("guid-review", classification="error")
        executor = RecordingExecutor({"the-hacker-news": SourceExecutionResult(
            "the-hacker-news", "completed", review_records=1, review=(review,))})
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); app = self._build(root, executor); client = TestClient(app)
            queued = client.post(f"{API_PREFIX}/jobs", json={"source_ids": ["the-hacker-news"]}, headers=self._headers()).json()
            terminal = self._wait(client, queued["job_id"], self._headers())
            run_id = terminal["result"]["run_id"]
            review_path = root / "review" / f"external_review_{run_id}.json"
            self.assertTrue(review_path.exists())
            self.assertIn("collector_review", review_path.read_text(encoding="utf-8"))
            self.assertEqual(client.get(f"{API_PREFIX}/exports/latest", headers=self._headers()).json()["review_records"], 1)
            self._close(app, root)

    def test_export_failure_keeps_collection_completed_and_returns_safe_export_error(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            environment = {"EXTERNAL_API_TOKEN": "collection-test-token", "EXTERNAL_API_ROLES": "operator"}
            with patch.dict(os.environ, environment):
                local = importlib.import_module("backend.app.pipeline.ingestion.external.integration.local")
                app = local.build_local_app(collection_executor=RecordingExecutor(), collection_exporter=FailingExportCoordinator(),
                    dark_web_config_path=root / "missing-dark-web.json",
                    state_directory=root / "state", processed_directory=root / "processed", review_directory=root / "review",
                    exports_directory=root / "exports", export_state_path=root / "state" / "exports.json",
                    manual_checkpoint_path=root / "state" / "manual_checkpoints.json",
                    manual_state_path=root / "state" / "manual.json", log_path=root / "logs" / "cti_tool.log")
            client = TestClient(app)
            queued = client.post(f"{API_PREFIX}/jobs", json={"source_ids": ["the-hacker-news"]}, headers=self._headers()).json()
            terminal = self._wait(client, queued["job_id"], self._headers())
            self.assertEqual((terminal["state"], terminal["result"]["export"]["error"]["code"]), ("completed", "export_failed"))
            self.assertNotIn("private filesystem", str(terminal))
            self.assertEqual(client.get(f"{API_PREFIX}/exports/latest", headers=self._headers()).status_code, 404)
            self._close(app, root)

    def test_latest_export_404_is_documented(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); app = self._build(root, RecordingExecutor()); client = TestClient(app)
            response = client.get(f"{API_PREFIX}/exports/latest", headers=self._headers())
            self.assertEqual((response.status_code, response.json()["code"]), (404, "export_not_found"))
            self._close(app, root)

    @staticmethod
    def _close(app, root: Path) -> None:
        app.state.services.job_runner.shutdown()
        target = (root / "logs" / "cti_tool.log").resolve()
        logger = logging.getLogger()
        for handler in tuple(logger.handlers):
            if isinstance(handler, logging.FileHandler) and Path(handler.baseFilename).resolve() == target:
                logger.removeHandler(handler); handler.close()


if __name__ == "__main__":
    unittest.main()
