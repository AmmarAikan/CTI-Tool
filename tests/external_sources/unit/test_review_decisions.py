from __future__ import annotations

import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from backend.app.pipeline.ingestion.external.common.run_manifest import RunManifest
from backend.app.pipeline.ingestion.external.common.state_manager import JsonStateManager
from backend.app.pipeline.ingestion.external.export.final_dataset import ExternalDatasetExporter, RunSourceOutput
with patch.dict(os.environ, {"EXTERNAL_API_TOKEN": "synthetic-review-test-token"}):
    from backend.app.pipeline.ingestion.external.integration.local import LocalReviewService, LocalValidatedExportReader
from tests.external_sources.integration.test_local_collection_job import export_item


class RecordingExporter:
    def __init__(self, delegate: ExternalDatasetExporter, *, fail_once: bool = False) -> None:
        self.delegate, self.state_manager, self.calls = delegate, delegate.state_manager, 0
        self.fail_once = fail_once

    def export(self, *args, **kwargs):
        self.calls += 1
        if self.fail_once:
            self.fail_once = False
            raise OSError("sanitized export failure")
        return self.delegate.export(*args, **kwargs)


class ReviewDecisionPersistenceTests(unittest.TestCase):
    def _fixture(self, root: Path, identity: str = "review-decision"):
        state = JsonStateManager(root / "state" / "exports.json")
        exporter = ExternalDatasetExporter(exports_dir=root / "exports", review_dir=root / "review", state_manager=state)
        record = export_item(identity, classification="error")
        manifest = RunManifest()
        exporter.export(manifest, (RunSourceOutput(manifest.run_id, "fixture", "completed", review=(record,)),))
        reader = LocalValidatedExportReader(root / "exports")
        service = LocalReviewService(root / "review", reader, exporter)
        projected = service.latest()["records"][0]
        return exporter, reader, service, projected

    def test_approve_persists_across_reload_and_enters_accepted_export(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); exporter, reader, service, record = self._fixture(root)
            decided = service.decide(record["record_id"], record["content_sha256"], "approved", None, requested_by="analyst")
            reloaded = LocalReviewService(root / "review", LocalValidatedExportReader(root / "exports"), exporter)
            self.assertEqual(reloaded.latest()["records"][0]["status"], "approved_processing")
            page = reader.run_accepted(decided["export_run_id"], limit=100, offset=0)
            self.assertEqual((decided["processing_state"], decided["retryable"], page["total"]), ("completed", False, 1))
            self.assertEqual(page["items"][0]["content_hash"], record["content_sha256"])
            replay = reloaded.decide(record["record_id"], record["content_sha256"], "approved", None, requested_by="analyst")
            self.assertEqual(replay, decided)

    def test_reject_persists_without_creating_an_export(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); exporter, _reader, service, record = self._fixture(root, "review-reject")
            recording = RecordingExporter(exporter); service = LocalReviewService(root / "review", service.export_reader, recording)
            decided = service.decide(record["record_id"], record["content_sha256"], "rejected", "duplicate", requested_by="analyst")
            reloaded = LocalReviewService(root / "review", LocalValidatedExportReader(root / "exports"), exporter)
            self.assertEqual((recording.calls, decided["export_run_id"], reloaded.latest()["records"]), (0, None, []))
            self.assertEqual(reloaded.decide(record["record_id"], record["content_sha256"], "rejected", "duplicate", requested_by="analyst"), decided)

    def test_stale_hash_and_conflicting_decisions_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); _exporter, _reader, service, record = self._fixture(root, "review-conflict")
            with self.assertRaisesRegex(RuntimeError, "review_content_changed"):
                service.decide(record["record_id"], "sha256:" + "0" * 64, "approved", None, requested_by="analyst")
            service.decide(record["record_id"], record["content_sha256"], "rejected", "duplicate", requested_by="analyst")
            with self.assertRaisesRegex(RuntimeError, "review_already_decided"):
                service.decide(record["record_id"], record["content_sha256"], "approved", None, requested_by="analyst")

    def test_export_failure_keeps_durable_decision_hidden_and_retryable(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); exporter, reader, service, record = self._fixture(root, "review-retry")
            failing = RecordingExporter(exporter, fail_once=True)
            first_service = LocalReviewService(root / "review", reader, failing)
            failed = first_service.decide(record["record_id"], record["content_sha256"], "approved", None, requested_by="analyst")
            self.assertEqual((failed["processing_state"], failed["retryable"], first_service.latest()["records"][0]["status"]), ("processing_failed", True, "processing_failed"))
            retried = LocalReviewService(root / "review", LocalValidatedExportReader(root / "exports"), exporter).decide(
                record["record_id"], record["content_sha256"], "approved", None, requested_by="analyst")
            self.assertEqual((retried["processing_state"], reader.run_accepted(retried["export_run_id"], limit=100, offset=0)["total"]), ("completed", 1))

    def test_concurrent_identical_decisions_serialize_to_one_export(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); exporter, reader, service, record = self._fixture(root, "review-concurrent")
            recording = RecordingExporter(exporter); service = LocalReviewService(root / "review", reader, recording)
            results, errors = [], []
            def decide():
                try: results.append(service.decide(record["record_id"], record["content_sha256"], "approved", None, requested_by="analyst"))
                except Exception as exc: errors.append(type(exc).__name__)
            threads = [threading.Thread(target=decide) for _ in range(4)]
            for thread in threads: thread.start()
            for thread in threads: thread.join(5)
            self.assertEqual((errors, len(results), recording.calls), ([], 4, 1))
            self.assertEqual(len({value["export_run_id"] for value in results}), 1)

    def test_concurrent_approve_reject_serializes_to_one_durable_decision(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); _exporter, _reader, service, record = self._fixture(root, "review-race")
            outcomes: list[str] = []
            def decide(action: str):
                try:
                    service.decide(record["record_id"], record["content_sha256"], action,
                                   "duplicate" if action == "rejected" else None, requested_by="analyst")
                    outcomes.append(action)
                except RuntimeError as exc:
                    outcomes.append(str(exc))
            threads = [threading.Thread(target=decide, args=(action,)) for action in ("approved", "rejected")]
            for thread in threads: thread.start()
            for thread in threads: thread.join(5)
            state = service.exporter.state_manager.load()["review_decisions"]
            self.assertEqual(len(state), 1)
            self.assertEqual(len([value for value in outcomes if value in {"approved", "rejected"}]), 1)
            self.assertIn("review_already_decided", outcomes)

    def test_reader_writer_use_the_same_canonical_directories(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); exporter, reader, service, _record = self._fixture(root, "review-paths")
            self.assertEqual(service.review_directory.resolve(), exporter.review_dir.resolve())
            self.assertEqual(reader.exports_directory.resolve(), exporter.exports_dir.resolve())
            self.assertEqual(exporter.state_manager.path.resolve(), (root / "state" / "exports.json").resolve())

    def test_older_pending_review_survives_a_newer_export_and_lifecycle_is_restart_safe(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); exporter, _reader, service, record = self._fixture(root, "older-pending")
            newer = RunManifest(); accepted = export_item("newer-accepted")
            exporter.export(newer, (RunSourceOutput(newer.run_id, "fixture", "completed", accepted=(accepted,)),))
            reloaded = LocalReviewService(root / "review", LocalValidatedExportReader(root / "exports"), exporter)
            self.assertEqual([item["record_id"] for item in reloaded.latest()["records"]], [record["record_id"]])
            pending = reloaded.lifecycle()["items"]
            self.assertEqual((len(pending), pending[0]["state"], pending[0]["stage"]), (1, "pending_review", "review"))
            decided = reloaded.decide(record["record_id"], record["content_sha256"], "approved", None, requested_by="analyst")
            restarted = LocalReviewService(root / "review", LocalValidatedExportReader(root / "exports"), exporter)
            lifecycle = restarted.lifecycle()["items"]
            match = next(item for item in lifecycle if item["record_id"] == record["record_id"])
            self.assertEqual((match["state"], match["stage"], match["export_run_id"], match["retryable"]),
                             ("approved_processing", "central_import", decided["export_run_id"], False))


if __name__ == "__main__":
    unittest.main()
