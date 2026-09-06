from __future__ import annotations

import tempfile
import threading
import unittest
import sqlite3
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path

from backend.app.pipeline.ingestion.external.application.manual_preview_service import (
    ManualPreviewService, PreviewConsumed, PreviewExpired, PreviewHashMismatch, SQLiteManualPreviewStore,
)
from backend.app.pipeline.ingestion.external.application.manual_source_service import CanonicalManualSourceService
from backend.app.pipeline.ingestion.external.common.state_manager import JsonStateManager
from backend.app.pipeline.ingestion.external.manual_source.url_policy import ManualURLPolicy
from tests.external_sources.integration.test_manual_source_service import AcceptClassification, FakeCrawler, PUBLIC, crawl

URL = "https://example.test/report?private=value"
NOW = datetime(2026, 9, 6, tzinfo=timezone.utc)


class ManualPreviewWorkflowTests(unittest.TestCase):
    def build(self, root: Path, clock=lambda: NOW):
        crawler = FakeCrawler([crawl(URL) for _ in range(4)])
        stored = []
        production = JsonStateManager(root / "manual_sources.json")
        manual = CanonicalManualSourceService(
            policy=ManualURLPolicy(resolver=PUBLIC), crawler=crawler, state_manager=production,
            classification_service=AcceptClassification(), record_sink=lambda item, disposition: stored.append((item, disposition)),
            clock=clock,
        )
        store = SQLiteManualPreviewStore(root / "manual_previews.sqlite3", ttl_seconds=900, clock=clock)
        service = ManualPreviewService(manual, store, lambda bundle, actor: manual.commit_preview(bundle, requested_by=actor))
        return service, crawler, production, stored

    def test_preview_is_bounded_sanitized_and_does_not_write_production_state(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); service, _crawler, production, stored = self.build(root)
            value = service.create(URL, requested_by="analyst")
            self.assertEqual(value["state"], "pending")
            self.assertEqual(value["display_url"], "https://example.test/report")
            self.assertNotIn("private=value", str(value)); self.assertLessEqual(len(value["excerpt"]), 500)
            self.assertFalse(production.path.exists()); self.assertEqual(stored, [])
            self.assertFalse(list(root.glob("manual_*.json")))
            database = root / "manual_previews.sqlite3"
            self.assertEqual(stat.S_IMODE(database.stat().st_mode), 0o600)

    def test_approve_commits_frozen_content_without_refetch_and_prevents_replay(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); service, crawler, production, stored = self.build(root)
            value = service.create(URL, requested_by="analyst")
            claimed = service.claim_approval(value["preview_id"], value["content_sha256"])
            result = service.approve_claimed(claimed, requested_by="analyst")
            self.assertEqual(len(crawler.calls), 1); self.assertEqual(result.accepted_records, 1)
            self.assertTrue(production.path.exists()); self.assertEqual(len(stored), 1)
            with self.assertRaises(PreviewConsumed): service.claim_approval(value["preview_id"], value["content_sha256"])

    def test_reject_hash_mismatch_expiry_and_atomic_decision(self):
        current = [NOW]
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); service, _crawler, production, stored = self.build(root, lambda: current[0])
            mismatch = service.create(URL, requested_by="analyst")
            with self.assertRaises(PreviewHashMismatch): service.claim_approval(mismatch["preview_id"], "sha256:" + "0" * 64)
            rejected = service.create(URL, requested_by="analyst")
            self.assertEqual(service.reject(rejected["preview_id"], "not_relevant", requested_by="analyst")["state"], "rejected")
            with self.assertRaises(PreviewConsumed): service.claim_approval(rejected["preview_id"], rejected["content_sha256"])
            expired = service.create(URL, requested_by="analyst"); current[0] += timedelta(minutes=16)
            with self.assertRaises(PreviewExpired): service.claim_approval(expired["preview_id"], expired["content_sha256"])
            with sqlite3.connect(root / "manual_previews.sqlite3") as db:
                state, payload = db.execute(
                    "SELECT state, payload_json FROM manual_url_previews WHERE preview_id=?", (expired["preview_id"],)
                ).fetchone()
            self.assertEqual(state, "expired"); self.assertIsNone(payload)
            self.assertFalse(production.path.exists()); self.assertEqual(stored, [])

    def test_failed_enqueue_claim_can_be_released_and_retried(self):
        with tempfile.TemporaryDirectory() as folder:
            service, _crawler, _production, _stored = self.build(Path(folder))
            value = service.create(URL, requested_by="analyst")
            service.claim_approval(value["preview_id"], value["content_sha256"])
            service.release_approval(value["preview_id"])
            retried = service.claim_approval(value["preview_id"], value["content_sha256"])
            self.assertEqual(retried.preview_id, value["preview_id"])

    def test_concurrent_approve_and_reject_allow_exactly_one_decision(self):
        with tempfile.TemporaryDirectory() as folder:
            service, _crawler, _production, _stored = self.build(Path(folder))
            value = service.create(URL, requested_by="analyst"); outcomes = []
            barrier = threading.Barrier(2)
            def approve():
                barrier.wait()
                try: service.claim_approval(value["preview_id"], value["content_sha256"]); outcomes.append("approve")
                except PreviewConsumed: outcomes.append("blocked")
            def reject():
                barrier.wait()
                try: service.reject(value["preview_id"], "duplicate", requested_by="analyst"); outcomes.append("reject")
                except PreviewConsumed: outcomes.append("blocked")
            threads = [threading.Thread(target=approve), threading.Thread(target=reject)]
            for thread in threads: thread.start()
            for thread in threads: thread.join()
            self.assertEqual(outcomes.count("blocked"), 1)
            self.assertEqual(len(set(outcomes) & {"approve", "reject"}), 1)


if __name__ == "__main__":
    unittest.main()
