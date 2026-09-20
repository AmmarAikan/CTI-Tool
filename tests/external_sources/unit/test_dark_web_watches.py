from __future__ import annotations
import stat, tempfile, unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from backend.app.pipeline.ingestion.external.application.dark_web_watch_service import SQLiteDarkWebWatchStore, WatchConflict, WatchValidationError, normalize_keyword

class DarkWebWatchTests(unittest.TestCase):
    def test_validation_normalization_duplicate_and_mode(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/"watches.sqlite3"; store=SQLiteDarkWebWatchStore(path,max_watches=2)
            watch=store.create("  Acme   شركة  ")
            self.assertEqual(watch["keyword"],"Acme شركة"); self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o600)
            with self.assertRaises(WatchConflict): store.create("acme شركة")
            for value in ("a","https://example.test","hidden.onion","site:example","<b>name</b>"):
                with self.subTest(value=value), self.assertRaises(WatchValidationError): normalize_keyword(value)

    def test_atomic_deduplication_and_new_known_counts(self):
        with tempfile.TemporaryDirectory() as folder:
            store=SQLiteDarkWebWatchStore(Path(folder)/"watches.sqlite3"); watch=store.create("Acme")
            item={"result_id":"dwr-"+"a"*32,"canonical_hash":"b"*64,"content_sha256":"c"*64,"onion_reference":"onion-ref:bbbbbbbbbbbb","title":"Acme report","excerpt":"Acme context","provider":"Approved","privacy_status":"reviewed","review_reasons":[]}
            first=store.commit_scan(watch["watch_id"],[item],partial=False); second=store.commit_scan(watch["watch_id"],[item],partial=False)
            self.assertEqual((first["new_result_count"],second["new_result_count"]),(1,0)); self.assertEqual(store.results(watch["watch_id"],25,0)["total"],1)

    def test_rejects_symlink_and_existing_unsafe_database_permissions(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); target=root/"target.sqlite3"; target.write_bytes(b"")
            link=root/"linked.sqlite3"; link.symlink_to(target)
            with self.assertRaisesRegex(RuntimeError,"unsafe"): SQLiteDarkWebWatchStore(link)
            unsafe=root/"unsafe.sqlite3"; unsafe.write_bytes(b""); unsafe.chmod(0o644)
            with self.assertRaisesRegex(RuntimeError,"permissions"): SQLiteDarkWebWatchStore(unsafe)

    def test_scheduler_leader_expiry_atomic_claim_and_allowed_intervals(self):
        with tempfile.TemporaryDirectory() as folder:
            store=SQLiteDarkWebWatchStore(Path(folder)/"watches.sqlite3"); watch=store.create("Acme")
            with self.assertRaises(WatchValidationError): store.configure_schedule(watch["watch_id"],True,7200)
            store.configure_schedule(watch["watch_id"],True,3600)
            now=datetime.now(timezone.utc)+timedelta(hours=2)
            self.assertTrue(store.acquire_leader("one",now=now))
            self.assertFalse(store.acquire_leader("two",now=now))
            claimed=store.claim_due("one",now=now); self.assertEqual(len(claimed),1)
            self.assertEqual(store.claim_due("one",now=now),[])
            self.assertTrue(store.acquire_leader("two",now=now+timedelta(seconds=31)))

    def test_alerts_new_changed_deduplicated_and_read(self):
        with tempfile.TemporaryDirectory() as folder:
            store=SQLiteDarkWebWatchStore(Path(folder)/"watches.sqlite3"); watch=store.create("Acme")
            item={"result_id":"dwr-"+"a"*32,"canonical_hash":"b"*64,"content_sha256":"c"*64,"onion_reference":"onion-ref:bbbbbbbbbbbb","title":"Acme report","excerpt":"Acme context","provider":"Approved","privacy_status":"reviewed","review_reasons":[],"matched_keywords":["Acme"]}
            store.commit_scan(watch["watch_id"],[item],partial=False);store.commit_scan(watch["watch_id"],[item],partial=False)
            page=store.alerts(watch_id=watch["watch_id"]);self.assertEqual((page["total"],page["unread"]),(1,1))
            changed={**item,"content_sha256":"d"*64,"excerpt":"changed"};store.commit_scan(watch["watch_id"],[changed],partial=False)
            page=store.alerts(watch_id=watch["watch_id"]);self.assertEqual((page["total"],page["unread"]),(2,2))
            alert=store.mark_alert_read(page["items"][0]["alert_id"]);self.assertIsNotNone(alert["read_at"])

if __name__ == "__main__": unittest.main()
