from __future__ import annotations
import stat, tempfile, unittest
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

if __name__ == "__main__": unittest.main()
