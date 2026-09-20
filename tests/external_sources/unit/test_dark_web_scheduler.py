import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

from backend.app.pipeline.ingestion.external.application.dark_web_watch_service import (
    DurableDarkWebScheduler, SQLiteDarkWebWatchStore,
)


class QueuedRunner:
    def __init__(self): self.operations=[]
    def submit(self, command_id, operation, **kwargs):
        self.operations.append(operation)
        return SimpleNamespace(job_id=f"job-{'1'*24}")


class Service:
    def __init__(self, store, fail=False): self.store,self.fail=store,fail
    def scan(self, watch_id):
        if self.fail: raise RuntimeError("sanitized")
        return {"status":"completed","accepted_records":1,"review_records":0,"rejected_records":0,"skipped_records":0,"error_count":0}


class DarkWebSchedulerTests(unittest.TestCase):
    def configured(self, root):
        store=SQLiteDarkWebWatchStore(Path(root)/"watches.sqlite3")
        watch=store.create("Example keyword")
        base=datetime(2026,1,1,tzinfo=timezone.utc)
        store.configure_schedule(watch["watch_id"],True,3600)
        with store._connect() as db:db.execute("UPDATE watches SET next_run_at=? WHERE watch_id=?",(base.isoformat().replace("+00:00","Z"),watch["watch_id"]))
        return store,watch,base

    def test_lease_renewal_submission_and_completion(self):
        with tempfile.TemporaryDirectory() as root:
            store,watch,base=self.configured(root);runner=QueuedRunner()
            scheduler=DurableDarkWebScheduler(Service(store),runner,owner="owner",lease_seconds=30)
            self.assertEqual(scheduler.tick(now=base),1);self.assertEqual(len(runner.operations),1)
            self.assertTrue(store.renew_leader("owner",now=base+timedelta(seconds=5)))
            runner.operations[0]()
            with store._connect() as db:row=db.execute("SELECT status FROM schedule_occurrences").fetchone()
            self.assertEqual(row[0],"completed");self.assertIsNotNone(store.get(watch["watch_id"])["last_success_at"])

    def test_restart_recovers_stale_submitted_occurrence_and_records_failure(self):
        with tempfile.TemporaryDirectory() as root:
            store,_watch,base=self.configured(root);first=QueuedRunner()
            DurableDarkWebScheduler(Service(store),first,owner="first",lease_seconds=5,recovery_seconds=5).tick(now=base)
            second=QueuedRunner();scheduler=DurableDarkWebScheduler(Service(store,fail=True),second,owner="second",lease_seconds=5,recovery_seconds=5)
            self.assertEqual(scheduler.tick(now=base+timedelta(seconds=6)),1)
            with self.assertRaises(RuntimeError):second.operations[0]()
            with store._connect() as db:row=db.execute("SELECT status FROM schedule_occurrences").fetchone()
            self.assertEqual(row[0],"failed")

    def test_start_stop_are_idempotent(self):
        with tempfile.TemporaryDirectory() as root:
            store=SQLiteDarkWebWatchStore(Path(root)/"watches.sqlite3")
            scheduler=DurableDarkWebScheduler(Service(store),QueuedRunner(),poll_seconds=.05)
            scheduler.start();scheduler.start();scheduler.stop();scheduler.stop()
            self.assertFalse(scheduler._thread.is_alive())


if __name__=="__main__":unittest.main()
