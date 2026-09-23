from __future__ import annotations

import threading
import time
import unittest
from types import SimpleNamespace

from backend.app.pipeline.ingestion.external.application.collection_service import (
    AllEnabledRunActiveError, CanonicalCollectionService, CollectionRequest, DisabledSourceError,
    RegisteredSource, SourceExecutionResult, UnknownSourceError,
)
from backend.app.pipeline.ingestion.external.application.manual_source_service import (
    ManualSourceResult, ManualTrackedRoot,
)
from backend.app.pipeline.ingestion.external.integration.jobs import InProcessJobRunner


ROOT_ONE = ManualTrackedRoot("manual-root-" + "a" * 32, "https://example.test/report-one")
ROOT_TWO = ManualTrackedRoot("manual-root-" + "b" * 32, "https://example.test/report-two")


class ImmediateRunner:
    def __init__(self): self.result = None; self.cancellation_event = None
    def submit(self, command_id, operation, *, safe_context=None, cancellation_event=None, on_queued_cancel=None):
        del command_id, safe_context, on_queued_cancel
        self.cancellation_event = cancellation_event
        self.result = operation()
        return SimpleNamespace(job_id="job-unified-000000000001")


class Executor:
    def __init__(self, values=None, *, cancel_after_first=False):
        self.values, self.calls, self.cancel_after_first, self.runner = values or {}, [], cancel_after_first, None
    def execute(self, source, *, force, command_id):
        self.calls.append((source.source_id, force, command_id))
        if self.cancel_after_first and len(self.calls) == 1: self.runner.cancellation_event.set()
        value = self.values.get(source.source_id)
        if isinstance(value, Exception): raise value
        return value or SourceExecutionResult(source.source_id, "completed", accepted_records=1)


class ManualService:
    def __init__(self, roots=(), values=None): self.roots, self.values, self.calls = tuple(roots), values or {}, []
    def list_tracked_roots(self): return self.roots
    def recheck_url(self, url, *, requested_by, force=False):
        self.calls.append((url, requested_by, force))
        value = self.values.get(url)
        if isinstance(value, Exception): raise value
        return value or ManualSourceResult("stored", "stored", accepted_records=1)


class UnifiedExporter:
    def __init__(self, *, error=None): self.calls, self.error = [], error
    def begin_manual_capture(self): pass
    def end_manual_capture(self): return ()
    def export_unified(self, run_id, started_at, results, manual_results, manual_review):
        self.calls.append((run_id, started_at, results, manual_results, manual_review))
        if self.error: raise self.error
        return {"status": "completed", "run_id": run_id, "dataset_sha256": "sha256:" + "a" * 64,
                "accepted_records": 1, "review_records": 0, "dataset_file": f"final_dataset_{run_id}.json",
                "manifest_file": f"external_export_manifest_{run_id}.json", "review_file": f"external_review_{run_id}.json"}


def registry():
    return {
        "rss-one": RegisteredSource("rss-one", "rss", True, {}),
        "dark-one": RegisteredSource("dark-one", "dark_web", True, {}),
    }


class UnifiedCollectionTests(unittest.TestCase):
    def run_unified(self, executor, manual, *, force=False, exporter=None):
        runner = ImmediateRunner(); executor.runner = runner
        exporter = exporter or UnifiedExporter()
        service = CanonicalCollectionService(runner, registry(), executor, exporter=exporter, manual_service=manual)
        accepted = service.start_collection(CollectionRequest(scope="all_enabled", force=force))
        self.assertEqual(accepted.job_id, "job-unified-000000000001")
        return runner.result

    def test_success_and_unchanged_are_completed_and_aggregated(self):
        manual = ManualService((ROOT_ONE, ROOT_TWO), {
            ROOT_ONE.canonical_url: ManualSourceResult("stored", "stored", accepted_records=1),
            ROOT_TWO.canonical_url: ManualSourceResult("unchanged", "unchanged", skipped_records=1),
        })
        result = self.run_unified(Executor(), manual)
        self.assertEqual((result["status"], result["registered_source_count"], result["manual_source_count"]),
                         ("completed", 2, 2))
        self.assertEqual((result["accepted_records"], result["skipped_records"]), (3, 1))
        self.assertEqual(set(result["manual_sources"]), {ROOT_ONE.root_id, ROOT_TWO.root_id})
        self.assertNotIn("example.test", str(result))
        self.assertEqual(result["export"]["status"], "completed")
        self.assertEqual(result["export"]["run_id"], result["run_id"])

    def test_registered_and_tor_failures_are_isolated(self):
        values = {
            "rss-one": SourceExecutionResult("rss-one", "completed", accepted_records=1),
            "dark-one": SourceExecutionResult("dark-one", "failed", error_count=1, errors=("tor_proxy_unavailable",)),
        }
        result = self.run_unified(Executor(values), ManualService((ROOT_ONE,)))
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["sources"]["dark-one"]["status"], "failed")
        self.assertEqual(result["manual_sources"][ROOT_ONE.root_id]["status"], "stored")

    def test_unchanged_source_and_failed_source_are_partial(self):
        values = {
            "rss-one": SourceExecutionResult("rss-one", "completed", skipped_records=45),
            "dark-one": SourceExecutionResult("dark-one", "failed", error_count=5),
        }
        result = self.run_unified(Executor(values), ManualService())
        self.assertEqual((result["status"], result["skipped_records"], result["error_count"]),
                         ("partial", 45, 5))

    def test_unexpected_registered_and_manual_failures_are_isolated_and_redacted(self):
        executor = Executor({"rss-one": RuntimeError("private URL"),
                             "dark-one": SourceExecutionResult("dark-one", "completed", accepted_records=1)})
        manual = ManualService((ROOT_ONE, ROOT_TWO), {
            ROOT_ONE.canonical_url: RuntimeError("private URL"),
            ROOT_TWO.canonical_url: ManualSourceResult("review_required", "review", review_records=1),
        })
        result = self.run_unified(executor, manual)
        self.assertEqual(result["status"], "partial")
        self.assertEqual((result["error_count"], result["review_records"]), (2, 1))
        self.assertNotIn("https://", str(result))
        diagnostic = result["sources"]["rss-one"]
        self.assertEqual(diagnostic, {"status": "failed", "accepted_records": 0,
            "review_records": 0, "rejected_records": 0, "skipped_records": 0,
            "error_count": 1, "failure_categories": {"internal_failure": 1},
            "collection_stage": "source_execution", "exception_class": "RuntimeError",
            "retryable": False})
        self.assertNotIn("private URL", str(diagnostic))

    def test_ordinary_multi_source_run_isolates_exceptions_and_preserves_handled_results(self):
        runner = ImmediateRunner()
        executor = Executor({"rss-one": SourceExecutionResult("rss-one", "completed", accepted_records=1),
                             "dark-one": RuntimeError("https://private.invalid token=secret body=private")})
        executor.runner = runner
        service = CanonicalCollectionService(runner, registry(), executor)
        service.start_collection(CollectionRequest(source_ids=("rss-one", "dark-one")))
        self.assertEqual((runner.result["status"], runner.result["accepted_records"],
                          runner.result["sources"]["dark-one"]["exception_class"]),
                         ("partial", 1, "RuntimeError"))
        self.assertNotIn("private.invalid", str(runner.result))
        self.assertNotIn("secret", str(runner.result))

    def test_failed_status_with_skipped_outcome_is_handled(self):
        values = {"rss-one": SourceExecutionResult("rss-one", "failed", skipped_records=2, error_count=1),
                  "dark-one": SourceExecutionResult("dark-one", "failed", error_count=1)}
        result = self.run_unified(Executor(values), ManualService())
        self.assertEqual((result["status"], result["sources"]["rss-one"]["status"], result["skipped_records"]),
                         ("partial", "partial", 2))

    def test_all_selected_operations_failed(self):
        failed = SourceExecutionResult("rss-one", "failed", error_count=1)
        values = {"rss-one": failed, "dark-one": SourceExecutionResult("dark-one", "failed", error_count=1)}
        manual = ManualService((ROOT_ONE,), {ROOT_ONE.canonical_url: ManualSourceResult("error", "failed", error_count=1)})
        self.assertEqual(self.run_unified(Executor(values), manual)["status"], "failed")

    def test_force_reaches_registered_and_manual_operations(self):
        executor, manual = Executor(), ManualService((ROOT_ONE,))
        result = self.run_unified(executor, manual, force=True)
        self.assertTrue(result["force"])
        self.assertTrue(all(call[1] for call in executor.calls))
        self.assertTrue(manual.calls[0][2])

    def test_cancellation_stops_before_next_source_and_manual_root(self):
        executor, manual, exporter = Executor(cancel_after_first=True), ManualService((ROOT_ONE,)), UnifiedExporter()
        result = self.run_unified(executor, manual, exporter=exporter)
        self.assertEqual(result["status"], "cancelled")
        self.assertEqual(len(executor.calls), 1)
        self.assertEqual(manual.calls, [])
        self.assertEqual(exporter.calls, [])
        self.assertEqual(result["export"]["reason"], "cancelled_before_export")

    def test_export_failure_retains_collection_and_becomes_partial(self):
        exporter = UnifiedExporter(error=OSError("private path"))
        result = self.run_unified(Executor(), ManualService((ROOT_ONE,)), exporter=exporter)
        self.assertEqual((result["status"], result["accepted_records"]), ("partial", 3))
        self.assertEqual(result["export"]["error"]["code"], "export_failed")
        self.assertNotIn("private path", str(result))
        self.assertEqual(len(exporter.calls), 1)

    def test_success_invokes_exporter_exactly_once_with_same_run(self):
        exporter = UnifiedExporter()
        result = self.run_unified(Executor(), ManualService(), exporter=exporter)
        self.assertEqual(len(exporter.calls), 1)
        self.assertEqual(exporter.calls[0][0], result["run_id"])

    def test_promoted_and_manual_onion_runs_do_not_use_discovery(self):
        runner=ImmediateRunner();executor=Executor();executor.runner=runner
        discovery_calls=[]
        promoted=RegisteredSource("dws-"+"a"*24,"dark_web",True,{"protected_url":"redacted"})
        service=CanonicalCollectionService(runner,{},executor,manual_service=ManualService((ROOT_ONE,)),
            dynamic_source=lambda source_id: promoted if source_id==promoted.source_id else discovery_calls.append(source_id))
        service.collect_source(promoted.source_id,requested_by="tester")
        self.assertEqual(executor.calls[0][0],promoted.source_id);self.assertEqual(discovery_calls,[])
        service.collect_source(ROOT_ONE.root_id,requested_by="tester")
        self.assertEqual(discovery_calls,[])

    def test_manual_and_promoted_sources_work_without_enabled_static_sources(self):
        runner=ImmediateRunner();executor=Executor();executor.runner=runner
        promoted=RegisteredSource("dws-"+"b"*24,"dark_web",True,{"protected_url":"redacted"})
        disabled=RegisteredSource("static-disabled","dark_web",False,{})
        service=CanonicalCollectionService(runner,{disabled.source_id:disabled},executor,
            manual_service=ManualService((ROOT_ONE,)),
            dynamic_source=lambda source_id: promoted if source_id==promoted.source_id else None)

        service.collect_source(ROOT_ONE.root_id,requested_by="tester")
        service.collect_source(promoted.source_id,requested_by="tester")
        self.assertEqual(executor.calls[0][0],promoted.source_id)
        with self.assertRaises(DisabledSourceError):
            service.collect_source(disabled.source_id,requested_by="tester")
        with self.assertRaises(UnknownSourceError):
            service.collect_source("static-missing",requested_by="tester")

    def test_overlapping_all_enabled_runs_are_rejected_while_single_source_contract_is_unchanged(self):
        started, release = threading.Event(), threading.Event()
        class BlockingExecutor:
            def execute(self, source, *, force, command_id):
                del source, force, command_id; started.set(); release.wait(3)
                return SourceExecutionResult("rss-one", "completed")
        runner = InProcessJobRunner(max_workers=2)
        service = CanonicalCollectionService(runner, {"rss-one": registry()["rss-one"]}, BlockingExecutor(),
                                             manual_service=ManualService())
        first = service.start_collection(CollectionRequest(scope="all_enabled"))
        self.assertTrue(started.wait(1))
        with self.assertRaises(AllEnabledRunActiveError):
            service.start_collection(CollectionRequest(scope="all_enabled"))
        release.set()
        deadline = time.monotonic() + 3
        while runner.get(first.job_id).state not in {"completed", "failed"} and time.monotonic() < deadline: time.sleep(.01)
        ordinary = service.collect_source("rss-one", requested_by="tester")
        self.assertTrue(ordinary.job_id.startswith("job-"))
        runner.shutdown()

    def test_cancelling_queued_unified_job_releases_run_lock(self):
        occupied, release = threading.Event(), threading.Event()
        runner = InProcessJobRunner(max_workers=1)
        runner.submit("cmd-blocking-worker", lambda: (occupied.set(), release.wait(3), {"status": "completed"})[-1])
        self.assertTrue(occupied.wait(1))
        service = CanonicalCollectionService(runner, {"rss-one": registry()["rss-one"]}, Executor(),
                                             manual_service=ManualService())
        queued = service.start_collection(CollectionRequest(scope="all_enabled"))
        self.assertEqual(runner.get(queued.job_id).state, "queued")
        runner.cancel(queued.job_id)
        replacement = service.start_collection(CollectionRequest(scope="all_enabled"))
        self.assertTrue(replacement.job_id.startswith("job-"))
        release.set(); runner.shutdown()

    def test_submission_is_bounded_and_shutdown_leaves_no_external_workers(self):
        started, release = threading.Event(), threading.Event()
        runner = InProcessJobRunner(max_workers=1)
        service = CanonicalCollectionService(runner, {"rss-one": registry()["rss-one"]},
            Executor({"rss-one": SourceExecutionResult("rss-one", "completed")}), manual_service=ManualService())
        original = service.executor
        class BlockingExecutor:
            def execute(self, source, *, force, command_id):
                started.set(); release.wait(3)
                return original.execute(source, force=force, command_id=command_id)
        service.executor = BlockingExecutor()
        before = time.monotonic()
        accepted = service.start_collection(CollectionRequest(scope="all_enabled"))
        self.assertLess(time.monotonic() - before, .5)
        self.assertEqual(accepted.state, "queued")
        self.assertTrue(started.wait(1))
        release.set(); runner.shutdown()
        self.assertFalse(any(thread.name.startswith("external-api-dev") and thread.is_alive()
                             for thread in threading.enumerate()))


if __name__ == "__main__": unittest.main()
