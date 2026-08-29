from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
import secrets
import threading
from typing import Any, Callable, Literal, Protocol

from backend.app.pipeline.ingestion.external.common.logging import get_logger
from backend.app.pipeline.ingestion.external.common.models import ExternalCTIItem
from backend.app.pipeline.ingestion.external.common.run_manifest import generate_run_id, utc_now_iso
from backend.app.pipeline.ingestion.external.application.manual_source_service import ManualSourceService, ManualTrackedRoot


LOGGER = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class CollectionRequest:
    source_ids: tuple[str, ...] = ()
    scope: Literal["all_enabled"] | None = None
    force: bool = False
    requested_by: str = "authorized_maintenance"
    options: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class JobAccepted:
    job_id: str
    state: str = "queued"
    command_id: str | None = None


class CollectionRequestError(ValueError):
    pass


class UnknownSourceError(CollectionRequestError):
    pass


class DisabledSourceError(CollectionRequestError):
    pass


class ManualSourceCommandError(CollectionRequestError):
    pass


class AllEnabledRunActiveError(CollectionRequestError):
    pass


@dataclass(frozen=True, slots=True)
class RegisteredSource:
    source_id: str
    source_type: str
    enabled: bool
    configuration: dict[str, Any]


@dataclass(frozen=True, slots=True)
class SourceExecutionResult:
    source_id: str
    status: str
    accepted_records: int = 0
    review_records: int = 0
    rejected_records: int = 0
    skipped_records: int = 0
    error_count: int = 0
    accepted: tuple[ExternalCTIItem, ...] = ()
    review: tuple[ExternalCTIItem, ...] = ()
    errors: tuple[str, ...] = ()
    rejected: tuple[ExternalCTIItem, ...] = ()


class SourceExecutor(Protocol):
    def execute(self, source: RegisteredSource, *, force: bool, command_id: str) -> SourceExecutionResult: ...


class CollectionJobRunner(Protocol):
    def submit(self, command_id: str, operation: Callable[[], Any], *, safe_context: dict[str, str] | None = None,
               cancellation_event: threading.Event | None = None,
               on_queued_cancel: Callable[[], None] | None = None) -> Any: ...


class CollectionExportCoordinator(Protocol):
    def export(self, run_id: str, started_at: str, results: tuple[SourceExecutionResult, ...]) -> dict[str, Any]: ...
    def begin_manual_capture(self) -> None: ...
    def end_manual_capture(self) -> tuple[tuple[ExternalCTIItem, str], ...]: ...
    def export_unified(self, run_id: str, started_at: str, results: tuple[SourceExecutionResult, ...],
                       manual_results: dict[str, dict[str, Any]],
                       manual_review: tuple[ExternalCTIItem, ...]) -> dict[str, Any]: ...


class CollectionService(ABC):
    """Application boundary used by authorized adapters, never collectors directly."""

    @abstractmethod
    def start_collection(self, request: CollectionRequest) -> JobAccepted:
        """Validate a collection request and enqueue a job."""

    @abstractmethod
    def collect_source(self, source_id: str, *, requested_by: str, force: bool = False) -> JobAccepted:
        """Validate and enqueue collection for one approved source."""


class CanonicalCollectionService(CollectionService):
    """Validate and orchestrate registered collectors behind the application boundary."""

    def __init__(self, runner: CollectionJobRunner, registry: dict[str, RegisteredSource], executor: SourceExecutor,
                 exporter: CollectionExportCoordinator | None = None, manual_service: ManualSourceService | None = None,
                 all_enabled_lock: threading.Lock | None = None) -> None:
        self.runner, self.registry, self.executor, self.exporter = runner, dict(registry), executor, exporter
        self.manual_service = manual_service
        self.all_enabled_lock = all_enabled_lock or threading.Lock()

    def start_collection(self, request: CollectionRequest) -> JobAccepted:
        if request.scope == "all_enabled" and request.source_ids:
            raise CollectionRequestError("scope=all_enabled cannot be combined with source_ids")
        source_ids = self._validated_ids(request.source_ids)
        command_id = f"cmd-{secrets.token_hex(12)}"
        run_id, started_at = generate_run_id(), utc_now_iso()
        if request.scope == "all_enabled":
            if not self.all_enabled_lock.acquire(blocking=False):
                raise AllEnabledRunActiveError("an all-enabled collection is already active")
            cancellation = threading.Event()
            try:
                job = self.runner.submit(command_id, lambda: self._run_unified(
                    source_ids, force=request.force, command_id=command_id, run_id=run_id,
                    started_at=started_at, cancellation=cancellation),
                    safe_context={"source_id": "all_enabled"}, cancellation_event=cancellation,
                    on_queued_cancel=self.all_enabled_lock.release)
            except Exception:
                self.all_enabled_lock.release()
                raise
            return JobAccepted(job.job_id, command_id=command_id)
        job = self.runner.submit(command_id, lambda: self._run(source_ids, force=request.force, command_id=command_id,
                                                                run_id=run_id, started_at=started_at),
                                 safe_context={"source_id": "multiple"})
        return JobAccepted(job.job_id, command_id=command_id)

    def _run_unified(self, source_ids: tuple[str, ...], *, force: bool, command_id: str, run_id: str,
                     started_at: str, cancellation: threading.Event) -> dict[str, Any]:
        registered: list[SourceExecutionResult] = []
        manual_results: dict[str, dict[str, Any]] = {}
        cancelled = False
        capture_started = False
        captured: tuple[tuple[ExternalCTIItem, str], ...] = ()
        try:
            for source_id in source_ids:
                if cancellation.is_set(): cancelled = True; break
                try: result = self.executor.execute(self.registry[source_id], force=force, command_id=command_id)
                except Exception:
                    result = SourceExecutionResult(source_id, "failed", error_count=1, errors=("source_execution_failed",))
                registered.append(result)
            roots: tuple[ManualTrackedRoot, ...] = ()
            if not cancelled and self.manual_service is not None:
                try: roots = self.manual_service.list_tracked_roots()
                except Exception: roots = ()
            if roots and self.exporter is not None and hasattr(self.exporter, "begin_manual_capture"):
                self.exporter.begin_manual_capture(); capture_started = True
            for root in roots:
                if cancellation.is_set(): cancelled = True; break
                try:
                    outcome = self.manual_service.recheck_url(root.canonical_url,
                        requested_by="unified_collection", force=force)
                    status = "failed" if outcome.status == "error" else outcome.status
                    manual_results[root.root_id] = {
                        "status": status, "accepted_records": outcome.accepted_records,
                        "review_records": outcome.review_records, "rejected_records": outcome.rejected_records,
                        "skipped_records": outcome.skipped_records, "error_count": outcome.error_count,
                    }
                except Exception:
                    manual_results[root.root_id] = {"status": "failed", "accepted_records": 0,
                        "review_records": 0, "rejected_records": 0, "skipped_records": 0, "error_count": 1}
            if capture_started:
                captured = self.exporter.end_manual_capture(); capture_started = False
            if cancellation.is_set(): cancelled = True
            aggregate = self._unified_result(run_id, force, registered, manual_results, cancelled)
            if cancelled:
                aggregate["export"] = {"status": "not_run", "reason": "cancelled_before_export"}
                return aggregate
            manual_review = tuple(item for item, disposition in captured if disposition == "review")
            if self.exporter is None or not hasattr(self.exporter, "export_unified"):
                aggregate["export"] = {"status": "failed", "error": {"code": "export_unavailable"}}
                if aggregate["status"] == "completed": aggregate["status"] = "partial"
                return aggregate
            try:
                aggregate["export"] = self.exporter.export_unified(
                    run_id, started_at, tuple(registered), manual_results, manual_review)
            except Exception as exc:
                LOGGER.error("unified external export failed run_id=%s command_id=%s exception_type=%s",
                             run_id, command_id, type(exc).__name__)
                aggregate["export"] = {"status": "failed", "error": {"code": "export_failed",
                    "message": "unified collection completed but export failed safely"}}
                if aggregate["status"] == "completed": aggregate["status"] = "partial"
            return aggregate
        finally:
            if capture_started:
                try: self.exporter.end_manual_capture()
                except Exception: pass
            self.all_enabled_lock.release()

    @staticmethod
    def _unified_result(run_id: str, force: bool, registered: list[SourceExecutionResult],
                        manual: dict[str, dict[str, Any]], cancelled: bool) -> dict[str, Any]:
        operations = [value.status for value in registered] + [value["status"] for value in manual.values()]
        failures = sum(value == "failed" for value in operations)
        if cancelled: overall = "cancelled"
        elif operations and failures == len(operations): overall = "failed"
        elif failures: overall = "partial"
        else: overall = "completed"
        def total(field: str) -> int:
            return sum(int(getattr(value, field)) for value in registered) + sum(int(value[field]) for value in manual.values())
        return {
            "status": overall, "scope": "all_enabled", "run_id": run_id, "force": force,
            "registered_source_count": len(registered), "manual_source_count": len(manual),
            "accepted_records": total("accepted_records"), "review_records": total("review_records"),
            "rejected_records": total("rejected_records"), "skipped_records": total("skipped_records"),
            "error_count": total("error_count"),
            "sources": {value.source_id: {"status": value.status, "accepted_records": value.accepted_records,
                "review_records": value.review_records, "rejected_records": value.rejected_records,
                "skipped_records": value.skipped_records, "error_count": value.error_count} for value in registered},
            "manual_sources": manual,
        }

    def collect_source(self, source_id: str, *, requested_by: str, force: bool = False) -> JobAccepted:
        del requested_by
        source_ids = self._validated_ids((source_id,))
        command_id = f"cmd-{secrets.token_hex(12)}"
        run_id, started_at = generate_run_id(), utc_now_iso()
        job = self.runner.submit(command_id, lambda: self._run(source_ids, force=force, command_id=command_id,
                                                                run_id=run_id, started_at=started_at),
                                 safe_context={"source_id": source_id})
        return JobAccepted(job.job_id, command_id=command_id)

    def _validated_ids(self, requested: tuple[str, ...]) -> tuple[str, ...]:
        source_ids = tuple(dict.fromkeys(requested)) if requested else tuple(
            source_id for source_id, source in self.registry.items() if source.enabled
        )
        if not source_ids:
            raise CollectionRequestError("no enabled collection sources were selected")
        for source_id in source_ids:
            if source_id.lower() in {"manual", "manual-url", "manual_url", "manual-sources"}:
                raise ManualSourceCommandError("manual URLs require the manual-source operation")
            source = self.registry.get(source_id)
            if source is None:
                raise UnknownSourceError(source_id)
            if not source.enabled:
                raise DisabledSourceError(source_id)
        return source_ids

    def _run(self, source_ids: tuple[str, ...], *, force: bool, command_id: str, run_id: str, started_at: str) -> dict[str, Any]:
        results = tuple(self.executor.execute(self.registry[source_id], force=force, command_id=command_id) for source_id in source_ids)
        failed = sum(result.status == "failed" for result in results)
        overall = "failed" if failed == len(results) else "partial" if failed else "completed"
        aggregate = {
            "status": overall,
            "source_count": len(results),
            "accepted_records": sum(result.accepted_records for result in results),
            "review_records": sum(result.review_records for result in results),
            "rejected_records": sum(result.rejected_records for result in results),
            "skipped_records": sum(result.skipped_records for result in results),
            "error_count": sum(result.error_count for result in results),
            "sources": {result.source_id: {"status": result.status, "accepted_records": result.accepted_records,
                                            "review_records": result.review_records, "error_count": result.error_count}
                        for result in results},
            "force": force,
            "run_id": run_id,
        }
        if len(results) == 1:
            aggregate["source_id"] = results[0].source_id
        if self.exporter is not None and overall != "failed":
            try:
                aggregate["export"] = self.exporter.export(run_id, started_at, results)
            except Exception as exc:
                LOGGER.error("external export failed run_id=%s command_id=%s exception_type=%s", run_id, command_id, type(exc).__name__)
                aggregate["export"] = {"status": "failed", "error": {"code": "export_failed",
                    "message": "collection completed but export generation failed safely", "retryable": True, "details": {}}}
        return aggregate
