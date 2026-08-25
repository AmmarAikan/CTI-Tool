from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
import secrets
from typing import Any, Callable, Protocol

from backend.app.pipeline.ingestion.external.common.logging import get_logger
from backend.app.pipeline.ingestion.external.common.models import ExternalCTIItem
from backend.app.pipeline.ingestion.external.common.run_manifest import generate_run_id, utc_now_iso


LOGGER = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class CollectionRequest:
    source_ids: tuple[str, ...] = ()
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


class SourceExecutor(Protocol):
    def execute(self, source: RegisteredSource, *, force: bool, command_id: str) -> SourceExecutionResult: ...


class CollectionJobRunner(Protocol):
    def submit(self, command_id: str, operation: Callable[[], Any], *, safe_context: dict[str, str] | None = None) -> Any: ...


class CollectionExportCoordinator(Protocol):
    def export(self, run_id: str, started_at: str, results: tuple[SourceExecutionResult, ...]) -> dict[str, Any]: ...


class CollectionService(ABC):
    """Application boundary used by authorized adapters, never collectors directly."""

    @abstractmethod
    def start_collection(self, request: CollectionRequest) -> JobAccepted:
        """Validate a collection request and enqueue a job."""

    @abstractmethod
    def collect_source(self, source_id: str, *, requested_by: str) -> JobAccepted:
        """Validate and enqueue collection for one approved source."""


class CanonicalCollectionService(CollectionService):
    """Validate and orchestrate registered collectors behind the application boundary."""

    def __init__(self, runner: CollectionJobRunner, registry: dict[str, RegisteredSource], executor: SourceExecutor,
                 exporter: CollectionExportCoordinator | None = None) -> None:
        self.runner, self.registry, self.executor, self.exporter = runner, dict(registry), executor, exporter

    def start_collection(self, request: CollectionRequest) -> JobAccepted:
        source_ids = self._validated_ids(request.source_ids)
        command_id = f"cmd-{secrets.token_hex(12)}"
        run_id, started_at = generate_run_id(), utc_now_iso()
        job = self.runner.submit(command_id, lambda: self._run(source_ids, force=request.force, command_id=command_id,
                                                                run_id=run_id, started_at=started_at),
                                 safe_context={"source_id": "multiple"})
        return JobAccepted(job.job_id, command_id=command_id)

    def collect_source(self, source_id: str, *, requested_by: str) -> JobAccepted:
        del requested_by
        source_ids = self._validated_ids((source_id,))
        command_id = f"cmd-{secrets.token_hex(12)}"
        run_id, started_at = generate_run_id(), utc_now_iso()
        job = self.runner.submit(command_id, lambda: self._run(source_ids, force=False, command_id=command_id,
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
