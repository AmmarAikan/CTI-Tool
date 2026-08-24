from __future__ import annotations

import secrets
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Protocol

from backend.app.pipeline.ingestion.external.common.logging import get_logger


LOGGER = get_logger(__name__)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


@dataclass(slots=True)
class IntegrationJob:
    job_id: str
    command_id: str
    state: str = "queued"
    created_at: str = field(default_factory=utc_now)
    updated_at: str = field(default_factory=utc_now)
    progress: dict[str, int] = field(default_factory=dict)
    result: dict[str, Any] | None = None
    error: dict[str, Any] | None = None
    cancellation_requested: bool = False

    def safe_dict(self) -> dict[str, Any]:
        return {key: value for key, value in asdict(self).items() if key != "cancellation_requested"}


class JobRunner(Protocol):
    def submit(self, command_id: str, operation: Callable[[], Any], *, safe_context: dict[str, str] | None = None) -> IntegrationJob: ...
    def get(self, job_id: str) -> IntegrationJob | None: ...
    def cancel(self, job_id: str) -> IntegrationJob | None: ...


class InProcessJobRunner:
    """Development-only memory/thread runner; not durable or cloud-ready."""

    def __init__(self, *, max_workers: int = 2) -> None:
        self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="external-api-dev")
        self._jobs: dict[str, IntegrationJob] = {}
        self._lock = threading.Lock()

    def submit(self, command_id: str, operation: Callable[[], Any], *, safe_context: dict[str, str] | None = None) -> IntegrationJob:
        job = IntegrationJob(f"job-{secrets.token_hex(12)}", command_id)
        with self._lock: self._jobs[job.job_id] = job
        self._executor.submit(self._run, job.job_id, operation, dict(safe_context or {}))
        return job

    def get(self, job_id: str) -> IntegrationJob | None:
        with self._lock: return self._jobs.get(job_id)

    def cancel(self, job_id: str) -> IntegrationJob | None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None: return None
            if job.state == "queued": job.state = "cancelled"
            elif job.state == "running": job.state = "cancellation_requested"; job.cancellation_requested = True
            job.updated_at = utc_now()
            return job

    def shutdown(self, *, wait: bool = True) -> None:
        self._executor.shutdown(wait=wait)

    def _run(self, job_id: str, operation: Callable[[], Any], safe_context: dict[str, str]) -> None:
        with self._lock:
            job = self._jobs[job_id]
            if job.state == "cancelled": return
            job.state, job.updated_at = "running", utc_now()
        try:
            value = operation()
            result = asdict(value) if is_dataclass(value) else value if isinstance(value, dict) else {"status": str(value)}
            with self._lock:
                job = self._jobs[job_id]
                if job.cancellation_requested: job.state = "cancelled"
                else: job.state, job.result = "completed", result
                job.updated_at = utc_now()
        except Exception as exc:
            source_id = safe_context.get("source_id", "not_applicable")
            LOGGER.error(
                "external job failed job_id=%s command_id=%s source_id=%s exception_type=%s",
                job_id, job.command_id, source_id, type(exc).__name__,
            )
            with self._lock:
                job = self._jobs[job_id]
                job.state = "cancelled" if job.cancellation_requested else "failed"
                job.error = None if job.cancellation_requested else {"code": "job_failed", "message": "job execution failed safely", "retryable": False, "details": {}}
                job.updated_at = utc_now()
