from __future__ import annotations

import re
import logging
import threading
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import requests
from sqlalchemy import or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.app.core.config import get_settings
from backend.app.db.database import SessionLocal
from backend.app.db.models import ExternalIngestionOperation, PipelineRun, Source
from backend.app.services.pipeline_service import PipelineService


TERMINAL = frozenset({"completed", "partial", "failed_terminal"})
RESUMABLE = frozenset({"queued", "published", "central_importing", "committed", "acknowledging"})
_DIGEST = re.compile(r"^(?:sha256:)?([0-9a-f]{64})$")
_wake = threading.Event()
_stop = threading.Event()
_thread: threading.Thread | None = None
LOGGER = logging.getLogger(__name__)


def now() -> datetime:
    return datetime.now(timezone.utc)


class ExternalIngestionService:
    def __init__(self, session: Session, client: Any) -> None:
        self.session, self.client = session, client

    def create_or_resume(self, job_id: str) -> ExternalIngestionOperation:
        job = self.client.get_job(job_id)
        if job.get("state") not in {"completed", "partial"}:
            raise ValueError("external_job_not_terminal")
        result = job.get("result") if isinstance(job.get("result"), dict) else {}
        export = result.get("export") if isinstance(result.get("export"), dict) else {}
        export_run_id = export.get("run_id")
        match = _DIGEST.fullmatch(str(export.get("dataset_sha256") or ""))
        if not isinstance(export_run_id, str) or not export_run_id or match is None:
            raise ValueError("external_job_export_invalid")
        digest = match.group(1)
        existing = self.session.scalar(select(ExternalIngestionOperation).where(
            ExternalIngestionOperation.external_job_id == job_id,
            ExternalIngestionOperation.export_run_id == export_run_id,
            ExternalIngestionOperation.dataset_sha256 == digest,
        ))
        if existing is not None:
            if existing.state == "failed_retryable":
                existing.state = _retry_state(existing.stage)
                existing.error_code = existing.error_category = None
                existing.updated_at = now(); self.session.commit(); _wake.set()
            return existing
        operation = ExternalIngestionOperation(
            external_job_id=job_id, export_run_id=export_run_id, dataset_sha256=digest,
            collected_count=int(result.get("accepted_records") or 0),
            exported_count=int(export.get("accepted_records") or 0),
        )
        self.session.add(operation)
        try:
            self.session.commit()
        except IntegrityError:
            self.session.rollback()
            operation = self.session.scalar(select(ExternalIngestionOperation).where(
                ExternalIngestionOperation.external_job_id == job_id,
                ExternalIngestionOperation.export_run_id == export_run_id,
                ExternalIngestionOperation.dataset_sha256 == digest,
            ))
            if operation is None: raise
        _wake.set()
        return operation

    def process(self, operation: ExternalIngestionOperation) -> None:
        operation.started_at = operation.started_at or now()
        operation.updated_at = now()
        try:
            if operation.state in {"queued", "failed_retryable"}:
                self._publish_exact_export(operation)
                operation.state, operation.stage = "published", "published"
                self.session.commit()
            connector = None
            if operation.state in {"published", "central_importing"}:
                operation.state, operation.stage = "central_importing", "central_importing"
                if not operation.pipeline_run_id:
                    run = PipelineRun(pipeline="external", status="running", details={
                        "external_ingestion_operation_id": operation.id,
                        "external_job_id": operation.external_job_id,
                        "export_run_id": operation.export_run_id,
                        "dataset_sha256": operation.dataset_sha256})
                    self.session.add(run); self.session.flush(); operation.pipeline_run_id = run.id
                self.session.commit()
                legacy = operation.external_job_id.startswith("gateway-legacy-")
                expected = (None if legacy else
                    (operation.external_job_id, operation.export_run_id, operation.dataset_sha256))
                connector = PipelineService.external_feed_connector(expected_identity=expected)
                operation_id = operation.id
                def persist_progress(offset: int, counts: dict[str, int]) -> None:
                    current = self.session.get(ExternalIngestionOperation, operation_id)
                    if current is None:
                        raise RuntimeError("external_operation_disappeared")
                    current.processed_offset = offset
                    current.imported_count = counts["stored"]
                    current.created_count = counts["created"]
                    current.updated_count = counts["updated"]
                    current.unchanged_count = counts["unchanged"]
                    current.failed_count = counts["failed"]
                    current.stage = "persisting"
                    current.updated_at = now()
                summary = PipelineService(self.session).run_external_feed(
                    connector, expected_identity=expected, acknowledge=False,
                    pipeline_run_id=operation.pipeline_run_id,
                    expected_checkpoint=operation.gateway_checkpoint,
                    require_unidentified=legacy,
                    start_offset=operation.processed_offset,
                    max_batches=1 if operation.priority <= 0 else None,
                    progress_callback=persist_progress)
                details = summary.get("details") if isinstance(summary.get("details"), dict) else {}
                operation = self.session.get(ExternalIngestionOperation, operation_id)
                if operation is None:
                    raise RuntimeError("external_operation_disappeared")
                operation.pipeline_run_id = summary["run_id"]
                operation.gateway_checkpoint = details.get("gateway_ack_checkpoint") or details.get("checkpoint")
                operation.imported_count = int(summary.get("stored_count") or 0)
                operation.created_count = int(details.get("created_items") or 0)
                operation.updated_count = int(details.get("updated_items") or 0)
                operation.unchanged_count = int(details.get("database_unchanged_items") or 0)
                operation.failed_count = int(summary.get("failed_count") or 0)
                if details.get("processing_complete") is False:
                    operation.state, operation.stage = "central_importing", "persisting"
                    operation.claim_token = None
                    operation.lease_expires_at = None
                    operation.updated_at = now()
                    self.session.commit()
                    _wake.set()
                    return
                operation.state, operation.stage = "committed", "committed"
                self.session.commit()
            if operation.state in {"committed", "acknowledging"}:
                operation.state, operation.stage = "acknowledging", "acknowledging"
                self.session.commit()
                legacy = operation.external_job_id.startswith("gateway-legacy-")
                expected = (None if legacy else
                    (operation.external_job_id, operation.export_run_id, operation.dataset_sha256))
                connector = connector or PipelineService.external_feed_connector(expected_identity=expected)
                if not operation.gateway_checkpoint or not operation.pipeline_run_id:
                    raise ValueError("committed_operation_identity_invalid")
                PipelineService(self.session).acknowledge_external_feed(
                    connector, operation.gateway_checkpoint, operation.pipeline_run_id)
            operation.state = "partial" if operation.failed_count else "completed"
            operation.stage = "completed"
            operation.retryable = False
            operation.acknowledged_count = operation.exported_count
            operation.completed_at = now(); operation.updated_at = now(); self.session.commit()
            self._release_claim(operation.id)
        except (requests.Timeout, requests.ConnectionError):
            self.session.rollback(); self._fail(operation.id, "upstream_unavailable", "transport", True)
        except requests.HTTPError as exc:
            self.session.rollback()
            status_code = exc.response.status_code if exc.response is not None else 0
            retryable = status_code == 409 or status_code >= 500
            code = "gateway_checkpoint_pending" if status_code == 409 else "upstream_http_failure"
            self._fail(operation.id, code, "http_status", retryable)
        except Exception as exc:
            self.session.rollback()
            LOGGER.exception("external ingestion failed operation_id=%s stage=%s exception_class=%s",
                             operation.id, operation.stage, type(exc).__name__)
            code, retryable = _safe_failure(exc, operation.stage)
            self._fail(operation.id, code, operation.stage[:100], retryable)

    def _publish_exact_export(self, operation: ExternalIngestionOperation) -> None:
        settings = get_settings()
        if self.client is None or not settings.external_feed_publish_token or not settings.external_feed_url:
            raise RuntimeError("external_feed_publish_not_configured")
        records, offset, total = [], 0, None
        while True:
            page = self.client.accepted_export_page(limit=250, offset=offset, run_id=operation.export_run_id)
            digest = str(page.get("dataset_sha256") or "").removeprefix("sha256:")
            if page.get("export_run_id") != operation.export_run_id or digest != operation.dataset_sha256:
                raise ValueError("external_export_identity_mismatch")
            if total is None: total = int(page["total"])
            elif total != int(page["total"]): raise RuntimeError("external_export_changed")
            records.extend(page["items"]); offset += len(page["items"])
            if offset >= total: break
            if not page["items"] or offset > 20_000: raise RuntimeError("external_export_pagination_invalid")
        publish_url = str(settings.external_feed_url).rstrip("/") + "/publish"
        response = requests.post(publish_url, headers={"Authorization": f"Bearer {settings.external_feed_publish_token}"},
            json={"schema_version":"1.0","external_job_id":operation.external_job_id,
                  "export_run_id":operation.export_run_id,"dataset_sha256":operation.dataset_sha256,
                  "generated_at":now().isoformat().replace("+00:00","Z"),"items":records},
            timeout=(settings.external_feed_connect_timeout_seconds, settings.external_feed_read_timeout_seconds),
            verify=settings.external_feed_verify_tls)
        response.raise_for_status()
        value=response.json()
        if not isinstance(value,dict) or value.get("status")!="accepted" or not value.get("etag"):
            raise RuntimeError("gateway_publish_contract_invalid")
        operation.exported_count=total or 0; operation.gateway_checkpoint=str(value["etag"]); self.session.commit()

    def _fail(self, operation_id: str, code: str, category: str, retryable: bool) -> None:
        operation = self.session.get(ExternalIngestionOperation, operation_id)
        if operation is None: return
        operation.state = "failed_retryable" if retryable else "failed_terminal"
        operation.stage = operation.stage or "central_importing"
        operation.retryable = retryable
        operation.error_code, operation.error_category = code[:100], category[:100]
        operation.updated_at = now(); operation.completed_at = None if retryable else now()
        operation.claim_token = None; operation.lease_expires_at = None
        self.session.commit()

    def _release_claim(self, operation_id: str) -> None:
        operation = self.session.get(ExternalIngestionOperation, operation_id)
        if operation is None: return
        operation.claim_token = None; operation.lease_expires_at = None
        self.session.commit()


def operation_dict(value: ExternalIngestionOperation) -> dict[str, Any]:
    return {name: getattr(value, name) for name in (
        "id", "operation_type", "state", "stage", "retryable", "attempt_count",
        "created_at", "started_at", "updated_at", "completed_at", "external_job_id",
        "export_run_id", "dataset_sha256", "gateway_checkpoint", "pipeline_run_id",
        "collected_count", "exported_count", "imported_count", "created_count",
        "updated_count", "unchanged_count", "failed_count", "acknowledged_count",
        "priority", "processed_offset", "fairness_skips",
        "error_code", "error_category")}


def _retry_state(stage: str) -> str:
    if stage == "acknowledging":
        return "acknowledging"
    if stage == "committed":
        return "committed"
    if stage == "central_importing":
        return "central_importing"
    if stage == "published":
        return "published"
    return "queued"


def _safe_failure(exc: Exception, stage: str) -> tuple[str, bool]:
    """Map internal failures to a bounded, payload-free API code."""
    if isinstance(exc, (ValueError, TypeError)):
        return "invalid_external_contract", False
    if stage == "published":
        return "gateway_publish_failed", True
    if stage == "acknowledging":
        return "gateway_ack_failed", True
    if stage in {"central_importing", "committed"}:
        return "central_processing_failed", True
    return "external_ingestion_failed", True


def _worker() -> None:
    while not _stop.is_set():
        with SessionLocal() as session:
            operation = _claim_next(session)
            if operation is None and get_settings().external_ingestion_auto_adopt_gateway:
                _ensure_gateway_operation(session)
                operation = _claim_next(session)
            if operation is not None:
                # Client is unused by feed processing; creation validates exact
                # External identity synchronously before the operation is queued.
                from backend.app.api.v1.router import external_control_client
                ExternalIngestionService(session, external_control_client()).process(operation)
                continue
        _wake.wait(max(1, min(get_settings().external_ingestion_poll_seconds, 60))); _wake.clear()


def _claim_next(session: Session) -> ExternalIngestionOperation | None:
    claimed_at = now()
    available = (
        ExternalIngestionOperation.state.in_(RESUMABLE),
        or_(ExternalIngestionOperation.claim_token.is_(None),
            ExternalIngestionOperation.lease_expires_at.is_(None),
            ExternalIngestionOperation.lease_expires_at <= claimed_at),
    )
    # Strict interactive priority at every claim boundary. Backlog processing is
    # limited to one committed batch in process(), so a newly queued interactive
    # operation is observed before another background batch is claimed. FIFO is
    # preserved inside each priority class and an in-flight batch is never cut.
    candidate = session.scalar(select(ExternalIngestionOperation.id).where(
        *available,
    ).order_by(ExternalIngestionOperation.priority.desc(),
               ExternalIngestionOperation.created_at,
               ExternalIngestionOperation.id).with_for_update(skip_locked=True).limit(1))
    if candidate is None:
        return None
    token = str(uuid.uuid4())
    lease_seconds = max(60, min(get_settings().external_ingestion_lease_seconds, 86_400))
    selected_priority = session.scalar(select(ExternalIngestionOperation.priority).where(
        ExternalIngestionOperation.id == candidate))
    result = session.execute(update(ExternalIngestionOperation).where(
        ExternalIngestionOperation.id == candidate,
        or_(ExternalIngestionOperation.claim_token.is_(None),
            ExternalIngestionOperation.lease_expires_at.is_(None),
            ExternalIngestionOperation.lease_expires_at <= claimed_at),
    ).values(claim_token=token, lease_expires_at=claimed_at + timedelta(seconds=lease_seconds),
             updated_at=claimed_at,
             attempt_count=ExternalIngestionOperation.attempt_count + 1,
             fairness_skips=0 if (selected_priority or 0) <= 0
                            else ExternalIngestionOperation.fairness_skips))
    session.commit()
    if result.rowcount != 1:
        return None
    return session.scalar(select(ExternalIngestionOperation).where(
        ExternalIngestionOperation.id == candidate,
        ExternalIngestionOperation.claim_token == token))


def _ensure_gateway_operation(session: Session) -> None:
    """Adopt a published Gateway checkpoint without acknowledging it early."""
    try:
        source = session.scalar(select(Source).where(Source.name == "Remote External Feed API",
                                                     Source.source_pipeline == "external"))
        connector = PipelineService.external_feed_connector(
            state=dict(source.config or {}) if source is not None else None)
        result = connector.fetch()
    except Exception:
        return
    if not result.checkpoint or result.not_modified:
        return
    complete_identity = bool(result.external_job_id and result.export_run_id and result.dataset_sha256)
    partial_identity = bool(result.external_job_id or result.export_run_id or result.dataset_sha256)
    if partial_identity and not complete_identity:
        return
    suffix = result.checkpoint[:16]
    external_job_id = result.external_job_id or f"gateway-legacy-{suffix}"
    export_run_id = result.export_run_id or f"gateway-checkpoint-{suffix}"
    digest = result.dataset_sha256 or result.checkpoint
    existing = session.scalar(select(ExternalIngestionOperation).where(
        ExternalIngestionOperation.external_job_id == external_job_id,
        ExternalIngestionOperation.export_run_id == export_run_id,
        ExternalIngestionOperation.dataset_sha256 == digest))
    if existing is not None:
        return
    session.add(ExternalIngestionOperation(
        external_job_id=external_job_id, export_run_id=export_run_id,
        dataset_sha256=digest, state="published", stage="published",
        exported_count=len(result.records), gateway_checkpoint=result.checkpoint,
        priority=0))
    try:
        session.commit()
    except IntegrityError:
        session.rollback()


def start_external_ingestion_worker() -> None:
    global _thread
    if not get_settings().external_ingestion_worker_enabled or (_thread and _thread.is_alive()): return
    _stop.clear(); _thread = threading.Thread(target=_worker, name="external-ingestion-worker", daemon=True); _thread.start()


def notify_external_ingestion_worker() -> None:
    _wake.set()


def stop_external_ingestion_worker() -> None:
    _stop.set(); _wake.set()
    if _thread: _thread.join(timeout=10)
