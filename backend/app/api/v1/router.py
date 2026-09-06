from __future__ import annotations

import hashlib
import uuid
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, File, Header, HTTPException, Query, UploadFile, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import desc, func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, selectinload

from backend.app.core.config import get_settings
from backend.app.core.security import (
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)
from backend.app.db.database import get_db
from backend.app.db.models import (
    AuditLog,
    CorrelationRecord,
    IndicatorRecord,
    OutlierSessionRecord,
    PipelineRun,
    Source,
    ThreatEvent,
    User,
)
from backend.app.integrations.external_control_client import (
    ExternalControlClient,
    ExternalControlError,
    ExternalControlRemoteError,
)
from backend.app.integrations.misp_client import MISPClient
from backend.app.integrations.stix_exporter import STIXExporter
from backend.app.repositories.cti_repository import CTIRepository
from backend.app.schemas.api import (
    BootstrapRequest,
    CorrelationRequest,
    ExternalCollectionStartRequest,
    ExternalManualSourceRequest,
    ExternalManualPreviewApproveRequest,
    ExternalManualPreviewRejectRequest,
    ExternalManualPreviewRequest,
    ExternalManualPreviewResponse,
    ExternalManualPreviewRejectedResponse,
    ExternalSourceRunRequest,
    LoginRequest,
    MISPSendRequest,
    SourceCreate,
    UserCreate,
)
from backend.app.services.model_evidence_service import ModelEvidenceService
from backend.app.services.pipeline_service import PipelineService

router = APIRouter()
security = HTTPBearer(auto_error=False)
SessionDep = Annotated[Session, Depends(get_db)]


def iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def get_current_user(
    db: SessionDep,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(security)],
) -> User:
    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    try:
        payload = decode_access_token(credentials.credentials)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
    user = db.get(User, payload["sub"])
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Inactive or unknown user")
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def require_roles(*roles: str):
    def dependency(user: CurrentUser) -> User:
        if user.role not in roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role")
        return user

    return dependency


def external_control_client() -> ExternalControlClient:
    settings = get_settings()
    if not settings.external_control_configured:
        raise HTTPException(status_code=503, detail="External Sources control API is not configured")
    try:
        return ExternalControlClient(
            str(settings.external_control_api_url),
            str(settings.external_control_api_token),
            verify_tls=settings.external_control_verify_tls,
            allow_http=settings.external_control_allow_http,
            timeout_seconds=settings.external_control_timeout_seconds,
            max_response_bytes=settings.external_control_max_bytes,
        )
    except ValueError as exc:
        raise HTTPException(status_code=503, detail="External Sources control configuration is invalid") from exc


def external_control_call(callback):
    try:
        return callback(external_control_client())
    except ExternalControlRemoteError as exc:
        status_code = exc.status_code if 400 <= exc.status_code < 500 else 502
        raise HTTPException(
            status_code=status_code,
            detail={"code": exc.code, "message": exc.message},
        ) from exc
    except ExternalControlError as exc:
        raise HTTPException(status_code=503, detail="External Sources control API is unreachable") from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


def event_query():
    return select(ThreatEvent).options(
        selectinload(ThreatEvent.indicators).selectinload(IndicatorRecord.enrichments),
        selectinload(ThreatEvent.entities),
        selectinload(ThreatEvent.relationships),
    )


def event_dict(event: ThreatEvent, detail: bool = False) -> dict[str, Any]:
    payload = {
        "id": event.id,
        "source_record_id": event.source_record_id,
        "source_type": event.source_type,
        "source_pipeline": event.source_pipeline,
        "title": event.title,
        "description": event.description if detail else event.description[:500],
        "classification_label": event.classification_label,
        "classification_confidence": event.classification_confidence,
        "classification_backend": event.classification_backend,
        "severity": event.severity,
        "risk_score": event.risk_score,
        "confidence": event.confidence,
        "tags": event.tags,
        "first_seen": iso(event.first_seen),
        "last_seen": iso(event.last_seen),
        "processing_status": event.processing_status,
        "created_at": iso(event.created_at),
        "indicator_count": len(event.indicators),
        "entity_count": len(event.entities),
    }
    if detail:
        payload.update(
            {
                "normalized_text": event.normalized_text,
                "raw_reference": event.raw_reference,
                "indicators": [
                    {
                        "id": item.id,
                        "type": item.indicator_type,
                        "value": item.value,
                        "confidence": item.confidence,
                        "extractor": item.extractor,
                        "semantic_role": "observable",
                        "enrichments": [
                            {
                                "provider": enrichment.provider,
                                "status": enrichment.status,
                                "data": enrichment.data,
                                "enriched_at": iso(enrichment.enriched_at),
                            }
                            for enrichment in item.enrichments
                        ],
                    }
                    for item in event.indicators
                ],
                "entities": [
                    {
                        "id": item.id,
                        "type": item.entity_type,
                        "value": item.value,
                        "confidence": item.confidence,
                        "extractor": item.extractor,
                    }
                    for item in event.entities
                ],
                "relationships": [
                    {
                        "subject": item.subject,
                        "relation": item.relation,
                        "object": item.object_value,
                        "confidence": item.confidence,
                        "method": item.extraction_method,
                    }
                    for item in event.relationships
                ],
            }
        )
    return payload


def audit(db: Session, user: User, action: str, resource_type: str, resource_id: str | None = None, **details) -> None:
    CTIRepository(db).audit(
        action,
        resource_type,
        resource_id,
        user_id=user.id,
        username=user.username,
        details=details,
    )


@router.get("/health", tags=["system"])
def health(db: SessionDep) -> dict[str, Any]:
    database_ok = True
    try:
        db.scalar(select(func.count()).select_from(Source))
    except SQLAlchemyError:
        database_ok = False
    return {"status": "ok" if database_ok else "degraded", "database": database_ok}


@router.post("/auth/bootstrap", tags=["auth"], status_code=201)
def bootstrap_admin(payload: BootstrapRequest, db: SessionDep) -> dict[str, Any]:
    if db.scalar(select(func.count()).select_from(User)):
        raise HTTPException(status_code=409, detail="Bootstrap is disabled after the first user is created")
    user = User(username=payload.username, password_hash=hash_password(payload.password), role="admin")
    db.add(user)
    db.flush()
    CTIRepository(db).audit("bootstrap_admin", "user", user.id, user_id=user.id, username=user.username)
    db.commit()
    return {"id": user.id, "username": user.username, "role": user.role}


@router.post("/auth/login", tags=["auth"])
def login(payload: LoginRequest, db: SessionDep) -> dict[str, Any]:
    user = db.scalar(select(User).where(User.username == payload.username))
    if user is None or not user.is_active or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    return {
        "access_token": create_access_token(user.id, user.role),
        "token_type": "bearer",
        "role": user.role,
    }


@router.get("/auth/me", tags=["auth"])
def me(user: CurrentUser) -> dict[str, Any]:
    return {"id": user.id, "username": user.username, "role": user.role, "is_active": user.is_active}


@router.post("/users", tags=["auth"], status_code=201)
def create_user(
    payload: UserCreate,
    db: SessionDep,
    admin: Annotated[User, Depends(require_roles("admin"))],
) -> dict[str, Any]:
    if db.scalar(select(User).where(User.username == payload.username)):
        raise HTTPException(status_code=409, detail="Username already exists")
    user = User(username=payload.username, password_hash=hash_password(payload.password), role=payload.role)
    db.add(user)
    db.flush()
    audit(db, admin, "create_user", "user", user.id, role=user.role)
    db.commit()
    return {"id": user.id, "username": user.username, "role": user.role}


@router.get("/sources", tags=["sources"])
def list_sources(db: SessionDep, _: CurrentUser) -> list[dict[str, Any]]:
    sources = db.scalars(select(Source).order_by(Source.name)).all()
    return [
        {
            "id": item.id,
            "name": item.name,
            "source_type": item.source_type,
            "source_pipeline": item.source_pipeline,
            "enabled": item.enabled,
            "config": item.config,
        }
        for item in sources
    ]


@router.post("/sources", tags=["sources"], status_code=201)
def create_source(
    payload: SourceCreate,
    db: SessionDep,
    user: Annotated[User, Depends(require_roles("admin", "analyst"))],
) -> dict[str, Any]:
    if db.scalar(select(Source).where(Source.name == payload.name)):
        raise HTTPException(status_code=409, detail="Source name already exists")
    source = Source(**payload.model_dump())
    db.add(source)
    db.flush()
    audit(db, user, "create_source", "source", source.id, source_type=source.source_type)
    db.commit()
    return {"id": source.id, **payload.model_dump()}


async def save_upload(file: UploadFile) -> Path:
    settings = get_settings()
    suffix = Path(file.filename or "upload.json").suffix.lower()
    if suffix not in {".json", ".jsonl", ".ndjson"}:
        raise HTTPException(status_code=400, detail="Only JSON, JSONL, and NDJSON files are accepted")
    content = await file.read(settings.max_upload_bytes + 1)
    if len(content) > settings.max_upload_bytes:
        raise HTTPException(status_code=413, detail="Upload exceeds configured size limit")
    digest = hashlib.sha256(content).hexdigest()[:16]
    safe_stem = "".join(ch for ch in Path(file.filename or "upload").stem if ch.isalnum() or ch in "-_")[:80] or "upload"
    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    destination = settings.upload_dir / f"{safe_stem}-{digest}{suffix}"
    destination.write_bytes(content)
    return destination


@router.post("/uploads/external", tags=["pipeline"])
async def upload_external(
    db: SessionDep,
    user: Annotated[User, Depends(require_roles("admin", "analyst"))],
    file: Annotated[UploadFile, File()],
) -> dict[str, Any]:
    path = await save_upload(file)
    result = PipelineService(db).run_external_files([path])
    audit(db, user, "run_external_pipeline", "pipeline_run", result["run_id"], filename=file.filename)
    db.commit()
    return result


@router.post("/uploads/wazuh", tags=["pipeline"])
async def upload_wazuh(
    db: SessionDep,
    user: Annotated[User, Depends(require_roles("admin", "analyst"))],
    file: Annotated[UploadFile, File()],
) -> dict[str, Any]:
    path = await save_upload(file)
    result = PipelineService(db).run_wazuh_files([path])
    audit(db, user, "run_internal_pipeline", "pipeline_run", result["run_id"], filename=file.filename)
    db.commit()
    return result


@router.post("/uploads/dionaea", tags=["pipeline"])
async def upload_dionaea(
    db: SessionDep,
    user: Annotated[User, Depends(require_roles("admin", "analyst"))],
    file: Annotated[UploadFile, File()],
) -> dict[str, Any]:
    path = await save_upload(file)
    result = PipelineService(db).run_dionaea_files([path])
    audit(db, user, "run_dionaea_pipeline", "pipeline_run", result["run_id"], filename=file.filename)
    db.commit()
    return result


@router.get("/integrations/status", tags=["integrations"])
def integration_status(_: CurrentUser) -> dict[str, Any]:
    """Report configuration state without returning URLs, usernames, or secrets."""
    return PipelineService.integration_status()


@router.get("/ml/status", tags=["ml"])
def ml_status(_: CurrentUser) -> dict[str, Any]:
    """Return runtime selection and saved held-out evaluation evidence."""
    return ModelEvidenceService.status()


@router.get("/integrations/external-feed/health", tags=["integrations"])
def external_feed_health(_: CurrentUser) -> dict[str, Any]:
    return PipelineService.external_feed_health()


@router.get("/integrations/external-control/health", tags=["external-control"])
def external_control_health(_: CurrentUser) -> dict[str, Any]:
    settings = get_settings()
    if not settings.external_control_configured:
        return {"configured": False, "reachable": False}
    return external_control_client().healthcheck()


@router.get("/integrations/external-control/sources", tags=["external-control"])
def external_control_sources(_: CurrentUser) -> list[dict[str, Any]]:
    return external_control_call(lambda client: client.list_sources())


@router.post("/integrations/external-control/jobs", tags=["external-control"], status_code=202)
def external_control_start_job(
    payload: ExternalCollectionStartRequest,
    db: SessionDep,
    user: Annotated[User, Depends(require_roles("admin", "analyst"))],
) -> dict[str, Any]:
    result = external_control_call(
        lambda client: client.start_collection(
            source_ids=payload.source_ids,
            scope=payload.scope,
            force=payload.force,
        )
    )
    audit(db, user, "start_external_collection", "external_collection_job", result["job_id"],
          scope=payload.scope, source_count=len(payload.source_ids), force=payload.force)
    db.commit()
    return result


@router.post(
    "/integrations/external-control/sources/{source_id}/jobs",
    tags=["external-control"],
    status_code=202,
)
def external_control_source_job(
    source_id: str,
    payload: ExternalSourceRunRequest,
    db: SessionDep,
    user: Annotated[User, Depends(require_roles("admin", "analyst"))],
) -> dict[str, Any]:
    result = external_control_call(lambda client: client.collect_source(source_id, force=payload.force))
    audit(db, user, "collect_external_source", "external_collection_job", result["job_id"],
          source_id=source_id, force=payload.force)
    db.commit()
    return result


@router.get("/integrations/external-control/jobs/{job_id}", tags=["external-control"])
def external_control_job(job_id: str, _: CurrentUser) -> dict[str, Any]:
    return external_control_call(lambda client: client.get_job(job_id))


@router.post(
    "/integrations/external-control/manual-sources",
    tags=["external-control"],
    status_code=202,
)
def external_control_manual_source(
    payload: ExternalManualSourceRequest,
    db: SessionDep,
    user: Annotated[User, Depends(require_roles("admin", "analyst"))],
) -> dict[str, Any]:
    result = external_control_call(
        lambda client: client.add_manual_source(str(payload.url), force=payload.force)
    )
    audit(db, user, "add_external_manual_source", "external_collection_job", result["job_id"],
          force=payload.force)
    db.commit()
    return result


@router.post(
    "/integrations/external-control/manual-sources/recheck",
    tags=["external-control"],
    status_code=202,
)
def external_control_manual_recheck(
    payload: ExternalManualSourceRequest,
    db: SessionDep,
    user: Annotated[User, Depends(require_roles("admin", "analyst"))],
) -> dict[str, Any]:
    result = external_control_call(lambda client: client.recheck_manual_source(str(payload.url)))
    audit(db, user, "recheck_external_manual_source", "external_collection_job", result["job_id"])
    db.commit()
    return result


@router.post("/integrations/external-control/manual-sources/previews", tags=["external-control"],
             response_model=ExternalManualPreviewResponse, response_model_exclude_none=True, status_code=201)
def external_control_manual_preview(payload: ExternalManualPreviewRequest, db: SessionDep,
                                    user: Annotated[User, Depends(require_roles("admin", "analyst"))]):
    result = external_control_call(lambda client: client.create_manual_preview(str(payload.url)))
    audit(db, user, "preview_external_manual_source", "external_manual_preview", result["preview_id"],
          content_sha256=result["content_sha256"], counts=result["counts"])
    db.commit(); return result


@router.post("/integrations/external-control/manual-sources/previews/{preview_id}/approve",
             tags=["external-control"], status_code=202)
def external_control_manual_preview_approve(preview_id: str, payload: ExternalManualPreviewApproveRequest,
                                            db: SessionDep,
                                            user: Annotated[User, Depends(require_roles("admin", "analyst"))],
                                            idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None):
    key = idempotency_key or str(uuid.uuid4())
    result = external_control_call(lambda client: client.approve_manual_preview(
        preview_id, payload.expected_content_sha256, idempotency_key=key))
    audit(db, user, "approve_external_manual_preview", "external_manual_preview", preview_id,
          content_sha256=payload.expected_content_sha256)
    db.commit(); return result


@router.post("/integrations/external-control/manual-sources/previews/{preview_id}/reject",
             tags=["external-control"], response_model=ExternalManualPreviewRejectedResponse)
def external_control_manual_preview_reject(preview_id: str, payload: ExternalManualPreviewRejectRequest,
                                           db: SessionDep,
                                           user: Annotated[User, Depends(require_roles("admin", "analyst"))],
                                           idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None):
    key = idempotency_key or str(uuid.uuid4())
    result = external_control_call(lambda client: client.reject_manual_preview(preview_id, payload.reason, idempotency_key=key))
    audit(db, user, "reject_external_manual_preview", "external_manual_preview", preview_id, decision="rejected", reason=payload.reason)
    db.commit(); return result


@router.get("/integrations/external-control/exports/latest", tags=["external-control"])
def external_control_latest_export(_: CurrentUser) -> dict[str, Any]:
    return external_control_call(lambda client: client.latest_export_summary())


@router.post("/integrations/external-feed/pull", tags=["integrations"])
def pull_external_feed(
    db: SessionDep,
    user: Annotated[User, Depends(require_roles("admin", "analyst"))],
) -> dict[str, Any]:
    try:
        result = PipelineService(db).run_external_feed()
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"External feed pull failed: {type(exc).__name__}") from exc
    audit(db, user, "pull_external_feed", "pipeline_run", result["run_id"], details=result["details"])
    db.commit()
    return result


@router.get("/integrations/wazuh/health", tags=["integrations"])
def wazuh_indexer_health(_: CurrentUser) -> dict[str, Any]:
    return PipelineService.wazuh_indexer_health()


@router.post("/integrations/wazuh/pull", tags=["integrations"])
def pull_wazuh_indexer(
    db: SessionDep,
    user: Annotated[User, Depends(require_roles("admin", "analyst"))],
) -> dict[str, Any]:
    try:
        result = PipelineService(db).run_wazuh_indexer()
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Wazuh indexer pull failed: {type(exc).__name__}") from exc
    audit(db, user, "pull_wazuh_indexer", "pipeline_run", result["run_id"], details=result["details"])
    db.commit()
    return result


@router.get("/integrations/dionaea/health", tags=["integrations"])
def dionaea_api_health(_: CurrentUser) -> dict[str, Any]:
    return PipelineService.dionaea_api_health()


@router.post("/integrations/dionaea/pull", tags=["integrations"])
def pull_dionaea_api(
    db: SessionDep,
    user: Annotated[User, Depends(require_roles("admin", "analyst"))],
) -> dict[str, Any]:
    try:
        result = PipelineService(db).run_dionaea_api()
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Dionaea API pull failed: {type(exc).__name__}",
        ) from exc
    audit(db, user, "pull_dionaea_api", "pipeline_run", result["run_id"], details=result["details"])
    db.commit()
    return result


@router.get("/integrations/host-auth/health", tags=["integrations"])
def host_auth_api_health(_: CurrentUser) -> dict[str, Any]:
    return PipelineService.security_sensor_health("linux_auth")


@router.post("/integrations/host-auth/pull", tags=["integrations"])
def pull_host_auth_api(
    db: SessionDep,
    user: Annotated[User, Depends(require_roles("admin", "analyst"))],
) -> dict[str, Any]:
    try:
        result = PipelineService(db).run_security_sensor_api("linux_auth")
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Host authentication sensor pull failed: {type(exc).__name__}",
        ) from exc
    audit(db, user, "pull_host_auth_sensor", "pipeline_run", result["run_id"], details=result["details"])
    db.commit()
    return result


@router.get("/integrations/web-access/health", tags=["integrations"])
def web_access_api_health(_: CurrentUser) -> dict[str, Any]:
    return PipelineService.security_sensor_health("web_access")


@router.post("/integrations/web-access/pull", tags=["integrations"])
def pull_web_access_api(
    db: SessionDep,
    user: Annotated[User, Depends(require_roles("admin", "analyst"))],
) -> dict[str, Any]:
    try:
        result = PipelineService(db).run_security_sensor_api("web_access")
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Web access sensor pull failed: {type(exc).__name__}",
        ) from exc
    audit(db, user, "pull_web_access_sensor", "pipeline_run", result["run_id"], details=result["details"])
    db.commit()
    return result


@router.post("/internal/dionaea/collect", tags=["internal"])
def collect_dionaea_log(
    db: SessionDep,
    user: Annotated[User, Depends(require_roles("admin", "analyst"))],
) -> dict[str, Any]:
    settings = get_settings()
    path = settings.dionaea_json_log_path
    if not path.is_file():
        raise HTTPException(status_code=404, detail=f"Dionaea JSON log not found at {path}")
    if path.stat().st_size > settings.dionaea_max_log_bytes:
        raise HTTPException(
            status_code=413,
            detail="Dionaea JSON log exceeds the configured collection limit; rotate it before ingestion",
        )
    result = PipelineService(db).run_dionaea_files([path])
    audit(db, user, "collect_dionaea_log", "pipeline_run", result["run_id"], path=str(path))
    db.commit()
    return result


@router.get("/events", tags=["cti"])
def list_events(
    db: SessionDep,
    _: CurrentUser,
    source_pipeline: str | None = None,
    severity: str | None = None,
    processing_status: str | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> list[dict[str, Any]]:
    query = event_query().order_by(desc(ThreatEvent.created_at)).limit(limit).offset(offset)
    if source_pipeline:
        query = query.where(ThreatEvent.source_pipeline == source_pipeline)
    if severity:
        query = query.where(ThreatEvent.severity == severity)
    if processing_status:
        query = query.where(ThreatEvent.processing_status == processing_status)
    events = db.scalars(query).unique().all()
    return [event_dict(item) for item in events]


@router.get("/events/{event_id}", tags=["cti"])
def get_event(event_id: str, db: SessionDep, _: CurrentUser) -> dict[str, Any]:
    event = db.scalar(event_query().where(ThreatEvent.id == event_id))
    if event is None:
        raise HTTPException(status_code=404, detail="Threat event not found")
    return event_dict(event, detail=True)


@router.post("/events/{event_id}/enrich/nvd", tags=["enrichment"])
def enrich_event(
    event_id: str,
    db: SessionDep,
    user: Annotated[User, Depends(require_roles("admin", "analyst"))],
) -> dict[str, Any]:
    try:
        results = PipelineService(db).enrich_event_cves(event_id)
    except LookupError:
        raise HTTPException(status_code=404, detail="Threat event not found")
    audit(db, user, "enrich_nvd", "threat_event", event_id, result_count=len(results))
    db.commit()
    return {"event_id": event_id, "results": results}


@router.get("/indicators", tags=["cti"])
def list_indicators(
    db: SessionDep,
    _: CurrentUser,
    indicator_type: str | None = None,
    limit: int = Query(200, ge=1, le=1000),
) -> list[dict[str, Any]]:
    query = select(IndicatorRecord).order_by(IndicatorRecord.indicator_type, IndicatorRecord.value).limit(limit)
    if indicator_type:
        query = query.where(IndicatorRecord.indicator_type == indicator_type)
    return [
        {
            "id": item.id,
            "event_id": item.event_id,
            "type": item.indicator_type,
            "value": item.value,
            "confidence": item.confidence,
            "extractor": item.extractor,
            "semantic_role": "observable",
        }
        for item in db.scalars(query)
    ]


@router.post("/correlations/run", tags=["correlation"])
def run_correlations(
    payload: CorrelationRequest,
    db: SessionDep,
    user: Annotated[User, Depends(require_roles("admin", "analyst"))],
) -> dict[str, int]:
    result = PipelineService(db).run_correlations(payload.similarity_threshold)
    audit(db, user, "run_correlations", "correlation", details=result)
    db.commit()
    return result


@router.get("/correlations", tags=["correlation"])
def list_correlations(db: SessionDep, _: CurrentUser, limit: int = Query(200, ge=1, le=1000)) -> list[dict[str, Any]]:
    records = db.scalars(select(CorrelationRecord).order_by(desc(CorrelationRecord.score)).limit(limit)).all()
    return [
        {
            "id": item.id,
            "event_a_id": item.event_a_id,
            "event_b_id": item.event_b_id,
            "type": item.correlation_type,
            "score": item.score,
            "reason": item.reason,
            "evidence": item.evidence,
        }
        for item in records
    ]


@router.get("/outliers", tags=["internal"])
def list_outliers(
    db: SessionDep,
    _: CurrentUser,
    only_outliers: bool = False,
    limit: int = Query(200, ge=1, le=1000),
) -> list[dict[str, Any]]:
    query = select(OutlierSessionRecord).order_by(desc(OutlierSessionRecord.started_at)).limit(limit)
    if only_outliers:
        query = query.where(OutlierSessionRecord.is_outlier.is_(True))
    return [
        {
            "id": item.id,
            "event_id": item.event_id,
            "source_ip": item.source_ip,
            "started_at": iso(item.started_at),
            "ended_at": iso(item.ended_at),
            "alert_count": item.alert_count,
            "features": item.features,
            "is_outlier": item.is_outlier,
            "anomaly_score": item.anomaly_score,
            "detector_backend": item.detector_backend,
        }
        for item in db.scalars(query)
    ]


@router.get("/runs", tags=["pipeline"])
def list_runs(db: SessionDep, _: CurrentUser, limit: int = Query(100, ge=1, le=500)) -> list[dict[str, Any]]:
    runs = db.scalars(select(PipelineRun).order_by(desc(PipelineRun.started_at)).limit(limit)).all()
    return [
        {
            "id": item.id,
            "pipeline": item.pipeline,
            "status": item.status,
            "counts": {
                "collected": item.collected_count,
                "processed": item.processed_count,
                "stored": item.stored_count,
                "failed": item.failed_count,
            },
            "details": item.details,
            "started_at": iso(item.started_at),
            "completed_at": iso(item.completed_at),
        }
        for item in runs
    ]


@router.get("/dashboard/summary", tags=["dashboard"])
def dashboard_summary(db: SessionDep, _: CurrentUser) -> dict[str, Any]:
    severity_rows = db.execute(select(ThreatEvent.severity, func.count()).group_by(ThreatEvent.severity)).all()
    pipeline_rows = db.execute(select(ThreatEvent.source_pipeline, func.count()).group_by(ThreatEvent.source_pipeline)).all()
    return {
        "events": db.scalar(select(func.count()).select_from(ThreatEvent)) or 0,
        "indicators": db.scalar(select(func.count()).select_from(IndicatorRecord)) or 0,
        "observables": db.scalar(select(func.count()).select_from(IndicatorRecord)) or 0,
        "correlations": db.scalar(select(func.count()).select_from(CorrelationRecord)) or 0,
        "sessions": db.scalar(select(func.count()).select_from(OutlierSessionRecord)) or 0,
        "outliers": db.scalar(
            select(func.count()).select_from(OutlierSessionRecord).where(OutlierSessionRecord.is_outlier.is_(True))
        ) or 0,
        "by_severity": {str(key or "unknown"): count for key, count in severity_rows},
        "by_pipeline": {str(key): count for key, count in pipeline_rows},
    }


@router.get("/events/{event_id}/stix", tags=["sharing"])
def export_stix(event_id: str, db: SessionDep, _: CurrentUser) -> dict[str, Any]:
    event = db.scalar(event_query().where(ThreatEvent.id == event_id))
    if event is None:
        raise HTTPException(status_code=404, detail="Threat event not found")
    return STIXExporter().export_event(event)


@router.post("/events/{event_id}/misp", tags=["sharing"])
def send_misp(
    event_id: str,
    payload: MISPSendRequest,
    db: SessionDep,
    user: Annotated[User, Depends(require_roles("admin", "analyst"))],
) -> dict[str, Any]:
    event = db.scalar(event_query().where(ThreatEvent.id == event_id))
    if event is None:
        raise HTTPException(status_code=404, detail="Threat event not found")
    if not payload.dry_run and user.role != "admin":
        raise HTTPException(status_code=403, detail="Only admins may send data to MISP")
    try:
        result = MISPClient().send_event(event, dry_run=payload.dry_run)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"MISP request failed: {exc}") from exc
    audit(db, user, "misp_dry_run" if payload.dry_run else "misp_send", "threat_event", event_id)
    db.commit()
    return result


@router.get("/misp/health", tags=["sharing"])
def misp_health(_: CurrentUser) -> dict[str, Any]:
    return MISPClient().healthcheck()


@router.get("/audit", tags=["audit"])
def list_audit_logs(
    db: SessionDep,
    _: Annotated[User, Depends(require_roles("admin"))],
    limit: int = Query(200, ge=1, le=1000),
) -> list[dict[str, Any]]:
    logs = db.scalars(select(AuditLog).order_by(desc(AuditLog.created_at)).limit(limit)).all()
    return [
        {
            "id": item.id,
            "username": item.username,
            "action": item.action,
            "resource_type": item.resource_type,
            "resource_id": item.resource_id,
            "details": item.details,
            "created_at": iso(item.created_at),
        }
        for item in logs
    ]
