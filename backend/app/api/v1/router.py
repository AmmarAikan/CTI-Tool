from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Annotated, Any

from fastapi import APIRouter, Depends, File, Header, HTTPException, Query, Request, UploadFile, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import case, desc, func, or_, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session, selectinload

from backend.app.core.config import get_settings
from backend.app.core.rate_limit import SlidingWindowRateLimiter, rate_limit_key, request_identity
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
    EnrichmentRecord,
    EntityRecord,
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
    AdminAuditPageResponse,
    AdminPasswordResetRequest,
    AdminUserActiveRequest,
    AdminUserCreateRequest,
    AdminUserPageResponse,
    AdminUserResponse,
    AdminUserRoleRequest,
    BootstrapRequest,
    CorrelationRequest,
    ExternalCollectionStartRequest,
    ExternalManualSourceRequest,
    ExternalManualPreviewApproveRequest,
    ExternalManualPreviewRejectRequest,
    ExternalManualPreviewRequest,
    DarkWebWatchCreateRequest, DarkWebWatchPatchRequest, DarkWebDiscoveryWatchCreateRequest, DarkWebDiscoveredSourcePatchRequest,
    ExternalManualPreviewResponse,
    ExternalManualPreviewRejectedResponse,
    ExternalSourceRunRequest,
    IntelligenceCorrelationPageResponse,
    IntelligenceEventDetailResponse,
    IntelligenceEventPageResponse,
    IntelligenceIndicatorPageResponse,
    IntelligenceIndicatorSummaryResponse,
    IntelligenceAttackMappingResponse,
    IntelligenceSearchResponse,
    IntelligenceMISPBatchRequest,
    IntelligenceMISPBatchResponse,
    IntelligenceMISPCandidatePageResponse,
    IntelligenceMISPDeliveryResponse,
    IntelligenceMISPDeliveryHistoryResponse,
    IntelligenceMISPHealthResponse,
    IntelligenceMISPPreviewResponse,
    IntelligenceMLStatusResponse,
    IntelligenceOutlierPageResponse,
    IntelligenceRunPageResponse,
    IntelligenceRunResponse,
    IntelligenceStorylineResponse,
    InternalEventPageResponse,
    InternalPullResponse,
    LoginRequest,
    MISPSendRequest,
    SourceCreate,
    RegisteredUserResponse,
    RegisterRequest,
    UserCreate,
)
from backend.app.services.model_evidence_service import ModelEvidenceService
from backend.app.pipeline.enrichment.observable_assessor import ObservableAssessor
from backend.app.services.attack_mapping_service import AttackMappingService
from backend.app.services.pipeline_service import PipelineService

router = APIRouter()
security = HTTPBearer(auto_error=False)
AUTH_RATE_LIMITER = SlidingWindowRateLimiter()
DUMMY_PASSWORD_HASH = "scrypt$16384$8$1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
SessionDep = Annotated[Session, Depends(get_db)]


def iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


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
            preview_timeout_seconds=settings.external_control_preview_timeout_seconds,
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


def _rate_limited(retry_after: int) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail="Too many authentication attempts. Try again later.",
        headers={"Retry-After": str(retry_after)},
    )


@router.post(
    "/auth/register",
    tags=["auth"],
    response_model=RegisteredUserResponse,
    status_code=status.HTTP_201_CREATED,
)
def register(payload: RegisterRequest, request: Request, db: SessionDep) -> dict[str, Any]:
    username = payload.username.casefold()
    identity = request_identity(request)
    ip_key = rate_limit_key("register", identity)
    retry_after = AUTH_RATE_LIMITER.consume(ip_key, limit=5, window_seconds=3600)
    if retry_after is not None:
        raise _rate_limited(retry_after)

    existing = db.scalar(select(User).where(func.lower(User.username) == username))
    if existing is not None:
        CTIRepository(db).audit(
            "self_register_rejected",
            "user",
            username=username,
            details={"reason": "username_unavailable"},
        )
        db.commit()
        raise HTTPException(status_code=409, detail="Username is unavailable")

    user = User(
        username=username,
        password_hash=hash_password(payload.password),
        role="viewer",
        is_active=True,
    )
    db.add(user)
    try:
        db.flush()
        CTIRepository(db).audit(
            "self_register",
            "user",
            user.id,
            user_id=user.id,
            username=user.username,
            details={"role": "viewer"},
        )
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Username is unavailable") from exc
    return {
        "id": user.id,
        "username": user.username,
        "role": "viewer",
        "is_active": user.is_active,
    }


@router.post("/auth/login", tags=["auth"])
def login(payload: LoginRequest, request: Request, db: SessionDep) -> dict[str, Any]:
    identity = request_identity(request)
    ip_key = rate_limit_key("login_ip", identity)
    account_key = rate_limit_key("login_account", identity, payload.username)
    for key, limit in ((ip_key, 30), (account_key, 10)):
        retry_after = AUTH_RATE_LIMITER.consume(key, limit=limit, window_seconds=300)
        if retry_after is not None:
            raise _rate_limited(retry_after)

    user = db.scalar(select(User).where(User.username == payload.username))
    candidate_hash = user.password_hash if user is not None else DUMMY_PASSWORD_HASH
    password_valid = verify_password(payload.password, candidate_hash)
    if user is None or not user.is_active or not password_valid:
        CTIRepository(db).audit(
            "login_rejected",
            "session",
            user_id=user.id if user is not None else None,
            username=payload.username,
            details={"reason": "invalid_credentials"},
        )
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid username or password")

    AUTH_RATE_LIMITER.clear(ip_key, account_key)
    CTIRepository(db).audit(
        "login_success",
        "session",
        user_id=user.id,
        username=user.username,
        details={"role": user.role},
    )
    db.commit()
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


def _admin_user_dict(user: User) -> dict[str, Any]:
    return {
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "is_active": user.is_active,
        "created_at": iso(user.created_at),
    }


def _protect_last_active_admin(db: Session, user: User) -> None:
    if user.role != "admin" or not user.is_active:
        return
    active_admins = db.scalar(
        select(func.count()).select_from(User).where(
            User.role == "admin", User.is_active.is_(True)
        )
    ) or 0
    if active_admins <= 1:
        raise HTTPException(
            status_code=409,
            detail="The last active administrator cannot be demoted or deactivated",
        )


@router.get("/admin/users", tags=["administration"], response_model=AdminUserPageResponse)
def admin_users(
    db: SessionDep,
    _: Annotated[User, Depends(require_roles("admin"))],
    search: str | None = Query(default=None, min_length=2, max_length=100),
    role: str | None = Query(default=None, pattern="^(viewer|analyst|admin)$"),
    is_active: bool | None = None,
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    filters = []
    if search:
        filters.append(User.username.ilike(f"%{search}%"))
    if role:
        filters.append(User.role == role)
    if is_active is not None:
        filters.append(User.is_active.is_(is_active))
    total = db.scalar(select(func.count()).select_from(User).where(*filters)) or 0
    users = db.scalars(
        select(User).where(*filters).order_by(User.username, User.id).limit(limit).offset(offset)
    ).all()
    return {"items": [_admin_user_dict(item) for item in users], "total": total, "limit": limit, "offset": offset}


@router.post("/admin/users", tags=["administration"], response_model=AdminUserResponse, status_code=201)
def admin_create_user(
    payload: AdminUserCreateRequest,
    db: SessionDep,
    admin: Annotated[User, Depends(require_roles("admin"))],
) -> dict[str, Any]:
    if db.scalar(select(User).where(User.username == payload.username)):
        raise HTTPException(status_code=409, detail="Username already exists")
    user = User(username=payload.username, password_hash=hash_password(payload.password), role=payload.role)
    db.add(user)
    db.flush()
    audit(db, admin, "admin_create_user", "user", user.id, role=user.role)
    db.commit()
    return _admin_user_dict(user)


@router.patch("/admin/users/{user_id}/role", tags=["administration"], response_model=AdminUserResponse)
def admin_update_role(
    user_id: str,
    payload: AdminUserRoleRequest,
    db: SessionDep,
    admin: Annotated[User, Depends(require_roles("admin"))],
) -> dict[str, Any]:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if user.role == "admin" and payload.role != "admin":
        _protect_last_active_admin(db, user)
    previous_role = user.role
    user.role = payload.role
    audit(db, admin, "admin_change_user_role", "user", user.id, previous_role=previous_role, role=user.role)
    db.commit()
    return _admin_user_dict(user)


@router.patch("/admin/users/{user_id}/active", tags=["administration"], response_model=AdminUserResponse)
def admin_update_active(
    user_id: str,
    payload: AdminUserActiveRequest,
    db: SessionDep,
    admin: Annotated[User, Depends(require_roles("admin"))],
) -> dict[str, Any]:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if user.is_active and not payload.is_active:
        _protect_last_active_admin(db, user)
    previous = user.is_active
    user.is_active = payload.is_active
    audit(db, admin, "admin_change_user_active", "user", user.id, previous_active=previous, is_active=user.is_active)
    db.commit()
    return _admin_user_dict(user)


@router.post("/admin/users/{user_id}/password", tags=["administration"], response_model=AdminUserResponse)
def admin_reset_password(
    user_id: str,
    payload: AdminPasswordResetRequest,
    db: SessionDep,
    admin: Annotated[User, Depends(require_roles("admin"))],
) -> dict[str, Any]:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    user.password_hash = hash_password(payload.password)
    audit(db, admin, "admin_reset_user_password", "user", user.id)
    db.commit()
    return _admin_user_dict(user)


@router.get("/admin/audit", tags=["administration"], response_model=AdminAuditPageResponse)
def admin_audit_logs(
    db: SessionDep,
    _: Annotated[User, Depends(require_roles("admin"))],
    action: str | None = Query(default=None, min_length=2, max_length=100),
    actor: str | None = Query(default=None, min_length=2, max_length=100),
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    filters = []
    if action:
        filters.append(AuditLog.action == action)
    if actor:
        filters.append(AuditLog.username == actor)
    total = db.scalar(select(func.count()).select_from(AuditLog).where(*filters)) or 0
    logs = db.scalars(
        select(AuditLog).where(*filters).order_by(desc(AuditLog.created_at), desc(AuditLog.id)).limit(limit).offset(offset)
    ).all()
    return {
        "items": [{"id": item.id, "actor": item.username, "action": item.action, "target_type": item.resource_type, "target_id": item.resource_id, "outcome": "success", "created_at": iso(item.created_at)} for item in logs],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


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


@router.get("/integrations/external-control/jobs", tags=["external-control"])
def external_control_jobs(_: CurrentUser, limit: int = Query(default=50, ge=1, le=100)) -> dict[str, Any]:
    return external_control_call(lambda client: client.list_jobs(limit=limit))


@router.post("/integrations/external-control/jobs/{job_id}/cancel", tags=["external-control"])
def external_control_cancel_job(job_id: str, db: SessionDep,
                                user: Annotated[User, Depends(require_roles("admin", "analyst"))]) -> dict[str, Any]:
    result = external_control_call(lambda client: client.cancel_job(job_id))
    audit(db, user, "cancel_external_job", "external_collection_job", job_id)
    db.commit()
    return result


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


@router.get("/integrations/external-control/reviews/latest", tags=["external-control"])
def external_control_latest_reviews(_: CurrentUser) -> dict[str, Any]:
    return external_control_call(lambda client: client.latest_reviews())

@router.get("/dark-web/watches", tags=["dark-web"])
def dark_web_watches(_: CurrentUser): return external_control_call(lambda c:c.list_dark_web_watches())

@router.post("/dark-web/watches", tags=["dark-web"], status_code=201)
def dark_web_watch_create(payload: DarkWebWatchCreateRequest, db: SessionDep, user: Annotated[User,Depends(require_roles("admin","analyst"))]):
    result=external_control_call(lambda c:c.create_dark_web_watch(payload.keyword)); audit(db,user,"create_dark_web_watch","dark_web_watch",result["watch_id"]); db.commit(); return result

@router.patch("/dark-web/watches/{watch_id}", tags=["dark-web"])
def dark_web_watch_patch(watch_id:str,payload:DarkWebWatchPatchRequest,db:SessionDep,user:Annotated[User,Depends(require_roles("admin","analyst"))]):
    result=external_control_call(lambda c:c.patch_dark_web_watch(watch_id,payload.enabled)); audit(db,user,"update_dark_web_watch","dark_web_watch",watch_id,enabled=payload.enabled); db.commit(); return result

@router.post("/dark-web/watches/{watch_id}/scan",tags=["dark-web"],status_code=202)
def dark_web_watch_scan(watch_id:str,db:SessionDep,user:Annotated[User,Depends(require_roles("admin","analyst"))],idempotency_key:Annotated[str|None,Header(alias="Idempotency-Key")]=None):
    result=external_control_call(lambda c:c.scan_dark_web_watch(watch_id,idempotency_key or str(uuid.uuid4()))); audit(db,user,"scan_dark_web_watch","dark_web_watch",watch_id,job_id=result["job_id"]); db.commit(); return result

@router.get("/dark-web/watches/{watch_id}/results",tags=["dark-web"])
def dark_web_watch_results(watch_id:str,_:CurrentUser,limit:int=Query(25,ge=1,le=100),offset:int=Query(0,ge=0)):
    return external_control_call(lambda c:c.dark_web_watch_results(watch_id,limit,offset))

@router.get("/dark-web/discovery/providers",tags=["dark-web"])
def dark_web_discovery_providers(_:CurrentUser): return external_control_call(lambda c:c.dark_web_discovery_providers())

@router.post("/dark-web/discovery/watches",tags=["dark-web"],status_code=201)
def dark_web_discovery_watch_create(payload:DarkWebDiscoveryWatchCreateRequest,db:SessionDep,user:Annotated[User,Depends(require_roles("admin","analyst"))]):
    result=external_control_call(lambda c:c.create_dark_web_discovery_watch(payload.model_dump()));audit(db,user,"create_dark_web_discovery_watch","dark_web_watch",result["watch_id"]);db.commit();return result

@router.post("/dark-web/watches/{watch_id}/results/{result_id}/promote",tags=["dark-web"])
def dark_web_result_promote(watch_id:str,result_id:str,db:SessionDep,user:Annotated[User,Depends(require_roles("admin","analyst"))],idempotency_key:Annotated[str|None,Header(alias="Idempotency-Key")]=None):
    result=external_control_call(lambda c:c.promote_dark_web_result(watch_id,result_id,idempotency_key or str(uuid.uuid4())));audit(db,user,"promote_dark_web_source","dark_web_discovered_source",result["source_id"],watch_id=watch_id);db.commit();return result

@router.get("/dark-web/watches/{watch_id}/discovered-sources",tags=["dark-web"])
def dark_web_discovered_sources(watch_id:str,_:CurrentUser): return external_control_call(lambda c:c.dark_web_discovered_sources(watch_id))

@router.patch("/dark-web/discovered-sources/{source_id}",tags=["dark-web"])
def dark_web_discovered_source_patch(source_id:str,payload:DarkWebDiscoveredSourcePatchRequest,db:SessionDep,user:Annotated[User,Depends(require_roles("admin","analyst"))]):
    result=external_control_call(lambda c:c.patch_dark_web_discovered_source(source_id,payload.enabled));audit(db,user,"update_dark_web_discovered_source","dark_web_discovered_source",source_id,enabled=payload.enabled);db.commit();return result


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


def _safe_internal_pull_result(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "run_id": result["run_id"],
        "pipeline": "internal",
        "status": result["status"],
        "collected_count": result["collected_count"],
        "processed_count": result["processed_count"],
        "stored_count": result["stored_count"],
        "failed_count": result["failed_count"],
    }


@router.post("/integrations/dionaea/pull", tags=["integrations"], response_model=InternalPullResponse)
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
    return _safe_internal_pull_result(result)


@router.get("/integrations/host-auth/health", tags=["integrations"])
def host_auth_api_health(_: CurrentUser) -> dict[str, Any]:
    return PipelineService.security_sensor_health("linux_auth")


@router.post("/integrations/host-auth/pull", tags=["integrations"], response_model=InternalPullResponse)
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
    return _safe_internal_pull_result(result)


@router.get("/integrations/web-access/health", tags=["integrations"])
def web_access_api_health(_: CurrentUser) -> dict[str, Any]:
    return PipelineService.security_sensor_health("web_access")


@router.post("/integrations/web-access/pull", tags=["integrations"], response_model=InternalPullResponse)
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
    return _safe_internal_pull_result(result)


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


_INTERNAL_EVENT_TYPES = {
    "dionaea": ("Dionaea", "dionaea_session"),
    "host-auth": ("Host Auth", "linux_auth_session"),
    "web-access": ("Web Access", "web_access_session"),
}


@router.get(
    "/internal/sources/{integration}/events",
    tags=["internal"],
    response_model=InternalEventPageResponse,
)
def list_internal_source_events(
    integration: str,
    db: SessionDep,
    _: CurrentUser,
    severity: str | None = Query(default=None, max_length=30),
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    """Return a bounded UI projection with no raw logs or sensor identifiers."""
    profile = _INTERNAL_EVENT_TYPES.get(integration)
    if profile is None:
        raise HTTPException(status_code=404, detail="Internal integration not found")
    source_name, event_type = profile
    filters = [
        ThreatEvent.source_pipeline == "internal",
        ThreatEvent.source_type == event_type,
    ]
    if severity:
        filters.append(ThreatEvent.severity == severity)
    total = db.scalar(select(func.count()).select_from(ThreatEvent).where(*filters)) or 0
    records = db.scalars(
        select(ThreatEvent)
        .where(*filters)
        .order_by(desc(ThreatEvent.created_at), desc(ThreatEvent.id))
        .limit(limit)
        .offset(offset)
    ).all()
    summary = {
        "dionaea": "جلسة رصد من مصيدة Dionaea",
        "host-auth": "حدث مصادقة مضيف تمت معالجته",
        "web-access": "حدث وصول ويب تمت معالجته",
    }[integration]
    return {
        "items": [
            {
                "id": item.id,
                "integration": integration,
                "source": source_name,
                "event_type": event_type,
                "category": item.classification_label,
                "severity": item.severity,
                "summary": summary,
                "first_seen": iso(item.first_seen),
                "last_seen": iso(item.last_seen),
                "created_at": iso(item.created_at),
            }
            for item in records
        ],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


def _safe_event_title(event: ThreatEvent) -> str:
    if event.source_pipeline == "internal":
        return f"Internal {event.source_type.replace('_', ' ')} event"
    return event.title[:500]


def _safe_event_summary(event: ThreatEvent) -> str:
    if event.source_pipeline == "internal":
        return "Internal telemetry event processed by the Central Backend."
    return event.description[:500]


def _indicator_dict(item: IndicatorRecord, event: ThreatEvent) -> dict[str, Any]:
    assessment = ObservableAssessor().assess(item, event).to_dict()
    return {
        "id": item.id,
        "event_id": item.event_id,
        "type": item.indicator_type,
        "value": item.value,
        "confidence": item.confidence,
        "source_pipeline": event.source_pipeline,
        "severity": event.severity,
        "first_seen": iso(item.first_seen),
        "last_seen": iso(item.last_seen),
        **assessment,
    }


def _intelligence_event_dict(event: ThreatEvent) -> dict[str, Any]:
    return {
        "id": event.id,
        "title": _safe_event_title(event),
        "summary": _safe_event_summary(event),
        "source_type": event.source_type,
        "source_pipeline": event.source_pipeline,
        "category": event.classification_label,
        "severity": event.severity,
        "risk_score": event.risk_score,
        "confidence": event.confidence,
        "processing_status": event.processing_status,
        "first_seen": iso(event.first_seen),
        "last_seen": iso(event.last_seen),
        "created_at": iso(event.created_at),
        "indicator_count": len(event.indicators),
        "entity_count": sum(item.entity_type != "source_ip" for item in event.entities),
    }


def _escape_search_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _search_filter(query: str, columns: tuple[Any, ...]):
    pattern = f"%{_escape_search_like(query)}%"
    return or_(*(column.ilike(pattern, escape="\\") for column in columns))


def _search_rank(query: str, columns: tuple[Any, ...]):
    lowered = query.casefold()
    prefix = f"{_escape_search_like(lowered)}%"
    exact = or_(*(func.lower(column) == lowered for column in columns))
    starts = or_(*(func.lower(column).like(prefix, escape="\\") for column in columns))
    return case((exact, 0), (starts, 1), else_=2)


def _search_match(query: str, fields: list[tuple[str, str]]) -> tuple[str, str]:
    needle = query.casefold()
    for quality, predicate in (
        ("exact", lambda value: value == needle),
        ("prefix", lambda value: value.startswith(needle)),
        ("contains", lambda value: needle in value),
    ):
        for field, value in fields:
            if predicate(value.casefold()):
                return field, quality
    return fields[0][0], "contains"


@router.get("/intelligence/search", tags=["intelligence"], response_model=IntelligenceSearchResponse)
def intelligence_search(
    db: SessionDep,
    _: CurrentUser,
    q: str = Query(min_length=2, max_length=100, pattern=r"^[^\x00-\x1F\x7F]+$"),
    limit_per_type: int = Query(default=5, ge=1, le=10),
) -> dict[str, Any]:
    query = q.strip()
    if len(query) < 2:
        raise HTTPException(status_code=422, detail="Search query must contain at least two non-space characters")

    row_limit = limit_per_type + 1
    items: list[dict[str, Any]] = []
    truncated = False

    event_columns = (ThreatEvent.id, ThreatEvent.title)
    event_rows = db.execute(
        select(ThreatEvent, Source)
        .outerjoin(Source, Source.id == ThreatEvent.source_id)
        .where(_search_filter(query, event_columns))
        .order_by(_search_rank(query, event_columns), desc(ThreatEvent.created_at), ThreatEvent.id)
        .limit(row_limit)
    ).all()
    truncated = truncated or len(event_rows) > limit_per_type
    for event, source in event_rows[:limit_per_type]:
        match_field, match_quality = _search_match(query, [("id", event.id), ("title", event.title)])
        items.append({
            "kind": "event", "id": event.id, "label": _safe_event_title(event),
            "context": _safe_event_summary(event) or event.source_type,
            "match_field": match_field, "match_quality": match_quality,
            "source_pipeline": event.source_pipeline, "source_type": event.source_type,
            "source_id": event.source_id, "source_name": source.name if source else None,
            "event_id": event.id, "severity": event.severity,
            "confidence": event.confidence, "created_at": iso(event.created_at),
        })

    indicator_columns = (IndicatorRecord.id, IndicatorRecord.value, IndicatorRecord.indicator_type)
    indicator_rows = db.execute(
        select(IndicatorRecord, ThreatEvent, Source)
        .join(ThreatEvent, ThreatEvent.id == IndicatorRecord.event_id)
        .outerjoin(Source, Source.id == ThreatEvent.source_id)
        .where(_search_filter(query, indicator_columns))
        .order_by(_search_rank(query, indicator_columns), desc(ThreatEvent.created_at), IndicatorRecord.id)
        .limit(row_limit)
    ).all()
    truncated = truncated or len(indicator_rows) > limit_per_type
    for indicator, event, source in indicator_rows[:limit_per_type]:
        match_field, match_quality = _search_match(query, [
            ("id", indicator.id), ("value", indicator.value), ("type", indicator.indicator_type),
        ])
        items.append({
            "kind": "indicator", "id": indicator.id, "label": indicator.value,
            "context": f"{indicator.indicator_type} · {_safe_event_title(event)}"[:500],
            "match_field": match_field, "match_quality": match_quality,
            "source_pipeline": event.source_pipeline, "source_type": event.source_type,
            "source_id": event.source_id, "source_name": source.name if source else None,
            "event_id": event.id, "severity": event.severity,
            "confidence": indicator.confidence, "created_at": iso(event.created_at),
        })

    entity_columns = (EntityRecord.id, EntityRecord.value, EntityRecord.entity_type)
    entity_rows = db.execute(
        select(EntityRecord, ThreatEvent, Source)
        .join(ThreatEvent, ThreatEvent.id == EntityRecord.event_id)
        .outerjoin(Source, Source.id == ThreatEvent.source_id)
        .where(EntityRecord.entity_type != "source_ip", _search_filter(query, entity_columns))
        .order_by(_search_rank(query, entity_columns), desc(ThreatEvent.created_at), EntityRecord.id)
        .limit(row_limit)
    ).all()
    truncated = truncated or len(entity_rows) > limit_per_type
    for entity, event, source in entity_rows[:limit_per_type]:
        match_field, match_quality = _search_match(query, [
            ("id", entity.id), ("value", entity.value), ("type", entity.entity_type),
        ])
        items.append({
            "kind": "entity", "id": entity.id, "label": entity.value,
            "context": f"{entity.entity_type} · {_safe_event_title(event)}"[:500],
            "match_field": match_field, "match_quality": match_quality,
            "source_pipeline": event.source_pipeline, "source_type": event.source_type,
            "source_id": event.source_id, "source_name": source.name if source else None,
            "event_id": event.id, "severity": event.severity,
            "confidence": entity.confidence, "created_at": iso(event.created_at),
        })

    source_columns = (Source.id, Source.name, Source.source_type)
    source_rows = db.scalars(
        select(Source)
        .where(_search_filter(query, source_columns))
        .order_by(_search_rank(query, source_columns), desc(Source.updated_at), Source.id)
        .limit(row_limit)
    ).all()
    truncated = truncated or len(source_rows) > limit_per_type
    for source in source_rows[:limit_per_type]:
        match_field, match_quality = _search_match(query, [
            ("id", source.id), ("name", source.name), ("type", source.source_type),
        ])
        items.append({
            "kind": "source", "id": source.id, "label": source.name,
            "context": source.source_type, "match_field": match_field,
            "match_quality": match_quality, "source_pipeline": source.source_pipeline,
            "source_type": source.source_type, "source_id": source.id,
            "source_name": source.name, "created_at": iso(source.created_at),
        })

    correlation_columns = (
        CorrelationRecord.id, CorrelationRecord.reason, CorrelationRecord.correlation_type,
        CorrelationRecord.event_a_id, CorrelationRecord.event_b_id,
    )
    correlation_rows = db.scalars(
        select(CorrelationRecord)
        .where(_search_filter(query, correlation_columns))
        .order_by(_search_rank(query, correlation_columns), desc(CorrelationRecord.score), CorrelationRecord.id)
        .limit(row_limit)
    ).all()
    truncated = truncated or len(correlation_rows) > limit_per_type
    for correlation in correlation_rows[:limit_per_type]:
        match_field, match_quality = _search_match(query, [
            ("id", correlation.id), ("reason", correlation.reason),
            ("type", correlation.correlation_type), ("event_id", correlation.event_a_id),
            ("event_id", correlation.event_b_id),
        ])
        items.append({
            "kind": "correlation", "id": correlation.id,
            "label": correlation.correlation_type,
            "context": correlation.reason or correlation.correlation_type,
            "match_field": match_field, "match_quality": match_quality,
            "event_id": correlation.event_a_id,
            "related_event_id": correlation.event_b_id,
            "confidence": correlation.score, "created_at": iso(correlation.created_at),
        })

    quality_order = {"exact": 0, "prefix": 1, "contains": 2}
    kind_order = {"event": 0, "indicator": 1, "entity": 2, "source": 3, "correlation": 4}
    items.sort(key=lambda item: (quality_order[item["match_quality"]], kind_order[item["kind"]]))
    return {
        "query": query, "items": items, "returned": len(items),
        "limit_per_type": limit_per_type, "truncated": truncated,
    }


@router.get("/intelligence/events", tags=["intelligence"], response_model=IntelligenceEventPageResponse)
def intelligence_events(
    db: SessionDep,
    _: CurrentUser,
    source_pipeline: str | None = Query(default=None, pattern="^(external|internal)$"),
    severity: str | None = Query(default=None, max_length=30),
    processing_status: str | None = Query(default=None, max_length=30),
    search: str | None = Query(default=None, min_length=2, max_length=100),
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    filters = []
    if source_pipeline:
        filters.append(ThreatEvent.source_pipeline == source_pipeline)
    if severity:
        filters.append(ThreatEvent.severity == severity)
    if processing_status:
        filters.append(ThreatEvent.processing_status == processing_status)
    if search:
        filters.append(ThreatEvent.title.ilike(f"%{search}%"))
    total = db.scalar(select(func.count()).select_from(ThreatEvent).where(*filters)) or 0
    records = db.scalars(
        event_query().where(*filters).order_by(desc(ThreatEvent.created_at), desc(ThreatEvent.id)).limit(limit).offset(offset)
    ).unique().all()
    return {"items": [_intelligence_event_dict(item) for item in records], "total": total, "limit": limit, "offset": offset}


@router.get("/intelligence/events/{event_id}", tags=["intelligence"], response_model=IntelligenceEventDetailResponse)
def intelligence_event_detail(event_id: str, db: SessionDep, _: CurrentUser) -> dict[str, Any]:
    event = db.scalar(event_query().where(ThreatEvent.id == event_id))
    if event is None:
        raise HTTPException(status_code=404, detail="Threat event not found")
    return {
        **_intelligence_event_dict(event),
        "indicators": [_indicator_dict(item, event) for item in event.indicators],
        "entities": [
            {"type": item.entity_type, "value": item.value, "confidence": item.confidence}
            for item in event.entities if item.entity_type != "source_ip"
        ],
        "relationships": [] if event.source_pipeline == "internal" else [
            {"subject": item.subject, "relation": item.relation, "object": item.object_value, "confidence": item.confidence}
            for item in event.relationships
        ],
    }


@router.get("/intelligence/indicators", tags=["intelligence"], response_model=IntelligenceIndicatorPageResponse)
def intelligence_indicators(
    db: SessionDep, _: CurrentUser,
    indicator_type: str | None = Query(default=None, max_length=50),
    semantic_role: str | None = Query(default=None, max_length=30),
    assessment: str | None = Query(default=None, max_length=30),
    validation_status: str | None = Query(default=None, max_length=20),
    search: str | None = Query(default=None, min_length=2, max_length=100),
    limit: int = Query(default=25, ge=1, le=100), offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    filters = []
    if indicator_type:
        filters.append(IndicatorRecord.indicator_type == indicator_type)
    if search:
        filters.append(IndicatorRecord.value.ilike(f"%{search}%"))
    joined = (
        select(IndicatorRecord, ThreatEvent)
        .join(ThreatEvent, ThreatEvent.id == IndicatorRecord.event_id)
        .where(*filters)
        .options(
            selectinload(IndicatorRecord.enrichments),
            selectinload(ThreatEvent.indicators).selectinload(IndicatorRecord.enrichments),
        )
        .order_by(desc(ThreatEvent.created_at), IndicatorRecord.id)
    )
    derived_filters = any((semantic_role, assessment, validation_status))
    if derived_filters:
        candidates = [
            _indicator_dict(item, event) for item, event in db.execute(joined).unique().all()
        ]
        records = [
            item
            for item in candidates
            if (not semantic_role or item["semantic_role"] == semantic_role)
            and (not assessment or item["assessment"] == assessment)
            and (not validation_status or item["validation_status"] == validation_status)
        ]
        total = len(records)
        items = records[offset : offset + limit]
    else:
        total = db.scalar(select(func.count()).select_from(IndicatorRecord).where(*filters)) or 0
        rows = db.execute(joined.limit(limit).offset(offset)).unique().all()
        items = [_indicator_dict(item, event) for item, event in rows]
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.get(
    "/intelligence/indicators-summary",
    tags=["intelligence"],
    response_model=IntelligenceIndicatorSummaryResponse,
)
def intelligence_indicator_summary(db: SessionDep, _: CurrentUser) -> dict[str, Any]:
    # Summary classification only needs indicators, enrichments, and the URL
    # values in the same event. Avoid loading every large ThreatEvent row and
    # its complete relationship graph; that exceeded the live proxy timeout.
    items = db.scalars(
        select(IndicatorRecord).options(selectinload(IndicatorRecord.enrichments))
    ).unique().all()
    urls_by_event: dict[str, list[IndicatorRecord]] = {}
    for item in items:
        if item.indicator_type.lower() == "url":
            urls_by_event.setdefault(item.event_id, []).append(item)
    event_contexts = {
        event_id: SimpleNamespace(indicators=urls)
        for event_id, urls in urls_by_event.items()
    }
    by_role: dict[str, int] = {}
    by_assessment: dict[str, int] = {}
    by_validation: dict[str, int] = {}
    by_type: dict[str, int] = {}
    assessor = ObservableAssessor()
    for item in items:
        result = assessor.assess(item, event_contexts.get(item.event_id))
        for bucket, key in (
            (by_role, result.semantic_role),
            (by_assessment, result.assessment),
            (by_validation, result.validation_status),
            (by_type, item.indicator_type),
        ):
            bucket[key] = bucket.get(key, 0) + 1
    return {
        "total": len(items),
        "by_role": by_role,
        "by_assessment": by_assessment,
        "by_validation": by_validation,
        "by_type": by_type,
    }


@router.get(
    "/intelligence/events/{event_id}/attack",
    tags=["intelligence"],
    response_model=IntelligenceAttackMappingResponse,
)
def intelligence_event_attack(event_id: str, db: SessionDep, _: CurrentUser) -> dict[str, Any]:
    event = db.scalar(event_query().where(ThreatEvent.id == event_id))
    if event is None:
        raise HTTPException(status_code=404, detail="Threat event not found")
    mapper = AttackMappingService()
    return {
        "event_id": event.id,
        "catalog_version": mapper.CATALOG_VERSION,
        "source": "built_in_subset",
        "official_dataset_url": "https://github.com/mitre-attack/attack-stix-data",
        "techniques": _safe_attack_techniques(event),
    }


@router.get("/intelligence/events/{event_id}/attack-navigator", tags=["intelligence"])
def intelligence_event_attack_navigator(event_id: str, db: SessionDep, _: CurrentUser) -> dict[str, Any]:
    event = db.scalar(event_query().where(ThreatEvent.id == event_id))
    if event is None:
        raise HTTPException(status_code=404, detail="Threat event not found")
    layer = AttackMappingService().navigator_layer(event)
    if event.source_pipeline == "internal":
        for item in layer["techniques"]:
            item["comment"] = (
                f"Internal telemetry matched {item['techniqueID']}; "
                "raw sensor evidence is hidden in this projection."
            )[:240]
    return layer


def _correlation_endpoint(event: ThreatEvent, source: Source | None) -> dict[str, Any]:
    return {
        "event_id": event.id,
        "title": _safe_event_title(event),
        "source_pipeline": event.source_pipeline,
        "source_type": event.source_type,
        "source_id": event.source_id,
        "source_name": source.name if source else None,
        "severity": event.severity,
        "risk_score": event.risk_score,
        "created_at": iso(event.created_at),
    }


def _correlation_factors(item: CorrelationRecord) -> tuple[str, str, list[dict[str, str]]]:
    evidence = item.evidence if isinstance(item.evidence, dict) else {}
    if item.correlation_type == "simple_indicator_match":
        raw_type = evidence.get("indicator_type")
        indicator_type = raw_type[:50] if isinstance(raw_type, str) and raw_type.strip() else "observable"
        raw_values = evidence.get("values")
        factors = []
        if isinstance(raw_values, list):
            for raw_value in raw_values[:20]:
                if not isinstance(raw_value, str):
                    continue
                value = raw_value.strip()
                if value:
                    factors.append({
                        "kind": "shared_observable",
                        "label": indicator_type,
                        "value": value[:2048],
                    })
        return "exact_observable_match", "available" if factors else "unavailable", factors

    if item.correlation_type == "text_similarity":
        factors = []
        backend = evidence.get("backend")
        if backend in {"tfidf_cosine", "token_jaccard_fallback"}:
            factors.append({"kind": "algorithm", "label": "backend", "value": backend})
        threshold = evidence.get("threshold")
        if isinstance(threshold, (int, float)) and not isinstance(threshold, bool) and 0 <= float(threshold) <= 1:
            factors.append({
                "kind": "threshold",
                "label": "minimum_score",
                "value": f"{float(threshold):.2f}",
            })
        status_value = "available" if len(factors) == 2 else "partial" if factors else "unavailable"
        return "normalized_text_similarity", status_value, factors

    return "recorded_correlation", "partial", [{
        "kind": "method",
        "label": "recorded_type",
        "value": item.correlation_type[:50],
    }]


def _safe_attack_techniques(event: ThreatEvent) -> list[dict[str, Any]]:
    techniques = AttackMappingService().map_event(event)
    if event.source_pipeline != "internal":
        return techniques
    return [
        {
            **item,
            "evidence": (
                f"Internal telemetry matched {item['technique_id']}; "
                "raw sensor evidence is hidden in this projection."
            )[:240],
        }
        for item in techniques
    ]


def _correlation_dict(
    item: CorrelationRecord,
    events: dict[str, tuple[ThreatEvent, Source | None]],
) -> dict[str, Any]:
    source_event, source = events[item.event_a_id]
    target_event, target_source = events[item.event_b_id]
    score_basis, evidence_status, factors = _correlation_factors(item)
    return {
        "id": item.id,
        "source_event_id": item.event_a_id,
        "target_event_id": item.event_b_id,
        "type": item.correlation_type,
        "score": item.score,
        "reason": item.reason,
        "source_event": _correlation_endpoint(source_event, source),
        "target_event": _correlation_endpoint(target_event, target_source),
        "cross_source": source_event.source_pipeline != target_event.source_pipeline,
        "score_basis": score_basis,
        "evidence_status": evidence_status,
        "factors": factors,
        "created_at": iso(item.created_at),
    }


_STORYLINE_RISK_FACTORS = (
    "base_severity_or_cvss",
    "indicators",
    "confidence",
    "source_diversity",
    "correlations",
    "internal_outlier",
)


def _storyline_risk(event: ThreatEvent) -> tuple[list[dict[str, Any]], dict[str, int | None]]:
    raw_reference = event.raw_reference if isinstance(event.raw_reference, dict) else {}
    stored_factors = raw_reference.get("risk_factors")
    stored_factors = stored_factors if isinstance(stored_factors, dict) else {}
    factors = []
    for key in _STORYLINE_RISK_FACTORS:
        value = stored_factors.get(key)
        if isinstance(value, (int, float)) and not isinstance(value, bool) and 0 <= float(value) <= 100:
            factors.append({"key": key, "value": float(value)})
    stored_context = raw_reference.get("risk_context")
    stored_context = stored_context if isinstance(stored_context, dict) else {}

    def safe_count(key: str) -> int | None:
        value = stored_context.get(key)
        return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None

    return factors, {
        "source_count": safe_count("source_count"),
        "correlation_count": safe_count("correlation_count"),
    }


@router.get(
    "/intelligence/events/{event_id}/storyline",
    tags=["intelligence"],
    response_model=IntelligenceStorylineResponse,
)
def intelligence_event_storyline(event_id: str, db: SessionDep, _: CurrentUser) -> dict[str, Any]:
    event = db.scalar(event_query().where(ThreatEvent.id == event_id))
    if event is None:
        raise HTTPException(status_code=404, detail="Threat event not found")
    source = db.get(Source, event.source_id) if event.source_id else None
    correlation_filter = or_(
        CorrelationRecord.event_a_id == event.id,
        CorrelationRecord.event_b_id == event.id,
    )
    correlation_total = db.scalar(
        select(func.count()).select_from(CorrelationRecord).where(correlation_filter)
    ) or 0
    correlation_rows = db.scalars(
        select(CorrelationRecord)
        .where(correlation_filter)
        .order_by(CorrelationRecord.created_at, desc(CorrelationRecord.score), CorrelationRecord.id)
        .limit(20)
    ).all()
    related_ids = {
        related_id
        for item in correlation_rows
        for related_id in (item.event_a_id, item.event_b_id)
    }
    related_rows = db.execute(
        select(ThreatEvent, Source)
        .outerjoin(Source, Source.id == ThreatEvent.source_id)
        .where(ThreatEvent.id.in_(related_ids))
    ).all() if related_ids else []
    events = {related_event.id: (related_event, related_source) for related_event, related_source in related_rows}
    events[event.id] = (event, source)
    correlations = [_correlation_dict(item, events) for item in correlation_rows]

    observables_total = len(event.indicators)
    entities = sorted(
        (item for item in event.entities if item.entity_type != "source_ip"),
        key=lambda item: item.id,
    )
    relationships = [] if event.source_pipeline == "internal" else sorted(
        event.relationships,
        key=lambda item: item.id,
    )
    observables = [
        _indicator_dict(item, event)
        for item in sorted(event.indicators, key=lambda item: item.id)[:20]
    ]
    safe_entities = [
        {"type": item.entity_type, "value": item.value, "confidence": item.confidence}
        for item in entities[:20]
    ]
    safe_relationships = [
        {
            "subject": item.subject,
            "relation": item.relation,
            "object": item.object_value,
            "confidence": item.confidence,
        }
        for item in relationships[:20]
    ]
    mapper = AttackMappingService()
    techniques = _safe_attack_techniques(event)
    attack = {
        "event_id": event.id,
        "catalog_version": mapper.CATALOG_VERSION,
        "source": "built_in_subset",
        "official_dataset_url": mapper.OFFICIAL_DATASET_URL,
        "techniques": techniques,
    }
    risk_factors, risk_context = _storyline_risk(event)
    observed_at = iso(event.first_seen or event.created_at)
    milestones = [{
        "id": f"{event.id}:observed",
        "kind": "observed",
        "occurred_at": observed_at,
        "event_id": event.id,
        "related_event_id": None,
        "title": _safe_event_title(event),
        "detail": _safe_event_summary(event) or "No event summary was recorded.",
        "source_pipeline": event.source_pipeline,
        "evidence_status": "recorded",
        "confidence": event.confidence,
        "score": None,
    }]
    last_observed_at = iso(event.last_seen)
    if last_observed_at and last_observed_at != observed_at:
        milestones.append({
            **milestones[0],
            "id": f"{event.id}:last-observed",
            "kind": "last_observed",
            "occurred_at": last_observed_at,
        })
    milestones.append({
        "id": f"{event.id}:processed",
        "kind": "processed",
        "occurred_at": iso(event.created_at),
        "event_id": event.id,
        "related_event_id": None,
        "title": event.processing_status or "processed",
        "detail": event.classification_label or event.processing_status or "processed",
        "source_pipeline": event.source_pipeline,
        "evidence_status": "recorded",
        "confidence": event.classification_confidence,
        "score": None,
    })
    for item, projection in zip(correlation_rows, correlations, strict=True):
        related_id = item.event_b_id if item.event_a_id == event.id else item.event_a_id
        related_event = events[related_id][0]
        milestones.append({
            "id": item.id,
            "kind": "correlated",
            "occurred_at": iso(item.created_at),
            "event_id": event.id,
            "related_event_id": related_id,
            "title": _safe_event_title(related_event),
            "detail": item.reason or item.correlation_type,
            "source_pipeline": related_event.source_pipeline,
            "evidence_status": "recorded",
            "confidence": None,
            "score": projection["score"],
        })
    for technique in techniques:
        milestones.append({
            "id": f"{event.id}:{technique['technique_id']}",
            "kind": "attack_mapping",
            "occurred_at": None,
            "event_id": event.id,
            "related_event_id": None,
            "title": f"{technique['technique_id']} - {technique['name']}",
            "detail": technique["evidence"] or technique["mapping_source"],
            "source_pipeline": event.source_pipeline,
            "evidence_status": "derived" if technique["mapping_source"] == "explicit_id" else "candidate",
            "confidence": technique["confidence"],
            "score": None,
        })
    milestone_order = {
        "observed": 0,
        "processed": 1,
        "last_observed": 2,
        "correlated": 3,
        "attack_mapping": 4,
    }
    milestones.sort(key=lambda item: (
        item["occurred_at"] is None,
        item["occurred_at"] or "",
        milestone_order[item["kind"]],
        item["id"],
    ))
    evidence_truncated = any((
        observables_total > 20,
        len(entities) > 20,
        len(relationships) > 20,
        correlation_total > 20,
    ))
    limitations = ["chronology_not_causality"]
    if any(item["mapping_source"] == "rule_based_candidate" for item in techniques):
        limitations.append("attack_candidates_require_review")
    if any(related_event.source_pipeline == "internal" for related_event, _ in events.values()):
        limitations.append("internal_raw_telemetry_hidden")
    if evidence_truncated:
        limitations.append("bounded_evidence")
    return {
        "event": _intelligence_event_dict(event),
        "source_name": source.name if source else None,
        "risk_method": "deterministic_rule_score",
        "risk_factors": risk_factors,
        "risk_context": risk_context,
        "evidence_counts": {
            "observables": observables_total,
            "entities": len(entities),
            "relationships": len(relationships),
            "correlations": correlation_total,
            "attack_mappings": len(techniques),
        },
        "observables": observables,
        "entities": safe_entities,
        "relationships": safe_relationships,
        "correlations": correlations,
        "attack": attack,
        "milestones": milestones,
        "evidence_truncated": evidence_truncated,
        "limitations": limitations,
    }


@router.get("/intelligence/correlations", tags=["intelligence"], response_model=IntelligenceCorrelationPageResponse)
def intelligence_correlations(db: SessionDep, _: CurrentUser, limit: int = Query(25, ge=1, le=100), offset: int = Query(0, ge=0)) -> dict[str, Any]:
    total = db.scalar(select(func.count()).select_from(CorrelationRecord)) or 0
    rows = db.scalars(select(CorrelationRecord).order_by(desc(CorrelationRecord.score), CorrelationRecord.id).limit(limit).offset(offset)).all()
    event_ids = {event_id for item in rows for event_id in (item.event_a_id, item.event_b_id)}
    event_rows = db.execute(
        select(ThreatEvent, Source)
        .outerjoin(Source, Source.id == ThreatEvent.source_id)
        .where(ThreatEvent.id.in_(event_ids))
    ).all() if event_ids else []
    events = {event.id: (event, source) for event, source in event_rows}
    items = [_correlation_dict(item, events) for item in rows]
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.get("/intelligence/outliers", tags=["intelligence"], response_model=IntelligenceOutlierPageResponse)
def intelligence_outliers(db: SessionDep, _: CurrentUser, only_outliers: bool = False, limit: int = Query(25, ge=1, le=100), offset: int = Query(0, ge=0)) -> dict[str, Any]:
    filters = [OutlierSessionRecord.is_outlier.is_(True)] if only_outliers else []
    total = db.scalar(select(func.count()).select_from(OutlierSessionRecord).where(*filters)) or 0
    rows = db.scalars(select(OutlierSessionRecord).where(*filters).order_by(desc(OutlierSessionRecord.started_at), OutlierSessionRecord.id).limit(limit).offset(offset)).all()
    return {"items": [{"id": item.id, "event_id": item.event_id, "started_at": iso(item.started_at), "ended_at": iso(item.ended_at), "alert_count": item.alert_count, "is_outlier": item.is_outlier, "anomaly_score": item.anomaly_score, "detector": item.detector_backend} for item in rows], "total": total, "limit": limit, "offset": offset}


def _intelligence_run_dict(item: PipelineRun) -> dict[str, Any]:
    duration = (item.completed_at - item.started_at).total_seconds() if item.completed_at else None
    return {"id": item.id, "pipeline": item.pipeline, "status": item.status, "collected": item.collected_count, "processed": item.processed_count, "stored": item.stored_count, "failed": item.failed_count, "error_category": "pipeline_error" if item.error_message else None, "started_at": iso(item.started_at), "completed_at": iso(item.completed_at), "duration_seconds": duration}


@router.get("/intelligence/runs", tags=["intelligence"], response_model=IntelligenceRunPageResponse)
def intelligence_runs(db: SessionDep, _: CurrentUser, limit: int = Query(25, ge=1, le=100), offset: int = Query(0, ge=0)) -> dict[str, Any]:
    total = db.scalar(select(func.count()).select_from(PipelineRun)) or 0
    rows = db.scalars(select(PipelineRun).order_by(desc(PipelineRun.started_at), PipelineRun.id).limit(limit).offset(offset)).all()
    return {"items": [_intelligence_run_dict(item) for item in rows], "total": total, "limit": limit, "offset": offset}


@router.get("/intelligence/runs/{run_id}", tags=["intelligence"], response_model=IntelligenceRunResponse)
def intelligence_run_detail(run_id: str, db: SessionDep, _: CurrentUser) -> dict[str, Any]:
    item = db.get(PipelineRun, run_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Pipeline run not found")
    return _intelligence_run_dict(item)


@router.get("/intelligence/ml/status", tags=["intelligence"], response_model=IntelligenceMLStatusResponse)
def intelligence_ml_status(_: CurrentUser) -> dict[str, Any]:
    status_payload = ModelEvidenceService.status()
    runtime = status_payload.get("runtime", {})
    models = status_payload.get("model_priority", {})
    bert = status_payload.get("held_out_test", {}).get("bert", {})
    return {"execution_model": "central_backend", "backend": str(runtime.get("backend") or "unavailable"), "primary_model": str(models.get("primary") or "dnrti_bert_ner"), "secondary_model": str(models.get("secondary_fallback") or "dnrti_sklearn_ner"), "primary_loaded": runtime.get("primary_model_loaded") is True, "secondary_loaded": runtime.get("secondary_fallback_loaded") is True, "quality_gates_passed": status_payload.get("all_quality_gates_passed") is True, "held_out_f1": bert.get("f1")}


@router.get("/intelligence/misp/health", tags=["intelligence"], response_model=IntelligenceMISPHealthResponse, response_model_exclude_none=True)
def intelligence_misp_health(_: CurrentUser) -> dict[str, Any]:
    try:
        result = MISPClient().healthcheck()
    except (ValueError, RuntimeError, TypeError) as exc:
        return {"configured": True, "reachable": False, "failure_category": type(exc).__name__}
    return {"configured": result.get("configured") is True, "reachable": result.get("reachable") is True, "failure_category": result.get("error_type")}


_MISP_HISTORY_ACTIONS = ("misp_send", "misp_send_skipped", "misp_send_failed")
_MISP_HISTORY_REASONS = {
    "event_not_found",
    "misp_unconfigured",
    "no_transferable_attributes",
    "preview_failed",
    "delivery_failed",
}


def _safe_misp_event_id(value: object) -> str | None:
    text = str(value or "").strip()
    return text if text.isdigit() and len(text) <= 64 else None


def _safe_misp_event_uuid(value: object) -> str | None:
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, TypeError, AttributeError):
        return None


def _misp_preview_projection(event: ThreatEvent, client: MISPClient) -> dict[str, Any]:
    payload = client.event_payload(event)
    mapped = payload["Event"]
    filtering = payload["cti_filtering"]
    return {
        "event_id": event.id,
        "title": _safe_event_title(event),
        "configured": client.configured,
        "published": False,
        "distribution": 0,
        "attributes": [
            {
                "type": item["type"],
                "category": item["category"],
                "value": item["value"],
                "to_ids": item["to_ids"],
            }
            for item in mapped.get("Attribute", [])
        ],
        "tags": [
            str(item.get("name"))
            for item in mapped.get("Tag", [])
            if item.get("name")
        ],
        "included": filtering["included"],
        "omitted": filtering["omitted"],
        "omitted_by_reason": filtering["omitted_by_reason"],
    }


def _misp_delivery_projection(event_id: str, result: dict[str, Any]) -> dict[str, Any]:
    return {
        "event_id": event_id,
        "created": result["created"],
        "attributes_requested": result["attributes_requested"],
        "attributes_added": result["attributes_added"],
        "attributes_verified": result["attributes_verified"],
        "published": result["published"],
        "misp_event_id": _safe_misp_event_id(
            result.get("misp_event_id") or result.get("event_id")
        ),
        "misp_event_uuid": _safe_misp_event_uuid(
            result.get("misp_event_uuid") or result.get("event_uuid")
        ),
    }


@router.get(
    "/intelligence/misp/candidates",
    tags=["intelligence"],
    response_model=IntelligenceMISPCandidatePageResponse,
)
def intelligence_misp_candidates(
    db: SessionDep,
    _: CurrentUser,
    source_pipeline: str | None = Query(default=None, pattern="^(external|internal)$"),
    search: str | None = Query(default=None, min_length=2, max_length=100),
    limit: int = Query(default=20, ge=1, le=50),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    filters = []
    if source_pipeline:
        filters.append(ThreatEvent.source_pipeline == source_pipeline)
    if search:
        filters.append(_search_filter(search, (ThreatEvent.title,)))
    total = db.scalar(
        select(func.count()).select_from(ThreatEvent).where(*filters)
    ) or 0
    events = db.scalars(
        event_query()
        .where(*filters)
        .order_by(desc(ThreatEvent.risk_score), desc(ThreatEvent.created_at), ThreatEvent.id)
        .limit(limit)
        .offset(offset)
    ).unique().all()
    try:
        client = MISPClient()
    except (ValueError, RuntimeError, TypeError) as exc:
        raise HTTPException(
            status_code=503,
            detail=f"MISP candidate preview unavailable: {type(exc).__name__}",
        ) from exc

    event_ids = [event.id for event in events]
    deliveries: dict[str, list[AuditLog]] = {event_id: [] for event_id in event_ids}
    if event_ids:
        rows = db.scalars(
            select(AuditLog)
            .where(
                AuditLog.action == "misp_send",
                AuditLog.resource_type == "threat_event",
                AuditLog.resource_id.in_(event_ids),
            )
            .order_by(desc(AuditLog.created_at), desc(AuditLog.id))
        ).all()
        for row in rows:
            if row.resource_id in deliveries:
                deliveries[row.resource_id].append(row)

    items = []
    for event in events:
        preview = _misp_preview_projection(event, client)
        event_deliveries = deliveries[event.id]
        latest = event_deliveries[0] if event_deliveries else None
        latest_details = latest.details if latest and isinstance(latest.details, dict) else {}
        if not client.configured:
            readiness_reason = "misp_unconfigured"
        elif preview["included"] == 0:
            readiness_reason = "no_transferable_attributes"
        else:
            readiness_reason = "ready"
        items.append(
            {
                "event_id": event.id,
                "title": _safe_event_title(event),
                "source_pipeline": event.source_pipeline,
                "severity": event.severity,
                "risk_score": event.risk_score,
                "included": preview["included"],
                "omitted": preview["omitted"],
                "omitted_by_reason": preview["omitted_by_reason"],
                "ready": readiness_reason == "ready",
                "readiness_reason": readiness_reason,
                "delivery_count": len(event_deliveries),
                "last_delivered_at": iso(latest.created_at) if latest else None,
                "last_misp_event_id": _safe_misp_event_id(
                    latest_details.get("misp_event_id")
                    or latest_details.get("event_id")
                ),
            }
        )
    return {
        "configured": client.configured,
        "items": items,
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get(
    "/intelligence/events/{event_id}/misp-preview",
    tags=["intelligence"],
    response_model=IntelligenceMISPPreviewResponse,
)
def intelligence_misp_preview(event_id: str, db: SessionDep, _: CurrentUser) -> dict[str, Any]:
    event = db.scalar(event_query().where(ThreatEvent.id == event_id))
    if event is None:
        raise HTTPException(status_code=404, detail="Threat event not found")
    try:
        return _misp_preview_projection(event, MISPClient())
    except (ValueError, RuntimeError, TypeError) as exc:
        raise HTTPException(
            status_code=503,
            detail=f"MISP preview unavailable: {type(exc).__name__}",
        ) from exc


@router.post("/intelligence/events/{event_id}/misp", tags=["intelligence"], response_model=IntelligenceMISPDeliveryResponse)
def intelligence_misp_send(
    event_id: str,
    db: SessionDep,
    user: Annotated[User, Depends(require_roles("admin"))],
) -> dict[str, Any]:
    event = db.scalar(event_query().where(ThreatEvent.id == event_id))
    if event is None:
        raise HTTPException(status_code=404, detail="Threat event not found")
    client = MISPClient()
    try:
        preview = _misp_preview_projection(event, client)
    except (ValueError, RuntimeError, TypeError) as exc:
        raise HTTPException(
            status_code=503,
            detail=f"MISP preview unavailable: {type(exc).__name__}",
        ) from exc
    if preview["included"] == 0:
        audit(
            db,
            user,
            "misp_send_skipped",
            "threat_event",
            event_id,
            reason="no_transferable_attributes",
        )
        db.commit()
        raise HTTPException(
            status_code=409,
            detail="No transferable attributes are eligible for MISP",
        )
    try:
        result = client.send_event(event, dry_run=False)["cti_delivery"]
    except Exception as exc:
        audit(
            db,
            user,
            "misp_send_failed",
            "threat_event",
            event_id,
            reason="delivery_failed",
            failure_category=type(exc).__name__,
        )
        db.commit()
        raise HTTPException(
            status_code=502,
            detail=f"MISP delivery failed: {type(exc).__name__}",
        ) from exc
    delivery = _misp_delivery_projection(event_id, result)
    audit(
        db,
        user,
        "misp_send",
        "threat_event",
        event_id,
        status="delivered",
        created=delivery["created"],
        attributes_requested=delivery["attributes_requested"],
        attributes_added=delivery["attributes_added"],
        attributes_verified=delivery["attributes_verified"],
        published=delivery["published"],
        misp_event_id=delivery["misp_event_id"],
        misp_event_uuid=delivery["misp_event_uuid"],
    )
    db.commit()
    return delivery


@router.post(
    "/intelligence/misp/batch",
    tags=["intelligence"],
    response_model=IntelligenceMISPBatchResponse,
)
def intelligence_misp_batch(
    payload: IntelligenceMISPBatchRequest,
    db: SessionDep,
    user: Annotated[User, Depends(require_roles("admin"))],
) -> dict[str, Any]:
    event_ids = list(dict.fromkeys(payload.event_ids))
    if any(not event_id.strip() or len(event_id) > 64 for event_id in event_ids):
        raise HTTPException(status_code=422, detail="Invalid event identifier")
    client = MISPClient()
    if not client.configured:
        raise HTTPException(status_code=503, detail="MISP is not configured")
    events = db.scalars(
        event_query().where(ThreatEvent.id.in_(event_ids))
    ).unique().all()
    events_by_id = {event.id: event for event in events}
    batch_id = str(uuid.uuid4())
    items: list[dict[str, Any]] = []

    for event_id in event_ids:
        event = events_by_id.get(event_id)
        if event is None:
            item = {
                "event_id": event_id,
                "status": "skipped",
                "reason": "event_not_found",
            }
            audit(
                db,
                user,
                "misp_send_skipped",
                "threat_event",
                event_id,
                batch_id=batch_id,
                reason=item["reason"],
            )
            db.commit()
            items.append(item)
            continue
        try:
            preview = _misp_preview_projection(event, client)
        except (ValueError, RuntimeError, TypeError) as exc:
            item = {
                "event_id": event_id,
                "status": "failed",
                "reason": "preview_failed",
            }
            audit(
                db,
                user,
                "misp_send_failed",
                "threat_event",
                event_id,
                batch_id=batch_id,
                reason=item["reason"],
                failure_category=type(exc).__name__,
            )
            db.commit()
            items.append(item)
            continue
        if preview["included"] == 0:
            item = {
                "event_id": event_id,
                "status": "skipped",
                "reason": "no_transferable_attributes",
            }
            audit(
                db,
                user,
                "misp_send_skipped",
                "threat_event",
                event_id,
                batch_id=batch_id,
                reason=item["reason"],
                omitted=preview["omitted"],
                omitted_by_reason=preview["omitted_by_reason"],
            )
            db.commit()
            items.append(item)
            continue
        try:
            raw_delivery = client.send_event(event, dry_run=False)["cti_delivery"]
            delivery = _misp_delivery_projection(event_id, raw_delivery)
        except Exception as exc:
            item = {
                "event_id": event_id,
                "status": "failed",
                "reason": "delivery_failed",
            }
            audit(
                db,
                user,
                "misp_send_failed",
                "threat_event",
                event_id,
                batch_id=batch_id,
                reason=item["reason"],
                failure_category=type(exc).__name__,
            )
            db.commit()
            items.append(item)
            continue
        item = {**delivery, "status": "delivered", "reason": None}
        audit(
            db,
            user,
            "misp_send",
            "threat_event",
            event_id,
            batch_id=batch_id,
            status="delivered",
            created=delivery["created"],
            attributes_requested=delivery["attributes_requested"],
            attributes_added=delivery["attributes_added"],
            attributes_verified=delivery["attributes_verified"],
            published=delivery["published"],
            misp_event_id=delivery["misp_event_id"],
            misp_event_uuid=delivery["misp_event_uuid"],
        )
        db.commit()
        items.append(item)

    delivered = sum(item["status"] == "delivered" for item in items)
    skipped = sum(item["status"] == "skipped" for item in items)
    failed = sum(item["status"] == "failed" for item in items)
    published = sum(item.get("published") is True for item in items)
    audit(
        db,
        user,
        "misp_batch",
        "misp_batch",
        batch_id,
        requested=len(event_ids),
        delivered=delivered,
        skipped=skipped,
        failed=failed,
        published=published,
    )
    db.commit()
    return {
        "batch_id": batch_id,
        "requested": len(event_ids),
        "delivered": delivered,
        "skipped": skipped,
        "failed": failed,
        "published": published,
        "items": items,
    }


@router.get(
    "/intelligence/misp/deliveries",
    tags=["intelligence"],
    response_model=IntelligenceMISPDeliveryHistoryResponse,
)
def intelligence_misp_deliveries(
    db: SessionDep,
    _: CurrentUser,
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    filters = [
        AuditLog.action.in_(_MISP_HISTORY_ACTIONS),
        AuditLog.resource_type == "threat_event",
    ]
    total = db.scalar(select(func.count()).select_from(AuditLog).where(*filters)) or 0
    rows = db.scalars(
        select(AuditLog)
        .where(*filters)
        .order_by(desc(AuditLog.created_at), desc(AuditLog.id))
        .limit(limit)
        .offset(offset)
    ).all()

    def optional_count(value: object) -> int | None:
        return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None

    def optional_bool(value: object) -> bool | None:
        return value if isinstance(value, bool) else None

    items = []
    for row in rows:
        details = row.details if isinstance(row.details, dict) else {}
        status_by_action = {
            "misp_send": "delivered",
            "misp_send_skipped": "skipped",
            "misp_send_failed": "failed",
        }
        reason = details.get("reason")
        items.append(
            {
                "id": row.id,
                "event_id": row.resource_id,
                "username": row.username,
                "created_at": iso(row.created_at),
                "status": status_by_action[row.action],
                "reason": reason if reason in _MISP_HISTORY_REASONS else None,
                "batch_id": _safe_misp_event_uuid(details.get("batch_id")),
                "misp_event_id": _safe_misp_event_id(
                    details.get("misp_event_id") or details.get("event_id")
                ),
                "misp_event_uuid": _safe_misp_event_uuid(
                    details.get("misp_event_uuid") or details.get("event_uuid")
                ),
                "created": optional_bool(details.get("created")),
                "attributes_requested": optional_count(details.get("attributes_requested")),
                "attributes_added": optional_count(details.get("attributes_added")),
                "attributes_verified": optional_count(details.get("attributes_verified")),
                "published": optional_bool(details.get("published")),
            }
        )
    return {"items": items, "total": total, "limit": limit, "offset": offset}


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
    observable_total = db.scalar(select(func.count()).select_from(IndicatorRecord)) or 0
    confirmed_indicator_ids = {
        row.indicator_id
        for row in db.scalars(select(EnrichmentRecord)).all()
        if ObservableAssessor._explicit_verdict([row]) is not None
    }
    return {
        "events": db.scalar(select(func.count()).select_from(ThreatEvent)) or 0,
        "indicators": len(confirmed_indicator_ids),
        "observables": observable_total,
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
        raise HTTPException(status_code=502, detail=f"MISP request failed: {type(exc).__name__}") from exc
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
