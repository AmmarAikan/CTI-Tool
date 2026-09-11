from __future__ import annotations

import secrets
from collections.abc import Callable
from dataclasses import asdict, dataclass
from typing import Any

from fastapi import Body, Depends, FastAPI, Header, Query, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse

from backend.app.pipeline.ingestion.external.application.collection_service import (
    AllEnabledRunActiveError,
    CollectionRequest,
    CollectionRequestError,
    CollectionService,
    DisabledSourceError,
    ManualSourceCommandError,
    UnknownSourceError,
)
from backend.app.pipeline.ingestion.external.application.job_service import JobService
from backend.app.pipeline.ingestion.external.application.manual_source_service import (
    ManualSourceService,
)
from backend.app.pipeline.ingestion.external.application.manual_preview_service import (
    ManualPreviewService, PreviewConsumed, PreviewExpired, PreviewHashMismatch, PreviewNotFound,
)
from backend.app.pipeline.ingestion.external.application.dark_web_watch_service import (
    DarkWebWatchService, WatchConflict, WatchNotFound, WatchValidationError,
)
from backend.app.pipeline.ingestion.external.application.review_service import (
    ReviewService,
)
from backend.app.pipeline.ingestion.external.application.source_management_service import (
    SourceManagementService,
    SourceView,
)
from backend.app.pipeline.ingestion.external.integration.auth import (
    AuthenticationError,
    Authenticator,
    AuthorizationError,
    Authorizer,
    Principal,
)
from backend.app.pipeline.ingestion.external.integration.idempotency import (
    IdempotencyStore,
)
from backend.app.pipeline.ingestion.external.integration.jobs import (
    JobRunner,
    utc_now,
)
from backend.app.pipeline.ingestion.external.integration.schemas import (
    CollectionRequestBody,
    HealthResponse,
    IntegrationErrorResponse,
    JobListResponse,
    JobSummaryResponse,
    JobStatusResponse,
    LatestExportResponse,
    LatestExportSummaryResponse,
    LatestReviewResponse,
    ManualPreviewApproveBody,
    ManualPreviewRejectBody,
    ManualPreviewRejectedResponse,
    ManualPreviewRequestBody,
    ManualPreviewResponse,
    ManualURLRequestBody,
    SourceCollectionRequestBody,
    SourceResponse,
    DarkWebWatchCreateBody, DarkWebWatchPatchBody, DarkWebWatchListResponse,
    DarkWebWatchResponse, DarkWebResultPageResponse,
)

API_PREFIX = "/api/v1/external-sources"
COLLECTION_ERROR_RESPONSES = {
    404: {"model": IntegrationErrorResponse, "description": "One or more source IDs are not registered."},
    409: {"model": IntegrationErrorResponse, "description": "A source is disabled, belongs to Manual Source, or an all-enabled job is already active."},
    422: {"model": IntegrationErrorResponse, "description": "The collection request is invalid; scope=all_enabled must not be combined with non-empty source_ids."},
    503: {"model": IntegrationErrorResponse, "description": "The collection service could not accept the command."},
}


class APIError(RuntimeError):
    def __init__(self, status_code: int, code: str, message: str, *, retryable: bool = False, details: dict[str, Any] | None = None) -> None:
        super().__init__(message); self.status_code, self.code, self.message = status_code, code, message
        self.retryable, self.details = retryable, details or {}


class JobBusinessError(RuntimeError):
    """Signal a safely categorized unsuccessful application result to the runner."""


@dataclass(frozen=True, slots=True)
class AdapterServices:
    authenticator: Authenticator
    authorizer: Authorizer
    collection_service: CollectionService
    manual_source_service: ManualSourceService
    source_service: SourceManagementService
    job_service: JobService
    job_runner: JobRunner
    idempotency: IdempotencyStore
    review_service: ReviewService | None = None
    manual_preview_service: ManualPreviewService | None = None
    dark_web_watch_service: DarkWebWatchService | None = None


def create_app(services: AdapterServices, *, docs_enabled: bool = False) -> FastAPI:
    app = FastAPI(
        title="CTI Tool External Sources Internal API",
        version="1.0.0",
        docs_url="/docs" if docs_enabled else None,
        redoc_url=None,
        openapi_url="/openapi.json" if docs_enabled else None,
    )
    app.state.services = services

    @app.exception_handler(APIError)
    async def api_error_handler(_request: Request, exc: APIError) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content=_error(exc.code, exc.message, exc.retryable, exc.details))

    @app.exception_handler(RequestValidationError)
    async def validation_handler(_request: Request, exc: RequestValidationError) -> JSONResponse:
        fields = sorted({".".join(str(part) for part in error.get("loc", ()) if part != "body") for error in exc.errors()})
        return JSONResponse(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, content=_error("request_validation_failed", "request validation failed", details={"fields": fields}))

    @app.exception_handler(Exception)
    async def unexpected_error_handler(_request: Request, _exc: Exception) -> JSONResponse:
        return JSONResponse(status_code=500, content=_error("internal_adapter_error", "internal adapter operation failed safely"))

    def principal(authorization: str | None = Header(default=None, alias="Authorization")) -> Principal:
        if not authorization or not authorization.startswith("Bearer "):
            raise APIError(401, "authentication_required", "internal authentication is required")
        try: return services.authenticator.authenticate(authorization[7:].strip())
        except AuthenticationError: raise APIError(401, "authentication_failed", "internal authentication failed") from None

    def permitted(permission: str) -> Callable[[Principal], Principal]:
        def dependency(current: Principal = Depends(principal)) -> Principal:
            try: services.authorizer.require(current, permission)
            except AuthorizationError: raise APIError(403, "authorization_denied", "operation is not permitted") from None
            return current
        return dependency

    @app.get(f"{API_PREFIX}/health", response_model=HealthResponse)
    def health() -> HealthResponse: return HealthResponse()

    @app.post(f"{API_PREFIX}/jobs", response_model=JobStatusResponse, status_code=202, responses=COLLECTION_ERROR_RESPONSES)
    def start_collection(body: CollectionRequestBody, current: Principal = Depends(permitted("jobs:create")),
                         idempotency_key: str | None = Header(default=None, alias="Idempotency-Key")) -> JobStatusResponse:
        cached = _cached(services, current, "start_collection", idempotency_key)
        if cached: return JobStatusResponse.model_validate(cached)
        command_id = _id("cmd")
        try: accepted = services.collection_service.start_collection(CollectionRequest(
            source_ids=tuple(body.source_ids), scope=body.scope, force=body.force,
            requested_by=current.subject, options=body.options,
        ))
        except AllEnabledRunActiveError: raise APIError(409, "all_enabled_job_active", "an all-enabled collection job is already active") from None
        except UnknownSourceError: raise APIError(404, "source_not_found", "one or more source identifiers were not found") from None
        except DisabledSourceError: raise APIError(409, "source_disabled", "one or more selected sources are disabled") from None
        except ManualSourceCommandError: raise APIError(409, "manual_source_route_required", "manual URLs must use the manual-source operation") from None
        except CollectionRequestError: raise APIError(422, "invalid_collection_request", "collection request is invalid") from None
        except Exception: raise APIError(503, "collection_unavailable", "collection command could not be accepted", retryable=True) from None
        response = _queued(accepted.job_id, accepted.command_id or command_id)
        _remember(services, current, "start_collection", idempotency_key, response.model_dump())
        return response

    @app.post(f"{API_PREFIX}/sources/{{source_id}}/jobs", response_model=JobStatusResponse, status_code=202, responses=COLLECTION_ERROR_RESPONSES)
    def collect_source(source_id: str, body: SourceCollectionRequestBody = Body(default=SourceCollectionRequestBody()),
                       current: Principal = Depends(permitted("jobs:create")),
                       idempotency_key: str | None = Header(default=None, alias="Idempotency-Key")) -> JobStatusResponse:
        _safe_source_id(source_id)
        cached = _cached(services, current, f"collect_source:{source_id}", idempotency_key)
        if cached: return JobStatusResponse.model_validate(cached)
        command_id = _id("cmd")
        try: accepted = services.collection_service.collect_source(source_id, requested_by=current.subject, force=body.force)
        except UnknownSourceError: raise APIError(404, "source_not_found", "source identifier was not found") from None
        except DisabledSourceError: raise APIError(409, "source_disabled", "selected source is disabled") from None
        except ManualSourceCommandError: raise APIError(409, "manual_source_route_required", "manual URLs must use the manual-source operation") from None
        except CollectionRequestError: raise APIError(422, "invalid_collection_request", "collection request is invalid") from None
        except Exception: raise APIError(503, "collection_unavailable", "source collection could not be accepted", retryable=True) from None
        response = _queued(accepted.job_id, accepted.command_id or command_id)
        _remember(services, current, f"collect_source:{source_id}", idempotency_key, response.model_dump())
        return response

    @app.post(f"{API_PREFIX}/manual-sources", response_model=JobStatusResponse, status_code=202)
    def add_manual(body: ManualURLRequestBody, current: Principal = Depends(permitted("manual:create")),
                   idempotency_key: str | None = Header(default=None, alias="Idempotency-Key")) -> JobStatusResponse:
        return _manual_job(services, current, str(body.url), body.force, idempotency_key)

    @app.post(f"{API_PREFIX}/manual-sources/recheck", response_model=JobStatusResponse, status_code=202)
    def recheck_manual(body: ManualURLRequestBody, current: Principal = Depends(permitted("manual:create")),
                       idempotency_key: str | None = Header(default=None, alias="Idempotency-Key")) -> JobStatusResponse:
        return _manual_job(services, current, str(body.url), True, idempotency_key, scope="recheck_url")

    @app.post(f"{API_PREFIX}/manual-sources/previews", response_model=ManualPreviewResponse,
              response_model_exclude_none=True, status_code=201)
    def create_manual_preview(body: ManualPreviewRequestBody,
                              current: Principal = Depends(permitted("manual:preview"))) -> ManualPreviewResponse:
        preview = _previews(services)
        try: value = preview.create(str(body.url), requested_by=current.subject)
        except Exception: raise APIError(422, "preview_unavailable", "URL could not be previewed safely") from None
        return ManualPreviewResponse.model_validate(value)

    @app.post(f"{API_PREFIX}/manual-sources/previews/{{preview_id}}/approve",
              response_model=JobStatusResponse, status_code=202)
    def approve_manual_preview(preview_id: str, body: ManualPreviewApproveBody,
                               current: Principal = Depends(permitted("manual:approve")),
                               idempotency_key: str | None = Header(default=None, alias="Idempotency-Key")) -> JobStatusResponse:
        cached = _cached(services, current, f"approve_preview:{preview_id}", idempotency_key)
        if cached: return JobStatusResponse.model_validate(cached)
        preview = _previews(services)
        try: claimed = preview.claim_approval(preview_id, body.expected_content_sha256)
        except Exception as exc: raise _preview_error(exc)
        command_id = _id("cmd")
        try:
            job = services.job_runner.submit(command_id, lambda: preview.approve_claimed(claimed, requested_by=current.subject))
        except Exception:
            preview.release_approval(preview_id)
            raise APIError(503, "preview_enqueue_failed", "manual preview approval could not be queued", retryable=True) from None
        response = _queued(job.job_id, command_id)
        _remember(services, current, f"approve_preview:{preview_id}", idempotency_key, response.model_dump())
        return response

    @app.post(f"{API_PREFIX}/manual-sources/previews/{{preview_id}}/reject",
              response_model=ManualPreviewRejectedResponse)
    def reject_manual_preview(preview_id: str, body: ManualPreviewRejectBody,
                              current: Principal = Depends(permitted("manual:reject")),
                              idempotency_key: str | None = Header(default=None, alias="Idempotency-Key")) -> ManualPreviewRejectedResponse:
        cached = _cached(services, current, f"reject_preview:{preview_id}", idempotency_key)
        if cached: return ManualPreviewRejectedResponse.model_validate(cached)
        try: value = _previews(services).reject(preview_id, body.reason, requested_by=current.subject)
        except Exception as exc: raise _preview_error(exc)
        response = ManualPreviewRejectedResponse.model_validate(value)
        _remember(services, current, f"reject_preview:{preview_id}", idempotency_key, response.model_dump())
        return response

    @app.get(f"{API_PREFIX}/sources", response_model=list[SourceResponse])
    def list_sources(_current: Principal = Depends(permitted("sources:read"))) -> list[SourceResponse]:
        return [_source(value) for value in services.source_service.list_sources()]

    def watches() -> DarkWebWatchService:
        if services.dark_web_watch_service is None: raise APIError(503, "dark_web_unconfigured", "dark web monitoring is not configured")
        return services.dark_web_watch_service

    @app.get(f"{API_PREFIX}/dark-web/watches", response_model=DarkWebWatchListResponse)
    def list_dark_web_watches(_current: Principal = Depends(permitted("dark_web_watches:read"))):
        return {"schema_version":"1.0","items":watches().store.list_watches()}

    @app.post(f"{API_PREFIX}/dark-web/watches", response_model=DarkWebWatchResponse, status_code=201)
    def create_dark_web_watch(body: DarkWebWatchCreateBody, _current: Principal = Depends(permitted("dark_web_watches:write"))):
        try: return watches().store.create(body.keyword)
        except WatchValidationError: raise APIError(422,"invalid_keyword","keyword is not permitted") from None
        except WatchConflict as exc: raise APIError(409,str(exc),"watch could not be created") from None

    @app.patch(f"{API_PREFIX}/dark-web/watches/{{watch_id}}", response_model=DarkWebWatchResponse)
    def patch_dark_web_watch(watch_id: str, body: DarkWebWatchPatchBody, _current: Principal = Depends(permitted("dark_web_watches:write"))):
        try: return watches().store.set_enabled(watch_id,body.enabled)
        except WatchNotFound: raise APIError(404,"watch_not_found","watch was not found") from None

    @app.post(f"{API_PREFIX}/dark-web/watches/{{watch_id}}/scan", response_model=JobStatusResponse, status_code=202)
    def scan_dark_web_watch(watch_id: str, current: Principal = Depends(permitted("dark_web_watches:scan")), idempotency_key: str | None = Header(default=None,alias="Idempotency-Key")):
        cached=_cached(services,current,f"scan_watch:{watch_id}",idempotency_key)
        if cached: return JobStatusResponse.model_validate(cached)
        try: watches().store.get(watch_id)
        except WatchNotFound: raise APIError(404,"watch_not_found","watch was not found") from None
        command_id=_id("cmd")
        job=services.job_runner.submit(command_id,lambda: watches().scan(watch_id),safe_context={"source_id":"dark-web-watch"})
        response=_queued(job.job_id,command_id); _remember(services,current,f"scan_watch:{watch_id}",idempotency_key,response.model_dump())
        return response

    @app.get(f"{API_PREFIX}/dark-web/watches/{{watch_id}}/results", response_model=DarkWebResultPageResponse)
    def dark_web_watch_results(watch_id: str, limit: int=Query(25,ge=1,le=100), offset: int=Query(0,ge=0), _current: Principal=Depends(permitted("dark_web_watches:read"))):
        try: page=watches().store.results(watch_id,limit,offset)
        except WatchNotFound: raise APIError(404,"watch_not_found","watch was not found") from None
        watch=watches().store.get(watch_id); last=watch.get("last_scan_at")
        items=[]
        for row in page["items"]:
            items.append({k:row[k] for k in ("result_id","watch_id","onion_reference","title","excerpt","provider","first_seen_at","last_seen_at","classification_label","classification_confidence","privacy_status","content_sha256")} | {"status":"new" if row["first_seen_at"]==last else "known","review_reasons":[v for v in row["review_reasons"].split(",") if v]})
        return {"schema_version":"1.0","items":items,"total":page["total"],"limit":limit,"offset":offset}

    @app.get(f"{API_PREFIX}/sources/{{source_id}}", response_model=SourceResponse)
    def get_source(source_id: str, _current: Principal = Depends(permitted("sources:read"))) -> SourceResponse:
        _safe_source_id(source_id); value = services.source_service.get_source_status(source_id)
        if value is None: raise APIError(404, "source_not_found", "source was not found")
        return _source(value)

    @app.post(f"{API_PREFIX}/sources/{{source_id}}/enable-requests", response_model=SourceResponse)
    def enable_source(source_id: str, current: Principal = Depends(permitted("sources:request_enable"))) -> SourceResponse:
        _safe_source_id(source_id); existing = services.source_service.get_source_status(source_id)
        if existing is None: raise APIError(404, "source_not_found", "source was not found")
        if existing.source_type.lower() == "dark_web":
            try: services.authorizer.require(current, "dark_web:approve")
            except AuthorizationError: raise APIError(403, "dark_web_approval_required", "dark-web source approval requires explicit authorization") from None
        value = services.source_service.request_source_enable(source_id, requested_by=current.subject)
        if value.status not in {"pending_review", "disabled"}:
            raise APIError(409, "unsafe_source_state", "source enablement did not enter review")
        return _source(value)

    @app.post(f"{API_PREFIX}/sources/{{source_id}}/disable", response_model=SourceResponse)
    def disable_source(source_id: str, current: Principal = Depends(permitted("sources:disable"))) -> SourceResponse:
        _safe_source_id(source_id)
        return _source(services.source_service.disable_source(source_id, requested_by=current.subject))

    @app.get(f"{API_PREFIX}/jobs/{{job_id}}", response_model=JobStatusResponse)
    def get_job(job_id: str, _current: Principal = Depends(permitted("jobs:read"))) -> JobStatusResponse:
        value = services.job_runner.get(job_id)
        if value is not None: return JobStatusResponse.model_validate(value.safe_dict())
        legacy = services.job_service.get_job_status(job_id)
        if legacy is None: raise APIError(404, "job_not_found", "job was not found")
        return _legacy_job(legacy)

    @app.get(f"{API_PREFIX}/jobs", response_model=JobListResponse)
    def list_jobs(limit: int = Query(default=50, ge=1, le=100),
                  _current: Principal = Depends(permitted("jobs:read"))) -> JobListResponse:
        count_keys = {"accepted_records", "review_records", "rejected_records", "skipped_records", "error_count"}
        summaries = []
        for job in services.job_runner.list(limit=limit):
            result = job.result if isinstance(job.result, dict) else {}
            counts = {key: value for key, value in result.items()
                      if key in count_keys and type(value) is int and value >= 0}
            error = job.error if isinstance(job.error, dict) else {}
            summaries.append(JobSummaryResponse(
                job_id=job.job_id, source_id=job.source_id, state=job.state,
                created_at=job.created_at, updated_at=job.updated_at, counts=counts,
                error_code=str(error.get("code"))[:100] if error.get("code") else None,
                error_message=str(error.get("message"))[:300] if error.get("message") else None,
            ))
        return JobListResponse(jobs=summaries)

    @app.post(f"{API_PREFIX}/jobs/{{job_id}}/cancel", response_model=JobStatusResponse)
    def cancel_job(job_id: str, current: Principal = Depends(permitted("jobs:cancel"))) -> JobStatusResponse:
        value = services.job_runner.cancel(job_id)
        if value is not None: return JobStatusResponse.model_validate(value.safe_dict())
        try: return _legacy_job(services.job_service.cancel_job(job_id, requested_by=current.subject))
        except Exception: raise APIError(404, "job_not_found", "job was not found") from None

    @app.get(f"{API_PREFIX}/exports/latest", response_model=LatestExportResponse, responses={
        404: {"model": IntegrationErrorResponse, "description": "No validated External Sources export is available."},
    })
    def latest_export(_current: Principal = Depends(permitted("exports:read"))) -> LatestExportResponse:
        value = services.job_service.get_latest_export()
        if not value: raise APIError(404, "export_not_found", "no validated export is available")
        allowed = {key: value[key] for key in LatestExportResponse.model_fields if key in value}
        return LatestExportResponse.model_validate(allowed)

    @app.get(f"{API_PREFIX}/exports/latest/summary", response_model=LatestExportSummaryResponse, responses={
        404: {"model": IntegrationErrorResponse, "description": "No validated External Sources export is available."},
    })
    def latest_export_summary(_current: Principal = Depends(permitted("exports:read"))) -> LatestExportSummaryResponse:
        value = services.job_service.get_latest_export()
        if not value: raise APIError(404, "export_not_found", "no validated export is available")
        allowed = {key: value[key] for key in LatestExportSummaryResponse.model_fields if key in value}
        return LatestExportSummaryResponse.model_validate(allowed)

    @app.get(f"{API_PREFIX}/reviews/latest", response_model=LatestReviewResponse, responses={
        404: {"model": IntegrationErrorResponse, "description": "No validated External Sources review artifact is available."},
        503: {"model": IntegrationErrorResponse, "description": "The review read adapter is not configured."},
    })
    def latest_reviews(_current: Principal = Depends(permitted("reviews:read"))) -> LatestReviewResponse:
        if services.review_service is None:
            raise APIError(503, "review_unavailable", "review read operation is unavailable")
        value = services.review_service.latest()
        if value is None: raise APIError(404, "review_not_found", "no validated review artifact is available")
        return LatestReviewResponse.model_validate(value)

    if docs_enabled:
        def secured_openapi() -> dict[str, Any]:
            if app.openapi_schema is not None:
                return app.openapi_schema
            schema = get_openapi(title=app.title, version=app.version, routes=app.routes)
            components = schema.setdefault("components", {})
            components.setdefault("securitySchemes", {})["HTTPBearer"] = {
                "type": "http", "scheme": "bearer", "bearerFormat": "token",
            }
            for path, methods in schema.get("paths", {}).items():
                if path == f"{API_PREFIX}/health":
                    continue
                for method, operation in methods.items():
                    if method.lower() in {"get", "post", "put", "patch", "delete"} and isinstance(operation, dict):
                        operation["security"] = [{"HTTPBearer": []}]
            app.openapi_schema = schema
            return schema

        app.openapi = secured_openapi

    return app


def _manual_job(services: AdapterServices, principal: Principal, url: str, force: bool, key: str | None, *, scope: str = "add_manual_source") -> JobStatusResponse:
    cached = _cached(services, principal, scope, key)
    if cached: return JobStatusResponse.model_validate(cached)
    try: url = services.manual_source_service.validate_url(url)
    except Exception: raise APIError(422, "url_policy_rejected", "URL was rejected by source security policy") from None
    command_id = _id("cmd")
    service_operation = (lambda: services.manual_source_service.recheck_url(url, requested_by=principal.subject, force=True)) if force else (lambda: services.manual_source_service.add_manual_source(url, requested_by=principal.subject))
    operation = lambda: _require_successful_business_result(service_operation())
    job = services.job_runner.submit(command_id, operation)
    response = _queued(job.job_id, command_id)
    _remember(services, principal, scope, key, response.model_dump())
    return response


def _previews(services: AdapterServices) -> ManualPreviewService:
    if services.manual_preview_service is None:
        raise APIError(503, "preview_unavailable", "manual preview service is unavailable", retryable=True)
    return services.manual_preview_service


def _preview_error(exc: Exception) -> APIError:
    if isinstance(exc, PreviewExpired): return APIError(410, exc.code, "manual preview has expired")
    if isinstance(exc, PreviewNotFound): return APIError(404, exc.code, "manual preview was not found")
    if isinstance(exc, (PreviewConsumed, PreviewHashMismatch)): return APIError(409, exc.code, "manual preview cannot be decided")
    return APIError(503, "preview_unavailable", "manual preview operation failed safely", retryable=True)


def _require_successful_business_result(result: Any) -> Any:
    if getattr(result, "status", None) == "error":
        raise JobBusinessError("application operation returned an error result")
    return result


def _queued(job_id: str, command_id: str) -> JobStatusResponse:
    now = utc_now(); return JobStatusResponse(job_id=job_id, command_id=command_id, state="queued", created_at=now, updated_at=now)


def _legacy_job(value: Any) -> JobStatusResponse:
    data = asdict(value); data.setdefault("command_id", f"cmd-{secrets.token_hex(8)}"); data.setdefault("schema_version", "1.0")
    return JobStatusResponse.model_validate(data)


def _source(value: SourceView) -> SourceResponse:
    safe_metadata = {key: item for key, item in value.metadata.items() if not any(token in key.lower() for token in ("url", "path", "token", "secret", "password", "authorization", "cookie"))}
    return SourceResponse(source_id=value.source_id, name=value.name, source_type=value.source_type, status=value.status, metadata=safe_metadata)


def _safe_source_id(value: str) -> None:
    if not value or len(value) > 128 or any(not (character.isalnum() or character in "-_.") for character in value):
        raise APIError(422, "invalid_source_id", "source identifier is invalid")


def _cached(services: AdapterServices, principal: Principal, scope: str, key: str | None) -> dict[str, Any] | None:
    if not key: return None
    if len(key) < 8 or len(key) > 128: raise APIError(422, "invalid_idempotency_key", "idempotency key length is invalid")
    return services.idempotency.get(f"{principal.subject}:{scope}", key)


def _remember(services: AdapterServices, principal: Principal, scope: str, key: str | None, value: dict[str, Any]) -> None:
    if key: services.idempotency.put(f"{principal.subject}:{scope}", key, value)


def _id(prefix: str) -> str: return f"{prefix}-{secrets.token_hex(12)}"


def _error(code: str, message: str, retryable: bool = False, details: dict[str, Any] | None = None) -> dict[str, Any]:
    return IntegrationErrorResponse(code=code, message=message, retryable=retryable, details=details or {}).model_dump()
