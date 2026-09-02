from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from fastapi import FastAPI, Header, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse

SENSITIVE_KEY_PARTS = ("authorization", "cookie", "password", "secret", "token", "api_key", "apikey")
STREAM_NAMES = frozenset({"dionaea", "host-auth", "web-access"})
EXTERNAL_API_PREFIX = "/api/v1/external-sources"
EXTERNAL_READ_ROLES = frozenset({"admin", "analyst", "viewer"})
EXTERNAL_CONTROL_ROLES = frozenset({"admin", "analyst"})
EXTERNAL_SOURCE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
EXTERNAL_JOB_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{9,199}$")
ONION_VALUE = re.compile(r"(?i)(?:https?://)?[a-z0-9.-]+\.onion(?:[^\s\"']*)")
EXTERNAL_ENDPOINTS = {
    ("GET", "/health"): "health",
    ("GET", "/sources"): "sources",
    ("GET", "/jobs/{job_id}"): "job",
    ("GET", "/exports/latest/summary"): "export_summary",
    ("GET", "/exports/latest"): "export",
    ("GET", "/reviews/latest"): "reviews",
    ("POST", "/jobs"): "job",
    ("POST", "/sources/{source_id}/jobs"): "job",
    ("POST", "/jobs/{job_id}/cancel"): "job",
    ("POST", "/manual-sources"): "job",
    ("POST", "/manual-sources/recheck"): "job",
}
MAX_EXTERNAL_RESPONSE_BYTES = 10 * 1024 * 1024
MAX_EXTERNAL_TIMEOUT_SECONDS = 30.0


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class GatewaySettings:
    feed_publish_token: str
    feed_read_token: str
    feed_hmac_secret: str
    sensor_read_token: str
    sensor_hmac_secret: str
    cursor_secret: str
    data_dir: Path = Path("/data")
    dionaea_path: Path = Path("/sensors/dionaea/dionaea.json")
    host_auth_path: Path = Path("/sensors/host/host_auth.jsonl")
    feed_id: str = "external-team-feed"
    sensor_id: str = "cti-vps"
    max_publish_bytes: int = 20 * 1024 * 1024
    max_sensor_bytes: int = 50 * 1024 * 1024
    max_feed_items: int = 20_000
    external_control_api_url: str | None = None
    external_control_api_token: str | None = None
    jwt_secret: str | None = None
    external_control_timeout_seconds: float = 10.0
    external_control_max_bytes: int = 2 * 1024 * 1024

    @classmethod
    def from_env(cls) -> GatewaySettings:
        required = {
            "feed_publish_token": os.getenv("FEED_PUBLISH_TOKEN", ""),
            "feed_read_token": os.getenv("FEED_READ_TOKEN", ""),
            "feed_hmac_secret": os.getenv("FEED_RESPONSE_HMAC_SECRET", ""),
            "sensor_read_token": os.getenv("SENSOR_READ_TOKEN", ""),
            "sensor_hmac_secret": os.getenv("SENSOR_RESPONSE_HMAC_SECRET", ""),
            "cursor_secret": os.getenv("CURSOR_HMAC_SECRET", ""),
        }
        missing = [name for name, value in required.items() if len(value) < 24]
        if missing:
            raise RuntimeError(f"Gateway secrets must contain at least 24 characters: {', '.join(missing)}")
        jwt_secret = os.getenv("JWT_SECRET", "")
        if len(jwt_secret) < 24:
            raise RuntimeError("JWT_SECRET must contain at least 24 characters")
        return cls(
            **required,
            data_dir=Path(os.getenv("GATEWAY_DATA_DIR", "/data")),
            dionaea_path=Path(os.getenv("DIONAEA_LOG_PATH", "/sensors/dionaea/dionaea.json")),
            host_auth_path=Path(os.getenv("HOST_AUTH_LOG_PATH", "/sensors/host/host_auth.jsonl")),
            feed_id=os.getenv("EXTERNAL_FEED_ID", "external-team-feed"),
            sensor_id=os.getenv("SENSOR_ID", "cti-vps"),
            max_publish_bytes=int(os.getenv("MAX_PUBLISH_BYTES", str(20 * 1024 * 1024))),
            max_sensor_bytes=int(os.getenv("MAX_SENSOR_BYTES", str(50 * 1024 * 1024))),
            max_feed_items=int(os.getenv("MAX_FEED_ITEMS", "20000")),
            external_control_api_url=os.getenv("EXTERNAL_CONTROL_API_URL"),
            external_control_api_token=os.getenv("EXTERNAL_CONTROL_API_TOKEN"),
            jwt_secret=jwt_secret,
            external_control_timeout_seconds=float(os.getenv("EXTERNAL_CONTROL_TIMEOUT_SECONDS", "10")),
            external_control_max_bytes=int(os.getenv("EXTERNAL_CONTROL_MAX_BYTES", str(2 * 1024 * 1024))),
        )


def create_app(settings: GatewaySettings) -> FastAPI:
    _validate_external_destination(settings)
    app = FastAPI(title="CTI VPS Gateway", version="1.0.0", docs_url=None, redoc_url=None)
    app.state.settings = settings
    app.state.write_lock = threading.Lock()

    @app.exception_handler(ExternalGatewayError)
    async def external_gateway_error_handler(_request: Request, exc: ExternalGatewayError) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content=exc.payload)

    @app.middleware("http")
    async def web_access_log(request: Request, call_next):
        started = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            _append_web_event(settings, app.state.write_lock, request, 500, started)
            raise
        if request.url.path not in {"/health", "/api/v1/sensors/web-access"}:
            _append_web_event(settings, app.state.write_lock, request, response.status_code, started)
        return response

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "service": "cti-vps-gateway",
            "feed_ready": _feed_path(settings).is_file(),
            "streams": {
                "dionaea": _safe_is_file(settings.dionaea_path),
                "host-auth": _safe_is_file(settings.host_auth_path),
                "web-access": _safe_is_file(_web_path(settings)),
            },
        }

    @app.get(f"{EXTERNAL_API_PREFIX}/health")
    def external_health(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        principal = _external_principal(authorization, settings)
        _require_external_role(principal, EXTERNAL_READ_ROLES)
        return _external_request(settings, "GET", "/health", authenticated=False)

    @app.get(f"{EXTERNAL_API_PREFIX}/sources")
    def external_sources(authorization: str | None = Header(default=None)) -> Any:
        principal = _external_principal(authorization, settings)
        _require_external_role(principal, EXTERNAL_READ_ROLES)
        return _external_request(settings, "GET", "/sources")

    @app.get(f"{EXTERNAL_API_PREFIX}/sources/{{source_id}}")
    def external_source(source_id: str, authorization: str | None = Header(default=None)) -> Any:
        principal = _external_principal(authorization, settings)
        _require_external_role(principal, EXTERNAL_READ_ROLES)
        _validate_external_id(source_id, EXTERNAL_SOURCE_ID, "source_id")
        return _external_request(settings, "GET", f"/sources/{source_id}")

    @app.get(f"{EXTERNAL_API_PREFIX}/jobs/{{job_id}}")
    def external_job(job_id: str, authorization: str | None = Header(default=None)) -> Any:
        principal = _external_principal(authorization, settings)
        _require_external_role(principal, EXTERNAL_READ_ROLES)
        _validate_external_id(job_id, EXTERNAL_JOB_ID, "job_id")
        return _external_request(settings, "GET", f"/jobs/{job_id}")

    @app.get(f"{EXTERNAL_API_PREFIX}/exports/latest/summary")
    def external_export_summary(authorization: str | None = Header(default=None)) -> Any:
        principal = _external_principal(authorization, settings)
        _require_external_role(principal, EXTERNAL_READ_ROLES)
        return _external_request(settings, "GET", "/exports/latest/summary")

    @app.get(f"{EXTERNAL_API_PREFIX}/exports/latest")
    def external_export(authorization: str | None = Header(default=None)) -> Any:
        principal = _external_principal(authorization, settings)
        _require_external_role(principal, EXTERNAL_READ_ROLES)
        return _external_request(settings, "GET", "/exports/latest")

    @app.get(f"{EXTERNAL_API_PREFIX}/reviews/latest")
    def external_reviews(authorization: str | None = Header(default=None)) -> Any:
        principal = _external_principal(authorization, settings)
        _require_external_role(principal, EXTERNAL_READ_ROLES)
        return _external_request(settings, "GET", "/reviews/latest")

    @app.post(f"{EXTERNAL_API_PREFIX}/jobs", status_code=status.HTTP_202_ACCEPTED)
    async def external_start_job(request: Request, authorization: str | None = Header(default=None)) -> Any:
        principal = _external_principal(authorization, settings)
        _require_external_role(principal, EXTERNAL_CONTROL_ROLES)
        body = await _bounded_json_request(request)
        if not isinstance(body, dict):
            raise _gateway_error(422, "request_validation_failed", "request body must be an object")
        allowed = {"source_ids", "scope", "force"}
        if set(body) - allowed or not isinstance(body.get("source_ids", []), list) or len(body.get("source_ids", [])) > 100:
            raise _gateway_error(422, "request_validation_failed", "collection request is invalid")
        for source_id in body.get("source_ids", []):
            if not isinstance(source_id, str) or not EXTERNAL_SOURCE_ID.fullmatch(source_id):
                raise _gateway_error(422, "invalid_source_id", "source identifier is invalid")
        if body.get("scope") not in {None, "all_enabled"} or not isinstance(body.get("force", False), bool):
            raise _gateway_error(422, "request_validation_failed", "collection request is invalid")
        return _external_request(settings, "POST", "/jobs", body)

    @app.post(f"{EXTERNAL_API_PREFIX}/sources/{{source_id}}/jobs", status_code=status.HTTP_202_ACCEPTED)
    async def external_start_source(source_id: str, request: Request, authorization: str | None = Header(default=None)) -> Any:
        principal = _external_principal(authorization, settings)
        _require_external_role(principal, EXTERNAL_CONTROL_ROLES)
        _validate_external_id(source_id, EXTERNAL_SOURCE_ID, "source_id")
        body = await _bounded_json_request(request)
        if not isinstance(body, dict) or set(body) - {"force"} or not isinstance(body.get("force", False), bool):
            raise _gateway_error(422, "request_validation_failed", "source collection request is invalid")
        return _external_request(settings, "POST", f"/sources/{source_id}/jobs", body)

    @app.post(f"{EXTERNAL_API_PREFIX}/jobs/{{job_id}}/cancel")
    def external_cancel_job(job_id: str, authorization: str | None = Header(default=None)) -> Any:
        principal = _external_principal(authorization, settings)
        _require_external_role(principal, EXTERNAL_CONTROL_ROLES)
        _validate_external_id(job_id, EXTERNAL_JOB_ID, "job_id")
        return _external_request(settings, "POST", f"/jobs/{job_id}/cancel", {})

    @app.post(f"{EXTERNAL_API_PREFIX}/manual-sources", status_code=status.HTTP_202_ACCEPTED)
    async def external_manual_source(request: Request, authorization: str | None = Header(default=None)) -> Any:
        principal = _external_principal(authorization, settings)
        _require_external_role(principal, EXTERNAL_CONTROL_ROLES)
        body = await _manual_body(request)
        return _external_request(settings, "POST", "/manual-sources", body)

    @app.post(f"{EXTERNAL_API_PREFIX}/manual-sources/recheck", status_code=status.HTTP_202_ACCEPTED)
    async def external_manual_recheck(request: Request, authorization: str | None = Header(default=None)) -> Any:
        principal = _external_principal(authorization, settings)
        _require_external_role(principal, EXTERNAL_CONTROL_ROLES)
        body = await _manual_body(request)
        body["force"] = True
        return _external_request(settings, "POST", "/manual-sources/recheck", body)

    @app.post("/api/v1/external-feed/publish", status_code=status.HTTP_202_ACCEPTED)
    async def publish_external_feed(request: Request, authorization: str | None = Header(default=None)):
        _authorize(authorization, settings.feed_publish_token)
        length = request.headers.get("content-length")
        if length and _safe_int(length, settings.max_publish_bytes + 1) > settings.max_publish_bytes:
            raise HTTPException(status_code=413, detail="publish body exceeds configured limit")
        body = await request.body()
        if len(body) > settings.max_publish_bytes:
            raise HTTPException(status_code=413, detail="publish body exceeds configured limit")
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HTTPException(status_code=422, detail="publish body must be UTF-8 JSON") from exc
        envelope = _normalize_publish(payload, settings)
        encoded = _json_bytes(envelope)
        digest = hashlib.sha256(encoded).hexdigest()
        _atomic_write(_feed_path(settings), encoded)
        return {
            "status": "accepted",
            "feed_id": settings.feed_id,
            "item_count": len(envelope["items"]),
            "etag": digest,
        }

    @app.get("/api/v1/external-feed")
    def external_feed(
        authorization: str | None = Header(default=None),
        if_none_match: str | None = Header(default=None, alias="If-None-Match"),
        limit: int = Query(250, ge=1, le=1000),
        cursor: str | None = None,
    ):
        _authorize(authorization, settings.feed_read_token)
        path = _feed_path(settings)
        if not path.is_file():
            raise HTTPException(status_code=404, detail="no external feed has been published")
        raw = _bounded_read(path, settings.max_publish_bytes)
        etag = hashlib.sha256(raw).hexdigest()
        quoted_etag = f'"{etag}"'
        if cursor is None and if_none_match and if_none_match.strip() in {etag, quoted_etag}:
            return Response(status_code=304, headers={"ETag": quoted_etag})
        payload = json.loads(raw.decode("utf-8"))
        start = _decode_cursor(cursor, "external-feed", settings.cursor_secret) if cursor else 0
        items = payload["items"]
        page = items[start : start + limit]
        end = start + len(page)
        has_more = end < len(items)
        response_payload = {
            "schema_version": "1.0",
            "feed_id": payload["feed_id"],
            "generated_at": payload["generated_at"],
            "items": page,
            "has_more": has_more,
            "next_cursor": _encode_cursor(end, "external-feed", settings.cursor_secret) if has_more else None,
            "checkpoint": etag,
        }
        return _signed_json(response_payload, settings.feed_hmac_secret, {"ETag": quoted_etag})

    @app.get("/api/v1/sensors/{stream_name}")
    def sensor_stream(
        stream_name: str,
        authorization: str | None = Header(default=None),
        limit: int = Query(500, ge=1, le=1000),
        cursor: str | None = None,
    ):
        _authorize(authorization, settings.sensor_read_token)
        if stream_name not in STREAM_NAMES:
            raise HTTPException(status_code=404, detail="sensor stream not found")
        events = _load_sensor_events(_stream_path(settings, stream_name), settings.max_sensor_bytes, stream_name)
        start = _decode_cursor(cursor, stream_name, settings.cursor_secret) if cursor else 0
        page = events[start : start + limit]
        end = start + len(page)
        has_more = end < len(events)
        payload = {
            "schema_version": "1.0",
            "sensor_id": f"{settings.sensor_id}:{stream_name}",
            "generated_at": utc_now(),
            "events": page,
            "has_more": has_more,
            "next_cursor": _encode_cursor(end, stream_name, settings.cursor_secret) if has_more else None,
            "checkpoint": _encode_cursor(end, stream_name, settings.cursor_secret),
        }
        return _signed_json(payload, settings.sensor_hmac_secret)

    return app


@dataclass(frozen=True, slots=True)
class ExternalPrincipal:
    subject: str
    role: str


class ExternalGatewayError(RuntimeError):
    def __init__(self, status_code: int, payload: dict[str, Any]) -> None:
        super().__init__(payload["message"])
        self.status_code = status_code
        self.payload = payload


def _gateway_error(code: int, error_code: str, message: str, *, retryable: bool = False) -> ExternalGatewayError:
    return ExternalGatewayError(code, {
        "schema_version": "1.0", "code": error_code, "message": message,
        "retryable": retryable, "details": {},
    })


def _validate_external_destination(settings: GatewaySettings) -> None:
    if not settings.external_control_api_url:
        return
    parsed = urlsplit(settings.external_control_api_url.rstrip("/"))
    if (parsed.scheme != "http" or parsed.hostname != "external-sources" or parsed.port != 8000
            or parsed.path != EXTERNAL_API_PREFIX or parsed.username or parsed.password
            or parsed.query or parsed.fragment):
        raise ValueError("EXTERNAL_CONTROL_API_URL must be the internal external-sources destination")


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


def _external_principal(header: str | None, settings: GatewaySettings) -> ExternalPrincipal:
    if not header or not header.startswith("Bearer "):
        raise _gateway_error(401, "authentication_required", "authentication is required")
    if not settings.jwt_secret or len(settings.jwt_secret) < 24:
        raise _gateway_error(503, "authentication_unavailable", "frontend authentication is not configured")
    try:
        encoded_header, encoded_payload, encoded_signature = header[7:].strip().split(".")
        signing_input = f"{encoded_header}.{encoded_payload}"
        expected = hmac.new(settings.jwt_secret.encode(), signing_input.encode("ascii"), hashlib.sha256).digest()
        supplied = _b64url_decode(encoded_signature)
        payload = json.loads(_b64url_decode(encoded_payload))
        token_header = json.loads(_b64url_decode(encoded_header))
        if not hmac.compare_digest(expected, supplied) or token_header.get("alg") != "HS256":
            raise ValueError
        if int(payload.get("exp", 0)) <= int(time.time()) or not payload.get("sub"):
            raise ValueError
        role = payload.get("role")
        if role not in EXTERNAL_READ_ROLES | EXTERNAL_CONTROL_ROLES:
            raise ValueError
        return ExternalPrincipal(str(payload["sub"]), str(role))
    except (ValueError, TypeError, KeyError, json.JSONDecodeError, binascii.Error):
        raise _gateway_error(401, "authentication_failed", "authentication failed") from None


def _require_external_role(principal: ExternalPrincipal, allowed: frozenset[str]) -> None:
    if principal.role not in allowed:
        raise _gateway_error(403, "authorization_denied", "operation is not permitted")


def _validate_external_id(value: str, pattern: re.Pattern[str], field: str) -> None:
    if not pattern.fullmatch(value):
        raise _gateway_error(422, f"invalid_{field}", f"{field} is invalid")


async def _bounded_json_request(request: Request) -> Any:
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            declared_length = int(content_length)
        except ValueError:
            declared_length = None
        if declared_length is not None and (declared_length < 0 or declared_length > 64 * 1024):
            raise _gateway_error(413, "request_too_large", "request body exceeds configured limit")
    chunks = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > 64 * 1024:
            raise _gateway_error(413, "request_too_large", "request body exceeds configured limit")
        chunks.append(chunk)
    body = b"".join(chunks)
    if total > 64 * 1024:
        raise _gateway_error(413, "request_too_large", "request body exceeds configured limit")
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise _gateway_error(422, "request_validation_failed", "request body must be valid JSON") from None


async def _manual_body(request: Request) -> dict[str, Any]:
    body = await _bounded_json_request(request)
    if not isinstance(body, dict) or set(body) - {"url", "force"} or not isinstance(body.get("url"), str):
        raise _gateway_error(422, "request_validation_failed", "manual source request is invalid")
    url = body["url"]
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise _gateway_error(422, "url_policy_rejected", "URL was rejected by source security policy")
    if not isinstance(body.get("force", False), bool):
        raise _gateway_error(422, "request_validation_failed", "manual source request is invalid")
    return {"url": url, "force": body.get("force", False)}


def _external_request(settings: GatewaySettings, method: str, path: str, payload: dict[str, Any] | None = None, *, authenticated: bool = True) -> Any:
    if not settings.external_control_api_url or not settings.external_control_api_token:
        raise _gateway_error(503, "external_control_unavailable", "External Sources control API is not configured", retryable=True)
    _validate_external_destination(settings)
    response_kind = EXTERNAL_ENDPOINTS.get((method, _endpoint_key(path)))
    if response_kind is None:
        raise _gateway_error(404, "route_not_allowlisted", "External Sources route is not allowlisted")
    base = settings.external_control_api_url.rstrip("/")
    headers = {"Accept": "application/json", "User-Agent": "cti-vps-gateway/1.0"}
    if authenticated:
        headers["Authorization"] = f"Bearer {settings.external_control_api_token}"
    if payload is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(f"{base}{path}", data=json.dumps(payload).encode() if payload is not None else None,
                                     headers=headers, method=method)
    response_limit = min(max(4096, settings.external_control_max_bytes), MAX_EXTERNAL_RESPONSE_BYTES)
    try:
        opener = urllib.request.build_opener(_NoRedirectHandler())
        with opener.open(request, timeout=min(max(1.0, settings.external_control_timeout_seconds), MAX_EXTERNAL_TIMEOUT_SECONDS)) as response:
            body = response.read(response_limit + 1)
            status_code = response.status
    except urllib.error.HTTPError as exc:
        body = exc.read(response_limit + 1)
        status_code = exc.code
    except (urllib.error.URLError, TimeoutError, OSError):
        raise _gateway_error(504, "external_control_timeout", "External Sources control API timed out or is unavailable", retryable=True) from None
    if len(body) > response_limit:
        raise _gateway_error(502, "external_control_response_too_large", "External Sources response exceeds configured limit")
    try:
        value = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise _gateway_error(502, "external_control_invalid_response", "External Sources returned invalid JSON") from None
    if status_code >= 400:
        value = _sanitize_external(value, (settings.external_control_api_token,))
        if isinstance(value, dict) and all(key in value for key in ("code", "message", "retryable", "details")):
            raise ExternalGatewayError(status_code, {
                "schema_version": "1.0", "code": str(value["code"]),
                "message": str(value["message"]), "retryable": bool(value["retryable"]),
                "details": value["details"] if isinstance(value["details"], dict) else {},
            })
        raise _gateway_error(status_code if status_code in {401, 403, 404, 409, 422} else 502,
                             "external_control_error", "External Sources control request failed", retryable=status_code >= 500)
    try:
        return _project_external(response_kind, value, (settings.external_control_api_token,))
    except ValueError:
        raise _gateway_error(502, "external_control_invalid_response", "External Sources returned an invalid response contract") from None


def _endpoint_key(path: str) -> str:
    parts = path.split("/")
    if len(parts) == 3 and parts[1] == "jobs":
        return "/jobs/{job_id}"
    if len(parts) == 4 and parts[1] == "sources" and parts[3] == "jobs":
        return "/sources/{source_id}/jobs"
    if len(parts) == 4 and parts[1] == "jobs" and parts[3] == "cancel":
        return "/jobs/{job_id}/cancel"
    return path


def _project_external(kind: str, value: Any, forbidden: tuple[str | None, ...]) -> Any:
    if kind == "health":
        if not isinstance(value, dict) or value.get("status") != "ok" or value.get("service") != "external-sources" or value.get("api_version") != "v1":
            raise ValueError
        return {key: value[key] for key in ("status", "service", "api_version")}
    if kind == "sources":
        if not isinstance(value, list):
            raise ValueError
        return [_project_source(item, forbidden) for item in value]
    if kind == "job":
        return _project_job(value, forbidden)
    if kind == "export_summary":
        return _project_export_summary(value, forbidden)
    if kind == "export":
        return _project_export(value, forbidden)
    if kind == "reviews":
        if not isinstance(value, dict) or not isinstance(value.get("run_id"), str) or not isinstance(value.get("records"), list):
            raise ValueError
        return {"run_id": value["run_id"], "records": [_project_review(item, forbidden) for item in value["records"]]}
    raise ValueError


def _project_source(value: Any, forbidden: tuple[str | None, ...]) -> dict[str, Any]:
    fields = {"source_id", "name", "source_type", "status", "metadata"}
    if not isinstance(value, dict) or set(value) - fields or not all(isinstance(value.get(key), str) for key in ("source_id", "name", "source_type", "status")):
        raise ValueError
    metadata = value.get("metadata", {})
    if not isinstance(metadata, dict):
        raise ValueError
    return {"source_id": value["source_id"], "name": value["name"], "source_type": value["source_type"],
            "status": value["status"], "metadata": _safe_nested(metadata, forbidden)}


def _project_job(value: Any, forbidden: tuple[str | None, ...]) -> dict[str, Any]:
    states = {"queued", "running", "completed", "partial", "failed", "cancellation_requested", "cancelled"}
    required = ("schema_version", "job_id", "command_id", "state", "created_at", "updated_at")
    fields = set(required) | {"progress", "result", "error"}
    if not isinstance(value, dict) or set(value) - fields or any(key not in value for key in required) or value.get("schema_version") != "1.0":
        raise ValueError
    if not all(isinstance(value.get(key), str) for key in ("job_id", "command_id", "created_at", "updated_at")) or value.get("state") not in states:
        raise ValueError
    result = value.get("result")
    error = value.get("error")
    projected_error = None
    if error is not None:
        if not isinstance(error, dict) or not isinstance(error.get("code"), str) or not isinstance(error.get("message"), str):
            raise ValueError
        projected_error = {"code": error["code"], "message": error["message"], "retryable": bool(error.get("retryable", False)),
                           "details": _safe_nested(error.get("details", {}), forbidden)}
    return {"schema_version": "1.0", "job_id": value["job_id"], "command_id": value["command_id"], "state": value["state"],
            "created_at": value["created_at"], "updated_at": value["updated_at"],
            "progress": _safe_nested(value.get("progress", {}), forbidden), "result": _safe_nested(result, forbidden), "error": projected_error}


def _project_export_summary(value: Any, forbidden: tuple[str | None, ...]) -> dict[str, Any]:
    fields = ("run_id", "status", "dataset_sha256", "accepted_records", "review_records", "completed_at")
    if not isinstance(value, dict) or set(value) - set(fields) or not isinstance(value.get("run_id"), str) or not isinstance(value.get("status"), str):
        raise ValueError
    return {key: _safe_nested(value.get(key), forbidden) for key in fields}


def _project_export(value: Any, forbidden: tuple[str | None, ...]) -> dict[str, Any]:
    result = _project_export_summary(value, forbidden)
    if not isinstance(value, dict) or set(value) - set(result) - {"dataset", "manifest"} or not isinstance(value.get("dataset", []), list) or not isinstance(value.get("manifest", {}), dict):
        raise ValueError
    result["dataset"] = [_project_dataset_item(item, forbidden) for item in value.get("dataset", [])]
    result["manifest"] = _project_manifest(value.get("manifest", {}), forbidden)
    return result


def _project_dataset_item(value: Any, forbidden: tuple[str | None, ...]) -> dict[str, Any]:
    fields = ("schema_version", "record_id", "source_item_id", "source", "source_type", "category", "title", "link", "content", "summary", "published", "updated_at", "author", "tags", "language", "collected_at", "content_hash", "classification", "metadata")
    if not isinstance(value, dict) or set(value) - set(fields) or any(field not in value for field in fields):
        raise ValueError
    classification = value["classification"]
    if not isinstance(classification, dict) or set(classification) - {"status", "label", "score", "model_version"}:
        raise ValueError
    return {field: (_safe_nested(classification, forbidden) if field == "classification" else _safe_nested(value[field], forbidden)) for field in fields}


def _project_manifest(value: dict[str, Any], forbidden: tuple[str | None, ...]) -> dict[str, Any]:
    fields = ("schema_version", "producer", "run_id", "started_at", "completed_at", "status", "dataset_file", "dataset_sha256", "total_records", "accepted_records", "review_records", "invalid_records", "duplicates_removed", "sources", "failed_sources", "classifier_model_version", "classifier_model_sha256")
    if set(value) - set(fields) or any(field not in value for field in fields):
        raise ValueError
    return {field: _safe_nested(value[field], forbidden) for field in fields}


def _project_review(value: Any, forbidden: tuple[str | None, ...]) -> dict[str, Any]:
    fields = ("record_id", "canonical_url", "title", "source_type", "review_reason", "review_reasons", "stage_status", "classification_label", "privacy_status", "collected_at", "published")
    if not isinstance(value, dict) or set(value) - set(fields) or not isinstance(value.get("record_id"), str) or not isinstance(value.get("review_reason"), str):
        raise ValueError
    return {field: _safe_nested(value.get(field), forbidden) for field in fields}


def _safe_nested(value: Any, forbidden: tuple[str | None, ...]) -> Any:
    if isinstance(value, dict):
        return {str(key): _safe_nested(item, forbidden) for key, item in value.items()
                if not any(part in str(key).lower() for part in SENSITIVE_KEY_PARTS)}
    if isinstance(value, list):
        return [_safe_nested(item, forbidden) for item in value]
    if isinstance(value, str):
        sanitized = ONION_VALUE.sub("[redacted-onion]", value)
        for secret in forbidden:
            if secret:
                sanitized = sanitized.replace(secret, "[redacted-secret]")
        return sanitized
    if value is None or isinstance(value, (bool, int, float)):
        return value
    raise ValueError


def _sanitize_external(value: Any, forbidden: tuple[str | None, ...] = ()) -> Any:
    if isinstance(value, dict):
        return {str(key): _sanitize_external(item, forbidden) for key, item in value.items()
                if not any(part in str(key).lower() for part in SENSITIVE_KEY_PARTS)}
    if isinstance(value, list):
        return [_sanitize_external(item, forbidden) for item in value]
    if isinstance(value, str):
        sanitized = ONION_VALUE.sub("[redacted-onion]", value)
        for secret in forbidden:
            if secret:
                sanitized = sanitized.replace(secret, "[redacted-secret]")
        return sanitized
    return value


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _authorize(header: str | None, expected: str) -> None:
    if not header or not header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="bearer authentication required")
    if not hmac.compare_digest(header[7:].strip(), expected):
        raise HTTPException(status_code=401, detail="authentication failed")


def _normalize_publish(payload: Any, settings: GatewaySettings) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise HTTPException(status_code=422, detail="publish payload must be an object")
    values = payload.get("items") if isinstance(payload.get("items"), list) else payload.get("dataset")
    if not isinstance(values, list):
        raise HTTPException(status_code=422, detail="publish payload must contain items or dataset")
    if len(values) > settings.max_feed_items:
        raise HTTPException(status_code=413, detail="feed contains too many items")
    items = [_normalize_external_item(value, index) for index, value in enumerate(values)]
    generated_at = str(payload.get("generated_at") or payload.get("completed_at") or utc_now())
    _validate_timestamp(generated_at)
    return {
        "schema_version": "1.0",
        "feed_id": settings.feed_id,
        "generated_at": generated_at,
        "items": items,
    }


def _normalize_external_item(value: Any, index: int) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise HTTPException(status_code=422, detail=f"item {index} must be an object")
    external_id = value.get("external_id") or value.get("record_id") or value.get("source_item_id") or value.get("id")
    title, content, summary = value.get("title"), value.get("content"), value.get("summary")
    if not external_id or not any(str(item or "").strip() for item in (title, content, summary)):
        raise HTTPException(status_code=422, detail=f"item {index} lacks stable identity or content")
    return {
        "external_id": str(external_id),
        "source": str(value.get("source") or "external-team"),
        "source_type": str(value.get("source_type") or "api"),
        "title": str(title or ""),
        "content": str(content or ""),
        "summary": str(summary or "") or None,
        "url": str(value.get("url") or value.get("link") or "") or None,
        "published_at": value.get("published_at") or value.get("published"),
        "collected_at": value.get("collected_at"),
        "category": value.get("category"),
        "tags": list(value.get("tags") or []),
        "metadata": _sanitize(value.get("metadata") or {}),
    }


def _sanitize(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): _sanitize(item)
            for key, item in value.items()
            if not any(part in str(key).lower() for part in SENSITIVE_KEY_PARTS)
        }
    if isinstance(value, list):
        return [_sanitize(item) for item in value]
    return value


def _load_sensor_events(path: Path, max_bytes: int, stream_name: str) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    candidates = sorted(path.glob("*.json*")) if path.is_dir() else [path]
    total = 0
    events: list[dict[str, Any]] = []
    for candidate in candidates:
        if not candidate.is_file():
            continue
        total += candidate.stat().st_size
        if total > max_bytes:
            raise HTTPException(status_code=413, detail="sensor evidence exceeds configured limit")
        text = candidate.read_text(encoding="utf-8", errors="replace")
        parsed = _parse_json_records(text)
        for item in parsed:
            normalized = dict(item)
            normalized.setdefault("id", _event_id(stream_name, normalized))
            events.append(normalized)
    return events


def _parse_json_records(text: str) -> list[dict[str, Any]]:
    stripped = text.strip()
    if not stripped:
        return []
    try:
        value = json.loads(stripped)
    except json.JSONDecodeError:
        result = []
        for line in text.splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                result.append(item)
        return result
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        for key in ("events", "items", "data", "results"):
            if isinstance(value.get(key), list):
                return [item for item in value[key] if isinstance(item, dict)]
        return [value]
    return []


def _append_web_event(settings: GatewaySettings, lock: threading.Lock, request: Request, code: int, started: float) -> None:
    source_ip = request.client.host if request.client else "unknown"
    failure = code >= 400
    level = 7 if code in {401, 403} else 5 if code >= 500 else 3 if code == 404 else 1
    event = {
        "id": f"web:{hashlib.sha256(f'{utc_now()}:{source_ip}:{request.method}:{request.url.path}:{code}'.encode()).hexdigest()[:24]}",
        "timestamp": utc_now(),
        "event": {"category": "web", "action": "http_request", "outcome": "failure" if failure else "success"},
        "source": {"ip": source_ip},
        "http": {"request": {"method": request.method}, "response": {"status_code": code}},
        "url": {"original": request.url.path},
        "rule": {"id": f"gateway_http_{code}", "level": level},
        "message": f"{request.method} {request.url.path} returned HTTP {code}",
        "duration_ms": round((time.perf_counter() - started) * 1000, 3),
    }
    encoded = _json_bytes(event)
    with lock:
        _web_path(settings).parent.mkdir(parents=True, exist_ok=True)
        with _web_path(settings).open("ab") as handle:
            handle.write(encoded)


def _signed_json(payload: dict[str, Any], secret: str, headers: dict[str, str] | None = None) -> Response:
    body = _json_bytes(payload).rstrip(b"\n")
    signature = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    response_headers = {"X-CTI-Signature": f"sha256={signature}", **(headers or {})}
    return Response(content=body, media_type="application/json", headers=response_headers)


def _encode_cursor(offset: int, scope: str, secret: str) -> str:
    value = f"{scope}:{max(0, offset)}"
    signature = hmac.new(secret.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()[:24]
    return base64.urlsafe_b64encode(f"{value}:{signature}".encode()).decode("ascii").rstrip("=")


def _decode_cursor(cursor: str, scope: str, secret: str) -> int:
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
        found_scope, offset_text, supplied = raw.rsplit(":", 2)
        value = f"{found_scope}:{offset_text}"
        expected = hmac.new(secret.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()[:24]
        if found_scope != scope or not hmac.compare_digest(supplied, expected):
            raise ValueError
        offset = int(offset_text)
        if offset < 0:
            raise ValueError
        return offset
    except (ValueError, UnicodeError, binascii.Error) as exc:
        raise HTTPException(status_code=422, detail="cursor is invalid") from exc


def _event_id(stream_name: str, value: dict[str, Any]) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return f"{stream_name}:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()[:24]}"


def _stream_path(settings: GatewaySettings, stream_name: str) -> Path:
    if stream_name == "dionaea":
        return settings.dionaea_path
    if stream_name == "host-auth":
        return settings.host_auth_path
    return _web_path(settings)


def _safe_is_file(path: Path) -> bool:
    try:
        return path.is_file()
    except OSError:
        return False


def _feed_path(settings: GatewaySettings) -> Path:
    return settings.data_dir / "external_feed.json"


def _web_path(settings: GatewaySettings) -> Path:
    return settings.data_dir / "web_access.jsonl"


def _bounded_read(path: Path, limit: int) -> bytes:
    if path.stat().st_size > limit:
        raise HTTPException(status_code=413, detail="stored object exceeds configured limit")
    return path.read_bytes()


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(data)
    os.replace(temporary, path)


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")


def _validate_timestamp(value: str) -> None:
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="generated_at must be ISO-8601") from exc


def _safe_int(value: str, default: int) -> int:
    try:
        return int(value)
    except ValueError:
        return default


app = create_app(GatewaySettings.from_env())
