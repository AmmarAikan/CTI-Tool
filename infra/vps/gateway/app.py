from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Query, Request, Response, status
from starlette.middleware.gzip import GZipMiddleware

SENSITIVE_KEY_PARTS = ("authorization", "cookie", "password", "secret", "token", "api_key", "apikey")
STREAM_NAMES = frozenset({"dionaea", "host-auth", "web-access"})


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
    max_feed_snapshot_bytes: int = 100 * 1024 * 1024
    max_sensor_bytes: int = 50 * 1024 * 1024
    max_feed_items: int = 20_000

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
        return cls(
            **required,
            data_dir=Path(os.getenv("GATEWAY_DATA_DIR", "/data")),
            dionaea_path=Path(os.getenv("DIONAEA_LOG_PATH", "/sensors/dionaea/dionaea.json")),
            host_auth_path=Path(os.getenv("HOST_AUTH_LOG_PATH", "/sensors/host/host_auth.jsonl")),
            feed_id=os.getenv("EXTERNAL_FEED_ID", "external-team-feed"),
            sensor_id=os.getenv("SENSOR_ID", "cti-vps"),
            max_publish_bytes=int(os.getenv("MAX_PUBLISH_BYTES", str(20 * 1024 * 1024))),
            max_feed_snapshot_bytes=int(
                os.getenv("MAX_FEED_SNAPSHOT_BYTES", str(100 * 1024 * 1024))
            ),
            max_sensor_bytes=int(os.getenv("MAX_SENSOR_BYTES", str(50 * 1024 * 1024))),
            max_feed_items=int(os.getenv("MAX_FEED_ITEMS", "20000")),
        )


def create_app(settings: GatewaySettings) -> FastAPI:
    app = FastAPI(title="CTI VPS Gateway", version="1.0.0", docs_url=None, redoc_url=None)
    app.add_middleware(GZipMiddleware, minimum_size=1024, compresslevel=5)
    app.state.settings = settings
    app.state.write_lock = threading.Lock()

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
        incoming = _normalize_publish(payload, settings)
        with app.state.write_lock:
            envelope, merge_counts = _merge_feed_snapshot(
                _feed_path(settings), incoming, settings
            )
            encoded = _json_bytes(envelope)
            digest = hashlib.sha256(encoded).hexdigest()
            _atomic_write(_feed_path(settings), encoded)
        return {
            "status": "accepted",
            "feed_id": settings.feed_id,
            "item_count": len(envelope["items"]),
            "published_items": len(incoming["items"]),
            **merge_counts,
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
        raw = _bounded_read(path, settings.max_feed_snapshot_bytes)
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


def _merge_feed_snapshot(
    path: Path,
    incoming: dict[str, Any],
    settings: GatewaySettings,
) -> tuple[dict[str, Any], dict[str, int]]:
    """Merge incremental exports into a bounded snapshot so offline consumers miss no run."""
    existing_items: list[dict[str, Any]] = []
    if path.is_file():
        try:
            existing = json.loads(
                _bounded_read(path, settings.max_feed_snapshot_bytes).decode("utf-8")
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HTTPException(status_code=500, detail="stored external feed is invalid") from exc
        if not isinstance(existing, dict) or not isinstance(existing.get("items"), list):
            raise HTTPException(status_code=500, detail="stored external feed contract is invalid")
        existing_items = existing["items"]

    merged: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(existing_items):
        if not isinstance(item, dict) or not str(item.get("external_id") or "").strip():
            raise HTTPException(
                status_code=500,
                detail=f"stored external feed item {index} is invalid",
            )
        merged[str(item["external_id"])] = item

    inserted = updated = unchanged = 0
    for item in incoming["items"]:
        external_id = str(item["external_id"])
        previous = merged.get(external_id)
        if previous is None:
            inserted += 1
        elif previous == item:
            unchanged += 1
        else:
            updated += 1
        merged[external_id] = item

    if len(merged) > settings.max_feed_items:
        raise HTTPException(status_code=413, detail="cumulative feed contains too many items")
    envelope = {
        "schema_version": "1.0",
        "feed_id": settings.feed_id,
        "generated_at": incoming["generated_at"],
        "items": [merged[key] for key in sorted(merged)],
    }
    if len(_json_bytes(envelope)) > settings.max_feed_snapshot_bytes:
        raise HTTPException(status_code=413, detail="cumulative feed exceeds configured limit")
    return envelope, {
        "inserted_items": inserted,
        "updated_items": updated,
        "unchanged_items": unchanged,
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
