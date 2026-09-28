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
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import Body, FastAPI, Header, HTTPException, Query, Request, Response, status
from starlette.middleware.gzip import GZipMiddleware
from starlette.requests import Request as StarletteRequest

SENSITIVE_KEY_PARTS = ("authorization", "cookie", "password", "secret", "token", "api_key", "apikey")
STREAM_NAMES = frozenset({"dionaea", "host-auth", "web-access"})
WEB_BASE_KEY = "_gateway_web_base_offset"
WEB_LOG_RESERVATION_BYTES = 16 * 1024
WEB_PAGE_MAX_BYTES = 8 * 1024 * 1024
JSON_WRITE_BUFFER_BYTES = 1024 * 1024
FEED_DELIVERY_STATE_VERSION = "1.0"
FEED_BATCH_STATE_VERSION = "2.0"
FEED_ACK_SIGNATURE_HEADER = "X-CTI-Ack-Signature"
FEED_PAGE_MAX_BYTES = 8 * 1024 * 1024


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
    max_web_log_bytes: int = 64 * 1024 * 1024
    dionaea_enabled: bool = True
    dionaea_container_running: bool = False

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
            max_web_log_bytes=int(os.getenv("MAX_WEB_LOG_BYTES", str(64 * 1024 * 1024))),
            dionaea_enabled=os.getenv("DIONAEA_ENABLED", "true").strip().lower()
            not in {"0", "false", "no", "off"},
            dionaea_container_running=os.getenv("DIONAEA_CONTAINER_RUNNING", "false").strip().lower()
            in {"1", "true", "yes", "on"},
        )


class WebAccessLogMiddleware:
    """Pure-ASGI access logger; avoids BaseHTTPMiddleware response buffering."""
    def __init__(self, app, *, settings: GatewaySettings, lock: threading.Lock) -> None:
        self.app, self.settings, self.lock = app, settings, lock
        self.reserved_bytes = 0

    async def __call__(self, scope, receive, send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        request = StarletteRequest(scope)
        started = time.perf_counter()
        loggable = request.url.path not in {
            "/health", "/api/v1/sensors/web-access", "/api/v1/sensors/dionaea",
            "/api/v1/sensors/host-auth", "/api/v1/external-feed",
            "/api/v1/external-feed/publish", "/api/v1/external-feed/ack",
        }
        if not loggable:
            await self.app(scope, receive, send)
            return
        with self.lock:
            path = _web_path(self.settings)
            size = path.stat().st_size if path.exists() else 0
            if size + self.reserved_bytes + WEB_LOG_RESERVATION_BYTES > self.settings.max_web_log_bytes:
                response = Response(status_code=503, headers={"Retry-After": "60"})
                await response(scope, receive, send)
                return
            self.reserved_bytes += WEB_LOG_RESERVATION_BYTES
        status_code = 500

        async def capture(message):
            nonlocal status_code
            if message.get("type") == "http.response.start":
                status_code = int(message.get("status") or 500)
            await send(message)

        try:
            await self.app(scope, receive, capture)
        finally:
            try:
                _append_web_event(self.settings, self.lock, request, status_code, started)
            finally:
                with self.lock:
                    self.reserved_bytes -= WEB_LOG_RESERVATION_BYTES


def create_app(settings: GatewaySettings) -> FastAPI:
    app = FastAPI(title="CTI VPS Gateway", version="1.0.0", docs_url=None, redoc_url=None)
    write_lock = threading.Lock()
    app.add_middleware(GZipMiddleware, minimum_size=1024, compresslevel=5)
    app.add_middleware(WebAccessLogMiddleware, settings=settings, lock=write_lock)
    app.state.settings = settings
    app.state.write_lock = write_lock
    app.state.web_reserved_bytes = 0
    app.state.feed_cache = {}

    @app.get("/health")
    async def health() -> dict[str, Any]:
        dionaea_state = _dionaea_state(settings)
        return {
            "status": "ok",
            "service": "cti-vps-gateway",
            "feed_ready": (_feed_path(settings).is_file()
                           or _feed_delivery_state_path(settings).is_file()),
            "dionaea_state": dionaea_state,
            "streams": {
                "dionaea": dionaea_state == "available",
                "host-auth": _safe_is_file(settings.host_auth_path),
                "web-access": _safe_is_file(_web_path(settings)),
            },
        }

    @app.post("/api/v1/external-feed/publish", status_code=status.HTTP_202_ACCEPTED)
    async def publish_external_feed(payload: Any = Body(...),
                                    authorization: str | None = Header(default=None),
                                    content_length: str | None = Header(default=None, alias="Content-Length")):
        _authorize(authorization, settings.feed_publish_token)
        if content_length and _safe_int(content_length, settings.max_publish_bytes + 1) > settings.max_publish_bytes:
            raise HTTPException(status_code=413, detail="publish body exceeds configured limit")
        incoming = _normalize_publish(payload, settings)
        identity = _identity(incoming)
        with app.state.write_lock:
            if all(value is None for value in identity):
                envelope, merge_counts, pending = _merge_feed_snapshot(
                    _feed_path(settings), incoming, settings)
                digest, byte_count = _atomic_write_json(
                    _feed_path(settings), envelope, settings.max_feed_snapshot_bytes)
                _write_feed_delivery_state(settings, digest, pending, last_publish=merge_counts)
                item_count, published_count = len(envelope["items"]), len(incoming["items"])
            elif None in identity:
                raise HTTPException(status_code=422, detail="complete export identity is required")
            else:
                digest, byte_count, created = _publish_batch(settings, incoming)
                merge_counts = {"inserted_items": len(incoming["items"]) if created else 0,
                                "updated_items": 0,
                                "unchanged_items": 0 if created else len(incoming["items"])}
                item_count = published_count = len(incoming["items"])
            app.state.feed_cache[digest] = envelope if all(value is None for value in identity) else incoming
        return {
            "status": "accepted",
            "feed_id": settings.feed_id,
            "item_count": item_count,
            "published_items": published_count,
            "stored_bytes": byte_count,
            **merge_counts,
            "etag": digest,
        }

    @app.post("/api/v1/external-feed/ack")
    async def acknowledge_external_feed(
        request: Request,
        authorization: str | None = Header(default=None),
        ack_signature: str | None = Header(default=None, alias=FEED_ACK_SIGNATURE_HEADER),
    ):
        _authorize(authorization, settings.feed_read_token)
        length = request.headers.get("content-length")
        if length and _safe_int(length, settings.max_publish_bytes + 1) > settings.max_publish_bytes:
            raise HTTPException(status_code=413, detail="ack body exceeds configured limit")
        body = await request.body()
        if len(body) > settings.max_publish_bytes:
            raise HTTPException(status_code=413, detail="ack body exceeds configured limit")
        expected_signature = hmac.new(
            settings.feed_hmac_secret.encode("utf-8"), body, hashlib.sha256
        ).hexdigest()
        supplied_signature = str(ack_signature or "").removeprefix("sha256=").strip().lower()
        if not supplied_signature or not hmac.compare_digest(supplied_signature, expected_signature):
            raise HTTPException(status_code=401, detail="external feed acknowledgement failed")
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HTTPException(status_code=422, detail="ack body must be UTF-8 JSON") from exc
        if not isinstance(payload, dict):
            raise HTTPException(status_code=422, detail="ack body must be an object")
        checkpoint = str(payload.get("checkpoint") or "").strip().strip('"')
        if len(checkpoint) != 64 or any(character not in "0123456789abcdef" for character in checkpoint):
            raise HTTPException(status_code=422, detail="ack checkpoint must be a SHA-256 digest")
        external_ids_value = payload.get("external_ids")
        if external_ids_value is not None and not isinstance(external_ids_value, list):
            raise HTTPException(status_code=422, detail="ack external_ids must be an array")
        with app.state.write_lock:
            supplied = (payload.get("external_job_id"), payload.get("export_run_id"),
                        str(payload.get("dataset_sha256") or "").removeprefix("sha256:") or None)
            if any(supplied) and not all(supplied):
                raise HTTPException(status_code=422, detail="complete export identity is required")
            result = (_acknowledge_batch(settings, supplied, checkpoint, external_ids_value)
                      if all(supplied) else
                      _acknowledge_feed_delivery(settings, checkpoint, external_ids_value))
        return _signed_json(result, settings.feed_hmac_secret)

    @app.get("/api/v1/external-feed")
    async def external_feed(
        authorization: str | None = Header(default=None),
        if_none_match: str | None = Header(default=None, alias="If-None-Match"),
        limit: int = Query(250, ge=1, le=1000),
        cursor: str | None = None,
        external_job_id: str | None = None,
        export_run_id: str | None = None,
        dataset_sha256: str | None = None,
    ):
        _authorize(authorization, settings.feed_read_token)
        supplied = (external_job_id, export_run_id,
                    str(dataset_sha256 or "").removeprefix("sha256:") or None)
        if any(supplied) and not all(supplied):
            raise HTTPException(status_code=422, detail="complete export identity is required")
        path = _batch_for_identity(settings, supplied) if all(supplied) else _feed_path(settings)
        if not path.is_file():
            raise HTTPException(status_code=404, detail="external export was not found")
        etag = _known_feed_checkpoint(settings, path) or _sha256_file(path)
        quoted_etag = f'"{etag}"'
        if cursor is None and if_none_match and if_none_match.strip() in {etag, quoted_etag}:
            return Response(status_code=304, headers={"ETag": quoted_etag})
        payload = app.state.feed_cache.get(etag)
        if payload is None:
            payload = _bounded_json_load(path, settings.max_feed_snapshot_bytes)
            if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
                raise HTTPException(status_code=500, detail="stored external feed contract is invalid")
            app.state.feed_cache = {etag: payload}
        actual_identity = _identity(payload)
        if all(supplied) and actual_identity != supplied:
            raise HTTPException(status_code=409, detail="stored export identity changed")
        cursor_scope = _cursor_scope(actual_identity, etag)
        start = _decode_cursor(cursor, cursor_scope, settings.cursor_secret) if cursor else 0
        items = payload["items"]
        page = items[start : start + limit]
        end = start + len(page)
        has_more = end < len(items)
        response_payload = {
            "schema_version": "1.0",
            "feed_id": payload["feed_id"],
            "generated_at": payload["generated_at"],
            "external_job_id": payload.get("external_job_id"),
            "export_run_id": payload.get("export_run_id"),
            "dataset_sha256": payload.get("dataset_sha256"),
            "items": page,
            "has_more": has_more,
            "next_cursor": _encode_cursor(end, cursor_scope, settings.cursor_secret) if has_more else None,
            "checkpoint": etag,
        }
        if len(_json_bytes(response_payload)) > FEED_PAGE_MAX_BYTES:
            raise HTTPException(status_code=413, detail="external feed page exceeds response limit")
        return _signed_json(response_payload, settings.feed_hmac_secret, {"ETag": quoted_etag})

    @app.get("/api/v1/sensors/{stream_name}")
    async def sensor_stream(
        stream_name: str,
        authorization: str | None = Header(default=None),
        limit: int = Query(500, ge=1, le=1000),
        cursor: str | None = None,
        ack_cursor: str | None = Header(default=None, alias="X-CTI-Ack-Cursor"),
        ack_signature: str | None = Header(default=None, alias="X-CTI-Ack-Signature"),
    ):
        _authorize(authorization, settings.sensor_read_token)
        if stream_name not in STREAM_NAMES:
            raise HTTPException(status_code=404, detail="sensor stream not found")
        start = _decode_cursor(cursor, stream_name, settings.cursor_secret) if cursor else 0
        if stream_name == "web-access":
            if bool(ack_cursor) != bool(ack_signature) or (ack_cursor and ack_cursor != cursor):
                raise HTTPException(status_code=422, detail="web-access acknowledgement is invalid")
            with app.state.write_lock:
                if ack_cursor:
                    expected = _web_ack_signature(ack_cursor, settings.sensor_read_token)
                    if not hmac.compare_digest(ack_signature or "", expected):
                        raise HTTPException(status_code=401, detail="web-access acknowledgement failed")
                    _compact_web_log(_web_path(settings), start)
                page, end, has_more = _web_page(_web_path(settings), start, limit)
        else:
            if ack_cursor or ack_signature:
                raise HTTPException(status_code=422, detail="sensor acknowledgement is unsupported")
            events = _load_sensor_events(_stream_path(settings, stream_name), settings.max_sensor_bytes, stream_name)
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
        if stream_name == "dionaea":
            payload["availability_state"] = _dionaea_state(settings)
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
    external_job_id = str(payload.get("external_job_id") or "")
    # Historical publishers used run_id without a complete delivery identity;
    # keep those snapshots on the isolated legacy backlog path.
    export_run_id = str(payload.get("export_run_id") or "")
    dataset_sha256 = str(payload.get("dataset_sha256") or "").removeprefix("sha256:")
    if external_job_id and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{7,199}", external_job_id):
        raise HTTPException(status_code=422, detail="external job identity is invalid")
    if export_run_id and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{7,199}", export_run_id):
        raise HTTPException(status_code=422, detail="export run identity is invalid")
    if dataset_sha256 and not re.fullmatch(r"[0-9a-f]{64}", dataset_sha256):
        raise HTTPException(status_code=422, detail="dataset digest is invalid")
    return {
        "schema_version": "1.0",
        "feed_id": settings.feed_id,
        "generated_at": generated_at,
        "external_job_id": external_job_id or None,
        "export_run_id": export_run_id or None,
        "dataset_sha256": dataset_sha256 or None,
        "items": items,
    }


def _merge_feed_snapshot(
    path: Path,
    incoming: dict[str, Any],
    settings: GatewaySettings,
) -> tuple[dict[str, Any], dict[str, int], set[str]]:
    """Merge into a bounded delivery snapshot without evicting unacknowledged records."""
    if path.is_file():
        try:
            existing = _bounded_json_load(path, settings.max_feed_snapshot_bytes)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HTTPException(status_code=500, detail="stored external feed is invalid") from exc
        if not isinstance(existing, dict) or not isinstance(existing.get("items"), list):
            raise HTTPException(status_code=500, detail="stored external feed contract is invalid")
    else:
        existing = {"items": []}
    existing_items = existing["items"]

    positions: dict[str, int] = {}
    retained = 0
    for index, item in enumerate(existing_items):
        if not isinstance(item, dict) or not str(item.get("external_id") or "").strip():
            raise HTTPException(
                status_code=500,
                detail=f"stored external feed item {index} is invalid",
            )
        external_id = str(item["external_id"])
        position = positions.get(external_id)
        if position is None:
            positions[external_id] = retained
            existing_items[retained] = item
            retained += 1
        else:
            existing_items[position] = item
    del existing_items[retained:]

    previous_count = len(existing_items)
    existing_digest = _sha256_file(path) if path.is_file() else None
    unacknowledged_ids, _ = _load_feed_delivery_state(
        settings,
        existing_digest,
        {str(item["external_id"]) for item in existing_items},
    )
    existing_identity = (existing.get("external_job_id"), existing.get("export_run_id"),
                         existing.get("dataset_sha256"))
    incoming_identity = (incoming.get("external_job_id"), incoming.get("export_run_id"),
                         incoming.get("dataset_sha256"))
    if unacknowledged_ids and incoming_identity != existing_identity:
        raise HTTPException(status_code=409,
            detail="unacknowledged feed identity must be committed before publishing another export")

    inserted = updated = unchanged = 0
    incoming_by_id: dict[str, dict[str, Any]] = {}
    for item in incoming["items"]:
        incoming_by_id[str(item["external_id"])] = item
    overlap_count = len(set(positions).intersection(incoming_by_id))
    new_count = len(set(incoming_by_id).difference(positions))
    for external_id in sorted(incoming_by_id):
        item = incoming_by_id[external_id]
        external_id = str(item["external_id"])
        position = positions.get(external_id)
        if position is None:
            inserted += 1
            positions[external_id] = len(existing_items)
            existing_items.append(item)
            unacknowledged_ids.add(external_id)
        elif existing_items[position] == item:
            unchanged += 1
        else:
            updated += 1
            existing_items[position] = item
            unacknowledged_ids.add(external_id)

    existing_items.sort(key=lambda item: str(item["external_id"]))
    existing.clear()
    existing.update(
        {
            "schema_version": "1.0",
            "feed_id": settings.feed_id,
            "generated_at": incoming["generated_at"],
            "external_job_id": incoming.get("external_job_id"),
            "export_run_id": incoming.get("export_run_id"),
            "dataset_sha256": incoming.get("dataset_sha256"),
            "items": existing_items,
        }
    )
    initial_size = _streamed_json_size(existing)
    safe_candidates = sorted(
        (item for item in existing_items if str(item["external_id"]) not in unacknowledged_ids),
        key=_retention_key,
    )
    pruned_ids: set[str] = set()
    candidate_index = 0
    current_size = initial_size
    current_count = len(existing_items)
    encoder = _canonical_json_encoder()
    while current_count > settings.max_feed_items or current_size > settings.max_feed_snapshot_bytes:
        if candidate_index >= len(safe_candidates):
            raise HTTPException(
                status_code=413,
                detail="feed capacity is exhausted by unacknowledged items",
            )
        candidate = safe_candidates[candidate_index]
        candidate_index += 1
        external_id = str(candidate["external_id"])
        pruned_ids.add(external_id)
        encoded_size = len(encoder.encode(candidate).encode("utf-8"))
        current_size -= encoded_size + (1 if current_count > 1 else 0)
        current_count -= 1
    if pruned_ids:
        existing["items"] = [
            item for item in existing_items if str(item["external_id"]) not in pruned_ids
        ]
    final_size = _streamed_json_size(existing)
    if final_size > settings.max_feed_snapshot_bytes:
        raise HTTPException(status_code=413, detail="cumulative feed exceeds configured limit")
    unacknowledged_ids.intersection_update(
        str(item["external_id"]) for item in existing["items"]
    )
    counts = {
        "previous_count": previous_count,
        "incoming_count": len(incoming["items"]),
        "overlap_count": overlap_count,
        "new_count": new_count,
        "pruned_count": len(pruned_ids),
        "final_count": len(existing["items"]),
        "inserted_items": inserted,
        "updated_items": updated,
        "unchanged_items": unchanged,
    }
    return existing, counts, unacknowledged_ids


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
    source_ip = (request.client.host if request.client else "unknown")[:128]
    method = request.method[:32]
    path_text = request.url.path[:512]
    failure = code >= 400
    level = 7 if code in {401, 403} else 5 if code >= 500 else 3 if code == 404 else 1
    event = {
        "id": f"web:{uuid.uuid4().hex}",
        "timestamp": utc_now(),
        "event": {"category": "web", "action": "http_request", "outcome": "failure" if failure else "success"},
        "source": {"ip": source_ip},
        "http": {"request": {"method": method}, "response": {"status_code": code}},
        "url": {"original": path_text},
        "rule": {"id": f"gateway_http_{code}", "level": level},
        "message": f"{method} {path_text} returned HTTP {code}",
        "duration_ms": round((time.perf_counter() - started) * 1000, 3),
    }
    encoded = _json_bytes(event)
    if len(encoded) > WEB_LOG_RESERVATION_BYTES:
        raise RuntimeError("web-access event exceeds reserved log size")
    with lock:
        path = _web_path(settings)
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists() and path.stat().st_size + len(encoded) > settings.max_web_log_bytes:
            raise HTTPException(status_code=503, detail="web-access log capacity reached")
        with path.open("ab") as handle:
            handle.write(encoded)
            handle.flush()

            os.fsync(handle.fileno())

def _web_ack_signature(cursor: str, secret: str) -> str:
    return hmac.new(secret.encode("utf-8"), f"web-access-ack:{cursor}".encode("utf-8"), hashlib.sha256).hexdigest()


def _web_file_base(handle) -> int:
    first = handle.readline()
    if not first:
        return 0
    try:
        value = json.loads(first)
    except (UnicodeDecodeError, json.JSONDecodeError):
        handle.seek(0)
        return 0
    if isinstance(value, dict) and WEB_BASE_KEY in value:
        base = value.get(WEB_BASE_KEY)
        if type(base) is not int or base < 0 or set(value) != {WEB_BASE_KEY}:
            raise HTTPException(status_code=500, detail="web-access log header is invalid")
        return base
    handle.seek(0)
    return 0


def _web_record(raw: bytes) -> dict[str, Any]:
    if len(raw) > WEB_PAGE_MAX_BYTES:
        raise HTTPException(status_code=413, detail="web-access event exceeds page limit")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=422, detail="web-access log contains malformed event") from exc
    if not isinstance(value, dict):
        raise HTTPException(status_code=422, detail="web-access log contains malformed event")
    return value


def _web_page(path: Path, start: int, limit: int) -> tuple[list[dict[str, Any]], int, bool]:
    if not path.exists():
        if start:
            raise HTTPException(status_code=409, detail="web-access cursor is outside retained log")
        return [], 0, False
    with path.open("rb") as handle:
        base = _web_file_base(handle)
        if start < base:
            raise HTTPException(status_code=409, detail="web-access cursor is outside retained log")
        index = base
        page: list[dict[str, Any]] = []
        page_bytes = 0
        for raw in handle:
            item = _web_record(raw)
            if index >= start:
                if len(page) == limit:
                    return page, start + len(page), True
                normalized = dict(item)
                normalized.setdefault("id", _event_id("web-access", normalized))
                item_bytes = len(_json_bytes(normalized))
                if item_bytes > WEB_PAGE_MAX_BYTES:
                    raise HTTPException(status_code=413, detail="web-access event exceeds page limit")
                if page and page_bytes + item_bytes > WEB_PAGE_MAX_BYTES:
                    return page, start + len(page), True
                page_bytes += item_bytes
                page.append(normalized)
            index += 1
        if start > index:
            raise HTTPException(status_code=409, detail="web-access cursor is beyond log end")
        return page, start + len(page), False


def _compact_web_log(path: Path, acknowledged: int) -> None:
    if not path.exists():
        if acknowledged:
            raise HTTPException(status_code=409, detail="web-access acknowledgement is beyond log end")
        return
    temporary = path.with_suffix(path.suffix + ".tmp")
    with path.open("rb") as source:
        base = _web_file_base(source)
        if acknowledged < base:
            raise HTTPException(status_code=409, detail="web-access acknowledgement is stale")
        if acknowledged == base:
            return
        index = base
        try:
            with temporary.open("wb") as target:
                target.write(_json_bytes({WEB_BASE_KEY: acknowledged}))
                for raw in source:
                    item = _web_record(raw)
                    if index >= acknowledged:
                        target.write(raw)
                    index += 1
                if acknowledged > index:
                    raise HTTPException(status_code=409, detail="web-access acknowledgement is beyond log end")
                target.flush()
                os.fsync(target.fileno())
            os.replace(temporary, path)
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            temporary.unlink(missing_ok=True)


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


def _dionaea_state(settings: GatewaySettings) -> str:
    if not settings.dionaea_enabled:
        return "disabled"
    if _safe_is_file(settings.dionaea_path):
        return "available"
    if settings.dionaea_container_running:
        return "running_without_docker_healthcheck"
    return "unavailable"


def _feed_path(settings: GatewaySettings) -> Path:
    return settings.data_dir / "external_feed.json"


def _feed_delivery_state_path(settings: GatewaySettings) -> Path:
    return settings.data_dir / "external_feed_delivery.json"


def _identity(payload: dict[str, Any]) -> tuple[str | None, str | None, str | None]:
    return (payload.get("external_job_id"), payload.get("export_run_id"),
            str(payload.get("dataset_sha256") or "").removeprefix("sha256:") or None)


def _batch_key(identity: tuple[str | None, str | None, str | None]) -> str:
    canonical = json.dumps(identity, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _batch_path(settings: GatewaySettings, key: str) -> Path:
    return settings.data_dir / "external_feed_batches" / f"{key}.json"


def _cursor_scope(identity: tuple[str | None, str | None, str | None], checkpoint: str) -> str:
    return f"external-feed:{_batch_key(identity)}:{checkpoint}"


def _load_batch_state(settings: GatewaySettings) -> dict[str, Any]:
    path = _feed_delivery_state_path(settings)
    if path.is_file():
        try:
            value = _bounded_json_load(path, settings.max_feed_snapshot_bytes)
            if isinstance(value, dict) and value.get("schema_version") == FEED_BATCH_STATE_VERSION \
                    and isinstance(value.get("batches"), dict):
                return value
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, HTTPException):
            pass
    # Version 1 remains on disk until the first v2 publish. It is represented as
    # a protected backlog reference; its snapshot and every protected ID remain unchanged.
    legacy = None
    if _feed_path(settings).is_file():
        checkpoint = _sha256_file(_feed_path(settings))
        protected_ids: list[str] = []
        try:
            previous = _bounded_json_load(path, settings.max_feed_snapshot_bytes) if path.is_file() else {}
            if (isinstance(previous, dict) and previous.get("schema_version") == FEED_DELIVERY_STATE_VERSION
                    and previous.get("snapshot_etag") == checkpoint
                    and isinstance(previous.get("unacknowledged_ids"), list)):
                protected_ids = sorted({str(value) for value in previous["unacknowledged_ids"]})
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, HTTPException):
            protected_ids = []
        if not protected_ids:
            try:
                snapshot = _bounded_json_load(_feed_path(settings), settings.max_feed_snapshot_bytes)
                protected_ids = sorted({str(item["external_id"]) for item in snapshot.get("items", [])})
            except (KeyError, TypeError, OSError, UnicodeDecodeError, json.JSONDecodeError, HTTPException):
                protected_ids = []
        legacy = {"path": _feed_path(settings).name, "checkpoint": checkpoint,
                  "status": "pending", "priority": "backlog",
                  "protected_ids": protected_ids, "item_count": len(protected_ids)}
    return {"schema_version": FEED_BATCH_STATE_VERSION, "batches": {}, "legacy_backlog": legacy}


def _write_batch_state(settings: GatewaySettings, state: dict[str, Any]) -> None:
    _atomic_write_json(_feed_delivery_state_path(settings), state, settings.max_feed_snapshot_bytes)


def _batch_for_identity(settings: GatewaySettings,
                        identity: tuple[str | None, str | None, str | None]) -> Path:
    state = _load_batch_state(settings)
    entry = state["batches"].get(_batch_key(identity))
    if not isinstance(entry, dict) or tuple(entry.get("identity") or ()) != identity:
        return _batch_path(settings, "missing")
    return _batch_path(settings, _batch_key(identity))


def _known_feed_checkpoint(settings: GatewaySettings, path: Path) -> str | None:
    """Resolve a durable checkpoint from the small state file without hashing a large feed."""
    state_path = _feed_delivery_state_path(settings)
    if not state_path.is_file():
        return None
    try:
        state = _bounded_json_load(state_path, settings.max_feed_snapshot_bytes)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, HTTPException):
        return None
    if not isinstance(state, dict):
        return None
    if state.get("schema_version") == FEED_DELIVERY_STATE_VERSION and path == _feed_path(settings):
        value = state.get("snapshot_etag")
        return str(value) if isinstance(value, str) else None
    if state.get("schema_version") != FEED_BATCH_STATE_VERSION:
        return None
    legacy = state.get("legacy_backlog")
    if path == _feed_path(settings) and isinstance(legacy, dict):
        value = legacy.get("checkpoint")
        return str(value) if isinstance(value, str) else None
    for entry in (state.get("batches") or {}).values():
        if isinstance(entry, dict) and path.name == entry.get("path"):
            value = entry.get("checkpoint")
            return str(value) if isinstance(value, str) else None
    return None


def _publish_batch(settings: GatewaySettings, incoming: dict[str, Any]) -> tuple[str, int, bool]:
    identity = _identity(incoming)
    key = _batch_key(identity)
    path = _batch_path(settings, key)
    state = _load_batch_state(settings)
    existing = state["batches"].get(key)
    if existing is not None:
        if tuple(existing.get("identity") or ()) != identity:
            raise HTTPException(status_code=409, detail="export identity collision")
        if str(existing.get("dataset_sha256")) != identity[2]:
            raise HTTPException(status_code=409, detail="export digest changed")
        return str(existing["checkpoint"]), int(existing["bytes"]), False
    checkpoint, byte_count = _atomic_write_json(path, incoming, settings.max_feed_snapshot_bytes)
    state["batches"][key] = {
        "identity": list(identity), "dataset_sha256": identity[2], "checkpoint": checkpoint,
        "path": path.name, "item_count": len(incoming["items"]), "bytes": byte_count,
        "status": "pending", "priority": "interactive", "created_at": utc_now(),
    }
    _write_batch_state(settings, state)
    return checkpoint, byte_count, True


def _acknowledge_batch(settings: GatewaySettings,
                       identity: tuple[str | None, str | None, str | None], checkpoint: str,
                       external_ids_value: list[Any] | None) -> dict[str, Any]:
    state = _load_batch_state(settings)
    key = _batch_key(identity)
    entry = state["batches"].get(key)
    if not isinstance(entry, dict) or tuple(entry.get("identity") or ()) != identity:
        raise HTTPException(status_code=404, detail="external export was not found")
    if not hmac.compare_digest(str(entry.get("checkpoint") or ""), checkpoint):
        raise HTTPException(status_code=409, detail="external export acknowledgement is stale")
    if external_ids_value is not None:
        snapshot = _bounded_json_load(_batch_path(settings, key), settings.max_feed_snapshot_bytes)
        existing_ids = {str(item.get("external_id") or "") for item in snapshot["items"]}
        supplied_ids = {str(value).strip() for value in external_ids_value}
        if "" in supplied_ids or not supplied_ids.issubset(existing_ids):
            raise HTTPException(status_code=422, detail="ack contains unknown identities")
        if supplied_ids != existing_ids:
            raise HTTPException(status_code=409, detail="partial batch acknowledgement is unsupported")
    newly = int(entry.get("item_count") or 0) if entry.get("status") != "acknowledged" else 0
    entry["status"] = "acknowledged"
    entry["acknowledged_at"] = utc_now()
    _write_batch_state(settings, state)
    return {"status": "acknowledged", "checkpoint": checkpoint,
            "newly_acknowledged_items": newly, "remaining_unacknowledged_items": 0}


def _canonical_json_encoder() -> json.JSONEncoder:
    return json.JSONEncoder(
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _streamed_json_size(value: Any) -> int:
    encoder = _canonical_json_encoder()
    return sum(len(chunk.encode("utf-8")) for chunk in _iter_json_chunks(value, encoder)) + 1


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _load_feed_delivery_state(
    settings: GatewaySettings,
    snapshot_etag: str | None,
    existing_ids: set[str],
) -> tuple[set[str], dict[str, Any]]:
    """Return protected IDs; missing/stale state fails closed by protecting everything."""
    state_path = _feed_delivery_state_path(settings)
    if not snapshot_etag or not state_path.is_file():
        return set(existing_ids), {}
    try:
        state = _bounded_json_load(state_path, settings.max_feed_snapshot_bytes)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, HTTPException):
        return set(existing_ids), {}
    if (
        not isinstance(state, dict)
        or state.get("schema_version") != FEED_DELIVERY_STATE_VERSION
        or state.get("snapshot_etag") != snapshot_etag
        or not isinstance(state.get("unacknowledged_ids"), list)
    ):
        return set(existing_ids), {}
    unacknowledged = {
        str(external_id)
        for external_id in state["unacknowledged_ids"]
        if str(external_id) in existing_ids
    }
    return unacknowledged, state


def _write_feed_delivery_state(
    settings: GatewaySettings,
    snapshot_etag: str,
    unacknowledged_ids: set[str],
    *,
    last_publish: dict[str, int] | None = None,
    last_ack: dict[str, Any] | None = None,
) -> None:
    state_path = _feed_delivery_state_path(settings)
    existing: dict[str, Any] = {}
    if state_path.is_file():
        try:
            value = _bounded_json_load(state_path, settings.max_feed_snapshot_bytes)
            if isinstance(value, dict):
                existing = value
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, HTTPException):
            existing = {}
    state = {
        "schema_version": FEED_DELIVERY_STATE_VERSION,
        "snapshot_etag": snapshot_etag,
        "unacknowledged_ids": sorted(unacknowledged_ids),
        "last_publish": last_publish if last_publish is not None else existing.get("last_publish"),
        "last_ack": last_ack if last_ack is not None else existing.get("last_ack"),
    }
    _atomic_write_json(state_path, state, settings.max_feed_snapshot_bytes)


def _acknowledge_feed_delivery(
    settings: GatewaySettings,
    checkpoint: str,
    external_ids_value: list[Any] | None,
) -> dict[str, Any]:
    path = _feed_path(settings)
    if not path.is_file():
        raise HTTPException(status_code=404, detail="no external feed has been published")
    snapshot_etag = _sha256_file(path)
    if not hmac.compare_digest(checkpoint, snapshot_etag):
        raise HTTPException(status_code=409, detail="external feed acknowledgement is stale")
    try:
        snapshot = _bounded_json_load(path, settings.max_feed_snapshot_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=500, detail="stored external feed is invalid") from exc
    if not isinstance(snapshot, dict) or not isinstance(snapshot.get("items"), list):
        raise HTTPException(status_code=500, detail="stored external feed contract is invalid")
    existing_ids = {str(item.get("external_id") or "") for item in snapshot["items"]}
    if "" in existing_ids:
        raise HTTPException(status_code=500, detail="stored external feed contains invalid identity")
    unacknowledged_ids, state = _load_feed_delivery_state(
        settings, snapshot_etag, existing_ids
    )
    if external_ids_value is None:
        acknowledged_ids = existing_ids
        acknowledgement_scope = "complete_snapshot"
    else:
        if len(external_ids_value) > settings.max_feed_items:
            raise HTTPException(status_code=413, detail="ack contains too many identities")
        acknowledged_ids = {str(external_id).strip() for external_id in external_ids_value}
        if "" in acknowledged_ids or not acknowledged_ids.issubset(existing_ids):
            raise HTTPException(status_code=422, detail="ack contains an unknown external identity")
        acknowledgement_scope = "verified_subset"
    previously_unacknowledged = len(unacknowledged_ids)
    unacknowledged_ids.difference_update(acknowledged_ids)
    last_ack = {
        "checkpoint": checkpoint,
        "scope": acknowledgement_scope,
        "acknowledged_at": utc_now(),
        "acknowledged_count": len(acknowledged_ids),
        "remaining_unacknowledged_count": len(unacknowledged_ids),
    }
    _write_feed_delivery_state(
        settings,
        snapshot_etag,
        unacknowledged_ids,
        last_publish=state.get("last_publish") if isinstance(state, dict) else None,
        last_ack=last_ack,
    )
    return {
        "status": "acknowledged",
        "checkpoint": checkpoint,
        "scope": acknowledgement_scope,
        "snapshot_items": len(existing_ids),
        "acknowledged_items": len(acknowledged_ids),
        "newly_acknowledged_items": previously_unacknowledged - len(unacknowledged_ids),
        "unacknowledged_items": len(unacknowledged_ids),
    }


def _retention_key(item: dict[str, Any]) -> tuple[str, str]:
    """Oldest acknowledged item is pruned first, with identity as a stable tie-breaker."""
    timestamp = str(item.get("collected_at") or item.get("published_at") or "")
    try:
        normalized = datetime.fromisoformat(timestamp.replace("Z", "+00:00")).astimezone(
            timezone.utc
        ).isoformat()
    except (ValueError, TypeError):
        normalized = ""
    return normalized, str(item["external_id"])


def _web_path(settings: GatewaySettings) -> Path:
    return settings.data_dir / "web_access.jsonl"


def _bounded_read(path: Path, limit: int) -> bytes:
    if path.stat().st_size > limit:
        raise HTTPException(status_code=413, detail="stored object exceeds configured limit")
    return path.read_bytes()


def _bounded_json_load(path: Path, limit: int) -> Any:
    if path.stat().st_size > limit:
        raise HTTPException(status_code=413, detail="stored object exceeds configured limit")
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(data)
    os.replace(temporary, path)


def _atomic_write_json(path: Path, value: Any, max_bytes: int) -> tuple[str, int]:
    """Serialize once in bounded chunks and atomically replace the destination."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    digest = hashlib.sha256()
    written = 0
    encoder = _canonical_json_encoder()
    buffer = bytearray()
    try:
        with temporary.open("wb") as handle:
            for text in _iter_json_chunks(value, encoder):
                encoded = text.encode("utf-8")
                written += len(encoded)
                if written > max_bytes:
                    raise HTTPException(
                        status_code=413,
                        detail="cumulative feed exceeds configured limit",
                    )
                buffer.extend(encoded)
                if len(buffer) >= JSON_WRITE_BUFFER_BYTES:
                    handle.write(buffer)
                    digest.update(buffer)
                    buffer.clear()
            if written + 1 > max_bytes:
                raise HTTPException(
                    status_code=413,
                    detail="cumulative feed exceeds configured limit",
                )
            buffer.extend(b"\n")
            written += 1
            handle.write(buffer)
            digest.update(buffer)
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return digest.hexdigest(), written


def _iter_json_chunks(value: Any, encoder: json.JSONEncoder) -> Iterator[str]:
    """Keep the large feed list streaming while encoding each bounded item efficiently."""
    if not (
        isinstance(value, dict)
        and isinstance(value.get("items"), list)
        and all(isinstance(key, str) for key in value)
    ):
        yield from encoder.iterencode(value)
        return
    yield "{"
    for key_index, key in enumerate(sorted(value)):
        if key_index:
            yield ","
        yield encoder.encode(key)
        yield ":"
        if key != "items":
            yield encoder.encode(value[key])
            continue
        yield "["
        for item_index, item in enumerate(value[key]):
            if item_index:
                yield ","
            yield encoder.encode(item)
        yield "]"
    yield "}"


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
