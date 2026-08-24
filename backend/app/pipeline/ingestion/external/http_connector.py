from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from backend.app.pipeline.common.cti_schema import RawRecord
from backend.app.pipeline.ingestion.base_connector import ExternalConnector
from backend.app.pipeline.ingestion.external.file_connector import (
    ExternalJsonFileConnector,
)


class ExternalFeedContractError(ValueError):
    """Raised when the remote feed violates the documented exchange contract."""


@dataclass(slots=True)
class ExternalFeedResult:
    records: list[RawRecord] = field(default_factory=list)
    pages: int = 0
    feed_id: str | None = None
    schema_version: str | None = None
    generated_at: str | None = None
    checkpoint: str | None = None
    etag: str | None = None
    not_modified: bool = False
    response_bytes: int = 0
    duplicate_items: int = 0

    def details(self) -> dict[str, Any]:
        return {
            "transport": "https_json_api",
            "feed_id": self.feed_id,
            "schema_version": self.schema_version,
            "generated_at": self.generated_at,
            "pages": self.pages,
            "response_bytes": self.response_bytes,
            "not_modified": self.not_modified,
            "duplicate_items": self.duplicate_items,
        }


class ExternalFeedAPIConnector(ExternalConnector):
    """Pull a paginated, authenticated JSON feed from the collaborator/VPS API."""

    SIGNATURE_HEADER = "X-CTI-Signature"

    def __init__(
        self,
        url: str,
        token: str,
        *,
        hmac_secret: str | None = None,
        verify_tls: bool = True,
        allow_http: bool = False,
        require_contract: bool = True,
        connect_timeout: int = 5,
        read_timeout: int = 60,
        max_bytes: int = 20 * 1024 * 1024,
        max_pages: int = 20,
        page_size: int = 250,
        session: requests.Session | None = None,
        if_none_match: str | None = None,
        checkpoint: str | None = None,
    ) -> None:
        self.url = url.strip()
        self.token = token
        self.hmac_secret = hmac_secret
        self.verify_tls = verify_tls
        self.require_contract = require_contract
        self.timeout = (max(1, connect_timeout), max(1, read_timeout))
        self.max_bytes = max(1024, max_bytes)
        self.max_pages = max(1, min(max_pages, 100))
        self.page_size = max(1, min(page_size, 1000))
        self.if_none_match = if_none_match
        self.checkpoint = checkpoint
        self.session = session or self._session()
        self.last_result: ExternalFeedResult | None = None
        self._validate_url(allow_http)

    def collect(self):
        self.last_result = self.fetch()
        yield from self.last_result.records

    def fetch(self) -> ExternalFeedResult:
        result = ExternalFeedResult()
        cursor = self.checkpoint
        seen_cursors: set[str] = set()
        seen_records: set[tuple[str, str]] = set()
        normalizer = ExternalJsonFileConnector([])

        for page_number in range(1, self.max_pages + 1):
            response = self._request_page(cursor, send_etag=page_number == 1)
            if response.status_code == 304:
                result.not_modified = True
                result.etag = self.if_none_match
                return result
            response.raise_for_status()
            body = self._response_body(response)
            result.response_bytes += len(body)
            if result.response_bytes > self.max_bytes:
                raise ExternalFeedContractError(
                    "Paginated remote feed exceeds EXTERNAL_FEED_MAX_BYTES"
                )
            self._verify_signature(body, response.headers.get(self.SIGNATURE_HEADER))
            payload = self._parse_payload(body)
            envelope = self._validate_envelope(payload)

            feed_id = envelope["feed_id"]
            if result.feed_id and feed_id != result.feed_id:
                raise ExternalFeedContractError("feed_id changed between pages")
            if result.schema_version and envelope["schema_version"] != result.schema_version:
                raise ExternalFeedContractError("schema_version changed between pages")
            items = envelope["items"]
            for item in items:
                normalized_item = dict(item)
                normalized_item.setdefault("source", feed_id)
                record = normalizer.normalize_item(normalized_item, Path(f"{feed_id}.json"))
                key = (record.source_name, record.external_id)
                if key in seen_records:
                    result.duplicate_items += 1
                    continue
                seen_records.add(key)
                result.records.append(record)

            result.pages = page_number
            result.feed_id = feed_id
            result.schema_version = envelope["schema_version"]
            result.generated_at = envelope["generated_at"]
            result.etag = response.headers.get("ETag") or result.etag
            result.checkpoint = envelope.get("checkpoint") or result.checkpoint

            if not envelope["has_more"]:
                return result
            next_cursor = envelope.get("next_cursor")
            if not next_cursor or next_cursor in seen_cursors:
                raise ExternalFeedContractError("has_more=true requires a new non-empty next_cursor")
            seen_cursors.add(next_cursor)
            cursor = next_cursor

        raise ExternalFeedContractError(
            f"Feed exceeded EXTERNAL_FEED_MAX_PAGES={self.max_pages}; no partial batch was stored"
        )

    def healthcheck(self) -> dict[str, Any]:
        try:
            response = self.session.get(
                self.url,
                headers=self._headers(send_etag=False),
                params={"limit": 1},
                timeout=self.timeout,
                verify=self.verify_tls,
            )
            response.raise_for_status()
            body = self._response_body(response)
            self._verify_signature(body, response.headers.get(self.SIGNATURE_HEADER))
            self._validate_envelope(self._parse_payload(body))
            return {
                "configured": True,
                "reachable": True,
                "status_code": response.status_code,
                "contract_valid": True,
                "contract_signature_required": bool(self.hmac_secret),
            }
        except (requests.RequestException, ExternalFeedContractError, ValueError) as exc:
            return {
                "configured": True,
                "reachable": False,
                "error_type": type(exc).__name__,
            }

    def _request_page(self, cursor: str | None, *, send_etag: bool) -> requests.Response:
        params: dict[str, Any] = {"limit": self.page_size}
        if cursor:
            params["cursor"] = cursor
        return self.session.get(
            self.url,
            headers=self._headers(send_etag=send_etag),
            params=params,
            timeout=self.timeout,
            verify=self.verify_tls,
        )

    def _headers(self, *, send_etag: bool) -> dict[str, str]:
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self.token}",
            "User-Agent": "graduation-cti-backend/2.0",
        }
        if send_etag and self.if_none_match:
            headers["If-None-Match"] = self.if_none_match
        return headers

    def _response_body(self, response: requests.Response) -> bytes:
        content_length = response.headers.get("Content-Length")
        if content_length:
            try:
                if int(content_length) > self.max_bytes:
                    raise ExternalFeedContractError("Remote feed exceeds EXTERNAL_FEED_MAX_BYTES")
            except ValueError:
                raise ExternalFeedContractError("Remote feed returned an invalid Content-Length") from None
        body = response.content
        if len(body) > self.max_bytes:
            raise ExternalFeedContractError("Remote feed exceeds EXTERNAL_FEED_MAX_BYTES")
        content_type = response.headers.get("Content-Type", "").lower()
        if content_type and "json" not in content_type:
            raise ExternalFeedContractError("Remote feed must return application/json")
        return body

    def _verify_signature(self, body: bytes, signature: str | None) -> None:
        if not self.hmac_secret:
            return
        if not signature:
            raise ExternalFeedContractError(f"Missing {self.SIGNATURE_HEADER} response header")
        supplied = signature.removeprefix("sha256=").strip().lower()
        expected = hmac.new(self.hmac_secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(supplied, expected):
            raise ExternalFeedContractError("Remote feed HMAC signature is invalid")

    def _parse_payload(self, body: bytes) -> Any:
        try:
            return json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ExternalFeedContractError("Remote feed body is not valid UTF-8 JSON") from exc

    def _validate_envelope(self, payload: Any) -> dict[str, Any]:
        if isinstance(payload, list) and not self.require_contract:
            return {
                "schema_version": "legacy-list",
                "feed_id": "remote-external-feed",
                "generated_at": None,
                "items": self._validate_items(payload),
                "has_more": False,
                "next_cursor": None,
                "checkpoint": None,
            }
        if not isinstance(payload, dict):
            raise ExternalFeedContractError("Remote feed must return a JSON object envelope")
        required = ("schema_version", "feed_id", "generated_at", "items")
        missing = [name for name in required if name not in payload]
        if missing:
            raise ExternalFeedContractError(f"Remote feed is missing fields: {', '.join(missing)}")
        schema_version = str(payload["schema_version"])
        if not schema_version.startswith("1."):
            raise ExternalFeedContractError(f"Unsupported external feed schema_version={schema_version}")
        feed_id = str(payload["feed_id"]).strip()
        if not feed_id or len(feed_id) > 200:
            raise ExternalFeedContractError("feed_id must contain 1-200 characters")
        generated_at = str(payload["generated_at"]).strip()
        if not generated_at:
            raise ExternalFeedContractError("generated_at must be a non-empty ISO-8601 timestamp")
        try:
            datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ExternalFeedContractError("generated_at must be a valid ISO-8601 timestamp") from exc
        return {
            "schema_version": schema_version,
            "feed_id": feed_id,
            "generated_at": generated_at,
            "items": self._validate_items(payload["items"]),
            "has_more": bool(payload.get("has_more", False)),
            "next_cursor": str(payload["next_cursor"]) if payload.get("next_cursor") else None,
            "checkpoint": str(payload["checkpoint"]) if payload.get("checkpoint") else None,
        }

    def _validate_items(self, items: Any) -> list[dict[str, Any]]:
        if not isinstance(items, list):
            raise ExternalFeedContractError("items must be a JSON array")
        validated: list[dict[str, Any]] = []
        for index, item in enumerate(items):
            if not isinstance(item, dict):
                raise ExternalFeedContractError(f"items[{index}] must be a JSON object")
            if not any(item.get(name) for name in ("external_id", "id")):
                raise ExternalFeedContractError(
                    f"items[{index}] must contain a stable external_id or id"
                )
            if not any(item.get(name) for name in ("content", "summary", "title")):
                raise ExternalFeedContractError(
                    f"items[{index}] must contain at least one of content, summary, or title"
                )
            validated.append(item)
        return validated

    def _validate_url(self, allow_http: bool) -> None:
        parsed = urlparse(self.url)
        if parsed.scheme not in {"https", "http"} or not parsed.hostname:
            raise ValueError("EXTERNAL_FEED_URL must be an absolute HTTP(S) URL")
        if parsed.scheme != "https" and not allow_http:
            raise ValueError("EXTERNAL_FEED_URL must use HTTPS unless EXTERNAL_FEED_ALLOW_HTTP=true")
        if parsed.username or parsed.password:
            raise ValueError("Credentials must not be embedded in EXTERNAL_FEED_URL")

    @staticmethod
    def _session() -> requests.Session:
        session = requests.Session()
        retry = Retry(
            total=3,
            connect=3,
            read=2,
            status=3,
            backoff_factor=0.5,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset({"GET"}),
            respect_retry_after_header=True,
        )
        session.mount("https://", HTTPAdapter(max_retries=retry))
        session.mount("http://", HTTPAdapter(max_retries=retry))
        return session
