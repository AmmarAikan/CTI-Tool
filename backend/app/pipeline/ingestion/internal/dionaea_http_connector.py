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
from backend.app.pipeline.ingestion.internal.base_internal_connector import (
    InternalConnector,
)
from backend.app.pipeline.ingestion.internal.dionaea_connector import (
    DionaeaFileConnector,
)


class DionaeaAPIContractError(ValueError):
    """Raised when the remote sensor API violates the JSON exchange contract."""


@dataclass(slots=True)
class DionaeaAPIResult:
    records: list[RawRecord] = field(default_factory=list)
    pages: int = 0
    sensor_id: str | None = None
    generated_at: str | None = None
    checkpoint: str | None = None
    response_bytes: int = 0
    duplicate_events: int = 0
    transport: str = "dionaea_https_json_api"

    def details(self) -> dict[str, Any]:
        return {
            "transport": self.transport,
            "sensor_id": self.sensor_id,
            "generated_at": self.generated_at,
            "pages": self.pages,
            "response_bytes": self.response_bytes,
            "duplicate_events": self.duplicate_events,
        }


class DionaeaAPIConnector(InternalConnector):
    SIGNATURE_HEADER = "X-CTI-Signature"

    def __init__(
        self,
        url: str,
        token: str,
        *,
        source_name: str = "Dionaea VPS",
        hmac_secret: str | None = None,
        verify_tls: bool = True,
        allow_http: bool = False,
        timeout: int = 30,
        max_bytes: int = 20 * 1024 * 1024,
        max_pages: int = 20,
        page_size: int = 500,
        checkpoint: str | None = None,
        session: requests.Session | None = None,
    ) -> None:
        self.url = url.strip()
        self.token = token
        self.source_name = source_name
        self.hmac_secret = hmac_secret
        self.verify_tls = verify_tls
        self.timeout = max(1, timeout)
        self.max_bytes = max(1024, max_bytes)
        self.max_pages = max(1, min(max_pages, 100))
        self.page_size = max(1, min(page_size, 1000))
        self.checkpoint = checkpoint
        self.session = session or self._session()
        self.last_result: DionaeaAPIResult | None = None
        self._validate_url(allow_http)

    def collect(self):
        self.last_result = self.fetch()
        yield from self.last_result.records

    def fetch(self) -> DionaeaAPIResult:
        result = DionaeaAPIResult(transport=self._transport_name())
        cursor = self.checkpoint
        seen_cursors: set[str] = set()
        seen_ids: set[str] = set()
        normalizer = self._normalizer()

        for page_number in range(1, self.max_pages + 1):
            response = self.session.get(
                self.url,
                headers=self._headers(),
                params={"limit": self.page_size, **({"cursor": cursor} if cursor else {})},
                timeout=self.timeout,
                verify=self.verify_tls,
            )
            response.raise_for_status()
            body = self._response_body(response)
            result.response_bytes += len(body)
            if result.response_bytes > self.max_bytes:
                raise DionaeaAPIContractError("Paginated Dionaea response exceeds configured bytes")
            self._verify_signature(body, response.headers.get(self.SIGNATURE_HEADER))
            envelope = self._validate_envelope(self._parse(body))

            if result.sensor_id and result.sensor_id != envelope["sensor_id"]:
                raise DionaeaAPIContractError("sensor_id changed between pages")
            for event in envelope["events"]:
                record = normalizer.normalize_item(event, Path("dionaea-remote.json"))
                if record.external_id in seen_ids:
                    result.duplicate_events += 1
                    continue
                seen_ids.add(record.external_id)
                result.records.append(record)

            result.pages = page_number
            result.sensor_id = envelope["sensor_id"]
            result.generated_at = envelope["generated_at"]
            result.checkpoint = envelope.get("checkpoint") or result.checkpoint
            if not envelope["has_more"]:
                return result
            next_cursor = envelope.get("next_cursor")
            if not next_cursor or next_cursor in seen_cursors:
                raise DionaeaAPIContractError(
                    "has_more=true requires a new non-empty next_cursor"
                )
            seen_cursors.add(next_cursor)
            cursor = next_cursor

        raise DionaeaAPIContractError(
            f"Dionaea API exceeded DIONAEA_API_MAX_PAGES={self.max_pages}"
        )

    def healthcheck(self) -> dict[str, Any]:
        try:
            response = self.session.get(
                self.url,
                headers=self._headers(),
                params={"limit": 1},
                timeout=self.timeout,
                verify=self.verify_tls,
            )
            response.raise_for_status()
            body = self._response_body(response)
            self._verify_signature(body, response.headers.get(self.SIGNATURE_HEADER))
            self._validate_envelope(self._parse(body))
            return {
                "configured": True,
                "reachable": True,
                "contract_valid": True,
                "hmac_verification": bool(self.hmac_secret),
            }
        except (requests.RequestException, ValueError, TypeError) as exc:
            return {
                "configured": True,
                "reachable": False,
                "error_type": type(exc).__name__,
            }

    def _response_body(self, response: requests.Response) -> bytes:
        content_length = response.headers.get("Content-Length")
        if content_length:
            try:
                if int(content_length) > self.max_bytes:
                    raise DionaeaAPIContractError("Dionaea response exceeds configured bytes")
            except ValueError:
                raise DionaeaAPIContractError("Invalid Dionaea Content-Length") from None
        if len(response.content) > self.max_bytes:
            raise DionaeaAPIContractError("Dionaea response exceeds configured bytes")
        content_type = response.headers.get("Content-Type", "").lower()
        if content_type and "json" not in content_type:
            raise DionaeaAPIContractError("Dionaea API must return application/json")
        return response.content

    def _verify_signature(self, body: bytes, signature: str | None) -> None:
        if not self.hmac_secret:
            return
        if not signature:
            raise DionaeaAPIContractError(f"Missing {self.SIGNATURE_HEADER}")
        supplied = signature.removeprefix("sha256=").strip().lower()
        expected = hmac.new(
            self.hmac_secret.encode("utf-8"),
            body,
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(supplied, expected):
            raise DionaeaAPIContractError("Dionaea API HMAC signature is invalid")

    @staticmethod
    def _parse(body: bytes) -> Any:
        try:
            return json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DionaeaAPIContractError("Dionaea API body is not valid UTF-8 JSON") from exc

    @staticmethod
    def _validate_envelope(payload: Any) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise DionaeaAPIContractError("Dionaea API must return a JSON object")
        missing = [
            name
            for name in ("schema_version", "sensor_id", "generated_at", "events")
            if name not in payload
        ]
        if missing:
            raise DionaeaAPIContractError(f"Dionaea API is missing: {', '.join(missing)}")
        if not str(payload["schema_version"]).startswith("1."):
            raise DionaeaAPIContractError("Unsupported Dionaea API schema_version")
        sensor_id = str(payload["sensor_id"]).strip()
        if not sensor_id or len(sensor_id) > 200:
            raise DionaeaAPIContractError("sensor_id must contain 1-200 characters")
        generated_at = str(payload["generated_at"]).strip()
        try:
            datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise DionaeaAPIContractError("generated_at must be ISO-8601") from exc
        events = payload["events"]
        if not isinstance(events, list) or not all(isinstance(item, dict) for item in events):
            raise DionaeaAPIContractError("events must be an array of JSON objects")
        return {
            "sensor_id": sensor_id,
            "generated_at": generated_at,
            "events": events,
            "has_more": bool(payload.get("has_more", False)),
            "next_cursor": str(payload["next_cursor"]) if payload.get("next_cursor") else None,
            "checkpoint": str(payload["checkpoint"]) if payload.get("checkpoint") else None,
        }

    def _headers(self) -> dict[str, str]:
        return {
            "Accept": "application/json",
            "Authorization": f"Bearer {self.token}",
            "User-Agent": "graduation-cti-backend/2.0",
        }

    def _normalizer(self):
        return DionaeaFileConnector([], source_name=self.source_name)

    @staticmethod
    def _transport_name() -> str:
        return "dionaea_https_json_api"

    def _validate_url(self, allow_http: bool) -> None:
        parsed = urlparse(self.url)
        if parsed.scheme not in {"https", "http"} or not parsed.hostname:
            raise ValueError("DIONAEA_API_URL must be an absolute HTTP(S) URL")
        if parsed.scheme != "https" and not allow_http:
            raise ValueError("DIONAEA_API_URL must use HTTPS unless DIONAEA_API_ALLOW_HTTP=true")
        if parsed.username or parsed.password:
            raise ValueError("Credentials must not be embedded in DIONAEA_API_URL")

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
