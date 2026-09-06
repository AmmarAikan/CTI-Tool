from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class ExternalControlError(RuntimeError):
    """Base error for the private VPS External Sources control API."""


class ExternalControlTransportError(ExternalControlError):
    """Raised when the private control API is unreachable or violates its contract."""


@dataclass(slots=True)
class ExternalControlRemoteError(ExternalControlError):
    status_code: int
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code} ({self.status_code})"


class ExternalControlClient:
    """Bounded client for the loopback-only VPS External Sources adapter."""

    SOURCE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")

    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        verify_tls: bool = True,
        allow_http: bool = False,
        timeout_seconds: int = 30,
        max_response_bytes: int = 2 * 1024 * 1024,
        session: requests.Session | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.verify_tls = verify_tls
        self.timeout_seconds = max(1, timeout_seconds)
        self.max_response_bytes = max(4096, max_response_bytes)
        self.session = session or self._session()
        self._validate_url(allow_http)
        if len(self.token) < 24:
            raise ValueError("EXTERNAL_CONTROL_API_TOKEN must contain at least 24 characters")

    def healthcheck(self) -> dict[str, Any]:
        try:
            payload = self._request("GET", "/health", authenticated=False)
            if not isinstance(payload, dict) or payload.get("status") != "ok":
                raise ExternalControlTransportError("External control health contract is invalid")
            return {
                "configured": True,
                "reachable": True,
                "service": payload.get("service"),
                "api_version": payload.get("api_version"),
            }
        except ExternalControlError as exc:
            return {
                "configured": True,
                "reachable": False,
                "error_type": type(exc).__name__,
            }

    def list_sources(self) -> list[dict[str, Any]]:
        payload = self._request("GET", "/sources")
        if not isinstance(payload, list) or not all(isinstance(item, dict) for item in payload):
            raise ExternalControlTransportError("External source list contract is invalid")
        return payload

    def start_collection(
        self,
        *,
        source_ids: list[str] | None = None,
        scope: str | None = None,
        force: bool = False,
    ) -> dict[str, Any]:
        values = source_ids or []
        for source_id in values:
            self._validate_source_id(source_id)
        body: dict[str, Any] = {"source_ids": values, "force": bool(force)}
        if scope is not None:
            if scope != "all_enabled":
                raise ValueError("External collection scope must be all_enabled or null")
            body["scope"] = scope
        return self._job_response(
            self._request(
                "POST",
                "/jobs",
                payload=body,
                idempotency_key=str(uuid.uuid4()),
            )
        )

    def collect_source(self, source_id: str, *, force: bool = False) -> dict[str, Any]:
        self._validate_source_id(source_id)
        return self._job_response(
            self._request(
                "POST",
                f"/sources/{quote(source_id, safe='')}/jobs",
                payload={"force": bool(force)},
                idempotency_key=str(uuid.uuid4()),
            )
        )

    def add_manual_source(self, url: str, *, force: bool = False) -> dict[str, Any]:
        self._validate_manual_url(url)
        return self._job_response(
            self._request(
                "POST",
                "/manual-sources",
                payload={"url": url, "force": bool(force)},
                idempotency_key=str(uuid.uuid4()),
            )
        )

    def recheck_manual_source(self, url: str) -> dict[str, Any]:
        self._validate_manual_url(url)
        return self._job_response(
            self._request(
                "POST",
                "/manual-sources/recheck",
                payload={"url": url, "force": True},
                idempotency_key=str(uuid.uuid4()),
            )
        )

    def create_manual_preview(self, url: str) -> dict[str, Any]:
        self._validate_manual_url(url)
        return self._preview_response(self._request("POST", "/manual-sources/previews", payload={"url": url}))

    def approve_manual_preview(self, preview_id: str, content_sha256: str, *, idempotency_key: str) -> dict[str, Any]:
        self._validate_preview_id(preview_id); self._validate_sha256(content_sha256)
        return self._job_response(self._request("POST", f"/manual-sources/previews/{quote(preview_id, safe='')}/approve",
            payload={"expected_content_sha256": content_sha256}, idempotency_key=idempotency_key))

    def reject_manual_preview(self, preview_id: str, reason: str, *, idempotency_key: str) -> dict[str, Any]:
        self._validate_preview_id(preview_id)
        if reason not in {"not_relevant", "duplicate", "user_cancelled"}: raise ValueError("Invalid preview rejection reason")
        value = self._request("POST", f"/manual-sources/previews/{quote(preview_id, safe='')}/reject",
                              payload={"reason": reason}, idempotency_key=idempotency_key)
        if not isinstance(value, dict) or value.get("schema_version") != "1.0" or value.get("state") != "rejected":
            raise ExternalControlTransportError("External preview decision contract is invalid")
        return {key: value[key] for key in ("schema_version", "preview_id", "state", "decided_at")}

    def get_job(self, job_id: str) -> dict[str, Any]:
        self._validate_job_id(job_id)
        return self._job_response(self._request("GET", f"/jobs/{quote(job_id, safe='')}"))

    def latest_export_summary(self) -> dict[str, Any]:
        payload = self._request("GET", "/exports/latest/summary")
        if not isinstance(payload, dict):
            raise ExternalControlTransportError("External export contract is invalid")
        return {
            key: payload.get(key)
            for key in (
                "run_id",
                "status",
                "dataset_sha256",
                "accepted_records",
                "review_records",
                "completed_at",
            )
        }

    def _request(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, Any] | None = None,
        authenticated: bool = True,
        idempotency_key: str | None = None,
    ) -> Any:
        headers = {"Accept": "application/json", "User-Agent": "graduation-cti-backend/2.0"}
        if authenticated:
            headers["Authorization"] = f"Bearer {self.token}"
        if payload is not None:
            headers["Content-Type"] = "application/json"
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        try:
            response = self.session.request(
                method,
                f"{self.base_url}{path}",
                headers=headers,
                json=payload,
                timeout=self.timeout_seconds,
                verify=self.verify_tls,
            )
        except requests.RequestException as exc:
            raise ExternalControlTransportError("External control API is unreachable") from exc

        body = self._bounded_body(response)
        value = self._parse_json(body)
        if response.status_code >= 400:
            code = str(value.get("code") or "external_control_error") if isinstance(value, dict) else "external_control_error"
            message = str(value.get("message") or "External control request failed") if isinstance(value, dict) else "External control request failed"
            raise ExternalControlRemoteError(response.status_code, code[:100], message[:300])
        return value

    def _bounded_body(self, response: requests.Response) -> bytes:
        length = response.headers.get("Content-Length")
        if length:
            try:
                if int(length) > self.max_response_bytes:
                    raise ExternalControlTransportError("External control response exceeds configured bytes")
            except ValueError:
                raise ExternalControlTransportError("External control Content-Length is invalid") from None
        body = response.content
        if len(body) > self.max_response_bytes:
            raise ExternalControlTransportError("External control response exceeds configured bytes")
        content_type = response.headers.get("Content-Type", "").lower()
        if content_type and "json" not in content_type:
            raise ExternalControlTransportError("External control API must return JSON")
        return body

    @staticmethod
    def _parse_json(body: bytes) -> Any:
        try:
            return json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ExternalControlTransportError("External control API returned invalid JSON") from exc

    @staticmethod
    def _job_response(payload: Any) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise ExternalControlTransportError("External job contract is invalid")
        if not isinstance(payload.get("job_id"), str) or not isinstance(payload.get("state"), str):
            raise ExternalControlTransportError("External job identity or state is invalid")
        return payload

    @staticmethod
    def _preview_response(payload: Any) -> dict[str, Any]:
        required = {"schema_version", "preview_id", "state", "created_at", "expires_at", "display_url", "page_type",
                    "title", "excerpt", "disposition", "classification_label", "classification_confidence",
                    "privacy_status", "review_reasons", "content_sha256", "counts"}
        if not isinstance(payload, dict) or set(payload) != required or payload.get("schema_version") != "1.0" or payload.get("state") != "pending":
            raise ExternalControlTransportError("External preview contract is invalid")
        if not isinstance(payload.get("preview_id"), str) or not isinstance(payload.get("counts"), dict):
            raise ExternalControlTransportError("External preview contract is invalid")
        return {key: payload[key] for key in required}

    @classmethod
    def _validate_source_id(cls, source_id: str) -> None:
        if not cls.SOURCE_ID.fullmatch(source_id):
            raise ValueError("External source id is invalid")

    @classmethod
    def _validate_job_id(cls, job_id: str) -> None:
        if len(job_id) < 10 or not cls.SOURCE_ID.fullmatch(job_id):
            raise ValueError("External job id is invalid")

    @classmethod
    def _validate_preview_id(cls, preview_id: str) -> None:
        if len(preview_id) < 20 or not cls.SOURCE_ID.fullmatch(preview_id): raise ValueError("External preview id is invalid")

    @staticmethod
    def _validate_sha256(value: str) -> None:
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", value): raise ValueError("External preview hash is invalid")

    @staticmethod
    def _validate_manual_url(url: str) -> None:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Manual source must be an absolute HTTP(S) URL")
        if parsed.username or parsed.password:
            raise ValueError("Manual source URL must not embed credentials")

    def _validate_url(self, allow_http: bool) -> None:
        parsed = urlparse(self.base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("EXTERNAL_CONTROL_API_URL must be an absolute HTTP(S) URL")
        if parsed.scheme != "https" and not allow_http:
            raise ValueError("EXTERNAL_CONTROL_API_URL must use HTTPS unless explicitly tunneled")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("EXTERNAL_CONTROL_API_URL must not contain credentials, query, or fragment")

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
