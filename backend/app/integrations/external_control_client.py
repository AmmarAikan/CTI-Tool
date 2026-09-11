from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime
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
    JOB_STATES = frozenset({"queued", "running", "completed", "partial", "failed", "cancellation_requested", "cancelled"})
    COUNT_KEYS = frozenset({"accepted_records", "review_records", "rejected_records", "skipped_records", "error_count"})
    SOURCE_METADATA_KEYS = frozenset({"category", "method"})

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
        return [self._source_response(item) for item in payload]

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

    def list_jobs(self, *, limit: int = 50) -> dict[str, Any]:
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("External job history limit is invalid")
        payload = self._request("GET", f"/jobs?limit={limit}")
        if not isinstance(payload, dict) or set(payload) != {"schema_version", "persistence", "jobs"} \
                or payload.get("schema_version") != "1.0" or payload.get("persistence") != "process_memory" \
                or not isinstance(payload.get("jobs"), list) or len(payload["jobs"]) > limit:
            raise ExternalControlTransportError("External job history contract is invalid")
        allowed = {"schema_version", "job_id", "source_id", "state", "created_at", "updated_at", "counts", "error_code", "error_message"}
        for item in payload["jobs"]:
            if not isinstance(item, dict) or set(item) != allowed or item.get("schema_version") != "1.0" \
                    or not isinstance(item.get("job_id"), str) or item.get("state") not in {"queued", "running", "completed", "partial", "failed", "cancellation_requested", "cancelled"} \
                    or not isinstance(item.get("counts"), dict):
                raise ExternalControlTransportError("External job history contract is invalid")
        return payload

    def cancel_job(self, job_id: str) -> dict[str, Any]:
        self._validate_job_id(job_id)
        return self._job_response(self._request("POST", f"/jobs/{quote(job_id, safe='')}/cancel"))

    def list_dark_web_watches(self) -> dict[str, Any]:
        return self._dark_web_payload(self._request("GET","/dark-web/watches"), "list")
    def create_dark_web_watch(self, keyword: str) -> dict[str, Any]:
        return self._dark_web_payload(self._request("POST","/dark-web/watches",payload={"keyword":keyword}), "watch")
    def patch_dark_web_watch(self, watch_id: str, enabled: bool) -> dict[str, Any]:
        self._validate_source_id(watch_id); return self._dark_web_payload(self._request("PATCH",f"/dark-web/watches/{quote(watch_id,safe='')}",payload={"enabled":enabled}),"watch")
    def scan_dark_web_watch(self, watch_id: str, idempotency_key: str) -> dict[str, Any]:
        self._validate_source_id(watch_id); return self._job_response(self._request("POST",f"/dark-web/watches/{quote(watch_id,safe='')}/scan",idempotency_key=idempotency_key))
    def dark_web_watch_results(self, watch_id: str, limit: int, offset: int) -> dict[str, Any]:
        self._validate_source_id(watch_id); return self._dark_web_payload(self._request("GET",f"/dark-web/watches/{quote(watch_id,safe='')}/results?limit={limit}&offset={offset}"),"results")

    @classmethod
    def _dark_web_payload(cls, value: Any, kind: str) -> dict[str, Any]:
        if not isinstance(value,dict): raise ExternalControlTransportError("Dark web response contract is invalid")
        raw=str(value)
        if re.search(r"https?://|\.onion\b|(?:token|password|secret)=",raw,re.I): raise ExternalControlTransportError("Dark web response leaked restricted data")
        if kind in {"list","results"} and value.get("schema_version")!="1.0": raise ExternalControlTransportError("Dark web response contract is invalid")
        return value

    def latest_reviews(self) -> dict[str, Any]:
        payload = self._request("GET", "/reviews/latest")
        if not isinstance(payload, dict) or set(payload) != {"run_id", "records"} or not isinstance(payload.get("run_id"), str) or not isinstance(payload.get("records"), list):
            raise ExternalControlTransportError("External review contract is invalid")
        allowed = {"record_id", "canonical_url", "title", "source_type", "review_reason", "review_reasons", "stage_status", "classification_label", "privacy_status", "collected_at", "published"}
        safe_records = []
        for item in payload["records"]:
            if not isinstance(item, dict) or set(item) != allowed or not isinstance(item.get("record_id"), str) or not isinstance(item.get("review_reasons"), list):
                raise ExternalControlTransportError("External review contract is invalid")
            safe_records.append({key: item.get(key) for key in allowed if key != "canonical_url" and key != "stage_status"})
        return {"run_id": payload["run_id"], "records": safe_records}

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
        allowed = {"schema_version", "job_id", "command_id", "state", "created_at", "updated_at", "progress", "result", "error"}
        if not isinstance(payload, dict) or set(payload) != allowed or payload.get("schema_version") != "1.0":
            raise ExternalControlTransportError("External job contract is invalid")
        if (not ExternalControlClient._safe_id(payload.get("job_id"), minimum=10)
                or not ExternalControlClient._safe_id(payload.get("command_id"), minimum=10)
                or payload.get("state") not in ExternalControlClient.JOB_STATES
                or not ExternalControlClient._timestamp(payload.get("created_at"))
                or not ExternalControlClient._timestamp(payload.get("updated_at"))):
            raise ExternalControlTransportError("External job identity or state is invalid")
        progress = ExternalControlClient._counts(payload.get("progress"), "External job progress contract is invalid")
        result = ExternalControlClient._job_result(payload.get("result"))
        error = ExternalControlClient._safe_error(payload.get("error"))
        return {"schema_version": "1.0", "job_id": payload["job_id"], "command_id": payload["command_id"],
                "state": payload["state"], "created_at": payload["created_at"], "updated_at": payload["updated_at"],
                "progress": progress, "result": result, "error": error}

    @classmethod
    def _source_response(cls, payload: dict[str, Any]) -> dict[str, Any]:
        if set(payload) != {"source_id", "name", "source_type", "status", "metadata"}:
            raise ExternalControlTransportError("External source contract is invalid")
        if (not cls._safe_id(payload.get("source_id"), minimum=1)
                or not cls._safe_text(payload.get("name"), 200)
                or not cls._safe_text(payload.get("source_type"), 80)
                or payload.get("status") not in {"enabled", "disabled", "pending_review"}
                or not isinstance(payload.get("metadata"), dict)
                or not set(payload["metadata"]) <= cls.SOURCE_METADATA_KEYS):
            raise ExternalControlTransportError("External source contract is invalid")
        metadata: dict[str, Any] = {}
        for key, value in payload["metadata"].items():
            if not cls._safe_text(value, 100) or cls._unsafe_text(value):
                raise ExternalControlTransportError("External source metadata contract is invalid")
            metadata[key] = value
        return {"source_id": payload["source_id"], "name": payload["name"], "source_type": payload["source_type"],
                "status": payload["status"], "metadata": metadata}

    @classmethod
    def _job_result(cls, value: Any) -> dict[str, Any] | None:
        if value is None: return None
        if not isinstance(value, dict): raise ExternalControlTransportError("External job result contract is invalid")
        scalar_keys = {"status", "scope", "run_id", "source_id"}
        integer_keys = cls.COUNT_KEYS | {"source_count", "registered_source_count", "manual_source_count",
                                        "records_created", "records_updated"}
        boolean_keys = {"force"}
        nested_keys = {"sources", "manual_sources"}
        private_keys = {"message", "canonical_url", "job_id"}
        allowed = scalar_keys | integer_keys | boolean_keys | nested_keys | {"export"} | private_keys
        if not set(value) <= allowed: raise ExternalControlTransportError("External job result contract is invalid")
        result: dict[str, Any] = {}
        for key in scalar_keys & set(value):
            item = value[key]
            if not cls._safe_text(item, 200) or cls._unsafe_text(item):
                raise ExternalControlTransportError("External job result contract is invalid")
            result[key] = item
        for key in integer_keys & set(value):
            item = value[key]
            if type(item) is not int or item < 0: raise ExternalControlTransportError("External job result contract is invalid")
            result[key] = item
        for key in boolean_keys & set(value):
            if not isinstance(value[key], bool): raise ExternalControlTransportError("External job result contract is invalid")
            result[key] = value[key]
        for key in nested_keys & set(value): result[key] = cls._source_counts(value[key])
        if "export" in value: result["export"] = cls._export_result(value["export"])
        for key in private_keys & set(value):
            if value[key] is not None and not isinstance(value[key], str):
                raise ExternalControlTransportError("External job result contract is invalid")
        return result

    @classmethod
    def _source_counts(cls, value: Any) -> dict[str, dict[str, Any]]:
        if not isinstance(value, dict) or len(value) > 100: raise ExternalControlTransportError("External source result contract is invalid")
        projected = {}
        for source_id, summary in value.items():
            if not cls._safe_id(source_id, minimum=1) or not isinstance(summary, dict):
                raise ExternalControlTransportError("External source result contract is invalid")
            allowed = cls.COUNT_KEYS | {"status"}
            if not set(summary) <= allowed or not cls._safe_text(summary.get("status"), 40):
                raise ExternalControlTransportError("External source result contract is invalid")
            projected[source_id] = {"status": summary["status"], **cls._counts(
                {key: summary[key] for key in cls.COUNT_KEYS if key in summary}, "External source result contract is invalid")}
        return projected

    @classmethod
    def _export_result(cls, value: Any) -> dict[str, Any]:
        if not isinstance(value, dict): raise ExternalControlTransportError("External export result contract is invalid")
        private_keys = {"dataset_file", "manifest_file", "review_file"}
        allowed = {"status", "run_id", "dataset_sha256", "accepted_records", "review_records", "error", "reason"} | private_keys
        if not set(value) <= allowed: raise ExternalControlTransportError("External export result contract is invalid")
        result: dict[str, Any] = {}
        for key in {"status", "run_id", "reason"} & set(value):
            if not cls._safe_text(value[key], 200) or cls._unsafe_text(value[key]):
                raise ExternalControlTransportError("External export result contract is invalid")
            result[key] = value[key]
        if "dataset_sha256" in value:
            digest = value["dataset_sha256"]
            if digest is not None and (not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)):
                raise ExternalControlTransportError("External export result contract is invalid")
            result["dataset_sha256"] = digest
        result.update(cls._counts({key: value[key] for key in ("accepted_records", "review_records") if key in value},
                                  "External export result contract is invalid"))
        if "error" in value: result["error"] = cls._safe_error(value["error"])
        for key in private_keys & set(value):
            item = value[key]
            if not isinstance(item, str) or not item or len(item) > 255 or item != item.rsplit("/", 1)[-1]:
                raise ExternalControlTransportError("External export result contract is invalid")
        return result

    @classmethod
    def _safe_error(cls, value: Any) -> dict[str, Any] | None:
        if value is None: return None
        if not isinstance(value, dict) or not set(value) <= {"code", "message", "retryable", "details"}:
            raise ExternalControlTransportError("External job error contract is invalid")
        code, message = value.get("code"), value.get("message", "external operation failed safely")
        if not cls._safe_text(code, 100) or not cls._safe_text(message, 300) or cls._unsafe_text(message):
            raise ExternalControlTransportError("External job error contract is invalid")
        if "retryable" in value and not isinstance(value["retryable"], bool):
            raise ExternalControlTransportError("External job error contract is invalid")
        if "details" in value and value["details"] not in ({}, None):
            raise ExternalControlTransportError("External job error contract is invalid")
        return {"code": code, "message": message, "retryable": bool(value.get("retryable", False)), "details": {}}

    @classmethod
    def _counts(cls, value: Any, message: str) -> dict[str, int]:
        if not isinstance(value, dict) or not set(value) <= cls.COUNT_KEYS: raise ExternalControlTransportError(message)
        if any(type(item) is not int or item < 0 for item in value.values()): raise ExternalControlTransportError(message)
        return dict(value)

    @classmethod
    def _safe_id(cls, value: Any, *, minimum: int) -> bool:
        return isinstance(value, str) and len(value) >= minimum and bool(cls.SOURCE_ID.fullmatch(value))

    @staticmethod
    def _safe_text(value: Any, maximum: int) -> bool:
        return isinstance(value, str) and bool(value) and len(value) <= maximum

    @staticmethod
    def _unsafe_text(value: str) -> bool:
        return bool(re.search(r"https?://|\.onion\b|(?:token|password|secret|authorization|cookie|api[_-]?key)\s*[=:]|(?:^|[\\/])(?:home|etc|opt|var|tmp)[\\/]", value, re.I))

    @staticmethod
    def _timestamp(value: Any) -> bool:
        if not isinstance(value, str) or len(value) > 40 or not value.endswith("Z"): return False
        try: datetime.fromisoformat(value[:-1] + "+00:00"); return True
        except ValueError: return False

    @staticmethod
    def _preview_response(payload: Any) -> dict[str, Any]:
        nullable = {"classification_label", "classification_confidence"}
        required = {"schema_version", "preview_id", "state", "created_at", "expires_at", "display_url", "page_type",
                    "title", "excerpt", "disposition", "privacy_status", "review_reasons", "content_sha256", "counts",
                    "items_preview", "items_preview_total", "items_preview_truncated"}
        if (not isinstance(payload, dict) or not required <= set(payload) or not set(payload) <= required | nullable
                or payload.get("schema_version") != "1.0" or payload.get("state") != "pending"):
            raise ExternalControlTransportError("External preview contract is invalid")
        if not isinstance(payload.get("preview_id"), str) or not isinstance(payload.get("counts"), dict):
            raise ExternalControlTransportError("External preview contract is invalid")
        items = payload.get("items_preview")
        item_keys = {"item_index", "title", "excerpt", "page_type", "disposition", "privacy_status",
                     "review_reasons", "content_sha256"}
        if (not isinstance(items, list) or len(items) > 20 or type(payload.get("items_preview_total")) is not int
                or payload["items_preview_total"] < len(items) or not isinstance(payload.get("items_preview_truncated"), bool)
                or payload["items_preview_truncated"] != (payload["items_preview_total"] > len(items))):
            raise ExternalControlTransportError("External preview contract is invalid")
        for index, item in enumerate(items, start=1):
            if (not isinstance(item, dict) or not item_keys <= set(item)
                    or not set(item) <= item_keys | nullable | {"published"}):
                raise ExternalControlTransportError("External preview item contract is invalid")
            confidence = item.get("classification_confidence")
            label = item.get("classification_label")
            reasons = item.get("review_reasons")
            published = item.get("published")
            if (type(item.get("item_index")) is not int or item["item_index"] != index
                    or not isinstance(item.get("title"), str) or len(item["title"]) > 200
                    or not isinstance(item.get("excerpt"), str) or len(item["excerpt"]) > 300
                    or item.get("page_type") != "article"
                    or item.get("disposition") not in {"accepted", "review", "rejected"}
                    or item.get("privacy_status") not in {"reviewed", "review_required"}
                    or (label is not None and (not isinstance(label, str) or len(label) > 80))
                    or (confidence is not None and (not isinstance(confidence, (int, float)) or isinstance(confidence, bool)
                                                    or confidence < 0 or confidence > 1))
                    or not isinstance(reasons, list) or len(reasons) > 3
                    or any(reason not in {"privacy_review", "classification_review", "relevance_rejected"} for reason in reasons)
                    or not isinstance(item.get("content_sha256"), str)
                    or not re.fullmatch(r"sha256:[0-9a-f]{64}", item["content_sha256"])
                    or (published is not None and (not isinstance(published, str) or len(published) > 40 or not published.endswith("Z")))
                    or ((item["privacy_status"] == "review_required" or item["disposition"] == "rejected") and item["excerpt"])):
                raise ExternalControlTransportError("External preview item contract is invalid")
        return {key: payload.get(key) for key in required | nullable}

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
