from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class ResponseTooLargeError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class HttpResponse:
    url: str
    status_code: int
    headers: dict[str, str]
    body: bytes
    not_modified: bool = False

    @property
    def etag(self) -> str | None:
        return self.headers.get("ETag") or self.headers.get("etag")

    @property
    def last_modified(self) -> str | None:
        return self.headers.get("Last-Modified") or self.headers.get("last-modified")


@dataclass(frozen=True, slots=True)
class HttpClientSettings:
    connect_timeout_seconds: float = 5.0
    read_timeout_seconds: float = 20.0
    max_response_bytes: int = 5 * 1024 * 1024
    max_redirects: int = 5
    retry_total: int = 3
    backoff_factor: float = 0.5
    user_agent: str = "CTI-Tool-External-Sources/1.0"
    retry_statuses: tuple[int, ...] = (429, 500, 502, 503, 504)


class ExternalHttpClient:
    """Bounded HTTP client foundation; URL safety policy is added in Phase 1/9."""

    def __init__(self, settings: HttpClientSettings | None = None, session: requests.Session | None = None) -> None:
        self.settings = settings or HttpClientSettings()
        self.session = session or requests.Session()
        self.session.max_redirects = self.settings.max_redirects
        retry = Retry(
            total=self.settings.retry_total,
            connect=self.settings.retry_total,
            read=self.settings.retry_total,
            status=self.settings.retry_total,
            backoff_factor=self.settings.backoff_factor,
            status_forcelist=self.settings.retry_statuses,
            allowed_methods=frozenset({"GET", "HEAD"}),
            respect_retry_after_header=True,
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def get(
        self,
        url: str,
        *,
        etag: str | None = None,
        last_modified: str | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> HttpResponse:
        request_headers = {"User-Agent": self.settings.user_agent, "Accept-Encoding": "gzip, deflate"}
        request_headers.update(headers or {})
        if etag:
            request_headers["If-None-Match"] = etag
        if last_modified:
            request_headers["If-Modified-Since"] = last_modified

        with self.session.get(
            url,
            headers=request_headers,
            timeout=(self.settings.connect_timeout_seconds, self.settings.read_timeout_seconds),
            allow_redirects=True,
            stream=True,
        ) as response:
            response_headers = {str(key): str(value) for key, value in response.headers.items()}
            if response.status_code == 304:
                return HttpResponse(str(response.url), 304, response_headers, b"", not_modified=True)
            response.raise_for_status()
            declared_length = response.headers.get("Content-Length")
            if declared_length and int(declared_length) > self.settings.max_response_bytes:
                raise ResponseTooLargeError("response exceeds configured size limit")
            chunks: list[bytes] = []
            size = 0
            for chunk in response.iter_content(chunk_size=64 * 1024):
                if not chunk:
                    continue
                size += len(chunk)
                if size > self.settings.max_response_bytes:
                    raise ResponseTooLargeError("response exceeds configured size limit")
                chunks.append(chunk)
            return HttpResponse(str(response.url), response.status_code, response_headers, b"".join(chunks))
