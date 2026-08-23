from __future__ import annotations

from typing import Mapping
from urllib.parse import urljoin

import requests

from backend.app.pipeline.ingestion.external.common.http_client import HttpClientSettings, HttpResponse, ResponseTooLargeError
from backend.app.pipeline.ingestion.external.manual_source.url_policy import ManualURLPolicy


class SSRFProtectedHttpClient:
    """GET-only client with DNS and redirect validation for manual public URLs."""

    def __init__(self, policy: ManualURLPolicy, settings: HttpClientSettings | None = None, session: requests.Session | None = None) -> None:
        self.policy, self.settings, self.session = policy, settings or HttpClientSettings(), session or requests.Session()
        self.session.trust_env = False

    def get(self, url: str, *, etag: str | None = None, last_modified: str | None = None,
            headers: Mapping[str, str] | None = None) -> HttpResponse:
        current = self.policy.validate(url, allow_onion=False).canonical_url
        safe_headers = {"User-Agent": self.settings.user_agent, "Accept": "text/html,application/xhtml+xml,application/rss+xml,application/atom+xml",
                        "Accept-Encoding": "gzip, deflate"}
        for key, value in (headers or {}).items():
            if key.lower() not in {"authorization", "cookie", "proxy-authorization"}: safe_headers[str(key)] = str(value)
        if etag: safe_headers["If-None-Match"] = etag
        if last_modified: safe_headers["If-Modified-Since"] = last_modified
        for _ in range(self.settings.max_redirects + 1):
            current = self.policy.validate(current, allow_onion=False).canonical_url
            with self.session.get(current, headers=safe_headers,
                                  timeout=(self.settings.connect_timeout_seconds, self.settings.read_timeout_seconds),
                                  allow_redirects=False, stream=True) as response:
                response_headers = {str(k): str(v) for k, v in response.headers.items()}
                if response.status_code in {301, 302, 303, 307, 308}:
                    location = response.headers.get("Location")
                    if not location: raise requests.TooManyRedirects("redirect missing destination")
                    current = urljoin(current, location)
                    continue
                if response.status_code == 304:
                    return HttpResponse(current, 304, response_headers, b"", not_modified=True)
                response.raise_for_status()
                declared = response.headers.get("Content-Length")
                if declared and int(declared) > self.settings.max_response_bytes:
                    raise ResponseTooLargeError("response exceeds configured size limit")
                body, size = [], 0
                for chunk in response.iter_content(65536):
                    size += len(chunk)
                    if size > self.settings.max_response_bytes: raise ResponseTooLargeError("response exceeds configured size limit")
                    body.append(chunk)
                return HttpResponse(current, response.status_code, response_headers, b"".join(body))
        raise requests.TooManyRedirects("redirect limit exceeded")
