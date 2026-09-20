from __future__ import annotations

import sys
from contextlib import ExitStack
from socket import timeout as SocketTimeout
from typing import Mapping
from urllib.parse import urljoin

import requests
from requests.adapters import HTTPAdapter
from urllib3 import connection
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.exceptions import ConnectTimeoutError, NewConnectionError

from backend.app.pipeline.ingestion.external.common.http_client import HttpClientSettings, HttpResponse, ResponseTooLargeError
from backend.app.pipeline.ingestion.external.manual_source.url_policy import ManualURLPolicy, URLPolicyError


class _PinnedConnection:
    """Connect only to addresses validated for this URL; keep the original TLS host."""

    _approved_addresses: tuple[str, ...]

    def _new_conn(self):
        last_error: OSError | None = None
        for address in self._approved_addresses:
            try:
                sock = connection.connection.create_connection(
                    (address, self.port),
                    self.timeout,
                    source_address=self.source_address,
                    socket_options=self.socket_options,
                )
            except (OSError, SocketTimeout) as exc:
                last_error = exc
                continue
            sys.audit("http.client.connect", self, self.host, self.port)
            return sock
        if isinstance(last_error, SocketTimeout):
            raise ConnectTimeoutError(self, f"Connection to {self.host} timed out") from last_error
        raise NewConnectionError(self, f"Could not connect to an approved address for {self.host}") from last_error


class _PinnedHTTPAdapter(HTTPAdapter):
    def __init__(self, approved_addresses: tuple[str, ...]) -> None:
        if not approved_addresses:
            raise URLPolicyError("destination has no approved public address")
        self._approved_addresses = approved_addresses
        super().__init__(max_retries=0)

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs) -> None:
        super().init_poolmanager(connections, maxsize, block, **pool_kwargs)
        addresses = self._approved_addresses

        class PinnedHTTPConnection(_PinnedConnection, HTTPConnection):
            _approved_addresses = addresses

        class PinnedHTTPSConnection(_PinnedConnection, HTTPSConnection):
            _approved_addresses = addresses

        class PinnedHTTPConnectionPool(HTTPConnectionPool):
            ConnectionCls = PinnedHTTPConnection

        class PinnedHTTPSConnectionPool(HTTPSConnectionPool):
            ConnectionCls = PinnedHTTPSConnection

        # A fresh adapter is used for each hop, so no connection survives DNS revalidation.
        self.poolmanager.pool_classes_by_scheme = {
            "http": PinnedHTTPConnectionPool,
            "https": PinnedHTTPSConnectionPool,
        }


class SSRFProtectedHttpClient:
    """GET-only client with DNS-pinned connections and validated redirects."""

    def __init__(self, policy: ManualURLPolicy, settings: HttpClientSettings | None = None) -> None:
        self.policy, self.settings = policy, settings or HttpClientSettings()

    def get(self, url: str, *, etag: str | None = None, last_modified: str | None = None,
            headers: Mapping[str, str] | None = None) -> HttpResponse:
        current = url
        safe_headers = {"User-Agent": self.settings.user_agent, "Accept": "text/html,application/xhtml+xml,application/rss+xml,application/atom+xml",
                        "Accept-Encoding": "gzip, deflate"}
        for key, value in (headers or {}).items():
            if key.lower() not in {"authorization", "cookie", "proxy-authorization", "host"}:
                safe_headers[str(key)] = str(value)
        if etag: safe_headers["If-None-Match"] = etag
        if last_modified: safe_headers["If-Modified-Since"] = last_modified
        for _ in range(self.settings.max_redirects + 1):
            validated = self.policy.validate(current, allow_onion=False)
            current = validated.canonical_url
            if not validated.approved_addresses:
                raise URLPolicyError("destination has no approved public address")
            with ExitStack() as stack:
                request_session = stack.enter_context(requests.Session())
                request_session.trust_env = False
                adapter = _PinnedHTTPAdapter(validated.approved_addresses)
                request_session.mount("http://", adapter)
                request_session.mount("https://", adapter)
                response = stack.enter_context(self._request(request_session, current, safe_headers))
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

    def _request(self, session: requests.Session, url: str, headers: Mapping[str, str]):
        return session.get(url, headers=headers,
                           timeout=(self.settings.connect_timeout_seconds, self.settings.read_timeout_seconds),
                           allow_redirects=False, stream=True)
