"""Small synchronous test facade over HTTPX's non-blocking ASGI transport.

Starlette's deprecated TestClient deadlocks with the repository's installed
AnyIO/HTTPX combination.  This facade keeps unittest call sites synchronous
while every request uses AsyncClient and ASGITransport.
"""
from __future__ import annotations

import asyncio
from typing import Any

import httpx
import fastapi.dependencies.utils
import fastapi.routing
import starlette.concurrency


async def _inline_sync_call(function, *args, **kwargs):
    """Test-only fallback for the incompatible AnyIO worker portal."""
    return function(*args, **kwargs)


# The installed AnyIO worker portal deadlocks even for a minimal independent
# synchronous FastAPI endpoint. Execute sync endpoints inline in this test-only
# ASGI transport; production servers keep their normal worker pool behavior.
fastapi.routing.run_in_threadpool = _inline_sync_call
fastapi.dependencies.utils.run_in_threadpool = _inline_sync_call
starlette.concurrency.run_in_threadpool = _inline_sync_call


class ASGITestClient:
    def __init__(self, app, *, raise_server_exceptions: bool = True, **_: Any) -> None:
        self.app = app
        self.raise_server_exceptions = raise_server_exceptions
        self.cookies = httpx.Cookies()
        self._lifespan = None

    async def _request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        transport = httpx.ASGITransport(
            app=self.app, raise_app_exceptions=self.raise_server_exceptions)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver",
            cookies=self.cookies, follow_redirects=True,
            headers={"Accept-Encoding": "identity"},
        ) as client:
            response = await client.request(method, url, **kwargs)
            self.cookies.update(client.cookies)
            return response

    def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        return asyncio.run(self._request(method, url, **kwargs))

    def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.request("PUT", url, **kwargs)

    def patch(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.request("PATCH", url, **kwargs)

    def delete(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.request("DELETE", url, **kwargs)

    def __enter__(self):
        self._lifespan = self.app.router.lifespan_context(self.app)
        asyncio.run(self._lifespan.__aenter__())
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        if self._lifespan is not None:
            asyncio.run(self._lifespan.__aexit__(exc_type, exc, traceback))
            self._lifespan = None

    def close(self) -> None:
        if self._lifespan is not None:
            self.__exit__(None, None, None)


TestClient = ASGITestClient
