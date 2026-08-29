from __future__ import annotations

import unittest
from unittest.mock import Mock

from backend.app.pipeline.ingestion.external.common.http_client import (
    ExternalHttpClient,
    HttpClientSettings,
    ResponseTooLargeError,
)


class ContextResponse:
    def __init__(self, *, status_code=200, body=b"ok", headers=None, url="https://example.test/final") -> None:
        self.status_code = status_code
        self._body = body
        self.headers = headers or {}
        self.url = url

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def raise_for_status(self):
        return None

    def iter_content(self, chunk_size):
        del chunk_size
        yield self._body


class HttpClientTests(unittest.TestCase):
    def test_conditional_headers_and_304(self) -> None:
        session = Mock()
        session.get.return_value = ContextResponse(status_code=304, body=b"", headers={"ETag": "v2"})
        client = ExternalHttpClient(HttpClientSettings(retry_total=1), session=session)
        result = client.get("https://example.test/feed", etag="v1", last_modified="yesterday")
        headers = session.get.call_args.kwargs["headers"]
        self.assertEqual(headers["If-None-Match"], "v1")
        self.assertEqual(headers["If-Modified-Since"], "yesterday")
        self.assertTrue(result.not_modified)

    def test_streamed_size_limit(self) -> None:
        session = Mock()
        session.get.return_value = ContextResponse(body=b"12345")
        client = ExternalHttpClient(HttpClientSettings(max_response_bytes=4, retry_total=1), session=session)
        with self.assertRaises(ResponseTooLargeError):
            client.get("https://example.test/large")


if __name__ == "__main__":
    unittest.main()
