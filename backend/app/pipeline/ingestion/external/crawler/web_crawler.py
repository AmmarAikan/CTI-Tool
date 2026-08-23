from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any

import requests
from bs4 import BeautifulSoup, Comment
from readability import Document

from backend.app.pipeline.ingestion.external.common.canonical_url import canonicalize_url
from backend.app.pipeline.ingestion.external.common.hashing import sha256_bytes, sha256_text
from backend.app.pipeline.ingestion.external.common.http_client import ExternalHttpClient, ResponseTooLargeError
from backend.app.pipeline.ingestion.external.crawler.page_type_detector import PageTypeDetector, PageTypeResult
from backend.app.pipeline.preprocessing.cleaner import TextCleaner


HTML_CONTENT_TYPES = frozenset({"text/html", "application/xhtml+xml"})
NOISE_SELECTORS = (
    "script, style, nav, footer, header, aside, form, iframe, noscript, template, "
    "[role='navigation'], [role='banner'], [role='contentinfo'], "
    ".advertisement, .advert, .ads, .cookie, .newsletter, .sidebar, .social-share"
)
CHARSET_RE = re.compile(r"charset\s*=\s*['\"]?([^\s;'\"]+)", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class CrawlError:
    category: str
    message: str
    retryable: bool = False


@dataclass(frozen=True, slots=True)
class CrawlResult:
    requested_url: str
    canonical_url: str | None
    status: str
    title: str = ""
    extracted_text: str = ""
    page_type: str = "unknown"
    confidence: float = 0.0
    candidate_links: tuple[str, ...] = ()
    signals: dict[str, Any] = field(default_factory=dict)
    response_metadata: dict[str, Any] = field(default_factory=dict)
    raw_content_hash: str | None = None
    extracted_content_hash: str | None = None
    errors: tuple[CrawlError, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["candidate_links"] = list(self.candidate_links)
        value["errors"] = [asdict(error) for error in self.errors]
        return value


class WebCrawler:
    """Fetch and extract one HTML page through the bounded shared External HTTP client."""

    def __init__(
        self,
        http_client: ExternalHttpClient | None = None,
        page_type_detector: PageTypeDetector | None = None,
        cleaner: TextCleaner | None = None,
    ) -> None:
        self.http_client = http_client or ExternalHttpClient()
        self.page_type_detector = page_type_detector or PageTypeDetector()
        self.cleaner = cleaner or TextCleaner()

    def crawl(self, url: str, *, etag: str | None = None, last_modified: str | None = None) -> CrawlResult:
        try:
            requested_canonical = canonicalize_url(url)
        except ValueError as exc:
            return self._error(url, None, "invalid_url", str(exc))

        try:
            response = self.http_client.get(requested_canonical, etag=etag, last_modified=last_modified)
        except ResponseTooLargeError as exc:
            return self._error(url, requested_canonical, "response_too_large", str(exc))
        except requests.Timeout:
            return self._error(url, requested_canonical, "timeout", "source request timed out", retryable=True)
        except requests.RequestException as exc:
            return self._error(url, requested_canonical, "request_failed", self._safe_request_message(exc), retryable=True)
        except Exception as exc:  # isolate client implementations and malformed responses
            return self._error(url, requested_canonical, "request_failed", type(exc).__name__, retryable=True)

        response_metadata = self._response_metadata(response.status_code, response.headers, response.url)
        try:
            final_canonical = canonicalize_url(response.url)
        except ValueError:
            return self._error(url, requested_canonical, "invalid_redirect", "final response URL is not allowed")

        if response.not_modified:
            return CrawlResult(url, final_canonical, "unchanged", response_metadata=response_metadata)

        media_type = self._media_type(response.headers)
        if media_type not in HTML_CONTENT_TYPES:
            return self._error(
                url,
                final_canonical,
                "unsupported_content_type",
                f"expected HTML-compatible content, received {media_type or 'missing content type'}",
                response_metadata=response_metadata,
            )

        raw_hash = sha256_bytes(response.body)
        html = self._decode(response.body, response.headers)
        if not html.strip():
            return self._error(
                url,
                final_canonical,
                "empty_response",
                "HTML response body is empty",
                response_metadata=response_metadata,
                raw_content_hash=raw_hash,
            )

        try:
            title, extracted_text = self._extract(html)
            detected = self.page_type_detector.detect(html, final_canonical, extracted_text)
        except Exception as exc:
            return self._error(
                url,
                final_canonical,
                "extraction_failed",
                type(exc).__name__,
                response_metadata=response_metadata,
                raw_content_hash=raw_hash,
            )

        return CrawlResult(
            requested_url=url,
            canonical_url=final_canonical,
            status="success",
            title=title,
            extracted_text=extracted_text,
            page_type=detected.page_type,
            confidence=detected.confidence,
            candidate_links=detected.candidate_links,
            signals=detected.signals,
            response_metadata=response_metadata,
            raw_content_hash=raw_hash,
            extracted_content_hash=sha256_text(extracted_text),
        )

    def _extract(self, html: str) -> tuple[str, str]:
        document = Document(html)
        title = self.cleaner.clean(document.short_title() or "")
        readable_html = document.summary(html_partial=True)
        soup = BeautifulSoup(readable_html, "lxml")
        for comment in soup.find_all(string=lambda value: isinstance(value, Comment)):
            comment.extract()
        for element in soup.select(NOISE_SELECTORS):
            element.decompose()

        blocks: list[str] = []
        for element in soup.find_all(["h1", "h2", "h3", "p", "li", "pre", "blockquote"]):
            text = self.cleaner.clean(element.get_text(" ", strip=True))
            if text and (not blocks or blocks[-1] != text):
                blocks.append(text)
        if not blocks:
            fallback = self.cleaner.clean(soup.get_text(" ", strip=True))
            if fallback:
                blocks.append(fallback)
        return title, "\n\n".join(blocks)

    @staticmethod
    def _decode(body: bytes, headers: dict[str, str]) -> str:
        content_type = headers.get("Content-Type") or headers.get("content-type") or ""
        match = CHARSET_RE.search(content_type)
        encoding = match.group(1) if match else "utf-8"
        try:
            return body.decode(encoding)
        except (LookupError, UnicodeDecodeError):
            return body.decode("utf-8", errors="replace")

    @staticmethod
    def _media_type(headers: dict[str, str]) -> str:
        value = headers.get("Content-Type") or headers.get("content-type") or ""
        return value.split(";", 1)[0].strip().lower()

    @staticmethod
    def _response_metadata(status_code: int, headers: dict[str, str], final_url: str) -> dict[str, Any]:
        return {
            "status_code": status_code,
            "final_url": final_url,
            "content_type": headers.get("Content-Type") or headers.get("content-type"),
            "etag": headers.get("ETag") or headers.get("etag"),
            "last_modified": headers.get("Last-Modified") or headers.get("last-modified"),
            "content_length": headers.get("Content-Length") or headers.get("content-length"),
        }

    @staticmethod
    def _safe_request_message(exc: requests.RequestException) -> str:
        return type(exc).__name__

    @staticmethod
    def _error(
        requested_url: str,
        canonical_url: str | None,
        category: str,
        message: str,
        *,
        retryable: bool = False,
        response_metadata: dict[str, Any] | None = None,
        raw_content_hash: str | None = None,
    ) -> CrawlResult:
        return CrawlResult(
            requested_url=requested_url,
            canonical_url=canonical_url,
            status="error",
            response_metadata=response_metadata or {},
            raw_content_hash=raw_content_hash,
            errors=(CrawlError(category, message, retryable),),
        )
