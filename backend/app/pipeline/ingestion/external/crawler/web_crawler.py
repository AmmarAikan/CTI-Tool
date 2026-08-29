from __future__ import annotations

import json
import math
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
EXTRACTION_IMPLEMENTATION_VERSION = "web_crawler_v4"
NOISE_SELECTORS = (
    "script, style, nav, footer, header, aside, form, iframe, noscript, template, "
    "[role='navigation'], [role='banner'], [role='contentinfo'], "
    ".advertisement, .advert, .ads, .cookie, .newsletter, .sidebar, .social-share, "
    ".related, .related-articles, .related-posts, .recommended, .recommendations"
)
CHARSET_RE = re.compile(r"charset\s*=\s*['\"]?([^\s;'\"]+)", re.IGNORECASE)
BYLINE_RE = re.compile(r"^\s*(?:written\s+by|by)\b", re.IGNORECASE)
BLOCK_TAGS = ("h1", "h2", "h3", "h4", "h5", "h6", "p", "li", "pre", "blockquote", "figcaption", "table")


@dataclass(frozen=True, slots=True)
class ExtractionSettings:
    """Tunable generic completeness thresholds; no source-specific selectors."""

    semantic_preference_ratio: float = 1.25
    minimum_candidate_characters: int = 120
    maximum_container_candidates: int = 40
    character_weight: float = 1.0
    block_weight: float = 0.35
    heading_weight: float = 0.8
    table_row_weight: float = 1.0

    def __post_init__(self) -> None:
        if self.semantic_preference_ratio < 1 or self.minimum_candidate_characters < 0:
            raise ValueError("invalid extraction completeness thresholds")
        if self.maximum_container_candidates <= 0:
            raise ValueError("maximum_container_candidates must be positive")


@dataclass(frozen=True, slots=True)
class _ExtractionCandidate:
    kind: str
    text: str
    block_count: int
    heading_count: int
    table_row_count: int
    order: int

    def score(self, settings: ExtractionSettings) -> float:
        return (
            math.log1p(len(self.text)) * settings.character_weight
            + math.log1p(self.block_count) * settings.block_weight
            + math.log1p(self.heading_count) * settings.heading_weight
            + math.log1p(self.table_row_count) * settings.table_row_weight
        )


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
    author: str | None = None
    published: str | None = None
    extraction_version: str = EXTRACTION_IMPLEMENTATION_VERSION

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
        extraction_settings: ExtractionSettings | None = None,
    ) -> None:
        self.http_client = http_client or ExternalHttpClient()
        self.page_type_detector = page_type_detector or PageTypeDetector()
        self.cleaner = cleaner or TextCleaner()
        self.extraction_settings = extraction_settings or ExtractionSettings()

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
            structural = self.page_type_detector.detect(html, final_canonical, "")
            title, author, published, extracted_text = self._extract(html)
            detected = (structural if structural.signals.get("strong_structural_listing")
                        else self.page_type_detector.detect(html, final_canonical, extracted_text))
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
            author=author,
            published=published,
            extracted_text=extracted_text,
            page_type=detected.page_type,
            confidence=detected.confidence,
            candidate_links=detected.candidate_links,
            signals=detected.signals,
            response_metadata=response_metadata,
            raw_content_hash=raw_hash,
            extracted_content_hash=sha256_text(extracted_text),
        )

    def _extract(self, html: str) -> tuple[str, str | None, str | None, str]:
        document = Document(html)
        full_soup = BeautifulSoup(html, "lxml")
        title, author, published = self._metadata(full_soup, document)
        candidates = self._candidates(full_soup, document)
        selected = self._select_candidate(candidates)
        return title, author, published, selected.text if selected else ""

    def _candidates(self, full_soup: BeautifulSoup, document: Document) -> list[_ExtractionCandidate]:
        candidates: list[_ExtractionCandidate] = []
        seen: set[str] = set()

        def add(kind: str, value: Any, order: int) -> None:
            candidate = self._candidate(kind, value, order)
            if candidate is None or candidate.text in seen:
                return
            seen.add(candidate.text)
            candidates.append(candidate)

        try:
            add("readability", document.summary(html_partial=True), 0)
        except Exception:
            pass
        order = 1
        for node in full_soup.find_all("article"):
            add("article", node, order); order += 1
        for node in full_soup.find_all("main"):
            add("main", node, order); order += 1
        schema_nodes = [
            *full_soup.select("[itemprop='articleBody']"),
            *full_soup.select("[itemtype*='Article']"),
            *full_soup.select("[itemtype*='BlogPosting']"),
            *full_soup.select("[itemtype*='NewsArticle']"),
        ]
        for node in schema_nodes:
            add("schema_article_body", node, order); order += 1

        coherent: list[tuple[int, Any]] = []
        for node in full_soup.find_all(["section", "div"], limit=self.extraction_settings.maximum_container_candidates * 20):
            paragraphs = len(node.find_all("p"))
            headings = len(node.find_all(["h1", "h2", "h3", "h4", "h5", "h6"]))
            if paragraphs >= 2 and paragraphs + headings >= 3:
                coherent.append((len(node.get_text(" ", strip=True)), node))
        if coherent:
            _, largest = max(coherent, key=lambda value: value[0])
            add("largest_container", largest, order)
        return candidates

    def _candidate(self, kind: str, value: Any, order: int) -> _ExtractionCandidate | None:
        soup = BeautifulSoup(value if isinstance(value, str) else str(value), "lxml")
        for comment in soup.find_all(string=lambda value: isinstance(value, Comment)):
            comment.extract()
        for element in soup.select(NOISE_SELECTORS):
            element.decompose()
        blocks: list[str] = []
        heading_count = table_row_count = 0
        for element in soup.find_all(BLOCK_TAGS):
            if element.name != "table" and element.find_parent("table") is not None:
                continue
            if element.name == "table":
                rows = self._table_rows(element)
                table_row_count += len(rows)
                for row in rows:
                    if not blocks or blocks[-1] != row: blocks.append(row)
                continue
            if element.name in {"h1", "h2", "h3", "h4", "h5", "h6"}:
                heading_count += 1
            text = self.cleaner.clean(element.get_text(" ", strip=True))
            if text and (not blocks or blocks[-1] != text): blocks.append(text)
        if not blocks:
            fallback = self.cleaner.clean(soup.get_text(" ", strip=True))
            if fallback: blocks.append(fallback)
        text = "\n\n".join(blocks)
        if len(text) < self.extraction_settings.minimum_candidate_characters:
            return None
        return _ExtractionCandidate(kind, text, len(blocks), heading_count, table_row_count, order)

    def _select_candidate(self, candidates: list[_ExtractionCandidate]) -> _ExtractionCandidate | None:
        if not candidates: return None
        readability = next((value for value in candidates if value.kind == "readability"), None)
        semantic = [value for value in candidates if value.kind in {"article", "main", "schema_article_body"}]
        best_semantic = max(semantic, key=lambda value: (value.score(self.extraction_settings), -value.order), default=None)
        if readability and best_semantic and len(best_semantic.text) >= len(readability.text) * self.extraction_settings.semantic_preference_ratio:
            return best_semantic
        return max(candidates, key=lambda value: (value.score(self.extraction_settings), -value.order))

    def _metadata(self, soup: BeautifulSoup, document: Document) -> tuple[str, str | None, str | None]:
        structured = self._article_json_ld(soup)
        semantic_h1 = soup.select_one("article h1, main h1, [itemprop='articleBody'] h1, h1")
        title = self.cleaner.clean(semantic_h1.get_text(" ", strip=True) if semantic_h1 else "")
        if not title:
            title = self._meta(soup, ("og:title", "twitter:title")) or self.cleaner.clean(str(structured.get("headline") or ""))
        if not title: title = self.cleaner.clean(document.short_title() or "")

        author = self._visible_byline(soup)
        if not author:
            author = self._meta(soup, ("author", "article:author")) or self._structured_authors(structured.get("author"))
        published = self._meta(soup, ("article:published_time", "datepublished", "date", "pubdate"))
        if not published: published = self.cleaner.clean(str(structured.get("datePublished") or "")) or None
        if not published:
            time_tag = soup.find("time")
            if time_tag: published = self.cleaner.clean(str(time_tag.get("datetime") or time_tag.get_text(" ", strip=True))) or None
        return title, author, published

    def _visible_byline(self, soup: BeautifulSoup) -> str | None:
        for text_node in soup.find_all(string=BYLINE_RE):
            remainder = BYLINE_RE.sub("", str(text_node), count=1).lstrip(" :")
            value = self._valid_author(remainder)
            if value: return value
            parent = text_node.parent
            if parent is not None:
                sibling = parent.find_next_sibling()
                sibling_classes = {str(value).lower() for value in (sibling.get("class", []) if sibling is not None else [])}
                sibling_rel = {str(value).lower() for value in (sibling.get("rel", []) if sibling is not None else [])}
                is_byline_sibling = sibling is not None and (
                    str(sibling.get("itemprop") or "").lower() == "author"
                    or bool(sibling_classes & {"author", "authors", "byline"})
                    or "author" in sibling_rel
                )
                if is_byline_sibling:
                    value = self._valid_author(sibling.get_text(" ", strip=True))
                    if value: return value
        for node in soup.select("[itemprop='author'], .byline, .author, [rel='author']"):
            text = self.cleaner.clean(node.get_text(" ", strip=True))
            value = BYLINE_RE.sub("", text, count=1).lstrip(" :") if BYLINE_RE.match(text) else text
            value = self._valid_author(value)
            if value: return value
        return None

    def _valid_author(self, value: str) -> str | None:
        cleaned = self.cleaner.clean(value).strip(" :|,-")
        if not 2 <= len(cleaned) <= 200 or not any(character.isalnum() for character in cleaned):
            return None
        return cleaned

    @staticmethod
    def _article_json_ld(soup: BeautifulSoup) -> dict[str, Any]:
        article_types = {"Article", "BlogPosting", "NewsArticle", "Report"}
        for script in soup.select("script[type='application/ld+json']"):
            try: value = json.loads(script.string or script.get_text())
            except (TypeError, ValueError): continue
            pending = list(value) if isinstance(value, list) else [value]
            while pending:
                current = pending.pop(0)
                if not isinstance(current, dict): continue
                graph = current.get("@graph")
                if isinstance(graph, list): pending.extend(graph)
                raw_type = current.get("@type")
                types = set(raw_type) if isinstance(raw_type, list) else {raw_type}
                if types & article_types: return current
        return {}

    def _meta(self, soup: BeautifulSoup, keys: tuple[str, ...]) -> str | None:
        wanted = {value.lower() for value in keys}
        for tag in soup.find_all("meta"):
            key = str(tag.get("property") or tag.get("name") or tag.get("itemprop") or "").lower()
            if key in wanted:
                value = self.cleaner.clean(str(tag.get("content") or ""))
                if value: return value
        return None

    def _structured_authors(self, value: Any) -> str | None:
        authors = value if isinstance(value, list) else [value]
        names = []
        for author in authors:
            raw = author.get("name") if isinstance(author, dict) else author
            name = self.cleaner.clean(str(raw or ""))
            if name and name not in names: names.append(name)
        return ", ".join(names) or None

    def _table_rows(self, table: Any) -> list[str]:
        rows = []
        for row in table.find_all("tr"):
            cells = [self.cleaner.clean(cell.get_text(" ", strip=True)) for cell in row.find_all(["th", "td"], recursive=False)]
            cells = [cell for cell in cells if cell]
            if cells: rows.append(" | ".join(cells))
        return rows

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
