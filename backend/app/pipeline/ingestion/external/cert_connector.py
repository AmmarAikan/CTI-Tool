from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

from backend.app.pipeline.common.cti_schema import RawRecord
from backend.app.pipeline.ingestion.base_connector import ExternalConnector
from backend.app.pipeline.ingestion.external.common.canonical_url import canonicalize_url
from backend.app.pipeline.ingestion.external.common.hashing import sha256_bytes, sha256_json, sha256_text
from backend.app.pipeline.ingestion.external.common.http_client import ExternalHttpClient
from backend.app.pipeline.ingestion.external.common.models import ExternalCTIItem, ExternalClassification
from backend.app.pipeline.ingestion.external.crawler.web_crawler import CrawlResult, WebCrawler
from backend.app.pipeline.ingestion.external.preprocessing.content_processor import ExternalContentProcessor
from backend.app.pipeline.ingestion.external.preprocessing.text_preprocessor import TextPreprocessor
from backend.app.pipeline.ingestion.external.privacy.privacy_filter import PrivacyFilter
from backend.app.pipeline.ingestion.external.rss_connector import RSSCollectionResult, RSSConnector


PROJECT_ROOT = Path(__file__).resolve().parents[5]


@dataclass(frozen=True, slots=True)
class CERTSource:
    source_id: str
    name: str
    url: str
    method: str
    category: str = "advisory"
    enabled: bool = True
    max_items: int = 50
    lookback_days: int = 30
    detail_path_pattern: str | None = None

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> "CERTSource":
        source_id = str(value.get("source_id") or "").strip()
        name, url = str(value.get("name") or "").strip(), str(value.get("url") or "").strip()
        method = str(value.get("method") or "").strip()
        max_items, lookback_days = int(value.get("max_items", 50)), int(value.get("lookback_days", 30))
        if not source_id or not name or not url or method not in {"rss", "official_listing"}:
            raise ValueError("invalid CERT source configuration")
        if max_items <= 0 or lookback_days < 0:
            raise ValueError("invalid CERT collection bounds")
        pattern = value.get("detail_path_pattern")
        if method == "official_listing" and not pattern:
            raise ValueError("official_listing sources require detail_path_pattern")
        if pattern:
            re.compile(str(pattern))
        return cls(source_id, name, canonicalize_url(url), method, str(value.get("category") or "advisory"), bool(value.get("enabled", True)), max_items, lookback_days, str(pattern) if pattern else None)


@dataclass(frozen=True, slots=True)
class CERTCollectionError:
    source_id: str
    category: str
    retryable: bool = False


@dataclass(slots=True)
class CERTCollectionResult:
    source_id: str
    status: str = "completed"
    accepted_items: list[ExternalCTIItem] = field(default_factory=list)
    review_items: list[ExternalCTIItem] = field(default_factory=list)
    errors: list[CERTCollectionError] = field(default_factory=list)
    skipped_items: int = 0

    @property
    def all_items(self) -> list[ExternalCTIItem]:
        return [*self.accepted_items, *self.review_items]


class CERTConnector(ExternalConnector):
    """Dedicated CERT orchestration over verified feed or bounded-listing delivery."""

    def __init__(
        self,
        source: CERTSource,
        *,
        http_client: ExternalHttpClient | None = None,
        crawler: WebCrawler | None = None,
        content_processor: ExternalContentProcessor | None = None,
        state: dict[str, Any] | None = None,
        clock: Callable[[], datetime] | None = None,
        rss_factory: Callable[..., RSSConnector] | None = None,
    ) -> None:
        self.source, self.source_name = source, source.name
        self.http_client, self.crawler = http_client or ExternalHttpClient(), crawler or WebCrawler()
        self.content_processor = content_processor or ExternalContentProcessor(
            TextPreprocessor(PROJECT_ROOT / "config" / "preprocessing_rules.json"),
            PrivacyFilter(PROJECT_ROOT / "config" / "privacy_rules.json"),
        )
        self.state = state if state is not None else {}
        self.state.setdefault("sources", {}); self.state.setdefault("items", {})
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.rss_factory = rss_factory or RSSConnector

    def collect(self) -> Iterable[RawRecord]:
        for item in self.collect_result().accepted_items:
            yield item.to_raw_record()

    def collect_result(self) -> CERTCollectionResult:
        if self.source.method == "rss":
            return self._collect_rss()
        return self._collect_listing()

    def _collect_rss(self) -> CERTCollectionResult:
        connector = self.rss_factory(
            self.source.url,
            self.source.name,
            source_id=self.source.source_id,
            category=self.source.category,
            max_items=self.source.max_items,
            lookback_days=self.source.lookback_days,
            http_client=self.http_client,
            crawler=self.crawler,
            content_processor=self.content_processor,
            state=self.state,
            clock=self.clock,
        )
        rss_result: RSSCollectionResult = connector.collect_result()
        result = CERTCollectionResult(self.source.source_id, rss_result.status, skipped_items=rss_result.skipped_items)
        result.accepted_items = [self._as_cert_item(item, "official_rss") for item in rss_result.accepted_items]
        result.review_items = [self._as_cert_item(item, "official_rss") for item in rss_result.review_items]
        result.errors = [CERTCollectionError(error.source_id, error.category, error.retryable) for error in rss_result.errors]
        return result

    def _collect_listing(self) -> CERTCollectionResult:
        result, checked_at = CERTCollectionResult(self.source.source_id), self._now_iso()
        source_state = self.state["sources"].setdefault(self.source.source_id, {})
        try:
            response = self.http_client.get(self.source.url, etag=source_state.get("etag"), last_modified=source_state.get("last_modified"))
        except Exception:
            result.status = "failed"; result.errors.append(CERTCollectionError(self.source.source_id, "listing_request_failed", True))
            source_state.update({"last_checked": checked_at, "last_status": "failed"}); return result
        source_state.update({"last_checked": checked_at, "etag": response.etag or source_state.get("etag"), "last_modified": response.last_modified or source_state.get("last_modified")})
        if response.not_modified:
            result.status = "unchanged"; source_state["last_status"] = "unchanged"; return result
        raw_hash = sha256_bytes(response.body)
        if source_state.get("raw_content_hash") != raw_hash: source_state["last_changed"] = checked_at
        source_state["raw_content_hash"] = raw_hash
        try:
            html = response.body.decode("utf-8", errors="replace")
            candidates = self._listing_candidates(html)
        except Exception:
            result.status = "failed"; result.errors.append(CERTCollectionError(self.source.source_id, "invalid_listing")); return result
        for candidate in candidates[: self.source.max_items]:
            if not self._within_lookback(candidate.get("published")):
                result.skipped_items += 1
                continue
            try: item, disposition = self._process_candidate(candidate, checked_at)
            except Exception: result.errors.append(CERTCollectionError(self.source.source_id, "item_processing_failed")); continue
            if item is None: result.skipped_items += 1
            elif disposition == "accepted": result.accepted_items.append(item)
            else: result.review_items.append(item)
        if result.errors: result.status = "partial" if result.all_items else "failed"
        source_state["last_status"] = result.status
        if result.status in {"completed", "partial"}: source_state["last_successful_run"] = checked_at
        return result

    def _listing_candidates(self, html: str) -> list[dict[str, str | None]]:
        soup, pattern = BeautifulSoup(html, "lxml"), re.compile(self.source.detail_path_pattern or "")
        scope, base_host, seen, candidates = soup.find("main") or soup, urlsplit(self.source.url).hostname, set(), []
        for anchor in scope.find_all("a", href=True):
            absolute = canonicalize_url(urljoin(self.source.url, str(anchor["href"])))
            if urlsplit(absolute).hostname != base_host or not pattern.search(urlsplit(absolute).path) or absolute in seen: continue
            title = anchor.get_text(" ", strip=True)
            if len(title) < 8: continue
            seen.add(absolute)
            time_tag = anchor.find_parent().find("time") if anchor.find_parent() else None
            published = str(time_tag.get("datetime") or time_tag.get_text(" ", strip=True)) if time_tag else None
            candidates.append({"title": title, "link": absolute, "published": published})
        return candidates

    def _process_candidate(self, candidate: dict[str, str | None], collected_at: str) -> tuple[ExternalCTIItem | None, str]:
        link, title = str(candidate["link"]), str(candidate["title"])
        record_id = f"cert-{sha256_text(link).split(':', 1)[1][:32]}"
        item_state = self.state["items"].setdefault(record_id, {})
        crawl: CrawlResult = self.crawler.crawl(link, etag=item_state.get("etag"), last_modified=item_state.get("last_modified"))
        if crawl.status == "unchanged" and item_state.get("record_hash"): return None, "unchanged"
        full = crawl.extracted_text if crawl.status == "success" else ""
        processing = self.content_processor.process(full)
        item = ExternalCTIItem(
            record_id=record_id, source_item_id=urlsplit(link).path.rstrip("/").rsplit("/", 1)[-1], source=self.source.name,
            source_type="cert", category=self.source.category, title=title, link=link, content=processing.export_content,
            summary="", published=candidate.get("published"), updated_at=None, author=None, tags=(), language="en",
            collected_at=collected_at, content_hash=sha256_text(processing.export_content),
            classification=ExternalClassification(status="not_required"),
            metadata={"delivery_method": "official_listing", "content_status": "full_text" if full else "unavailable", "observed_in": [self.source.source_id], **processing.metadata, "crawler": {"status": crawl.status, "raw_content_hash": crawl.raw_content_hash, "extracted_content_hash": crawl.extracted_content_hash, "response": crawl.response_metadata}},
        )
        stable = item.to_dict(); stable.pop("collected_at", None)
        record_hash, previous_hash = sha256_json(stable), item_state.get("record_hash")
        item_state.update({"canonical_url": link, "record_hash": record_hash, "clean_content_hash": processing.preprocessing.output_hash, "privacy_output_hash": processing.privacy.output_hash, "last_checked": collected_at, "last_changed": collected_at if previous_hash != record_hash else item_state.get("last_changed", collected_at), "etag": crawl.response_metadata.get("etag"), "last_modified": crawl.response_metadata.get("last_modified")})
        if previous_hash == record_hash: return None, "unchanged"
        return item, "review" if not full or processing.review_required else "accepted"

    def _as_cert_item(self, item: ExternalCTIItem, method: str) -> ExternalCTIItem:
        metadata = {**item.metadata, "delivery_method": method, "cert_source_id": self.source.source_id}
        return replace(item, source_type="cert", metadata=metadata)

    def _within_lookback(self, published: str | None) -> bool:
        if self.source.lookback_days == 0 or not published:
            return True
        try:
            value = datetime.fromisoformat(published.strip().replace("Z", "+00:00"))
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
        except (TypeError, ValueError):
            return True
        cutoff = self.clock().astimezone(timezone.utc) - timedelta(days=self.source.lookback_days)
        return value.astimezone(timezone.utc) >= cutoff

    def _now_iso(self) -> str:
        return self.clock().astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class ConfiguredCERTCollector:
    """Run enabled CERT sources without allowing one failure to stop others."""

    def __init__(
        self,
        sources: Sequence[CERTSource | dict[str, Any]],
        *,
        connector_factory: Callable[[CERTSource], CERTConnector] | None = None,
    ) -> None:
        self.sources = tuple(source if isinstance(source, CERTSource) else CERTSource.from_mapping(source) for source in sources)
        self.connector_factory = connector_factory or CERTConnector

    def collect_results(self) -> list[CERTCollectionResult]:
        results: list[CERTCollectionResult] = []
        for source in self.sources:
            if not source.enabled: continue
            try: results.append(self.connector_factory(source).collect_result())
            except Exception: results.append(CERTCollectionResult(source.source_id, "failed", errors=[CERTCollectionError(source.source_id, "source_failed")]))
        return results
