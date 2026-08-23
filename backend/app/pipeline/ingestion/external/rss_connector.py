from __future__ import annotations

import calendar
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import feedparser

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


PROJECT_ROOT = Path(__file__).resolve().parents[5]


@dataclass(frozen=True, slots=True)
class RSSSource:
    source_id: str
    name: str
    url: str
    category: str
    enabled: bool = True
    max_items: int = 100
    lookback_days: int = 7

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> "RSSSource":
        name, url = str(value.get("name") or "").strip(), str(value.get("url") or "").strip()
        source_id = str(value.get("source_id") or name.lower().replace(" ", "-")).strip()
        max_items, lookback_days = int(value.get("max_items", 100)), int(value.get("lookback_days", 7))
        if not source_id or not name or not url or max_items <= 0 or lookback_days < 0:
            raise ValueError("invalid RSS source configuration")
        return cls(source_id, name, canonicalize_url(url), str(value.get("category") or "news"), bool(value.get("enabled", True)), max_items, lookback_days)


@dataclass(frozen=True, slots=True)
class RSSCollectionError:
    source_id: str
    category: str
    retryable: bool = False


@dataclass(slots=True)
class RSSCollectionResult:
    source_id: str
    status: str = "completed"
    accepted_items: list[ExternalCTIItem] = field(default_factory=list)
    review_items: list[ExternalCTIItem] = field(default_factory=list)
    errors: list[RSSCollectionError] = field(default_factory=list)
    skipped_items: int = 0

    @property
    def all_items(self) -> list[ExternalCTIItem]:
        return [*self.accepted_items, *self.review_items]


class RSSConnector(ExternalConnector):
    """One trusted RSS/Atom feed with conditional state and full-article enrichment."""

    def __init__(
        self, feed_url: str, source_name: str = "rss_feed", timeout: int = 20, *,
        source_id: str | None = None, category: str = "news", max_items: int = 100,
        lookback_days: int = 7, http_client: ExternalHttpClient | None = None,
        crawler: WebCrawler | None = None, content_processor: ExternalContentProcessor | None = None,
        state: dict[str, Any] | None = None, clock: Callable[[], datetime] | None = None,
    ) -> None:
        del timeout
        self.source = RSSSource(source_id or source_name.lower().replace(" ", "-"), source_name, canonicalize_url(feed_url), category, True, max_items, lookback_days)
        self.source_name, self.http_client, self.crawler = source_name, http_client or ExternalHttpClient(), crawler or WebCrawler()
        self.content_processor = content_processor or ExternalContentProcessor(
            TextPreprocessor(PROJECT_ROOT / "config" / "preprocessing_rules.json"),
            PrivacyFilter(PROJECT_ROOT / "config" / "privacy_rules.json"),
        )
        self.state = state if state is not None else {}
        self.state.setdefault("sources", {}); self.state.setdefault("items", {})
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    @classmethod
    def from_source(cls, source: RSSSource, **dependencies: Any) -> "RSSConnector":
        return cls(source.url, source.name, source_id=source.source_id, category=source.category, max_items=source.max_items, lookback_days=source.lookback_days, **dependencies)

    def collect(self) -> Iterable[RawRecord]:
        for item in self.collect_result().accepted_items:
            yield item.to_raw_record()

    def collect_result(self) -> RSSCollectionResult:
        result, checked_at = RSSCollectionResult(self.source.source_id), self._now_iso()
        feed_state = self.state["sources"].setdefault(self.source.source_id, {})
        try:
            response = self.http_client.get(self.source.url, etag=feed_state.get("etag"), last_modified=feed_state.get("last_modified"))
        except Exception:
            result.status = "failed"; result.errors.append(RSSCollectionError(self.source.source_id, "feed_request_failed", True))
            feed_state.update({"last_checked": checked_at, "last_status": "failed"}); return result

        feed_state.update({"last_checked": checked_at, "etag": response.etag or feed_state.get("etag"), "last_modified": response.last_modified or feed_state.get("last_modified")})
        if response.not_modified:
            result.status = "unchanged"; feed_state["last_status"] = "unchanged"; return result
        raw_hash = sha256_bytes(response.body)
        if feed_state.get("raw_content_hash") != raw_hash: feed_state["last_changed"] = checked_at
        feed_state["raw_content_hash"] = raw_hash
        parsed = feedparser.parse(response.body)
        if getattr(parsed, "bozo", False) and not parsed.entries:
            result.status = "failed"; result.errors.append(RSSCollectionError(self.source.source_id, "invalid_feed")); feed_state["last_status"] = "failed"; return result

        for entry in list(parsed.entries)[: self.source.max_items]:
            if not self._within_lookback(entry): result.skipped_items += 1; continue
            try: item, disposition = self._process_entry(entry, checked_at)
            except Exception: result.errors.append(RSSCollectionError(self.source.source_id, "item_processing_failed")); continue
            if item is None: result.skipped_items += 1
            elif disposition == "accepted": result.accepted_items.append(item)
            else: result.review_items.append(item)
        if result.errors: result.status = "partial" if result.all_items else "failed"
        feed_state["last_status"] = result.status
        if result.status in {"completed", "partial"}: feed_state["last_successful_run"] = checked_at
        return result

    def _process_entry(self, entry: Any, collected_at: str) -> tuple[ExternalCTIItem | None, str]:
        title, link_value = str(entry.get("title") or "Untitled RSS item").strip(), str(entry.get("link") or "").strip()
        link = canonicalize_url(link_value) if link_value else None
        source_item_id = str(entry.get("id") or entry.get("guid") or link or "").strip() or None
        stable = source_item_id or sha256_json({"source": self.source.source_id, "title": title, "published": self._published(entry)})
        record_id = f"rss-{sha256_text(stable).split(':', 1)[1][:32]}"
        item_state = self.state["items"].setdefault(record_id, {})
        crawl = self.crawler.crawl(link, etag=item_state.get("etag"), last_modified=item_state.get("last_modified")) if link else None
        if crawl and crawl.status == "unchanged" and item_state.get("record_hash"): return None, "unchanged"
        summary_source = str(entry.get("summary") or entry.get("description") or "")
        full = crawl.extracted_text if crawl and crawl.status == "success" and crawl.extracted_text.strip() else ""
        content_status, processing = ("full_text" if full else "summary_only"), self.content_processor.process(full or summary_source)
        summary_processing = self.content_processor.process(summary_source)
        tags = tuple(str(tag.get("term") or "").strip() for tag in entry.get("tags", []) if isinstance(tag, dict) and str(tag.get("term") or "").strip())
        metadata: dict[str, Any] = {
            "feed_url": self.source.url,
            "feed_source_id": self.source.source_id,
            "content_status": content_status,
            "observed_in": [self.source.source_id],
            **processing.metadata,
            "summary_processing": summary_processing.metadata,
        }
        if crawl:
            metadata["crawler"] = {"status": crawl.status, "page_type": crawl.page_type, "raw_content_hash": crawl.raw_content_hash, "extracted_content_hash": crawl.extracted_content_hash, "response": crawl.response_metadata}
        item = ExternalCTIItem(
            record_id=record_id, source_item_id=source_item_id, source=self.source.name, source_type="rss", category=self.source.category,
            title=title, link=link, content=processing.export_content, summary=summary_processing.export_content, published=self._published(entry), updated_at=self._updated(entry),
            author=str(entry.get("author") or "").strip() or None, tags=tags, language=str(entry.get("language") or "en"), collected_at=collected_at,
            content_hash=sha256_text(processing.export_content), classification=ExternalClassification(status="not_required"), metadata=metadata,
        )
        stable_item = item.to_dict()
        stable_item.pop("collected_at", None)
        record_hash, previous_hash = sha256_json(stable_item), item_state.get("record_hash")
        item_state.update({"source_item_id": source_item_id, "canonical_url": link, "clean_content_hash": processing.preprocessing.output_hash, "privacy_output_hash": processing.privacy.output_hash, "record_hash": record_hash, "last_checked": collected_at, "last_changed": collected_at if previous_hash != record_hash else item_state.get("last_changed", collected_at), "etag": crawl.response_metadata.get("etag") if crawl else None, "last_modified": crawl.response_metadata.get("last_modified") if crawl else None})
        if previous_hash == record_hash:
            return None, "unchanged"
        return item, "review" if content_status == "summary_only" or processing.review_required or summary_processing.review_required else "accepted"

    def _within_lookback(self, entry: Any) -> bool:
        if self.source.lookback_days == 0: return True
        parsed = entry.get("published_parsed") or entry.get("updated_parsed")
        if not parsed: return True
        return datetime.fromtimestamp(calendar.timegm(parsed), tz=timezone.utc) >= self.clock().astimezone(timezone.utc) - timedelta(days=self.source.lookback_days)

    @staticmethod
    def _published(entry: Any) -> str | None: return str(entry.get("published") or "").strip() or None
    @staticmethod
    def _updated(entry: Any) -> str | None: return str(entry.get("updated") or "").strip() or None
    def _now_iso(self) -> str: return self.clock().astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class ConfiguredRSSCollector:
    """Run enabled configured feeds with per-feed failure isolation."""

    def __init__(self, sources: Sequence[RSSSource | dict[str, Any]], *, connector_factory: Callable[[RSSSource], RSSConnector] | None = None) -> None:
        self.sources = tuple(source if isinstance(source, RSSSource) else RSSSource.from_mapping(source) for source in sources)
        self.connector_factory = connector_factory or RSSConnector.from_source

    def collect_results(self) -> list[RSSCollectionResult]:
        results: list[RSSCollectionResult] = []
        for source in self.sources:
            if not source.enabled: continue
            try: results.append(self.connector_factory(source).collect_result())
            except Exception: results.append(RSSCollectionResult(source.source_id, "failed", errors=[RSSCollectionError(source.source_id, "source_failed")]))
        return results
