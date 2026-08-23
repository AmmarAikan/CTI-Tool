from __future__ import annotations

from abc import ABC, abstractmethod
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Protocol
from urllib.parse import urlsplit

from backend.app.pipeline.ingestion.external.classification.classification_service import ClassificationService
from backend.app.pipeline.ingestion.external.common.hashing import sha256_json, sha256_text
from backend.app.pipeline.ingestion.external.common.models import ExternalCTIItem
from backend.app.pipeline.ingestion.external.common.state_manager import JsonStateManager
from backend.app.pipeline.ingestion.external.crawler.web_crawler import CrawlResult, WebCrawler
from backend.app.pipeline.ingestion.external.manual_source.url_policy import ManualURLPolicy, URLPolicyError
from backend.app.pipeline.ingestion.external.manual_source.url_router import ManualURLRouter, URLRoute
from backend.app.pipeline.ingestion.external.preprocessing.content_processor import ExternalContentProcessor
from backend.app.pipeline.ingestion.external.preprocessing.text_preprocessor import TextPreprocessor
from backend.app.pipeline.ingestion.external.privacy.privacy_filter import PrivacyFilter


PROJECT_ROOT = Path(__file__).resolve().parents[6]


@dataclass(frozen=True, slots=True)
class ManualSourceResult:
    status: str
    message: str
    records_created: int = 0
    records_updated: int = 0
    canonical_url: str | None = None
    job_id: str | None = None


class ManualSourceService(ABC):
    @abstractmethod
    def add_manual_source(self, url: str, *, requested_by: str) -> ManualSourceResult:
        """Validate and submit a public URL through policy-aware routing."""

    @abstractmethod
    def recheck_url(self, url: str, *, requested_by: str, force: bool = False) -> ManualSourceResult:
        """Request an incremental recheck without bypassing policy."""


@dataclass(frozen=True, slots=True)
class AdapterResult:
    status: str
    items: tuple[ExternalCTIItem, ...] = ()
    message: str = "adapter completed"


class ManualAdapter(Protocol):
    def collect_url(self, canonical_url: str, *, identifier: str | None, state: dict[str, Any]) -> AdapterResult: ...


class CanonicalManualSourceService(ManualSourceService):
    """Framework-independent URL operation for a future authenticated adapter."""

    def __init__(self, *, policy: ManualURLPolicy, crawler: WebCrawler, state_manager: JsonStateManager,
                 adapters: dict[str, ManualAdapter] | None = None, router: ManualURLRouter | None = None,
                 content_processor: ExternalContentProcessor | None = None,
                 classification_service: ClassificationService | None = None,
                 record_sink: Callable[[ExternalCTIItem, str], None] | None = None,
                 max_listing_links: int = 20, clock: Callable[[], datetime] | None = None) -> None:
        if not 1 <= max_listing_links <= 20: raise ValueError("max_listing_links must be between 1 and 20")
        self.policy, self.crawler, self.state_manager = policy, crawler, state_manager
        self.adapters, self.router = adapters or {}, router or ManualURLRouter()
        self.content_processor = content_processor or ExternalContentProcessor(
            TextPreprocessor(PROJECT_ROOT / "config" / "preprocessing_rules.json"),
            PrivacyFilter(PROJECT_ROOT / "config" / "privacy_rules.json"),
        )
        self.classification_service = classification_service or ClassificationService()
        self.record_sink, self.max_listing_links = record_sink or (lambda _item, _disposition: None), max_listing_links
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def add_manual_source(self, url: str, *, requested_by: str) -> ManualSourceResult:
        del requested_by  # authorization belongs to the future Phase 11 adapter
        try: validated = self.policy.validate(url)
        except URLPolicyError as exc: return ManualSourceResult("error", str(exc))
        canonical, route = validated.canonical_url, self.router.route(validated.canonical_url)
        state = deepcopy(self.state_manager.load())
        state.setdefault("urls", {}); state.setdefault("items", {}); state.setdefault("sources", {})
        if route.kind != "generic_web":
            return self._run_adapter(route, canonical, state)
        return self._run_web(canonical, state, force=False)

    def recheck_url(self, url: str, *, requested_by: str, force: bool = False) -> ManualSourceResult:
        if not force: return self.add_manual_source(url, requested_by=requested_by)
        try: canonical = self.policy.validate(url).canonical_url
        except URLPolicyError as exc: return ManualSourceResult("error", str(exc))
        state = deepcopy(self.state_manager.load())
        route = self.router.route(canonical)
        return self._run_adapter(route, canonical, state) if route.kind != "generic_web" else self._run_web(canonical, state, force=True)

    def _run_adapter(self, route: URLRoute, canonical: str, state: dict[str, Any]) -> ManualSourceResult:
        state.setdefault("sources", {}).setdefault("manual_url", {})["source_config_hash"] = sha256_json({"route": route.kind})
        adapter = self.adapters.get(route.kind)
        if adapter is None: return ManualSourceResult("ignored", f"{route.kind} adapter is not configured", canonical_url=canonical)
        try: outcome = adapter.collect_url(canonical, identifier=route.identifier, state=state)
        except Exception: return ManualSourceResult("error", f"{route.kind} adapter failed", canonical_url=canonical)
        created = updated = 0
        for item in outcome.items:
            existed = item.record_id in state.setdefault("items", {})
            self.record_sink(item, "review" if outcome.status == "review_required" else "accepted")
            state["items"].setdefault(item.record_id, {})["record_hash"] = self._record_hash(item)
            updated += int(existed); created += int(not existed)
        self.state_manager.save(state)
        return ManualSourceResult(outcome.status, outcome.message, created, updated, canonical)

    def _run_web(self, canonical: str, state: dict[str, Any], *, force: bool) -> ManualSourceResult:
        state.setdefault("sources", {}).setdefault("manual_url", {})["source_config_hash"] = sha256_json({"route": "generic_web", "max_listing_links": self.max_listing_links})
        url_state = state["urls"].setdefault(canonical, {})
        stage_fingerprint = self._stage_fingerprint()
        same_pipeline = url_state.get("stage_fingerprint") == stage_fingerprint
        crawl = self.crawler.crawl(canonical, etag=None if force or not same_pipeline else url_state.get("etag"),
                                   last_modified=None if force or not same_pipeline else url_state.get("last_modified"))
        if crawl.status == "unchanged":
            url_state["last_checked"] = self._now(); self.state_manager.save(state)
            return ManualSourceResult("unchanged", "source has not changed", canonical_url=canonical)
        if crawl.status != "success":
            media_type = str(crawl.response_metadata.get("content_type") or "").split(";", 1)[0].lower()
            if media_type in {"application/rss+xml", "application/atom+xml", "application/xml", "text/xml"}:
                return self._run_adapter(URLRoute("rss"), canonical, state)
            return ManualSourceResult("error", "URL collection failed safely", canonical_url=canonical)
        if crawl.page_type == "listing": return self._process_listing(canonical, crawl, state, stage_fingerprint)
        item, disposition, changed = self._process_article(canonical, crawl, state, stage_fingerprint)
        if item is None:
            self.state_manager.save(state); return ManualSourceResult("unchanged", "processed record has not changed", canonical_url=canonical)
        self.record_sink(item, disposition); self.state_manager.save(state)
        status = "review_required" if disposition == "review" else ("ignored" if disposition == "rejected" else "stored")
        return ManualSourceResult(status, "manual URL processed", int(changed == "created"), int(changed == "updated"), canonical)

    def _process_listing(self, canonical: str, crawl: CrawlResult, state: dict[str, Any], fingerprint: str) -> ManualSourceResult:
        host = (urlsplit(canonical).hostname or "").lower()
        candidates = []
        for value in crawl.candidate_links:
            try: child = self.policy.validate(value, allow_onion=False).canonical_url
            except URLPolicyError: continue
            if (urlsplit(child).hostname or "").lower() == host and child not in candidates: candidates.append(child)
            if len(candidates) >= self.max_listing_links: break
        listing_state = state["urls"].setdefault(canonical, {})
        previous = set(listing_state.get("known_sub_links", [])); current = set(candidates)
        for missing in sorted(previous - current):
            state["urls"].setdefault(missing, {})["missing_from_source"] = self._now()
        created = updated = 0
        for child in candidates:
            child_state = state["urls"].get(child, {})
            child_crawl = self.crawler.crawl(child, etag=child_state.get("etag") if child in previous else None,
                                             last_modified=child_state.get("last_modified") if child in previous else None)
            if child_crawl.status != "success": continue
            item, disposition, changed = self._process_article(child, child_crawl, state, fingerprint, parent=canonical)
            if item is not None:
                self.record_sink(item, disposition); created += int(changed == "created"); updated += int(changed == "updated")
        listing_state.update({"raw_content_hash": crawl.raw_content_hash, "extracted_content_hash": crawl.extracted_content_hash,
                              "sorted_link_set_hash": sha256_json(sorted(current)), "known_sub_links": sorted(current),
                              "stage_fingerprint": fingerprint, "last_checked": self._now(), **self._conditional(crawl)})
        self.state_manager.save(state)
        return ManualSourceResult("listing_processed", "bounded listing processed", created, updated, canonical)

    def _process_article(self, canonical: str, crawl: CrawlResult, state: dict[str, Any], fingerprint: str,
                         *, parent: str | None = None) -> tuple[ExternalCTIItem | None, str, str]:
        processed = self.content_processor.process(crawl.extracted_text)
        record_id = f"manual-{sha256_text(canonical).split(':', 1)[1][:32]}"
        item = ExternalCTIItem(record_id=record_id, source_item_id=canonical, source="Manual URL", source_type="manual_url",
                               category="manual", title=crawl.title or canonical, link=canonical, content=processed.export_content,
                               summary=processed.export_content[:300], collected_at=self._now(), content_hash=sha256_text(processed.export_content),
                               metadata={"parent_listing": parent, **processed.metadata})
        classified = self.classification_service.classify_item(item)
        final, disposition = classified.item, classified.disposition
        if processed.review_required or not processed.export_content or disposition == "review": disposition = "review"
        item_state = state["items"].setdefault(record_id, {})
        previous = item_state.get("record_hash"); record_hash = self._record_hash(final)
        changed = "updated" if previous else "created"
        url_state = state["urls"].setdefault(canonical, {})
        stages = {"extraction": {"input_hash": crawl.raw_content_hash, "output_hash": crawl.extracted_content_hash, "status": "completed", "timestamp": self._now(), "version": "web_crawler_v1"},
                  "cleaning": {"input_hash": processed.preprocessing.input_hash, "output_hash": processed.preprocessing.output_hash, "status": "completed", "timestamp": self._now(), "version": processed.preprocessing.implementation_version},
                  "privacy": {"input_hash": processed.privacy.input_hash, "output_hash": processed.privacy.output_hash, "status": processed.privacy.status, "timestamp": self._now(), "version": processed.privacy.implementation_version},
                  "classification": {"input_hash": final.content_hash, "output_hash": final.metadata.get("classification_stage", {}).get("output_hash"), "status": final.classification.status, "timestamp": self._now(), "version": final.classification.model_version}}
        url_state.update({"raw_content_hash": crawl.raw_content_hash, "extracted_content_hash": crawl.extracted_content_hash,
                          "clean_content_hash": processed.preprocessing.output_hash, "privacy_output_hash": processed.privacy.output_hash,
                          "stage_fingerprint": fingerprint, "stages": stages, "last_checked": self._now(), **self._conditional(crawl)})
        item_state.update({"record_hash": record_hash, "last_checked": self._now(), "stages": stages})
        if previous == record_hash: return None, disposition, changed
        return final, disposition, changed

    def _stage_fingerprint(self) -> str:
        classifier = getattr(self.classification_service, "classifier", None)
        return sha256_json({"preprocessing_rules": self.content_processor.preprocessor.rules_hash,
                            "privacy_rules": self.content_processor.privacy_filter.rules_hash,
                            "model_version": getattr(classifier, "model_version", None)})

    @staticmethod
    def _conditional(crawl: CrawlResult) -> dict[str, Any]:
        return {"etag": crawl.response_metadata.get("etag"), "last_modified": crawl.response_metadata.get("last_modified")}
    @staticmethod
    def _record_hash(item: ExternalCTIItem) -> str:
        value = item.to_dict(); value.pop("collected_at", None); return sha256_json(value)
    def _now(self) -> str:
        return self.clock().astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
