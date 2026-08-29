from __future__ import annotations

from abc import ABC, abstractmethod
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Protocol
from urllib.parse import urlsplit

from backend.app.pipeline.ingestion.external.classification.classification_service import ClassificationService
from backend.app.pipeline.ingestion.external.common.hashing import sha256_json, sha256_text
from backend.app.pipeline.ingestion.external.common.canonical_url import canonicalize_url
from backend.app.pipeline.ingestion.external.common.models import ExternalCTIItem, ExternalClassification
from backend.app.pipeline.ingestion.external.common.state_manager import JsonStateManager
from backend.app.pipeline.ingestion.external.crawler.web_crawler import EXTRACTION_IMPLEMENTATION_VERSION, CrawlResult, WebCrawler
from backend.app.pipeline.ingestion.external.crawler.page_type_detector import PAGE_DETECTION_IMPLEMENTATION_VERSION
from backend.app.pipeline.ingestion.external.manual_source.url_policy import ManualURLPolicy, URLPolicyError
from backend.app.pipeline.ingestion.external.manual_source.url_router import ManualURLRouter, URLRoute
from backend.app.pipeline.ingestion.external.preprocessing.content_processor import ExternalContentProcessor
from backend.app.pipeline.ingestion.external.preprocessing.text_preprocessor import TextPreprocessor
from backend.app.pipeline.ingestion.external.privacy.privacy_filter import PrivacyFilter


PROJECT_ROOT = Path(__file__).resolve().parents[6]
MIN_MANUAL_CONTENT_CHARACTERS = 120
MANUAL_TRACKED_ROOTS_VERSION = "1.0"
REVIEW_STAGE_IMPLEMENTATION_VERSION = "manual_review_v2"
UTILITY_PATH_SEGMENTS = frozenset({"contact", "support", "login", "signin", "signup", "account", "privacy", "terms", "legal"})


@dataclass(frozen=True, slots=True)
class ManualSourceResult:
    status: str
    message: str
    records_created: int = 0
    records_updated: int = 0
    canonical_url: str | None = None
    job_id: str | None = None
    accepted_records: int = 0
    review_records: int = 0
    rejected_records: int = 0
    skipped_records: int = 0
    error_count: int = 0


@dataclass(frozen=True, slots=True)
class ManualTrackedRoot:
    root_id: str
    canonical_url: str = field(repr=False)
    active: bool = True
    origin: str = "explicit"

    def safe_dict(self) -> dict[str, Any]:
        return {"root_id": self.root_id, "active": self.active, "origin": self.origin}


class ManualSourceService(ABC):
    @abstractmethod
    def validate_url(self, url: str) -> str:
        """Return the policy-approved canonical URL before a command is queued."""

    @abstractmethod
    def add_manual_source(self, url: str, *, requested_by: str) -> ManualSourceResult:
        """Validate and submit a public URL through policy-aware routing."""

    @abstractmethod
    def recheck_url(self, url: str, *, requested_by: str, force: bool = False) -> ManualSourceResult:
        """Request an incremental recheck without bypassing policy."""

    @abstractmethod
    def list_tracked_roots(self) -> tuple[ManualTrackedRoot, ...]:
        """Enumerate active operator-submitted roots without exposing them in API results."""


@dataclass(frozen=True, slots=True)
class AdapterResult:
    status: str
    items: tuple[ExternalCTIItem, ...] = ()
    message: str = "adapter completed"
    review_items: tuple[ExternalCTIItem, ...] = ()
    rejected_items: tuple[ExternalCTIItem, ...] = ()


class ManualAdapter(Protocol):
    def collect_url(self, canonical_url: str, *, identifier: str | None, source_id: str | None,
                    state: dict[str, Any]) -> AdapterResult: ...


class CanonicalManualSourceService(ManualSourceService):
    """Framework-independent URL operation for a future authenticated adapter."""

    def __init__(self, *, policy: ManualURLPolicy, crawler: WebCrawler, state_manager: JsonStateManager,
                 adapters: dict[str, ManualAdapter] | None = None, router: ManualURLRouter | None = None,
                 content_processor: ExternalContentProcessor | None = None,
                 classification_service: ClassificationService | None = None,
                 record_sink: Callable[[ExternalCTIItem, str], None] | None = None,
                 record_seen: Callable[[str, str, str | None], None] | None = None,
                 record_retire: Callable[[str, str, str, str | None], None] | None = None,
                 record_reconcile: Callable[[str, tuple[str, ...], str], tuple[tuple[str, str], ...]] | None = None,
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
        self.record_seen = record_seen or (lambda _record_id, _seen_at, _parent: None)
        self.record_retire = record_retire or (lambda _record_id, _reason, _retired_at, _parent: None)
        self.record_reconcile = record_reconcile or (lambda _parent, _current, _at: ())
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def add_manual_source(self, url: str, *, requested_by: str) -> ManualSourceResult:
        del requested_by  # authorization belongs to the future Phase 11 adapter
        try: validated = self.policy.validate(url)
        except URLPolicyError as exc: return ManualSourceResult("error", str(exc))
        canonical, route = validated.canonical_url, self.router.route(validated.canonical_url)
        state = deepcopy(self.state_manager.load())
        state.setdefault("urls", {}); state.setdefault("items", {}); state.setdefault("sources", {})
        self._migrate_tracked_roots(state)
        self._register_tracked_root(state, canonical)
        self.state_manager.save(state)
        if route.kind != "generic_web":
            return self._run_adapter(route, canonical, state)
        return self._run_web(canonical, state, force=False)

    def list_tracked_roots(self) -> tuple[ManualTrackedRoot, ...]:
        state = deepcopy(self.state_manager.load())
        changed = self._migrate_tracked_roots(state)
        if changed:
            self.state_manager.save(state)
        roots = state.get("tracked_roots", {})
        if not isinstance(roots, dict):
            return ()
        result = []
        for root_id in sorted(roots):
            value = roots[root_id]
            if not isinstance(value, dict) or value.get("active") is not True:
                continue
            canonical = value.get("canonical_url")
            if isinstance(canonical, str) and canonical:
                result.append(ManualTrackedRoot(root_id, canonical, True, str(value.get("origin") or "legacy_inferred")))
        return tuple(result)

    def validate_url(self, url: str) -> str:
        return self.policy.validate(url).canonical_url

    def recheck_url(self, url: str, *, requested_by: str, force: bool = False) -> ManualSourceResult:
        if not force: return self.add_manual_source(url, requested_by=requested_by)
        try: canonical = self.policy.validate(url).canonical_url
        except URLPolicyError as exc: return ManualSourceResult("error", str(exc))
        state = deepcopy(self.state_manager.load())
        route = self.router.route(canonical)
        return self._run_adapter(route, canonical, state) if route.kind != "generic_web" else self._run_web(canonical, state, force=True)

    def _run_adapter(self, route: URLRoute, canonical: str, state: dict[str, Any]) -> ManualSourceResult:
        state.setdefault("sources", {}).setdefault("manual_url", {})["source_config_hash"] = sha256_json(
            {"route": route.kind, "source_id": route.source_id}
        )
        adapter = self.adapters.get(route.kind)
        if adapter is None: return ManualSourceResult("ignored", f"{route.kind} adapter is not configured", canonical_url=canonical, rejected_records=1)
        try: outcome = adapter.collect_url(canonical, identifier=route.identifier, source_id=route.source_id, state=state)
        except Exception: return ManualSourceResult("error", f"{route.kind} adapter failed", canonical_url=canonical, error_count=1)
        created = updated = 0
        dispositions = [(item, "accepted") for item in outcome.items]
        dispositions.extend((item, "review") for item in outcome.review_items)
        dispositions.extend((item, "rejected") for item in outcome.rejected_items)
        for item, disposition in dispositions:
            existed = item.record_id in state.setdefault("items", {})
            self.record_sink(item, disposition)
            state["items"].setdefault(item.record_id, {})["record_hash"] = self._record_hash(item)
            updated += int(existed); created += int(not existed)
        self.state_manager.save(state)
        return ManualSourceResult(outcome.status, outcome.message, created, updated, canonical,
            accepted_records=len(outcome.items), review_records=len(outcome.review_items),
            rejected_records=len(outcome.rejected_items), skipped_records=int(outcome.status == "unchanged"),
            error_count=int(outcome.status == "error"))

    def _run_web(self, canonical: str, state: dict[str, Any], *, force: bool) -> ManualSourceResult:
        state.setdefault("sources", {}).setdefault("manual_url", {})["source_config_hash"] = sha256_json({"route": "generic_web", "max_listing_links": self.max_listing_links})
        url_state = state["urls"].setdefault(canonical, {})
        stage_fingerprint = self._stage_fingerprint()
        same_pipeline = url_state.get("stage_fingerprint") == stage_fingerprint
        crawl = self.crawler.crawl(canonical, etag=None if force or not same_pipeline else url_state.get("etag"),
                                   last_modified=None if force or not same_pipeline else url_state.get("last_modified"))
        if crawl.status == "unchanged":
            url_state["last_checked"] = self._now(); self.state_manager.save(state)
            return ManualSourceResult("unchanged", "source has not changed", canonical_url=canonical, skipped_records=1)
        if crawl.status != "success":
            media_type = str(crawl.response_metadata.get("content_type") or "").split(";", 1)[0].lower()
            if media_type in {"application/rss+xml", "application/atom+xml", "application/xml", "text/xml"}:
                return self._run_adapter(URLRoute("rss"), canonical, state)
            return ManualSourceResult("error", "URL collection failed safely", canonical_url=canonical, error_count=1)
        if crawl.page_type == "listing": return self._process_listing(canonical, crawl, state, stage_fingerprint)
        item, disposition, changed = self._process_article(canonical, crawl, state, stage_fingerprint)
        if item is None:
            self.state_manager.save(state); return ManualSourceResult("unchanged", "processed record has not changed", canonical_url=canonical, skipped_records=1)
        self.record_sink(item, disposition); self.state_manager.save(state)
        status = "review_required" if disposition == "review" else ("ignored" if disposition == "rejected" else "stored")
        return ManualSourceResult(status, "manual URL processed", int(changed == "created"), int(changed == "updated"), canonical,
            accepted_records=int(disposition == "accepted"), review_records=int(disposition == "review"),
            rejected_records=int(disposition == "rejected"))

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
        reconciled_at = self._now()
        reconciled = {link: record_id for record_id, link in self.record_reconcile(
            canonical, tuple(sorted(current)), reconciled_at
        )}
        missing_records = {missing: self._record_id(missing) for missing in previous - current}
        missing_records.update(reconciled)
        for missing, record_id in sorted(missing_records.items()):
            retired_at = reconciled_at
            state["urls"].setdefault(missing, {}).update({"missing_from_source": retired_at, "active": False,
                                                           "retired_at": retired_at, "retired_reason": "no_longer_discovered"})
            state["items"].setdefault(record_id, {}).update({"active": False, "retired_at": retired_at,
                                                              "retired_reason": "no_longer_discovered"})
            if missing not in reconciled:
                self.record_retire(record_id, "no_longer_discovered", retired_at, canonical)
        created = updated = accepted_count = review_count = rejected_count = skipped_count = 0
        for child in candidates:
            seen_at, record_id = self._now(), self._record_id(child)
            state["urls"].setdefault(child, {}).update({"active": True, "last_seen_at": seen_at})
            if record_id in state["items"]:
                state["items"][record_id].update({"active": True, "last_seen_at": seen_at})
                self.record_seen(record_id, seen_at, canonical)
            child_state = state["urls"].get(child, {})
            child_crawl = self.crawler.crawl(child, etag=child_state.get("etag") if child in previous else None,
                                             last_modified=child_state.get("last_modified") if child in previous else None)
            if child_crawl.status != "success": continue
            item, disposition, changed = self._process_article(child, child_crawl, state, fingerprint, parent=canonical)
            if item is not None:
                self.record_sink(item, disposition); created += int(changed == "created"); updated += int(changed == "updated")
                accepted_count += int(disposition == "accepted"); review_count += int(disposition == "review")
                rejected_count += int(disposition == "rejected")
            else: skipped_count += 1
        listing_state.update({"raw_content_hash": crawl.raw_content_hash, "extracted_content_hash": crawl.extracted_content_hash,
                              "sorted_link_set_hash": sha256_json(sorted(current)), "known_sub_links": sorted(current),
                              "stage_fingerprint": fingerprint, "last_checked": self._now(), **self._conditional(crawl)})
        self.state_manager.save(state)
        return ManualSourceResult("listing_processed", "bounded listing processed", created, updated, canonical,
            accepted_records=accepted_count, review_records=review_count, rejected_records=rejected_count,
            skipped_records=skipped_count)

    def _process_article(self, canonical: str, crawl: CrawlResult, state: dict[str, Any], fingerprint: str,
                         *, parent: str | None = None) -> tuple[ExternalCTIItem | None, str, str]:
        processed = self.content_processor.process(crawl.extracted_text)
        record_id, observed_at = self._record_id(canonical), self._now()
        metadata = {"parent_listing": parent, "lifecycle": {"active": True, "last_seen_at": observed_at}, **processed.metadata}
        item = ExternalCTIItem(record_id=record_id, source_item_id=canonical, source="Manual URL", source_type="manual_url",
                               category="manual", title=crawl.title or canonical, link=canonical, content=processed.export_content,
                               summary=self._article_summary(processed.export_content, crawl.title), published=crawl.published,
                               author=crawl.author, collected_at=observed_at, content_hash=sha256_text(processed.export_content),
                               metadata=metadata)
        gate = self._preclassification_gate(canonical, item.title, processed.export_content)
        if gate == "utility_page":
            final = ExternalCTIItem(**{**item.to_dict(), "tags": item.tags,
                "classification": ExternalClassification(status="rejected", label="utility_page"),
                "metadata": {**item.metadata, "relevance_gate": {"status": "excluded", "reason": gate}}})
            disposition = "rejected"
        elif gate == "short_content":
            final = ExternalCTIItem(**{**item.to_dict(), "tags": item.tags,
                "classification": ExternalClassification(status="not_run"),
                "metadata": {**item.metadata, "relevance_gate": {"status": "review_required", "reason": gate}}})
            disposition = "review"
        else:
            classified = self.classification_service.classify_item(item)
            final, disposition = classified.item, classified.disposition
        if processed.review_required or not processed.export_content or disposition == "review": disposition = "review"
        item_state = state["items"].setdefault(record_id, {})
        previous = item_state.get("record_hash"); record_hash = self._record_hash(final)
        changed = "updated" if previous else "created"
        url_state = state["urls"].setdefault(canonical, {})
        stages = {"extraction": {"input_hash": crawl.raw_content_hash, "output_hash": crawl.extracted_content_hash, "status": "completed", "timestamp": self._now(), "version": crawl.extraction_version},
                  "cleaning": {"input_hash": processed.preprocessing.input_hash, "output_hash": processed.preprocessing.output_hash, "status": "completed", "timestamp": self._now(), "version": processed.preprocessing.implementation_version},
                  "privacy": {"input_hash": processed.privacy.input_hash, "output_hash": processed.privacy.output_hash, "status": processed.privacy.status, "timestamp": self._now(), "version": processed.privacy.implementation_version},
                  "classification": {"input_hash": final.content_hash, "output_hash": final.metadata.get("classification_stage", {}).get("output_hash"), "status": final.classification.status, "timestamp": self._now(), "version": final.classification.model_version}}
        url_state.update({"raw_content_hash": crawl.raw_content_hash, "extracted_content_hash": crawl.extracted_content_hash,
                          "clean_content_hash": processed.preprocessing.output_hash, "privacy_output_hash": processed.privacy.output_hash,
                          "stage_fingerprint": fingerprint, "stages": stages, "last_checked": self._now(), **self._conditional(crawl)})
        item_state.update({"record_hash": record_hash, "last_checked": self._now(), "last_seen_at": observed_at,
                           "active": disposition == "accepted", "stages": stages})
        if previous == record_hash: return None, disposition, changed
        return final, disposition, changed

    def _stage_fingerprint(self) -> str:
        classifier = getattr(self.classification_service, "classifier", None)
        return sha256_json({"preprocessing_rules": self.content_processor.preprocessor.rules_hash,
                            "privacy_rules": self.content_processor.privacy_filter.rules_hash,
                            "model_version": getattr(classifier, "model_version", None),
                            "extraction_version": EXTRACTION_IMPLEMENTATION_VERSION,
                            "page_detection_version": PAGE_DETECTION_IMPLEMENTATION_VERSION,
                            "review_version": REVIEW_STAGE_IMPLEMENTATION_VERSION})

    @staticmethod
    def _article_summary(content: str, title: str, *, maximum_characters: int = 300) -> str:
        normalized_title = title.strip().casefold()
        meaningful = []
        for raw in content.splitlines():
            line = raw.strip()
            if not line or line.casefold() == normalized_title or len(line) < 40:
                continue
            meaningful.append(line)
            if len(" ".join(meaningful)) >= maximum_characters: break
        source = " ".join(meaningful) or content.strip()
        if len(source) <= maximum_characters: return source
        clipped = source[:maximum_characters + 1]
        boundary = clipped.rfind(" ", 0, maximum_characters + 1)
        return clipped[:boundary if boundary > maximum_characters // 2 else maximum_characters].rstrip()

    def _register_tracked_root(self, state: dict[str, Any], canonical: str) -> None:
        root_id = self._root_id(canonical)
        roots = state.setdefault("tracked_roots", {})
        previous = roots.get(root_id) if isinstance(roots.get(root_id), dict) else {}
        now = self._now()
        roots[root_id] = {
            **previous,
            "canonical_url": canonical,
            "active": True,
            "origin": "explicit",
            "added_at": previous.get("added_at") or now,
            "last_submitted_at": now,
        }

    def _migrate_tracked_roots(self, state: dict[str, Any]) -> bool:
        migrations = state.setdefault("migrations", {})
        marker = migrations.get("manual_tracked_roots")
        if isinstance(marker, dict) and marker.get("version") == MANUAL_TRACKED_ROOTS_VERSION:
            return False
        urls = state.get("urls", {})
        roots = state.setdefault("tracked_roots", {})
        known_children: set[str] = set()
        if isinstance(urls, dict):
            for value in urls.values():
                if not isinstance(value, dict): continue
                for child in value.get("known_sub_links", ()):
                    try: known_children.add(canonicalize_url(str(child)))
                    except ValueError: continue
            for raw_url, value in sorted(urls.items()):
                if not isinstance(value, dict): continue
                try: canonical = canonicalize_url(str(raw_url))
                except ValueError: continue
                if canonical in known_children: continue
                root_id = self._root_id(canonical)
                if root_id in roots: continue
                active = value.get("active") is not False and not value.get("retired_at") and not value.get("missing_from_source")
                roots[root_id] = {
                    "canonical_url": canonical,
                    "active": bool(active),
                    "origin": "legacy_inferred",
                    "added_at": value.get("first_seen_at") or value.get("last_checked") or self._now(),
                }
        migrations["manual_tracked_roots"] = {
            "version": MANUAL_TRACKED_ROOTS_VERSION,
            "applied_at": self._now(),
            "known_child_count": len(known_children),
        }
        return True

    @staticmethod
    def _conditional(crawl: CrawlResult) -> dict[str, Any]:
        return {"etag": crawl.response_metadata.get("etag"), "last_modified": crawl.response_metadata.get("last_modified")}
    @staticmethod
    def _record_hash(item: ExternalCTIItem) -> str:
        value = item.to_dict(); value.pop("collected_at", None)
        lifecycle = value.get("metadata", {}).get("lifecycle")
        if isinstance(lifecycle, dict): lifecycle.pop("last_seen_at", None); lifecycle.pop("retired_at", None)
        return sha256_json(value)
    @staticmethod
    def _record_id(url: str) -> str: return f"manual-{sha256_text(url).split(':', 1)[1][:32]}"
    @staticmethod
    def _root_id(url: str) -> str: return f"manual-root-{sha256_text(url).split(':', 1)[1][:32]}"
    @staticmethod
    def _preclassification_gate(url: str, title: str, content: str) -> str | None:
        segments = tuple(value.lower() for value in urlsplit(url).path.split("/") if value)
        lowered = f"{title} {content}".lower()
        marketing = sum(marker in lowered for marker in ("contact sales", "get started", "request a demo", "learn more about our products"))
        if any(value in UTILITY_PATH_SEGMENTS for value in segments) or (len(segments) == 3 and segments[:2] == ("blog", "products")) or marketing >= 2:
            return "utility_page"
        if len(content.strip()) < MIN_MANUAL_CONTENT_CHARACTERS: return "short_content"
        return None
    def _now(self) -> str:
        return self.clock().astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
