from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

from backend.app.pipeline.common.cti_schema import RawRecord
from backend.app.pipeline.ingestion.base_connector import ExternalConnector
from backend.app.pipeline.ingestion.external.classification.classification_service import ClassificationService
from backend.app.pipeline.ingestion.external.common.hashing import sha256_json, sha256_text
from backend.app.pipeline.ingestion.external.common.models import ExternalCTIItem
from backend.app.pipeline.ingestion.external.crawler.web_crawler import WebCrawler
from backend.app.pipeline.ingestion.external.preprocessing.content_processor import ExternalContentProcessor
from backend.app.pipeline.ingestion.external.preprocessing.text_preprocessor import TextPreprocessor
from backend.app.pipeline.ingestion.external.privacy.privacy_filter import PrivacyFilter
from backend.app.pipeline.ingestion.external.manual_source.safe_http_client import SSRFProtectedHttpClient
from backend.app.pipeline.ingestion.external.manual_source.url_policy import ManualURLPolicy, URLPolicyError, ValidatedURL


PROJECT_ROOT = Path(__file__).resolve().parents[5]


class PlatformURLPolicy:
    """Apply public-network validation plus an exact HTTPS host/path constraint."""

    def __init__(self, host: str, path_validator: Callable[[str], bool], *, base: ManualURLPolicy | None = None) -> None:
        self.host, self.path_validator, self.base = host, path_validator, base or ManualURLPolicy()

    def validate(self, url: str, *, allow_onion: bool = False) -> ValidatedURL:
        del allow_onion
        validated = self.base.validate(url, allow_onion=False)
        parts = urlsplit(validated.canonical_url)
        if parts.scheme != "https" or parts.hostname != self.host or parts.port is not None or not self.path_validator(parts.path):
            raise URLPolicyError("source URL is outside the approved public transport")
        return validated


@dataclass(frozen=True, slots=True)
class SocialCandidate:
    source_id: str
    source_name: str
    platform: str
    item_id: str
    title: str
    canonical_url: str
    body: str = ""
    external_url: str | None = None
    published: str | None = None
    author: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class SocialError:
    source_id: str
    category: str
    retryable: bool = False


@dataclass(slots=True)
class SocialCollectionResult:
    source_id: str
    status: str = "completed"
    accepted_items: list[ExternalCTIItem] = field(default_factory=list)
    review_items: list[ExternalCTIItem] = field(default_factory=list)
    rejected_items: list[ExternalCTIItem] = field(default_factory=list)
    errors: list[SocialError] = field(default_factory=list)
    skipped_items: int = 0

    @property
    def all_items(self) -> list[ExternalCTIItem]:
        return [*self.accepted_items, *self.review_items, *self.rejected_items]


class SocialItemProcessor:
    """Shared social item enrichment, processing, state, and classification."""

    def __init__(self, *, crawler: WebCrawler | None = None, content_processor: ExternalContentProcessor | None = None, classification_service: ClassificationService | None = None, state: dict[str, Any] | None = None, clock=None) -> None:
        self.crawler = crawler or WebCrawler(http_client=SSRFProtectedHttpClient(ManualURLPolicy()))
        self.content_processor = content_processor or ExternalContentProcessor(TextPreprocessor(PROJECT_ROOT / "config" / "preprocessing_rules.json"), PrivacyFilter(PROJECT_ROOT / "config" / "privacy_rules.json"))
        self.classification_service = classification_service or ClassificationService()
        self.state = state if state is not None else {}
        self.state.setdefault("sources", {}); self.state.setdefault("items", {})
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def process(self, candidate: SocialCandidate) -> tuple[ExternalCTIItem | None, Literal["accepted", "review", "rejected", "unchanged"]]:
        record_id = f"social-{sha256_text(f'{candidate.platform}:{candidate.item_id}').split(':', 1)[1][:32]}"
        item_state = self.state["items"].setdefault(record_id, {})
        full_text, crawl_metadata, warning, exported_external_url = "", None, None, None
        if candidate.external_url:
            crawl = self.crawler.crawl(candidate.external_url, etag=item_state.get("etag"), last_modified=item_state.get("last_modified"))
            if crawl.status == "unchanged" and item_state.get("record_hash"):
                return None, "unchanged"
            if crawl.status == "success": full_text, exported_external_url = crawl.extracted_text, candidate.external_url
            else: warning = "external_article_unavailable"
            crawl_metadata = {"status": crawl.status, "error_categories": sorted({error.category for error in crawl.errors})}
        processing = self.content_processor.process(full_text or candidate.body)
        item = ExternalCTIItem(
            record_id=record_id, source_item_id=candidate.item_id, source=candidate.source_name,
            source_type=candidate.platform, category="social", title=candidate.title,
            link=candidate.canonical_url, content=processing.export_content,
            summary=processing.export_content[:300], published=candidate.published,
            updated_at=None, author=candidate.author, collected_at=self._now_iso(),
            content_hash=sha256_text(processing.export_content), metadata={"platform": candidate.platform,
            "observed_in": [candidate.source_id], "external_url": exported_external_url,
            "content_status": "full_text" if full_text else "source_text", **candidate.metadata,
            **processing.metadata, "crawler": crawl_metadata, "warning_category": warning},
        )
        classified = self.classification_service.classify_item(item)
        item = classified.item
        stable = item.to_dict(); stable.pop("collected_at", None)
        record_hash, previous = sha256_json(stable), item_state.get("record_hash")
        item_state.update({"source_item_id": candidate.item_id, "canonical_url": candidate.canonical_url,
            "raw_content_hash": sha256_json({"body": candidate.body, "metadata": candidate.metadata}),
            "extracted_content_hash": sha256_text(full_text or candidate.body),
            "clean_content_hash": processing.preprocessing.output_hash, "privacy_output_hash": processing.privacy.output_hash,
            "classification_output_hash": item.metadata.get("classification_stage", {}).get("output_hash"),
            "record_hash": record_hash, "last_checked": self._now_iso(),
            "last_changed": self._now_iso() if previous != record_hash else item_state.get("last_changed")})
        if previous == record_hash: return None, "unchanged"
        if processing.review_required or not processing.export_content: return item, "review"
        return item, classified.disposition if classified.disposition in {"accepted", "rejected"} else "review"

    def _now_iso(self) -> str: return self.clock().astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class SocialConnector(ExternalConnector):
    source_name = "social"

    def collect(self) -> Iterable[RawRecord]:
        for item in self.collect_result().accepted_items:
            yield item.to_raw_record()

    def collect_result(self) -> SocialCollectionResult:
        raise NotImplementedError

    @staticmethod
    def add(result: SocialCollectionResult, value: tuple[ExternalCTIItem | None, str]) -> None:
        item, disposition = value
        if item is None: result.skipped_items += 1
        elif disposition == "accepted": result.accepted_items.append(item)
        elif disposition == "rejected": result.rejected_items.append(item)
        else: result.review_items.append(item)


class ConfiguredSocialCollector:
    """Run independent social connectors with source-level failure isolation."""

    def __init__(self, connectors: Sequence[SocialConnector | Callable[[], SocialConnector]]) -> None:
        self.connectors = tuple(connectors)

    def collect_results(self) -> list[SocialCollectionResult]:
        results = []
        for configured in self.connectors:
            try:
                connector = configured() if callable(configured) else configured
                results.append(connector.collect_result())
            except Exception:
                source_id = getattr(getattr(configured, "source", None), "source_id", "unknown-social-source")
                results.append(SocialCollectionResult(source_id, "failed", errors=[SocialError(source_id, "source_failed")]))
        return results
