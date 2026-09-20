from __future__ import annotations

import os
import re
import threading
from collections import Counter
from copy import deepcopy
from pathlib import Path
from urllib.parse import urlsplit
from typing import Any, Callable

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError
from pydantic import ValidationError as PydanticValidationError

from backend.app.pipeline.ingestion.external.application.collection_service import (
    CanonicalCollectionService, CollectionExportCoordinator, RegisteredSource, SourceExecutionResult, SourceExecutor,
)
from backend.app.pipeline.ingestion.external.application.job_service import JobService, JobView
from backend.app.pipeline.ingestion.external.application.manual_source_service import (
    CanonicalManualSourceService, ManualAdapter, ManualSourceResult, ManualSourceService,
)
from backend.app.pipeline.ingestion.external.application.manual_preview_service import ManualPreviewService, SQLiteManualPreviewStore
from backend.app.pipeline.ingestion.external.application.dark_web_watch_service import SQLiteDarkWebWatchStore, DarkWebWatchScanner, DarkWebWatchService, DurableDarkWebScheduler
from backend.app.pipeline.ingestion.external.application.dark_web_discovery import AhmiaHTMLDiscovery, CandidateVerifier, DynamicDiscoveryScanner, ProviderHttpClient, load_discovery_providers
from backend.app.pipeline.ingestion.external.classification.classification_service import ClassificationService
from backend.app.pipeline.ingestion.external.common.canonical_url import canonicalize_url
from backend.app.pipeline.ingestion.external.common.models import ExternalCTIItem
from backend.app.pipeline.ingestion.external.common.hashing import sha256_bytes, sha256_json
from backend.app.pipeline.ingestion.external.common.run_manifest import RunManifest, generate_run_id
from backend.app.pipeline.ingestion.external.application.source_management_service import SourceManagementService, SourceView
from backend.app.pipeline.ingestion.external.common.json_storage import load_json, utc_now
from backend.app.pipeline.ingestion.external.common.json_storage import save_json
from backend.app.pipeline.ingestion.external.common.logging import configure_file_logging, get_logger
from backend.app.pipeline.ingestion.external.common.state_manager import JsonStateManager
from backend.app.pipeline.ingestion.external.integration.api import AdapterServices, create_app
from backend.app.pipeline.ingestion.external.integration.auth import RoleAuthorizer, StaticTokenAuthenticator
from backend.app.pipeline.ingestion.external.integration.idempotency import InMemoryIdempotencyStore
from backend.app.pipeline.ingestion.external.integration.jobs import InProcessJobRunner
from backend.app.pipeline.ingestion.external.integration.schemas import ReviewRecordResponse
from backend.app.pipeline.ingestion.external.cert_connector import CERTConnector, CERTSource
from backend.app.pipeline.ingestion.external.csaf_connector import CSAFConnector, CSAFSource
from backend.app.pipeline.ingestion.external.crawler.web_crawler import WebCrawler
from backend.app.pipeline.ingestion.external.manual_source.safe_http_client import SSRFProtectedHttpClient
from backend.app.pipeline.ingestion.external.manual_source.url_policy import ManualURLPolicy
from backend.app.pipeline.ingestion.external.manual_source.url_router import ManualURLRouter
from backend.app.pipeline.ingestion.external.manual_source.adapters import (
    DarkWebManualAdapter, build_registered_manual_adapters,
)
from backend.app.pipeline.ingestion.external.dark_web_connector import (
    LOCAL_CONFIG, DarkWebConfigurationError, DarkWebConnector, DarkWebSource, TorHttpClient, load_dark_web_config,
)
from backend.app.pipeline.ingestion.external.preprocessing.content_processor import ExternalContentProcessor
from backend.app.pipeline.ingestion.external.preprocessing.text_preprocessor import TextPreprocessor
from backend.app.pipeline.ingestion.external.privacy.privacy_filter import PrivacyFilter
from backend.app.pipeline.ingestion.external.rss_connector import RSSConnector, RSSSource
from backend.app.pipeline.ingestion.external.hackernews_connector import HackerNewsConnector, HackerNewsSource
from backend.app.pipeline.ingestion.external.reddit_connector import RedditConnector, RedditSource
from backend.app.pipeline.ingestion.external.social_common import PlatformURLPolicy, SocialItemProcessor
from backend.app.pipeline.ingestion.external.telegram_connector import TelegramConnector, TelegramSource
from backend.app.pipeline.ingestion.external.vulnerability_connector import VulnerabilityConnector, VulnerabilitySource
from backend.app.pipeline.ingestion.external.export.final_dataset import ExternalDatasetExporter, RunSourceOutput


PROJECT_ROOT = Path(__file__).resolve().parents[6]
ACTIVE_LOG_PATH = PROJECT_ROOT / "logs" / "cti_tool.log"
LOGGER = get_logger(__name__)
RSSConnectorFactory = Callable[[RSSSource, dict[str, Any]], RSSConnector]
MANUAL_LISTING_RECONCILIATION_VERSION = "1.0"


def load_collection_registry(path: Path = PROJECT_ROOT / "config" / "sources.json",
                             *, dark_web_sources: tuple[DarkWebSource, ...] = ()) -> dict[str, RegisteredSource]:
    config = load_json(path, default={})
    sections = {
        "rss_sources": "rss", "cert_sources": "cert", "vulnerability_sources": "vulnerability",
        "social_media_sources": "reddit", "hackernews_sources": "hackernews", "telegram_sources": "telegram",
    }
    registry: dict[str, RegisteredSource] = {}
    for section, source_type in sections.items():
        entries = config.get(section, []) if isinstance(config, dict) else []
        for raw in entries if isinstance(entries, list) else []:
            if not isinstance(raw, dict):
                continue
            source_id = str(raw.get("source_id") or "").strip()
            if source_id:
                configuration = dict(raw)
                if source_id in registry: raise ValueError("duplicate external source id")
                supported = True
                try:
                    if source_type == "reddit": RedditSource.from_mapping(configuration)
                    elif source_type == "telegram": TelegramSource.from_mapping(configuration)
                except ValueError: supported = False
                oauth = source_type == "reddit" and configuration.get("transport") == "reddit_oauth"
                configured = not oauth or all(os.environ.get(key) for key in ("REDDIT_CLIENT_ID", "REDDIT_CLIENT_SECRET", "REDDIT_USER_AGENT"))
                if oauth and bool(raw.get("enabled", True)) and not configured:
                    configuration["requires_configuration"] = True
                if not supported: configuration = {"source_id": source_id, "name": str(raw.get("name") or source_id), "unsupported_configuration": True}
                registry[source_id] = RegisteredSource(source_id, source_type, bool(raw.get("enabled", True)) and configured and supported, configuration)
    for source in dark_web_sources:
        if source.source_id in registry:
            raise DarkWebConfigurationError(f"duplicate external source id: {source.source_id}")
        registry[source.source_id] = RegisteredSource(source.source_id, "dark_web", source.enabled,
            {"source_id": source.source_id, "name": source.name, "category": source.category})
    return registry


class LocalCanonicalSourceExecutor(SourceExecutor):
    """Compose registered definitions with existing canonical collectors."""

    def __init__(self, *, rss_factory: RSSConnectorFactory | None = None,
                 dark_web_sources: tuple[DarkWebSource, ...] = (), dark_web_client: TorHttpClient | None = None,
                 state_directory: Path = PROJECT_ROOT / "data" / "external" / "state",
                 processed_directory: Path = PROJECT_ROOT / "data" / "external" / "processed",
                 review_directory: Path = PROJECT_ROOT / "data" / "external" / "review") -> None:
        self.rss_factory = rss_factory or (lambda source, state: RSSConnector.from_source(source, state=state))
        # An injected RSS factory marks a fully isolated connector composition; never add a live fallback behind it.
        self.compose_live_csaf = rss_factory is None
        self.state_directory, self.processed_directory, self.review_directory = state_directory, processed_directory, review_directory
        self.dark_web_sources = {source.source_id: source for source in dark_web_sources}
        self.dark_web_client = dark_web_client

    def execute(self, source: RegisteredSource, *, force: bool, command_id: str) -> SourceExecutionResult:
        stage = "state_load"
        try:
            manager = JsonStateManager(self.state_directory / f"{source.source_type}_{source.source_id}.json")
            state = manager.load()
            if force and source.source_type != "dark_web":
                state.setdefault("sources", {}).pop(source.source_id, None)
            stage = "connector_composition"
            connector = self._connector(source, state)
            stage = "connector_collection"
            result = connector.collect_result(force=force) if source.source_type == "dark_web" else connector.collect_result()
            stage = "state_save"
            manager.save(state)
        except Exception as exc:
            LOGGER.error("external source stage failed source_id=%s source_type=%s stage=%s exception_type=%s",
                         source.source_id, source.source_type, stage, type(exc).__name__)
            raise
        accepted = list(getattr(result, "accepted_items", []))
        review = list(getattr(result, "review_items", []))
        rejected = list(getattr(result, "rejected_items", []))
        suffix = command_id.removeprefix("cmd-")
        prefix = f"{source.source_type}_{source.source_id}_{suffix}"
        if accepted:
            save_json([item.to_dict() for item in accepted], self.processed_directory / f"{prefix}.json")
        if review or rejected:
            save_json([item.to_dict() for item in [*review, *rejected]], self.review_directory / f"{prefix}.json")
        errors = list(getattr(result, "errors", []))
        handled_count = len(accepted) + len(review) + len(rejected) + int(getattr(result, "skipped_items", 0))
        status = self._terminal_status(str(getattr(result, "status", "failed")), handled_count, len(errors))
        failure_categories = dict(Counter(
            str(getattr(error, "category", "internal_failure"))
            for error in errors
            if re.fullmatch(r"[a-z][a-z0-9_]{0,63}", str(getattr(error, "category", "")))
        ).most_common(20))
        category, retryable = self._safe_failure(errors)
        if errors:
            LOGGER.warning("external source completed with safe errors source_id=%s source_type=%s stage=connector_collection status=%s error_category=%s retryable=%s error_count=%s",
                           source.source_id, source.source_type, status, category or "internal_failure", retryable, len(errors))
        return SourceExecutionResult(source_id=source.source_id, status=status, accepted_records=len(accepted),
            review_records=len(review), rejected_records=len(rejected),
            skipped_records=int(getattr(result, "skipped_items", 0)), error_count=len(errors),
            accepted=tuple(accepted), review=tuple(review), errors=tuple(str(value) for value in errors),
            rejected=tuple(rejected), failure_category=category, retryable=retryable,
            collection_method=str(state.get("sources", {}).get(source.source_id, {}).get("collection_method") or "") or None,
            failure_categories=failure_categories)

    @staticmethod
    def _terminal_status(raw_status: str, handled_count: int, error_count: int) -> str:
        if raw_status in {"cancelled", "cancellation_requested"}:
            return raw_status
        if error_count:
            return "partial" if handled_count else "failed"
        return "completed"

    @staticmethod
    def _safe_failure(errors: list[Any]) -> tuple[str | None, bool]:
        if not errors:
            return None, False
        raw = str(getattr(errors[0], "category", "internal_failure"))
        if raw == "rate_limited":
            category = "rate_limited"
        elif raw in {"configuration_required", "source_configuration", "credentials_missing", "authorization_failed", "request_rejected"}:
            category = "source_configuration"
        elif raw == "source_access_unavailable":
            category = "source_access_unavailable"
        elif raw in {"rss_timeout", "rss_network_failure", "rss_http_failure", "playwright_unavailable", "browser_launch_failure", "navigation_timeout", "blocked_challenge_page", "rss_insufficient_results", "browser_insufficient_results"}:
            category = "upstream_temporarily_unavailable"
        elif raw in {"rss_parsing_failure", "dom_contract_change", "browser_redirect_rejected"}:
            category = "parsing_contract"
        elif raw in {"csaf_catalog_failed", "csaf_catalog_empty", "csaf_document_invalid",
                     "csaf_document_media_type", "csaf_mapping_invalid", "csaf_record_invalid"}:
            category = "parsing_contract"
        elif raw == "csaf_document_request_failed":
            category = "upstream_temporarily_unavailable"
        elif raw in {"invalid_feed", "invalid_response", "malformed_response", "parse_failed", "contract_failed", "parsing_contract"}:
            category = "parsing_contract"
        elif raw in {"network_failure", "network_timeout", "upstream_unavailable", "upstream_temporarily_unavailable", "feed_request_failed", "request_failed", "timeout"}:
            category = "upstream_temporarily_unavailable"
        else:
            category = "internal_failure"
        return category, bool(getattr(errors[0], "retryable", False))

    def _connector(self, source: RegisteredSource, state: dict[str, Any]):
        raw = source.configuration
        if source.source_type == "rss":
            return self.rss_factory(RSSSource.from_mapping(raw), state)
        if source.source_type == "cert":
            cert_source = CERTSource.from_mapping(raw)
            if cert_source.source_id == "cisa-advisories":
                policy = PlatformURLPolicy("www.cisa.gov", lambda path: path == "/cybersecurity-advisories/all.xml")
                csaf = None
                catalog_url = raw.get("csaf_catalog_url")
                document_base = raw.get("csaf_document_base_url")
                if self.compose_live_csaf and isinstance(catalog_url, str) and isinstance(document_base, str):
                    catalog_policy = PlatformURLPolicy("api.github.com", lambda path: path == "/repos/cisagov/CSAF/git/trees/develop")
                    document_policy = PlatformURLPolicy("raw.githubusercontent.com", lambda path: path.startswith("/cisagov/CSAF/develop/csaf_files/"))
                    processor = ExternalContentProcessor(
                        TextPreprocessor(PROJECT_ROOT / "config" / "preprocessing_rules.json"),
                        PrivacyFilter(PROJECT_ROOT / "config" / "privacy_rules.json"),
                    )
                    csaf = CSAFConnector(CSAFSource(
                        cert_source.source_id, cert_source.name, catalog_url, document_base,
                        max_advisories=min(cert_source.max_items, int(raw.get("csaf_max_advisories", cert_source.max_items))),
                    ), catalog_client=SSRFProtectedHttpClient(catalog_policy),
                        document_client=SSRFProtectedHttpClient(document_policy), content_processor=processor, state=state)
                return CERTConnector(cert_source, http_client=SSRFProtectedHttpClient(policy), state=state,
                                     csaf_connector=csaf)
            return CERTConnector(cert_source, state=state)
        if source.source_type == "vulnerability":
            return VulnerabilityConnector([VulnerabilitySource.from_mapping(raw)], state=state)
        processor = SocialItemProcessor(state=state)
        if source.source_type == "hackernews":
            return HackerNewsConnector(HackerNewsSource.from_mapping(raw), processor=processor)
        if source.source_type == "telegram":
            return TelegramConnector(TelegramSource.from_mapping(raw), processor=processor)
        if source.source_type == "reddit":
            return RedditConnector(RedditSource.from_mapping(raw), processor=processor)
        if source.source_type == "dark_web":
            configured = self.dark_web_sources.get(source.source_id)
            if configured is None and self.dark_web_client is not None and isinstance(raw.get("protected_url"),str):
                path=urlsplit(raw["protected_url"]).path or "/"
                configured=DarkWebSource(source.source_id,str(raw.get("name") or source.source_id),raw["protected_url"],(path,),True,max_items=1)
            if configured is None or self.dark_web_client is None:
                raise ValueError("registered dark-web source composition is unavailable")
            return DarkWebConnector((configured,), self.dark_web_client, state=state)
        raise ValueError("registered source type has no canonical connector")


class LocalManualRecordSink:
    """Atomic local operational sink and explicit accepted-manual checkpoint set."""

    def __init__(self, processed_directory: Path, review_directory: Path, checkpoint_manager: JsonStateManager,
                 provenance_resolver: Callable[[str], str | None] | None = None,
                 listing_state_manager: JsonStateManager | None = None) -> None:
        self.processed_directory, self.review_directory = processed_directory, review_directory
        self.checkpoint_manager, self._local, self._lock = checkpoint_manager, threading.local(), threading.Lock()
        self.provenance_resolver = provenance_resolver or (lambda _record_id: None)
        self.listing_state_manager = listing_state_manager

    def __call__(self, item: ExternalCTIItem, disposition: str) -> None:
        directory = self.processed_directory if disposition == "accepted" else self.review_directory
        persisted = item.to_dict()
        with self._lock:
            checkpoints = self.checkpoint_manager.load(); accepted = checkpoints.setdefault("accepted", {})
            retired = checkpoints.setdefault("retired", {})
            if disposition == "accepted":
                previous = accepted.get(item.record_id)
                if isinstance(previous, dict):
                    persisted["collected_at"] = previous.get("collected_at") or persisted["collected_at"]
                    previous_run = previous.get("metadata", {}).get("run_id")
                    if previous_run: persisted.setdefault("metadata", {})["run_id"] = previous_run
                accepted[item.record_id] = persisted
            else:
                previous = accepted.pop(item.record_id, None)
                if previous:
                    retired[item.record_id] = {"record": previous, "reason": "no_longer_accepted",
                                               "retired_at": item.collected_at}
            self.checkpoint_manager.save(checkpoints)
        save_json(persisted, directory / f"manual_{item.record_id}.json")
        captured = getattr(self._local, "captured", None)
        if captured is not None:
            captured.append((item, disposition)); self._local.material = True

    def begin(self) -> None: self._local.captured, self._local.material = [], False
    def end(self) -> tuple[tuple[tuple[ExternalCTIItem, str], ...], bool]:
        values = tuple(getattr(self._local, "captured", ())); material = bool(getattr(self._local, "material", False))
        self._local.captured, self._local.material = None, False
        return values, material
    def accepted(self) -> tuple[dict[str, Any], ...]:
        values = self.checkpoint_manager.load().get("accepted", {})
        if not isinstance(values, dict): return ()
        listing_state = self.listing_state_manager.load() if self.listing_state_manager else None
        return tuple(values[key] for key in sorted(values) if self._is_active(values[key], listing_state))

    @staticmethod
    def _is_active(record: dict[str, Any], listing_state: dict[str, Any] | None) -> bool:
        metadata = record.get("metadata", {}); lifecycle = metadata.get("lifecycle", {})
        if "active" in lifecycle: return lifecycle["active"] is True
        parent = metadata.get("parent_listing")
        if not parent: return True
        if listing_state is None: return True
        try:
            canonical_parent = canonicalize_url(str(parent))
            link = canonicalize_url(str(record.get("link") or record.get("source_item_id") or ""))
            known = listing_state.get("urls", {}).get(canonical_parent, {}).get("known_sub_links", ())
            return link in {canonicalize_url(str(value)) for value in known}
        except (TypeError, ValueError):
            return False

    def mark_seen(self, record_id: str, seen_at: str, parent: str | None) -> None:
        with self._lock:
            checkpoints = self.checkpoint_manager.load(); record = checkpoints.setdefault("accepted", {}).get(record_id)
            if not isinstance(record, dict): return
            lifecycle = record.setdefault("metadata", {}).setdefault("lifecycle", {})
            lifecycle.update({"active": True, "last_seen_at": seen_at})
            if parent: lifecycle["parent_listing"] = parent
            self.checkpoint_manager.save(checkpoints)

    def retire(self, record_id: str, reason: str, retired_at: str, parent: str | None) -> None:
        with self._lock:
            checkpoints = self.checkpoint_manager.load(); accepted = checkpoints.setdefault("accepted", {})
            record = accepted.pop(record_id, None)
            if not isinstance(record, dict): return
            lifecycle = record.setdefault("metadata", {}).setdefault("lifecycle", {})
            self._backfill_provenance(record_id, record)
            lifecycle.update({"active": False, "retired_at": retired_at, "reason": reason, "retired_reason": reason})
            if parent: lifecycle["parent_listing"] = parent
            checkpoints.setdefault("retired", {})[record_id] = {
                "record": record, "reason": reason, "retired_at": retired_at, "parent_listing": parent,
            }
            self.checkpoint_manager.save(checkpoints)
            if getattr(self._local, "captured", None) is not None: self._local.material = True

    def reconcile_listing(self, parent: str, current_links: tuple[str, ...], reconciled_at: str) -> tuple[tuple[str, str], ...]:
        """Migrate and reconcile legacy accepted children against one authoritative listing snapshot."""
        canonical_parent = canonicalize_url(parent)
        current = {canonicalize_url(link) for link in current_links}
        retired_values: list[tuple[str, str]] = []
        with self._lock:
            checkpoints = self.checkpoint_manager.load(); accepted = checkpoints.setdefault("accepted", {})
            retired = checkpoints.setdefault("retired", {})
            for record_id in sorted(tuple(accepted)):
                record = accepted.get(record_id)
                if not isinstance(record, dict) or record.get("source_type") != "manual_url": continue
                metadata = record.setdefault("metadata", {})
                record_parent = metadata.get("parent_listing")
                if not record_parent:
                    continue  # legacy standalone Manual URLs remain active
                try:
                    if canonicalize_url(str(record_parent)) != canonical_parent: continue
                    link = canonicalize_url(str(record.get("link") or record.get("source_item_id") or ""))
                except ValueError:
                    continue
                self._backfill_provenance(record_id, record)
                lifecycle = metadata.setdefault("lifecycle", {})
                if link in current:
                    lifecycle.update({"active": True, "last_seen_at": reconciled_at})
                    continue
                lifecycle.update({"active": False, "retired_at": reconciled_at,
                                  "reason": "no_longer_discovered", "retired_reason": "no_longer_discovered"})
                accepted.pop(record_id, None)
                retired.setdefault(record_id, {"record": record, "reason": "no_longer_discovered",
                                                "retired_at": reconciled_at, "parent_listing": canonical_parent})
                retired_values.append((record_id, link))
            migrations = checkpoints.setdefault("migrations", {})
            migration = migrations.setdefault("manual_listing_reconciliation", {
                "version": MANUAL_LISTING_RECONCILIATION_VERSION, "parents": {},
            })
            migration["version"] = MANUAL_LISTING_RECONCILIATION_VERSION
            migration["last_applied_at"] = reconciled_at
            migration.setdefault("parents", {})[canonical_parent] = {
                "snapshot_hash": sha256_json(sorted(current)), "reconciled_at": reconciled_at,
            }
            self.checkpoint_manager.save(checkpoints)
            if retired_values and getattr(self._local, "captured", None) is not None: self._local.material = True
        return tuple(retired_values)

    def _backfill_provenance(self, record_id: str, record: dict[str, Any]) -> None:
        metadata = record.setdefault("metadata", {})
        if metadata.get("run_id"): return
        original_run_id = self.provenance_resolver(record_id)
        if original_run_id: metadata["run_id"] = original_run_id


def build_canonical_manual_service(*, policy: ManualURLPolicy | None = None, crawler: WebCrawler | None = None,
                                   classification_service: ClassificationService | None = None,
                                   adapters: dict[str, ManualAdapter] | None = None,
                                   router: ManualURLRouter | None = None,
                                   state_path: Path = PROJECT_ROOT / "data" / "external" / "state" / "manual_sources.json",
                                   processed_directory: Path = PROJECT_ROOT / "data" / "external" / "processed",
                                   review_directory: Path = PROJECT_ROOT / "data" / "external" / "review",
                                   record_sink: LocalManualRecordSink | None = None) -> CanonicalManualSourceService:
    url_policy = policy or ManualURLPolicy()
    web_crawler = crawler or WebCrawler(http_client=SSRFProtectedHttpClient(url_policy))
    processor = ExternalContentProcessor(
        TextPreprocessor(PROJECT_ROOT / "config" / "preprocessing_rules.json"),
        PrivacyFilter(PROJECT_ROOT / "config" / "privacy_rules.json"),
    )
    resolved_sink = record_sink or LocalManualRecordSink(
        processed_directory, review_directory,
        JsonStateManager(PROJECT_ROOT / "data" / "external" / "state" / "manual_checkpoints.json"),
        listing_state_manager=JsonStateManager(state_path),
    )
    return CanonicalManualSourceService(
        policy=url_policy,
        crawler=web_crawler,
        state_manager=JsonStateManager(state_path),
        adapters=adapters,
        router=router,
        content_processor=processor,
        classification_service=classification_service or ClassificationService(),
        record_sink=resolved_sink,
        record_seen=resolved_sink.mark_seen,
        record_retire=resolved_sink.retire,
        record_reconcile=resolved_sink.reconcile_listing,
    )


class DevelopmentSourceService(SourceManagementService):
    def __init__(self, registry: dict[str, RegisteredSource], manual_service: ManualSourceService | None = None,
                 dark_web_store: SQLiteDarkWebWatchStore | None=None,job_runner:InProcessJobRunner|None=None) -> None:
        self._manual_service = manual_service
        self._dark_web_store,self._job_runner=dark_web_store,job_runner
        self._sources = {source_id: SourceView(source_id, str(source.configuration.get("name") or source_id),
            source.source_type, "unsupported_configuration" if source.configuration.get("unsupported_configuration") else "requires_configuration" if source.configuration.get("requires_configuration") else "ready" if source.enabled and source.source_type in {"reddit", "telegram"} else "enabled" if source.enabled else "disabled",
            {"transport": str(source.configuration["transport"]), "limitation": "public_feed_availability" if source.source_type == "reddit" else "configured_public_channels_only"}
            if source.source_type in {"reddit", "telegram"} and source.configuration.get("transport") else {} if source.source_type=="dark_web" else {"origin": "seeded"})
            for source_id, source in registry.items()}
        self._review_state={source_id:("approved" if source.enabled else "pending") for source_id,source in registry.items()}
    def _manual(self) -> dict[str, SourceView]:
        if self._manual_service is None: return {}
        return {root.root_id: SourceView(root.root_id, root.safe_dict()["label"], "dark_web" if root.method=="dark_web" else "manual_url",
            "enabled" if root.active else "disabled", {"origin": "user", "method": root.method})
            for root in self._manual_service.list_tracked_roots()}
    def _promoted(self)->dict[str,SourceView]:
        if self._dark_web_store is None:return {}
        return {item["source_id"]:SourceView(item["source_id"],item["onion_reference"],"dark_web","enabled" if item["enabled"] else "disabled",{"origin":"promoted","method":"tor"}) for item in self._dark_web_store.list_all_discovered()}
    def list_sources(self) -> list[SourceView]: return sorted((*self._sources.values(), *self._manual().values(),*self._promoted().values()), key=lambda value: value.source_id)
    def get_source_status(self, source_id: str) -> SourceView | None: return self._sources.get(source_id) or self._manual().get(source_id) or self._promoted().get(source_id)
    def request_source_enable(self, source_id: str, *, requested_by: str) -> SourceView:
        del requested_by
        if source_id in self._manual():
            self._manual_service.set_tracked_root_enabled(source_id, True)
            return self._manual()[source_id]
        if source_id in self._promoted():
            self._dark_web_store.set_discovered_enabled(source_id,True)
            return self._promoted()[source_id]
        current = self._required(source_id)
        status="enabled" if self._review_state[source_id]=="approved" else "pending_review"
        value = SourceView(current.source_id, current.name, current.source_type, status, current.metadata); self._sources[source_id] = value; return value
    def disable_source(self, source_id: str, *, requested_by: str) -> SourceView:
        del requested_by
        if source_id in self._manual():
            self._manual_service.set_tracked_root_enabled(source_id, False)
            return self._manual()[source_id]
        if source_id in self._promoted():
            self._dark_web_store.set_discovered_enabled(source_id,False)
            return self._promoted()[source_id]
        current = self._required(source_id); value = SourceView(current.source_id, current.name, current.source_type, "disabled", current.metadata); self._sources[source_id] = value; return value
    def delete_source(self, source_id: str, *, requested_by: str) -> None:
        del requested_by
        if source_id in self._sources: raise ValueError("seeded_source")
        if source_id in self._promoted():
            if self._job_runner is not None and self._job_runner.has_active_source(source_id):raise ValueError("active_job")
            self._dark_web_store.archive_discovered(source_id);return
        if source_id not in self._manual(): raise KeyError(source_id)
        self._manual_service.remove_tracked_root(source_id)
    def _required(self, source_id: str) -> SourceView:
        if source_id not in self._sources: raise KeyError(source_id)
        return self._sources[source_id]


class LocalValidatedExportReader:
    def __init__(self, exports_directory: Path) -> None:
        self.exports_directory = exports_directory
        self.item_validator = Draft202012Validator(load_json(PROJECT_ROOT / "contracts" / "external_cti_item.schema.json"))
        self.manifest_validator = Draft202012Validator(load_json(PROJECT_ROOT / "contracts" / "external_export_manifest.schema.json"))

    def latest(self) -> dict[str, Any] | None:
        candidates = sorted(self.exports_directory.glob("external_export_manifest_*.json"), key=lambda value: value.stat().st_mtime_ns, reverse=True)
        for path in candidates:
            validated = self._validated(path)
            if validated is None: continue
            value, dataset = validated
            result = {key: value.get(key) for key in ("run_id", "status", "dataset_sha256", "accepted_records", "review_records", "completed_at")}
            result.update({"dataset": dataset, "manifest": value})
            return result
        return None

    def earliest_run_id(self, record_id: str) -> str | None:
        matches: list[tuple[str, str]] = []
        for path in self.exports_directory.glob("external_export_manifest_*.json"):
            validated = self._validated(path)
            if validated is None: continue
            manifest, dataset = validated
            if any(record.get("record_id") == record_id for record in dataset):
                matches.append((str(manifest.get("started_at") or manifest.get("completed_at") or ""), str(manifest["run_id"])))
        return min(matches)[1] if matches else None

    def historical_accepted(self, *, limit: int, offset: int) -> dict[str, Any] | None:
        latest = self.latest()
        if latest is None:
            return None
        versions: dict[str, tuple[str, dict[str, Any]]] = {}
        manifests = []
        for path in self.exports_directory.glob("external_export_manifest_*.json"):
            validated = self._validated(path)
            if validated is not None:
                manifests.append(validated)
        for manifest, dataset in sorted(manifests, key=lambda value: (
                str(value[0].get("completed_at") or ""), str(value[0]["run_id"]))):
            for record in dataset:
                record_id = str(record.get("record_id") or "")
                if record_id:
                    versions[record_id] = (str(manifest["run_id"]), record)
            if len(versions) > 10_000:
                raise ValueError("historical accepted export exceeds bounded synchronization limit")
        items = []
        for record_id in sorted(versions)[offset:offset + limit]:
            run_id, record = versions[record_id]
            projected = dict(record)
            link = str(projected.get("link") or "")
            if ".onion" in link.lower():
                projected["link"] = None
            projected["metadata"] = {**dict(projected.get("metadata") or {}), "export_run_id": run_id}
            items.append(projected)
        return {"schema_version": "1.0", "export_run_id": str(latest["run_id"]),
                "dataset_sha256": str(latest["dataset_sha256"]), "items": items,
                "total": len(versions), "limit": limit, "offset": offset}

    def run_accepted(self, run_id: str, *, limit: int, offset: int) -> dict[str, Any] | None:
        if not run_id or Path(run_id).name != run_id: return None
        candidates = self.exports_directory.glob("external_export_manifest_*.json")
        validated = next((value for path in candidates if (value := self._validated(path)) is not None
                          and str(value[0].get("run_id")) == run_id), None)
        if validated is None: return None
        manifest, dataset = validated
        items = []
        for record in dataset[offset:offset + limit]:
            projected = dict(record)
            if ".onion" in str(projected.get("link") or "").lower(): projected["link"] = None
            projected["metadata"] = {**dict(projected.get("metadata") or {}), "export_run_id": run_id}
            items.append(projected)
        return {"schema_version": "1.0", "export_run_id": run_id,
                "dataset_sha256": str(manifest["dataset_sha256"]), "items": items,
                "total": len(dataset), "limit": limit, "offset": offset}

    def _validated(self, path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]] | None:
        value = load_json(path, default={})
        try:
            self.manifest_validator.validate(value)
            name = str(value["dataset_file"])
            if Path(name).name != name: return None
            dataset_path = self.exports_directory / name
            dataset = load_json(dataset_path, default=None)
            if not isinstance(dataset, list) or sha256_bytes(dataset_path.read_bytes()) != value["dataset_sha256"]: return None
            for record in dataset: self.item_validator.validate(record)
        except (OSError, KeyError, TypeError, ValueError, ValidationError):
            return None
        return value, dataset


class DevelopmentJobService(JobService):
    def __init__(self, runner: InProcessJobRunner, export_reader: LocalValidatedExportReader) -> None:
        self.runner, self.export_reader = runner, export_reader
    def get_job_status(self, job_id: str) -> JobView | None: return None
    def cancel_job(self, job_id: str, *, requested_by: str) -> JobView:
        del requested_by; raise KeyError(job_id)
    def get_latest_export(self) -> dict[str, Any] | None: return self.export_reader.latest()


class LocalReviewService:
    """Project a validated run's review file into the narrow authenticated API contract."""

    def __init__(self, review_directory: Path, export_reader: LocalValidatedExportReader,
                 exporter: ExternalDatasetExporter) -> None:
        self.review_directory, self.export_reader, self.exporter = review_directory, export_reader, exporter
        self._lock = threading.Lock()

    def latest(self) -> dict[str, Any] | None:
        latest = self.export_reader.latest()
        if not latest: return None
        run_id = str(latest["run_id"])
        values: list[dict[str, Any]] = []
        # Review artifacts are immutable run snapshots. Pending work is therefore
        # the bounded union of snapshots, not merely the newest export's file.
        paths = sorted(self.review_directory.glob("external_review_*.json"),
                       key=lambda value: value.stat().st_mtime_ns, reverse=True)[:100]
        seen: set[tuple[str, str]] = set()
        for path in paths:
            entries = load_json(path, default=None)
            if not isinstance(entries, list): continue
            for entry in entries[:1000]:
                record = entry.get("record") if isinstance(entry, dict) else None
                identity = (str(record.get("record_id") or ""), str(record.get("content_hash") or "")) if isinstance(record, dict) else ("", "")
                if identity not in seen:
                    seen.add(identity); values.append(entry)
        state = self.exporter.state_manager.load()
        decisions = state.get("review_decisions") if isinstance(state.get("review_decisions"), dict) else {}
        decided = {(str(value.get("record_id")), str(value.get("content_sha256"))) for value in decisions.values()
                   if isinstance(value, dict) and value.get("decision") in {"approved", "rejected"}}
        records = []
        for entry in values[:1000]:
            if not isinstance(entry, dict) or not isinstance(entry.get("record"), dict): continue
            record = entry["record"]
            metadata = record.get("metadata") if isinstance(record.get("metadata"), dict) else {}
            privacy = metadata.get("privacy") if isinstance(metadata.get("privacy"), dict) else {}
            classification = record.get("classification") if isinstance(record.get("classification"), dict) else {}
            stages = metadata.get("stages") if isinstance(metadata.get("stages"), dict) else {}
            stage_status = {str(key): str(value.get("status")) for key, value in stages.items()
                            if key in {"extraction", "cleaning", "privacy", "classification"} and isinstance(value, dict) and value.get("status")}
            link = str(record.get("link") or "") or None
            if link and ".onion" in link.lower(): link = "onion://[redacted]"
            reasons = [str(value) for value in entry.get("reason_codes", []) if isinstance(value, str)]
            specific = next((value for value in reasons if value != "collector_review"), str(entry.get("reason") or "collector_review"))
            record_id=str(record.get("record_id") or "");content_hash=str(record.get("content_hash") or "")
            content = str(record.get("content") or "");summary=str(record.get("summary") or "")
            if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{15,99}",record_id)
                    or not re.fullmatch(r"sha256:[0-9a-f]{64}",content_hash) or not content.strip()): continue
            decision = decisions.get(f"{record_id}:{content_hash}")
            if isinstance(decision, dict) and decision.get("decision") == "rejected": continue
            status = "pending"
            if isinstance(decision, dict) and decision.get("decision") == "approved":
                status = "processing_failed" if decision.get("processing_state") == "processing_failed" else "approved_processing"
            safe=lambda value,limit:re.sub(r"https?://\S+|\b\S*\.onion\b","[redacted]"," ".join(str(value or "").split()),flags=re.I)[:limit]
            projected={"record_id": record_id, "canonical_url": link,
                "title": safe(record.get("title"),300) or None, "source_type": safe(record.get("source_type"),100) or None,
                "review_reason": specific, "review_reasons": reasons, "stage_status": stage_status,
                "classification_label": classification.get("label"), "privacy_status": privacy.get("status"),
                "collected_at": record.get("collected_at"), "published": record.get("published"),
                "content_sha256": content_hash, "review_version":str(entry.get("review_version") or "external_review_v2")[:40],
                "summary":safe(summary,500),"excerpt": safe(content,2000),
                "source": safe(record.get("source") or "Unknown",200),
                "category": str(record.get("category") or "unknown")[:80], "status": status}
            try: records.append(ReviewRecordResponse.model_validate(projected).model_dump())
            except PydanticValidationError: continue
        return {"run_id": run_id, "records": sorted(records, key=lambda value: value["record_id"])[:100]}

    def lifecycle(self) -> dict[str, Any]:
        latest = self.latest()
        pending = {(item["record_id"], item["content_sha256"]): item for item in (latest or {}).get("records", [])}
        state = self.exporter.state_manager.load()
        decisions = state.get("review_decisions") if isinstance(state.get("review_decisions"), dict) else {}
        items: list[dict[str, Any]] = []
        for (record_id, content_hash), record in pending.items():
            decision = decisions.get(f"{record_id}:{content_hash}")
            if not isinstance(decision, dict):
                items.append({"record_id": record_id, "review_id": record_id, "content_sha256": content_hash,
                    "external_job_id": None, "export_run_id": None, "dataset_sha256": None,
                    "state": "pending_review", "stage": "review", "retryable": False,
                    "updated_at": str(record.get("collected_at") or utc_now())})
        for value in decisions.values():
            if not isinstance(value, dict): continue
            decision = value.get("decision")
            processing = value.get("processing_state")
            lifecycle_state = "rejected" if decision == "rejected" else "processing_failed" if processing == "processing_failed" else "approved_processing"
            export_run_id = value.get("export_run_id") if isinstance(value.get("export_run_id"), str) else None
            dataset_sha256 = None
            if export_run_id:
                export = self.export_reader.run_accepted(export_run_id, limit=1, offset=0)
                dataset_sha256 = export.get("dataset_sha256") if isinstance(export, dict) else None
            items.append({"record_id": value.get("record_id"), "review_id": value.get("record_id"),
                "content_sha256": value.get("content_sha256"), "external_job_id": value.get("external_job_id"),
                "export_run_id": export_run_id, "dataset_sha256": dataset_sha256,
                "state": lifecycle_state, "stage": "review" if decision == "rejected" else "central_import" if processing == "completed" else "export",
                "retryable": value.get("retryable") is True, "updated_at": value.get("decided_at")})
        return {"schema_version": "1.0", "items": items[-1000:]}

    def decide(self, record_id: str, expected_content_sha256: str, decision: str, reason: str | None,
               *, requested_by: str) -> dict[str, Any]:
        if decision not in {"approved", "rejected"} or (decision == "rejected" and reason not in {
                "not_relevant", "duplicate", "privacy_risk", "low_quality"}):
            raise ValueError("invalid_review_decision")
        key = f"{record_id}:{expected_content_sha256}"
        with self._lock:
            state = self.exporter.state_manager.load()
            decisions = state.setdefault("review_decisions", {})
            for value in decisions.values():
                if isinstance(value, dict) and value.get("record_id") == record_id and value.get("content_sha256") != expected_content_sha256:
                    raise RuntimeError("review_content_changed")
            previous = decisions.get(key)
            if isinstance(previous, dict):
                if previous.get("decision") != decision or previous.get("reason") != reason:
                    raise RuntimeError("review_already_decided")
                if previous.get("processing_state") is None and previous.get("export_run_id"):
                    previous.update({"processing_state": "completed", "retryable": False,
                                     "export_run_id": previous.get("export_run_id") if decision == "approved" else None})
                    decisions[key] = previous; self.exporter.state_manager.save(state)
                if previous.get("processing_state") == "completed": return self._public_decision(previous)
            source_run_id = str(previous.get("source_run_id")) if isinstance(previous, dict) else ""
            review_entries = None
            selected = None
            paths = ([self.review_directory / f"external_review_{source_run_id}.json"] if source_run_id else
                     sorted(self.review_directory.glob("external_review_*.json"),
                            key=lambda value: value.stat().st_mtime_ns, reverse=True)[:100])
            for review_path in paths:
                entries = load_json(review_path, default=None)
                if not isinstance(entries, list): continue
                match = next((entry for entry in entries if isinstance(entry, dict)
                              and isinstance(entry.get("record"), dict)
                              and entry["record"].get("record_id") == record_id), None)
                if match is not None:
                    review_entries, selected = entries, match
                    if not source_run_id:
                        source_run_id = review_path.name.removeprefix("external_review_").removesuffix(".json")
                    break
            if selected is None: raise KeyError("review_not_found")
            record = selected["record"]
            if record.get("content_hash") != expected_content_sha256: raise RuntimeError("review_content_changed")
            if previous is None:
                previous = {"schema_version": "1.0", "record_id": record_id,
                            "content_sha256": expected_content_sha256, "decision": decision,
                            "reason": reason, "decided_at": utc_now(), "decided_by": requested_by,
                            "source_run_id": source_run_id, "processing_state": "pending_export" if decision == "approved" else "completed",
                            "retryable": decision == "approved", "export_run_id": generate_run_id() if decision == "approved" else None}
                decisions[key] = previous
                self.exporter.state_manager.save(state)
                LOGGER.info("review lifecycle boundary stage=decision_persisted record_id=%s review_id=%s content_hash=%s export_run_id=%s",
                            record_id, record_id, expected_content_sha256, previous.get("export_run_id"))
            if decision == "rejected": return self._public_decision(previous)
            try:
                latest_source = self.export_reader.run_accepted(source_run_id, limit=10_000, offset=0)
                prior_accepted = tuple(latest_source.get("items", ())) if isinstance(latest_source, dict) else ()
                remaining = tuple(entry["record"] for entry in review_entries if entry is not selected
                                  and isinstance(entry, dict) and isinstance(entry.get("record"), dict))
                approved_record = self._approved_record(record, previous)
                manifest = RunManifest(run_id=str(previous["export_run_id"]), started_at=str(previous["decided_at"]))
                exported = self.exporter.export(manifest, (RunSourceOutput(
                    manifest.run_id, "review_decision", "completed", prior_accepted + (approved_record,), remaining),))
                exported_records = load_json(exported.dataset_path, default=[])
                if (not isinstance(exported_records, list)
                        or not any(value.get("content_hash") == expected_content_sha256 for value in exported_records if isinstance(value, dict))):
                    raise RuntimeError("approved_record_not_exported")
                previous.update({"processing_state": "completed", "retryable": False,
                                 "export_run_id": exported.manifest["run_id"]})
                state = self.exporter.state_manager.load(); state.setdefault("review_decisions", {})[key] = previous
                self.exporter.state_manager.save(state)
                LOGGER.info("review lifecycle boundary stage=export_ready record_id=%s review_id=%s content_hash=%s export_run_id=%s dataset_digest=%s",
                            record_id, record_id, expected_content_sha256, exported.manifest["run_id"], exported.manifest["dataset_sha256"])
                return self._public_decision(previous)
            except Exception as exc:
                state = self.exporter.state_manager.load()
                failed = dict(state.setdefault("review_decisions", {}).get(key) or previous)
                failed.update({"processing_state": "processing_failed", "retryable": True})
                state["review_decisions"][key] = failed; self.exporter.state_manager.save(state)
                LOGGER.warning("review lifecycle boundary stage=export_failed record_id=%s review_id=%s content_hash=%s export_run_id=%s exception_class=%s",
                               record_id, record_id, expected_content_sha256, failed.get("export_run_id"), type(exc).__name__)
                return self._public_decision(failed)

    @staticmethod
    def _approved_record(record: dict[str, Any], decision: dict[str, Any]) -> dict[str, Any]:
        approved = deepcopy(record)
        classification = approved.get("classification") if isinstance(approved.get("classification"), dict) else {}
        privacy = approved.setdefault("metadata", {}).get("privacy")
        approved.setdefault("metadata", {})["review_approval"] = {
            "decision": "approved", "decided_at": decision["decided_at"],
            "original_classification_status": classification.get("status"),
            "original_privacy_status": privacy.get("status") if isinstance(privacy, dict) else None,
        }
        approved["classification"] = {**classification, "status": "accepted"}
        if isinstance(privacy, dict):
            privacy["status"] = "reviewed"; privacy["high_confidence_unresolved"] = False
        return approved

    @staticmethod
    def _public_decision(value: dict[str, Any]) -> dict[str, Any]:
        return {key: value.get(key) for key in ("schema_version", "record_id", "content_sha256", "decision", "reason",
                                                "decided_at", "export_run_id", "processing_state", "retryable")}


class LocalCollectionExportCoordinator(CollectionExportCoordinator):
    """Adapt run-scoped collection results to the sole canonical Phase 10 exporter."""

    def __init__(self, exporter: ExternalDatasetExporter, manual_sink: LocalManualRecordSink) -> None:
        self.exporter, self.manual_sink = exporter, manual_sink

    def begin_manual_capture(self) -> None:
        self.manual_sink.begin()

    def end_manual_capture(self) -> tuple[tuple[ExternalCTIItem, str], ...]:
        captured, _material = self.manual_sink.end()
        return captured

    def export(self, run_id: str, started_at: str, results: tuple[SourceExecutionResult, ...]) -> dict[str, Any]:
        manifest = RunManifest(run_id=run_id, started_at=started_at)
        outputs = tuple(RunSourceOutput(run_id, value.source_id, value.status, value.accepted, value.review, value.errors)
                        for value in results)
        manual = self.manual_sink.accepted()
        if manual: outputs += (RunSourceOutput(run_id, "manual_url", "completed", manual),)
        exported = self.exporter.export(manifest, outputs)
        return {"status": "completed", "run_id": run_id, "dataset_sha256": exported.manifest["dataset_sha256"],
                "accepted_records": exported.manifest["accepted_records"], "review_records": exported.manifest["review_records"]}

    def export_unified(self, run_id: str, started_at: str, results: tuple[SourceExecutionResult, ...],
                       manual_results: dict[str, dict[str, Any]],
                       manual_review: tuple[ExternalCTIItem, ...]) -> dict[str, Any]:
        manifest = RunManifest(run_id=run_id, started_at=started_at)
        outputs = [RunSourceOutput(run_id, value.source_id, value.status, value.accepted, value.review, value.errors)
                   for value in results]
        active_manual = self.manual_sink.accepted()
        if active_manual or manual_review:
            outputs.append(RunSourceOutput(run_id, "manual_url", "completed", active_manual, manual_review))
        for root_id, value in sorted(manual_results.items()):
            if value.get("status") == "failed":
                outputs.append(RunSourceOutput(run_id, root_id, "failed", errors=("manual_source_failed",)))
        exported = self.exporter.export(manifest, tuple(outputs))
        return {"status": "completed", "run_id": run_id,
                "dataset_sha256": exported.manifest["dataset_sha256"],
                "accepted_records": exported.manifest["accepted_records"],
                "review_records": exported.manifest["review_records"],
                "dataset_file": exported.dataset_path.name,
                "manifest_file": exported.manifest_path.name,
                "review_file": exported.review_path.name}


class ExportingManualSourceService(ManualSourceService):
    """Export explicit Manual Source checkpoints after a material operation."""

    def __init__(self, delegate: ManualSourceService, sink: LocalManualRecordSink,
                 exporter: ExternalDatasetExporter, reader: LocalValidatedExportReader) -> None:
        self.delegate, self.sink, self.exporter, self.reader = delegate, sink, exporter, reader

    def validate_url(self, url: str) -> str: return self.delegate.validate_url(url)
    def list_tracked_roots(self): return self.delegate.list_tracked_roots()
    def set_tracked_root_enabled(self, root_id: str, enabled: bool):
        return self.delegate.set_tracked_root_enabled(root_id, enabled)
    def remove_tracked_root(self, root_id: str) -> None: self.delegate.remove_tracked_root(root_id)
    def add_manual_source(self, url: str, *, requested_by: str) -> ManualSourceResult:
        return self._run(lambda: self.delegate.add_manual_source(url, requested_by=requested_by))
    def recheck_url(self, url: str, *, requested_by: str, force: bool = False) -> ManualSourceResult:
        return self._run(lambda: self.delegate.recheck_url(url, requested_by=requested_by, force=force))
    def commit_preview(self, bundle, *, requested_by: str) -> ManualSourceResult:
        return self.delegate.commit_preview(bundle, requested_by=requested_by)

    def _run(self, operation: Callable[[], ManualSourceResult]) -> ManualSourceResult:
        self.sink.begin()
        try: result = operation()
        finally: captured, material = self.sink.end()
        if not material or result.status == "unchanged": return result
        accepted = self.sink.accepted()
        current_review = tuple(item for item, disposition in captured if disposition != "accepted")
        latest = self.reader.latest()
        prior = tuple(record for record in (latest or {}).get("dataset", ()) if record.get("source_type") != "manual_url")
        run_id = generate_run_id(); manifest = RunManifest(run_id=run_id)
        grouped_prior: dict[str, list[dict[str, Any]]] = {}
        for record in prior:
            observed = record.get("metadata", {}).get("observed_in", [])
            source_id = str(observed[0] if observed else record.get("source_type") or "external")
            grouped_prior.setdefault(source_id, []).append(record)
        outputs = [RunSourceOutput(run_id, source_id, "completed", tuple(records))
                   for source_id, records in sorted(grouped_prior.items())]
        if accepted or current_review:
            outputs.append(RunSourceOutput(run_id, "manual_url", "completed", accepted, current_review))
        try: self.exporter.export(manifest, outputs)
        except Exception:
            return ManualSourceResult("error", "manual record was checkpointed but export failed safely",
                                      result.records_created, result.records_updated, result.canonical_url)
        return result


def build_local_app(*, connector_factory: RSSConnectorFactory | None = None,
                    collection_executor: SourceExecutor | None = None,
                    dark_web_config_path: Path = LOCAL_CONFIG, dark_web_client: TorHttpClient | None = None,
                    state_directory: Path = PROJECT_ROOT / "data" / "external" / "state",
                    processed_directory: Path = PROJECT_ROOT / "data" / "external" / "processed",
                    review_directory: Path = PROJECT_ROOT / "data" / "external" / "review",
                    exports_directory: Path = PROJECT_ROOT / "data" / "external" / "exports",
                    export_state_path: Path = PROJECT_ROOT / "data" / "external" / "state" / "export_runs.json",
                    collection_exporter: CollectionExportCoordinator | None = None,
                    log_path: Path = ACTIVE_LOG_PATH, docs_enabled: bool | None = None,
                    manual_policy: ManualURLPolicy | None = None, manual_crawler: WebCrawler | None = None,
                    manual_classification_service: ClassificationService | None = None,
                    manual_adapters: dict[str, ManualAdapter] | None = None,
                    manual_state_path: Path = PROJECT_ROOT / "data" / "external" / "state" / "manual_sources.json",
                    manual_checkpoint_path: Path = PROJECT_ROOT / "data" / "external" / "state" / "manual_checkpoints.json"):
    token = os.environ.get("EXTERNAL_API_TOKEN", "")
    if not token: raise RuntimeError("EXTERNAL_API_TOKEN must be set before starting the local internal API")
    roles = frozenset(value.strip() for value in os.environ.get("EXTERNAL_API_ROLES", "operator").split(",") if value.strip())
    if docs_enabled is None:
        docs_enabled = os.environ.get("EXTERNAL_API_DOCS_ENABLED", "").strip().lower() == "true"
    # Static Onion sources are optional. Manual roots and promoted discoveries
    # are resolved independently and must continue to work with this tuple empty
    # or containing only disabled definitions.
    dark_proxy, dark_sources = (load_dark_web_config(dark_web_config_path)
                                if dark_web_config_path.exists() else (None, ()))
    resolved_dark_client = dark_web_client or (TorHttpClient(dark_proxy) if dark_proxy is not None else None)
    registry = load_collection_registry(dark_web_sources=dark_sources)
    configure_file_logging(log_path)
    runner = InProcessJobRunner(max_workers=int(os.environ.get("EXTERNAL_API_DEV_WORKERS", "2")))
    executor = collection_executor or LocalCanonicalSourceExecutor(rss_factory=connector_factory, state_directory=state_directory,
                                                                   processed_directory=processed_directory, review_directory=review_directory,
                                                                   dark_web_sources=dark_sources, dark_web_client=resolved_dark_client)
    canonical_exporter = ExternalDatasetExporter(exports_dir=exports_directory, review_dir=review_directory,
                                                  state_manager=JsonStateManager(export_state_path))
    export_reader = LocalValidatedExportReader(exports_directory)
    manual_sink = LocalManualRecordSink(processed_directory, review_directory, JsonStateManager(manual_checkpoint_path),
                                        provenance_resolver=export_reader.earliest_run_id,
                                        listing_state_manager=JsonStateManager(manual_state_path))
    exporter = collection_exporter or LocalCollectionExportCoordinator(canonical_exporter, manual_sink)
    resolved_policy = manual_policy
    resolved_adapters = build_registered_manual_adapters(registry)
    if dark_sources and resolved_dark_client is not None:
        dark_connector = DarkWebConnector(dark_sources, resolved_dark_client, state={})
        resolved_adapters["dark_web"] = DarkWebManualAdapter(dark_sources, dark_connector)
    if manual_adapters: resolved_adapters.update(manual_adapters)
    if resolved_policy is None:
        resolved_policy = ManualURLPolicy(approved_onion=lambda url: any(
            source.enabled and source.allows(url) for source in dark_sources
        ))
    manual_delegate = build_canonical_manual_service(policy=resolved_policy, crawler=manual_crawler,
                                            classification_service=manual_classification_service,
                                            adapters=resolved_adapters, router=ManualURLRouter(registry), state_path=manual_state_path,
                                            processed_directory=processed_directory, review_directory=review_directory,
                                            record_sink=manual_sink)
    manual = ExportingManualSourceService(manual_delegate, manual_sink, canonical_exporter, export_reader)
    preview_store = SQLiteManualPreviewStore(
        state_directory / "manual_previews.sqlite3",
        ttl_seconds=int(os.environ.get("EXTERNAL_PREVIEW_TTL_SECONDS", "900")),
    )
    previews = ManualPreviewService(
        manual_delegate, preview_store,
        lambda bundle, actor: manual.commit_preview(bundle, requested_by=actor),
    )
    discovery_scanner=None
    discovery_path=Path(os.environ.get("EXTERNAL_DARK_WEB_DISCOVERY_CONFIG_PATH", "")) if os.environ.get("EXTERNAL_DARK_WEB_DISCOVERY_CONFIG_PATH") else None
    if discovery_path is not None and resolved_dark_client is not None:
        providers=load_discovery_providers(discovery_path); provider_http=ProviderHttpClient(resolved_dark_client.proxy.url)
        discoveries={provider.provider_id:AhmiaHTMLDiscovery(provider,provider_http.fetch) for provider in providers}
        privacy=PrivacyFilter(PROJECT_ROOT / "config" / "privacy_rules.json")
        candidate_client=TorHttpClient(
            resolved_dark_client.proxy, connect_timeout=resolved_dark_client.connect_timeout,
            read_timeout=min(resolved_dark_client.read_timeout,15), max_response_bytes=1_048_576,
            retries=resolved_dark_client.retries, backoff_seconds=resolved_dark_client.backoff_seconds,
            max_redirects=resolved_dark_client.max_redirects,
            allowed_content_types=("text/html","text/plain"),
        )
        verifier=CandidateVerifier(candidate_client,lambda text:(lambda result:(result.content,result.status,["privacy_review"] if result.status=="review_required" else []))(privacy.apply(text)))
        discovery_scanner=DynamicDiscoveryScanner(discoveries,verifier)
    watch_service = (DarkWebWatchService(SQLiteDarkWebWatchStore(state_directory / "dark_web_watches.sqlite3"),
                                         DarkWebWatchScanner(dark_sources, resolved_dark_client),discovery_scanner)
                     if resolved_dark_client is not None and (dark_sources or discovery_scanner is not None) else None)
    def promoted_source(source_id:str)->RegisteredSource|None:
        item=watch_service.store.resolve_discovered(source_id) if watch_service else None
        return (RegisteredSource(source_id,"dark_web",item["enabled"],{"source_id":source_id,"name":item["onion_reference"],"protected_url":item["protected_url"]}) if item else None)
    collection = CanonicalCollectionService(runner, registry, executor, exporter, manual_service=manual,dynamic_source=promoted_source)
    scheduler=(DurableDarkWebScheduler(watch_service,runner,
               poll_seconds=float(os.environ.get("EXTERNAL_DARK_WEB_SCHEDULER_POLL_SECONDS","5")),
               lease_seconds=int(os.environ.get("EXTERNAL_DARK_WEB_SCHEDULER_LEASE_SECONDS","30")))
               if watch_service is not None else None)
    return create_app(AdapterServices(StaticTokenAuthenticator(token, roles=roles), RoleAuthorizer(), collection,
        manual, DevelopmentSourceService(registry, manual,watch_service.store if watch_service else None,runner), DevelopmentJobService(runner, export_reader), runner,
        InMemoryIdempotencyStore(), LocalReviewService(review_directory, export_reader, canonical_exporter), previews, watch_service, scheduler),
        docs_enabled=docs_enabled)


app = build_local_app(dark_web_config_path=Path(os.environ.get("EXTERNAL_DARK_WEB_CONFIG_PATH", str(LOCAL_CONFIG))))
