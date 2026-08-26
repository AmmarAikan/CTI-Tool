from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import Any, Callable

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from backend.app.pipeline.ingestion.external.application.collection_service import (
    CanonicalCollectionService, CollectionExportCoordinator, RegisteredSource, SourceExecutionResult, SourceExecutor,
)
from backend.app.pipeline.ingestion.external.application.job_service import JobService, JobView
from backend.app.pipeline.ingestion.external.application.manual_source_service import (
    CanonicalManualSourceService, ManualAdapter, ManualSourceResult, ManualSourceService,
)
from backend.app.pipeline.ingestion.external.classification.classification_service import ClassificationService
from backend.app.pipeline.ingestion.external.common.canonical_url import canonicalize_url
from backend.app.pipeline.ingestion.external.common.models import ExternalCTIItem
from backend.app.pipeline.ingestion.external.common.hashing import sha256_bytes, sha256_json
from backend.app.pipeline.ingestion.external.common.run_manifest import RunManifest, generate_run_id
from backend.app.pipeline.ingestion.external.application.source_management_service import SourceManagementService, SourceView
from backend.app.pipeline.ingestion.external.common.json_storage import load_json
from backend.app.pipeline.ingestion.external.common.json_storage import save_json
from backend.app.pipeline.ingestion.external.common.logging import configure_file_logging
from backend.app.pipeline.ingestion.external.common.state_manager import JsonStateManager
from backend.app.pipeline.ingestion.external.integration.api import AdapterServices, create_app
from backend.app.pipeline.ingestion.external.integration.auth import RoleAuthorizer, StaticTokenAuthenticator
from backend.app.pipeline.ingestion.external.integration.idempotency import InMemoryIdempotencyStore
from backend.app.pipeline.ingestion.external.integration.jobs import InProcessJobRunner
from backend.app.pipeline.ingestion.external.cert_connector import CERTConnector, CERTSource
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
from backend.app.pipeline.ingestion.external.social_common import SocialItemProcessor
from backend.app.pipeline.ingestion.external.telegram_connector import TelegramConnector, TelegramSource
from backend.app.pipeline.ingestion.external.vulnerability_connector import VulnerabilityConnector, VulnerabilitySource
from backend.app.pipeline.ingestion.external.export.final_dataset import ExternalDatasetExporter, RunSourceOutput


PROJECT_ROOT = Path(__file__).resolve().parents[6]
ACTIVE_LOG_PATH = PROJECT_ROOT / "logs" / "cti_tool.log"
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
                registry[source_id] = RegisteredSource(source_id, source_type, bool(raw.get("enabled", True)), dict(raw))
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
        self.state_directory, self.processed_directory, self.review_directory = state_directory, processed_directory, review_directory
        self.dark_web_sources = {source.source_id: source for source in dark_web_sources}
        self.dark_web_client = dark_web_client

    def execute(self, source: RegisteredSource, *, force: bool, command_id: str) -> SourceExecutionResult:
        manager = JsonStateManager(self.state_directory / f"{source.source_type}_{source.source_id}.json")
        state = manager.load()
        if force and source.source_type != "dark_web":
            state.setdefault("sources", {}).pop(source.source_id, None)
        connector = self._connector(source, state)
        result = connector.collect_result(force=force) if source.source_type == "dark_web" else connector.collect_result()
        manager.save(state)
        accepted = list(getattr(result, "accepted_items", []))
        review = list(getattr(result, "review_items", []))
        rejected = list(getattr(result, "rejected_items", []))
        suffix = command_id.removeprefix("cmd-")
        prefix = f"{source.source_type}_{source.source_id}_{suffix}"
        if accepted:
            save_json([item.to_dict() for item in accepted], self.processed_directory / f"{prefix}.json")
        if review or rejected:
            save_json([item.to_dict() for item in [*review, *rejected]], self.review_directory / f"{prefix}.json")
        status = str(getattr(result, "status", "failed"))
        if source.source_type == "dark_web" and status == "unavailable": status = "failed"
        errors = list(getattr(result, "errors", []))
        return SourceExecutionResult(source_id=source.source_id, status=status, accepted_records=len(accepted),
            review_records=len(review), rejected_records=len(rejected),
            skipped_records=int(getattr(result, "skipped_items", 0)), error_count=len(errors),
            accepted=tuple(accepted), review=tuple(review), errors=tuple(str(value) for value in errors),
            rejected=tuple(rejected))

    def _connector(self, source: RegisteredSource, state: dict[str, Any]):
        raw = source.configuration
        if source.source_type == "rss":
            return self.rss_factory(RSSSource.from_mapping(raw), state)
        if source.source_type == "cert":
            return CERTConnector(CERTSource.from_mapping(raw), state=state)
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
    def __init__(self, registry: dict[str, RegisteredSource]) -> None:
        self._sources = {source_id: SourceView(source_id, str(source.configuration.get("name") or source_id),
            source.source_type, "enabled" if source.enabled else "disabled", {})
            for source_id, source in registry.items()}
    def list_sources(self) -> list[SourceView]: return sorted(self._sources.values(), key=lambda value: value.source_id)
    def get_source_status(self, source_id: str) -> SourceView | None: return self._sources.get(source_id)
    def request_source_enable(self, source_id: str, *, requested_by: str) -> SourceView:
        del requested_by; current = self._required(source_id); value = SourceView(current.source_id, current.name, current.source_type, "pending_review", current.metadata); self._sources[source_id] = value; return value
    def disable_source(self, source_id: str, *, requested_by: str) -> SourceView:
        del requested_by; current = self._required(source_id); value = SourceView(current.source_id, current.name, current.source_type, "disabled", current.metadata); self._sources[source_id] = value; return value
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
    def add_manual_source(self, url: str, *, requested_by: str) -> ManualSourceResult:
        return self._run(lambda: self.delegate.add_manual_source(url, requested_by=requested_by))
    def recheck_url(self, url: str, *, requested_by: str, force: bool = False) -> ManualSourceResult:
        return self._run(lambda: self.delegate.recheck_url(url, requested_by=requested_by, force=force))

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
    collection = CanonicalCollectionService(runner, registry, executor, exporter, manual_service=manual_delegate)
    manual = ExportingManualSourceService(manual_delegate, manual_sink, canonical_exporter, export_reader)
    return create_app(AdapterServices(StaticTokenAuthenticator(token, roles=roles), RoleAuthorizer(), collection,
        manual, DevelopmentSourceService(registry), DevelopmentJobService(runner, export_reader), runner, InMemoryIdempotencyStore()),
        docs_enabled=docs_enabled)


app = build_local_app(dark_web_config_path=Path(os.environ.get("EXTERNAL_DARK_WEB_CONFIG_PATH", str(LOCAL_CONFIG))))
