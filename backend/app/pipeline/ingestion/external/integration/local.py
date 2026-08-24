from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Any, Callable

from backend.app.pipeline.ingestion.external.application.collection_service import CollectionRequest, CollectionService, JobAccepted
from backend.app.pipeline.ingestion.external.application.job_service import JobService, JobView
from backend.app.pipeline.ingestion.external.application.manual_source_service import ManualSourceResult, ManualSourceService
from backend.app.pipeline.ingestion.external.application.source_management_service import SourceManagementService, SourceView
from backend.app.pipeline.ingestion.external.common.json_storage import latest_file, load_json
from backend.app.pipeline.ingestion.external.common.json_storage import save_json
from backend.app.pipeline.ingestion.external.common.logging import configure_file_logging
from backend.app.pipeline.ingestion.external.common.state_manager import JsonStateManager
from backend.app.pipeline.ingestion.external.integration.api import AdapterServices, create_app
from backend.app.pipeline.ingestion.external.integration.auth import RoleAuthorizer, StaticTokenAuthenticator
from backend.app.pipeline.ingestion.external.integration.idempotency import InMemoryIdempotencyStore
from backend.app.pipeline.ingestion.external.integration.jobs import InProcessJobRunner
from backend.app.pipeline.ingestion.external.rss_connector import RSSConnector, RSSSource


PROJECT_ROOT = Path(__file__).resolve().parents[6]
ACTIVE_LOG_PATH = PROJECT_ROOT / "logs" / "cti_tool.log"
RSSConnectorFactory = Callable[[RSSSource, dict[str, Any]], RSSConnector]


class DevelopmentCollectionService(CollectionService):
    """Local application-service composition for approved canonical RSS jobs."""

    def __init__(self, runner: InProcessJobRunner, *, sources_path: Path = PROJECT_ROOT / "config" / "sources.json",
                 connector_factory: RSSConnectorFactory | None = None,
                 state_directory: Path = PROJECT_ROOT / "data" / "external" / "state",
                 processed_directory: Path = PROJECT_ROOT / "data" / "external" / "processed",
                 review_directory: Path = PROJECT_ROOT / "data" / "external" / "review") -> None:
        self.runner = runner
        self.connector_factory = connector_factory or (lambda source, state: RSSConnector.from_source(source, state=state))
        self.state_directory, self.processed_directory, self.review_directory = state_directory, processed_directory, review_directory
        config = load_json(sources_path, default={})
        entries = config.get("rss_sources", []) if isinstance(config, dict) else []
        self.rss_sources = {source.source_id: source for source in (RSSSource.from_mapping(raw) for raw in entries if isinstance(raw, dict))}

    def start_collection(self, request: CollectionRequest) -> JobAccepted:
        source_ids = request.source_ids or tuple(source_id for source_id, source in self.rss_sources.items() if source.enabled)
        for source_id in source_ids:
            self._require_enabled_rss(source_id)
        command_id = f"cmd-{secrets.token_hex(12)}"
        job = self.runner.submit(command_id, lambda: self._collect_many(source_ids), safe_context={"source_id": "multiple"})
        return JobAccepted(job.job_id, command_id=command_id)

    def collect_source(self, source_id: str, *, requested_by: str) -> JobAccepted:
        del requested_by
        self._require_enabled_rss(source_id)
        command_id = f"cmd-{secrets.token_hex(12)}"
        job = self.runner.submit(command_id, lambda: self._collect_rss(source_id, command_id), safe_context={"source_id": source_id})
        return JobAccepted(job.job_id, command_id=command_id)

    def _require_enabled_rss(self, source_id: str) -> RSSSource:
        source = self.rss_sources.get(source_id)
        if source is None:
            raise KeyError("source is not an RSS source in the local registry")
        if not source.enabled:
            raise ValueError("source is disabled")
        return source

    def _collect_many(self, source_ids: tuple[str, ...]) -> dict[str, Any]:
        results = [self._collect_rss(source_id, f"batch-{index:04d}") for index, source_id in enumerate(source_ids)]
        return {"status": "completed", "source_count": len(results), "accepted_records": sum(value["accepted_records"] for value in results),
                "review_records": sum(value["review_records"] for value in results)}

    def _collect_rss(self, source_id: str, output_id: str) -> dict[str, Any]:
        source = self._require_enabled_rss(source_id)
        state_manager = JsonStateManager(self.state_directory / f"rss_{source_id}.json")
        state = state_manager.load()
        result = self.connector_factory(source, state).collect_result()
        state_manager.save(state)
        safe_output_id = output_id.replace("cmd-", "")
        if result.accepted_items:
            save_json([item.to_dict() for item in result.accepted_items], self.processed_directory / f"rss_{source_id}_{safe_output_id}.json")
        if result.review_items:
            save_json([item.to_dict() for item in result.review_items], self.review_directory / f"rss_{source_id}_{safe_output_id}.json")
        if result.status == "failed":
            raise RuntimeError("canonical RSS source collection failed")
        return {"status": result.status, "source_id": source_id, "accepted_records": len(result.accepted_items),
                "review_records": len(result.review_items), "skipped_records": result.skipped_items, "error_count": len(result.errors)}


class DevelopmentManualService(ManualSourceService):
    def __init__(self) -> None:
        from backend.app.pipeline.ingestion.external.manual_source.url_policy import ManualURLPolicy
        self.policy = ManualURLPolicy()
    def validate_url(self, url: str) -> str:
        return self.policy.validate(url, allow_onion=False).canonical_url
    def add_manual_source(self, url: str, *, requested_by: str) -> ManualSourceResult:
        del url, requested_by
        return ManualSourceResult("error", "manual-source runtime composition is not configured")
    def recheck_url(self, url: str, *, requested_by: str, force: bool = False) -> ManualSourceResult:
        del url, requested_by, force
        return ManualSourceResult("error", "manual-source runtime composition is not configured")


class DevelopmentSourceService(SourceManagementService):
    def __init__(self, path: Path = PROJECT_ROOT / "config" / "sources.json") -> None:
        value = load_json(path, default={}); self._sources: dict[str, SourceView] = {}
        for section, entries in value.items() if isinstance(value, dict) else []:
            if not isinstance(entries, list): continue
            for raw in entries:
                if not isinstance(raw, dict): continue
                source_id = str(raw.get("source_id") or raw.get("id") or "").strip()
                if source_id:
                    self._sources[source_id] = SourceView(source_id, str(raw.get("name") or source_id), str(raw.get("type") or section), "enabled" if raw.get("enabled") else "disabled", {})
    def list_sources(self) -> list[SourceView]: return sorted(self._sources.values(), key=lambda value: value.source_id)
    def get_source_status(self, source_id: str) -> SourceView | None: return self._sources.get(source_id)
    def request_source_enable(self, source_id: str, *, requested_by: str) -> SourceView:
        del requested_by; current = self._required(source_id); value = SourceView(current.source_id, current.name, current.source_type, "pending_review", current.metadata); self._sources[source_id] = value; return value
    def disable_source(self, source_id: str, *, requested_by: str) -> SourceView:
        del requested_by; current = self._required(source_id); value = SourceView(current.source_id, current.name, current.source_type, "disabled", current.metadata); self._sources[source_id] = value; return value
    def _required(self, source_id: str) -> SourceView:
        if source_id not in self._sources: raise KeyError(source_id)
        return self._sources[source_id]


class DevelopmentJobService(JobService):
    def __init__(self, runner: InProcessJobRunner) -> None: self.runner = runner
    def get_job_status(self, job_id: str) -> JobView | None: return None
    def cancel_job(self, job_id: str, *, requested_by: str) -> JobView:
        del requested_by; raise KeyError(job_id)
    def get_latest_export(self) -> dict[str, Any] | None:
        path = latest_file(PROJECT_ROOT / "data" / "external" / "exports", "external_export_manifest")
        if path is None: return None
        value = load_json(path, default={})
        return {key: value.get(key) for key in ("run_id", "status", "dataset_sha256", "accepted_records", "review_records", "completed_at")}


def build_local_app(*, connector_factory: RSSConnectorFactory | None = None,
                    state_directory: Path = PROJECT_ROOT / "data" / "external" / "state",
                    processed_directory: Path = PROJECT_ROOT / "data" / "external" / "processed",
                    review_directory: Path = PROJECT_ROOT / "data" / "external" / "review",
                    log_path: Path = ACTIVE_LOG_PATH):
    token = os.environ.get("EXTERNAL_API_TOKEN", "")
    if not token: raise RuntimeError("EXTERNAL_API_TOKEN must be set before starting the local internal API")
    roles = frozenset(value.strip() for value in os.environ.get("EXTERNAL_API_ROLES", "operator").split(",") if value.strip())
    configure_file_logging(log_path)
    runner = InProcessJobRunner(max_workers=int(os.environ.get("EXTERNAL_API_DEV_WORKERS", "2")))
    collection = DevelopmentCollectionService(runner, connector_factory=connector_factory, state_directory=state_directory,
                                              processed_directory=processed_directory, review_directory=review_directory)
    return create_app(AdapterServices(StaticTokenAuthenticator(token, roles=roles), RoleAuthorizer(), collection,
        DevelopmentManualService(), DevelopmentSourceService(), DevelopmentJobService(runner), runner, InMemoryIdempotencyStore()))


app = build_local_app()
