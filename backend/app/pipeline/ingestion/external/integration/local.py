from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from backend.app.pipeline.ingestion.external.application.collection_service import CollectionRequest, CollectionService, JobAccepted
from backend.app.pipeline.ingestion.external.application.job_service import JobService, JobView
from backend.app.pipeline.ingestion.external.application.manual_source_service import ManualSourceResult, ManualSourceService
from backend.app.pipeline.ingestion.external.application.source_management_service import SourceManagementService, SourceView
from backend.app.pipeline.ingestion.external.common.json_storage import latest_file, load_json
from backend.app.pipeline.ingestion.external.integration.api import AdapterServices, create_app
from backend.app.pipeline.ingestion.external.integration.auth import RoleAuthorizer, StaticTokenAuthenticator
from backend.app.pipeline.ingestion.external.integration.idempotency import InMemoryIdempotencyStore
from backend.app.pipeline.ingestion.external.integration.jobs import InProcessJobRunner


PROJECT_ROOT = Path(__file__).resolve().parents[6]


class DevelopmentCollectionService(CollectionService):
    def __init__(self, runner: InProcessJobRunner) -> None: self.runner = runner
    def start_collection(self, request: CollectionRequest) -> JobAccepted:
        job = self.runner.submit("cmd-local-collection", lambda: self._unavailable())
        return JobAccepted(job.job_id)
    def collect_source(self, source_id: str, *, requested_by: str) -> JobAccepted:
        del source_id, requested_by
        job = self.runner.submit("cmd-local-source", lambda: self._unavailable())
        return JobAccepted(job.job_id)
    @staticmethod
    def _unavailable() -> dict[str, Any]:
        raise RuntimeError("collector orchestration must be supplied by the deployment composition")


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


def build_local_app():
    token = os.environ.get("EXTERNAL_API_TOKEN", "")
    if not token: raise RuntimeError("EXTERNAL_API_TOKEN must be set before starting the local internal API")
    roles = frozenset(value.strip() for value in os.environ.get("EXTERNAL_API_ROLES", "operator").split(",") if value.strip())
    runner = InProcessJobRunner(max_workers=int(os.environ.get("EXTERNAL_API_DEV_WORKERS", "2")))
    return create_app(AdapterServices(StaticTokenAuthenticator(token, roles=roles), RoleAuthorizer(), DevelopmentCollectionService(runner),
        DevelopmentManualService(), DevelopmentSourceService(), DevelopmentJobService(runner), runner, InMemoryIdempotencyStore()))


app = build_local_app()
