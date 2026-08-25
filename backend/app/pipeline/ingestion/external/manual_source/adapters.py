from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from backend.app.pipeline.ingestion.external.application.collection_service import RegisteredSource
from backend.app.pipeline.ingestion.external.application.manual_source_service import AdapterResult, ManualAdapter
from backend.app.pipeline.ingestion.external.cert_connector import CERTConnector, CERTSource
from backend.app.pipeline.ingestion.external.common.canonical_url import canonicalize_url
from backend.app.pipeline.ingestion.external.dark_web_connector import DarkWebConnector, DarkWebSource
from backend.app.pipeline.ingestion.external.reddit_connector import RedditConnector, RedditSource
from backend.app.pipeline.ingestion.external.rss_connector import RSSConnector, RSSSource
from backend.app.pipeline.ingestion.external.social_common import SocialItemProcessor
from backend.app.pipeline.ingestion.external.telegram_connector import TelegramConnector, TelegramSource
from backend.app.pipeline.ingestion.external.vulnerability_connector import VulnerabilityConnector, VulnerabilitySource


ConnectorFactory = Callable[[RegisteredSource, dict[str, Any]], Any]


class UnsupportedManualAdapter(ManualAdapter):
    def __init__(self, route_name: str) -> None: self.route_name = route_name
    def collect_url(self, canonical_url: str, *, identifier: str | None, source_id: str | None,
                    state: dict[str, Any]) -> AdapterResult:
        del canonical_url, identifier, source_id, state
        return AdapterResult("ignored", message=f"{self.route_name} URL is not safely supported by an existing connector")


class RegisteredConnectorManualAdapter(ManualAdapter):
    """Translate one registry match into its existing canonical connector."""

    def __init__(self, registry: Mapping[str, RegisteredSource], route_kind: str,
                 connector_factory: ConnectorFactory | None = None) -> None:
        self.registry, self.route_kind, self.connector_factory = dict(registry), route_kind, connector_factory

    def collect_url(self, canonical_url: str, *, identifier: str | None, source_id: str | None,
                    state: dict[str, Any]) -> AdapterResult:
        if not source_id or source_id not in self.registry:
            return AdapterResult("ignored", message=f"unconfigured {self.route_kind} URL is unsupported")
        source = self.registry[source_id]
        if not source.enabled:
            return AdapterResult("ignored", message=f"configured source {source_id} is disabled")
        if self.route_kind == "cert" and canonicalize_url(canonical_url) != canonicalize_url(str(source.configuration.get("url") or "")):
            return AdapterResult("ignored", message="specific CERT item URL is unsupported by the existing connector")
        try:
            connector = self.connector_factory(source, state) if self.connector_factory else self._connector(source, state)
            if self.route_kind in {"vulnerability", "github_advisory"}:
                if not identifier:
                    return AdapterResult("ignored", message="a stable vulnerability identifier is required")
                result = connector.collect_identifier(VulnerabilitySource.from_mapping(source.configuration), identifier)
            else:
                result = connector.collect_result()
        except Exception:
            return AdapterResult("error", message=f"{self.route_kind} connector failed safely")
        return self._result(result)

    def _connector(self, source: RegisteredSource, state: dict[str, Any]):
        raw = source.configuration
        if self.route_kind == "rss":
            if source.source_type == "cert": return CERTConnector(CERTSource.from_mapping(raw), state=state)
            return RSSConnector.from_source(RSSSource.from_mapping(raw), state=state)
        if self.route_kind == "cert": return CERTConnector(CERTSource.from_mapping(raw), state=state)
        if self.route_kind in {"vulnerability", "github_advisory", "registered_source"}:
            return VulnerabilityConnector([VulnerabilitySource.from_mapping(raw)], state=state)
        processor = SocialItemProcessor(state=state)
        if self.route_kind == "telegram": return TelegramConnector(TelegramSource.from_mapping(raw), processor=processor)
        if self.route_kind == "reddit": return RedditConnector(RedditSource.from_mapping(raw), processor=processor)
        raise ValueError("registered source has no compatible canonical connector")

    @staticmethod
    def _result(result: Any) -> AdapterResult:
        accepted = tuple(getattr(result, "accepted_items", ()))
        review = tuple(getattr(result, "review_items", ()))
        rejected = tuple(getattr(result, "rejected_items", ()))
        status = str(getattr(result, "status", "failed"))
        categories = {str(getattr(error, "category", error)).split(":")[-1] for error in getattr(result, "errors", ())}
        if status == "unchanged" or (not accepted and not review and not rejected and int(getattr(result, "skipped_items", 0)) > 0):
            return AdapterResult("unchanged", message="structured source has not changed")
        if status in {"disabled", "unavailable"} or "credentials_missing" in categories:
            reason = "credentials are not configured" if "credentials_missing" in categories else "structured source is unavailable"
            return AdapterResult("ignored", message=reason)
        if status == "failed" and not (accepted or review or rejected):
            return AdapterResult("error", message="structured connector failed safely")
        public_status = "stored" if accepted else "review_required" if review or rejected else "unchanged"
        return AdapterResult(public_status, accepted, "structured connector completed", review, rejected)


class DarkWebManualAdapter(ManualAdapter):
    def __init__(self, sources: tuple[DarkWebSource, ...], connector: DarkWebConnector) -> None:
        self.sources, self.connector = sources, connector

    def collect_url(self, canonical_url: str, *, identifier: str | None, source_id: str | None,
                    state: dict[str, Any]) -> AdapterResult:
        del identifier, source_id
        source = next((value for value in self.sources if value.enabled and value.allows(canonical_url)), None)
        if source is None: return AdapterResult("ignored", message="onion URL is not an enabled configured source")
        self.connector.state = state
        result = self.connector.collect_url(source, canonical_url)
        return RegisteredConnectorManualAdapter._result(result)


def build_registered_manual_adapters(registry: Mapping[str, RegisteredSource]) -> dict[str, ManualAdapter]:
    return {
        kind: RegisteredConnectorManualAdapter(registry, kind)
        for kind in ("rss", "cert", "vulnerability", "github_advisory", "telegram", "reddit", "registered_source")
    } | {"github_public": UnsupportedManualAdapter("public GitHub")}
