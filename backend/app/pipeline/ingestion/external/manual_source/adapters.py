from __future__ import annotations

from collections.abc import Callable, Mapping
import hashlib
from typing import Any
from urllib.parse import urlsplit

from backend.app.pipeline.ingestion.external.application.collection_service import RegisteredSource
from backend.app.pipeline.ingestion.external.application.manual_source_service import AdapterResult, ManualAdapter
from backend.app.pipeline.ingestion.external.cert_connector import CERTConnector, CERTSource
from backend.app.pipeline.ingestion.external.common.canonical_url import canonicalize_url
from backend.app.pipeline.ingestion.external.dark_web_connector import DarkWebConnector, DarkWebSource, V3_ONION_LABEL
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
        source = self.registry.get(source_id or "") or self._candidate_source(canonical_url)
        if source is None:
            return AdapterResult("ignored", message=f"unconfigured {self.route_kind} URL is unsupported")
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

    def _candidate_source(self, canonical_url: str) -> RegisteredSource | None:
        """Build an in-memory, bounded source for preview; it is never added to the registry."""
        parts = urlsplit(canonical_url)
        host = (parts.hostname or "").lower()
        suffix = hashlib.sha256(canonical_url.encode()).hexdigest()[:20]
        if self.route_kind == "reddit":
            segments = [value for value in parts.path.split("/") if value]
            if host not in {"reddit.com", "www.reddit.com", "old.reddit.com"} or len(segments) < 2 or segments[0].lower() != "r":
                return None
            raw = {"source_id": f"manual-reddit-{suffix}", "name": f"Reddit r/{segments[1]}",
                   "source_type": "reddit", "subreddit": segments[1], "enabled": True,
                   "transport": "reddit_public_rss", "max_items": 20, "fetch_linked_articles": True}
            return RegisteredSource(raw["source_id"], "reddit", True, raw)
        if self.route_kind in {"vulnerability", "github_advisory"}:
            if self.route_kind == "github_advisory":
                source_type, base, name = "github_advisories", "https://api.github.com/advisories", "GitHub Advisory"
            elif host == "nvd.nist.gov":
                source_type, base, name = "nvd", "https://services.nvd.nist.gov/rest/json/cves/2.0", "NVD"
            else:
                source_type, base, name = "cve", "https://cveawg.mitre.org/api/cve", "CVE Program"
            raw = {"source_id": f"manual-{source_type}-{suffix}", "name": name, "type": source_type,
                   "base_url": base, "enabled": True, "results_per_page": 1, "max_pages": 1,
                   "lookback_days": 0, "delay_seconds": 0}
            return RegisteredSource(raw["source_id"], "vulnerability", True, raw)
        return None

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
    def __init__(self, sources: tuple[DarkWebSource, ...], connector: DarkWebConnector,
                 *, allow_preview_candidate: bool = False) -> None:
        self.sources, self.connector, self.allow_preview_candidate = sources, connector, allow_preview_candidate

    @staticmethod
    def valid_candidate_url(url: str) -> bool:
        try: parts = urlsplit(canonicalize_url(url))
        except ValueError: return False
        host = (parts.hostname or "").lower()
        return (parts.scheme in {"http", "https"} and not parts.username and not parts.password
                and host.endswith(".onion") and bool(V3_ONION_LABEL.fullmatch(host[:-6])))

    def collect_url(self, canonical_url: str, *, identifier: str | None, source_id: str | None,
                    state: dict[str, Any]) -> AdapterResult:
        del identifier, source_id
        source = next((value for value in self.sources if value.enabled and value.allows(canonical_url)), None)
        if source is None and self.allow_preview_candidate and self.valid_candidate_url(canonical_url):
            path = urlsplit(canonical_url).path or "/"
            source = DarkWebSource(
                "manual-preview-" + hashlib.sha256(canonical_url.encode()).hexdigest()[:20],
                "Manual Onion Preview", canonical_url, (path,), True, max_items=1,
                rate_limit_seconds=0, trusted_curated=False,
            )
        if source is None: return AdapterResult("ignored", message="onion URL is not an approved v3 source")
        self.connector.state = state
        result = self.connector.collect_url(source, canonical_url)
        errors = {str(error).lower() for error in getattr(result, "errors", ())}
        if "tor_proxy_unavailable" in errors or "tor_unavailable" in errors:
            return AdapterResult("error", message="Tor service is unavailable")
        if "onion_source_unavailable" in errors:
            return AdapterResult("error", message="Onion source is temporarily unavailable")
        return RegisteredConnectorManualAdapter._result(result)


def build_registered_manual_adapters(registry: Mapping[str, RegisteredSource]) -> dict[str, ManualAdapter]:
    return {
        kind: RegisteredConnectorManualAdapter(registry, kind)
        for kind in ("rss", "cert", "vulnerability", "github_advisory", "telegram", "reddit", "registered_source")
    } | {"github_public": UnsupportedManualAdapter("public GitHub")}
