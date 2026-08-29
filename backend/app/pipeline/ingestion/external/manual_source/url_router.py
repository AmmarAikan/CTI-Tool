from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal, Mapping
from urllib.parse import urlsplit

from backend.app.pipeline.ingestion.external.common.canonical_url import canonicalize_url


RouteKind = Literal[
    "dark_web", "vulnerability", "github_advisory", "github_public", "rss", "cert",
    "telegram", "reddit", "registered_source", "generic_web",
]
CVE_RE = re.compile(r"(?:^|/)(CVE-\d{4}-\d{4,19})(?:$|[/?#])", re.I)
GHSA_RE = re.compile(r"(?:^|/)(GHSA-[23456789CFGHJMPQRVWX]{4}-[23456789CFGHJMPQRVWX]{4}-[23456789CFGHJMPQRVWX]{4})(?:$|[/?#])", re.I)
FEED_SUFFIXES = (".rss", ".atom", ".xml")
FEED_SEGMENTS = frozenset({"feed", "rss", "atom"})
TELEGRAM_HOSTS = frozenset({"t.me", "telegram.me", "www.telegram.me"})
REDDIT_HOSTS = frozenset({"reddit.com", "www.reddit.com", "old.reddit.com"})


@dataclass(frozen=True, slots=True)
class URLRoute:
    kind: RouteKind
    identifier: str | None = None
    source_id: str | None = None


@dataclass(frozen=True, slots=True)
class _RegisteredURL:
    source_id: str
    source_type: str
    configuration: dict[str, Any]
    host: str
    path: str


class ManualURLRouter:
    def __init__(self, registry: Mapping[str, Any] | None = None) -> None:
        self.registered = self._registered_urls(registry or {})

    def route(self, canonical_url: str, *, detected_feed: bool = False) -> URLRoute:
        canonical_url = canonicalize_url(canonical_url)
        parts, path = urlsplit(canonical_url), urlsplit(canonical_url).path.lower()
        host = (parts.hostname or "").lower()
        if host.endswith(".onion"): return URLRoute("dark_web")
        cve = CVE_RE.search(parts.path)
        if cve and host in {"nvd.nist.gov", "www.cve.org", "cve.org", "cve.mitre.org"}:
            expected = "nvd" if host == "nvd.nist.gov" else "cve"
            source = self._source(lambda value: value.source_type == "vulnerability" and
                                  str(value.configuration.get("type", "")).lower() == expected)
            return URLRoute("vulnerability", cve.group(1).upper(), source.source_id if source else None)
        ghsa = GHSA_RE.search(parts.path)
        if host in {"github.com", "api.github.com"} and ghsa:
            source = self._source(lambda value: str(value.configuration.get("type", "")).lower() == "github_advisories")
            return URLRoute("github_advisory", ghsa.group(1).upper(), source.source_id if source else None)
        if host in {"github.com", "api.github.com", "raw.githubusercontent.com"}: return URLRoute("github_public")

        matches = [value for value in self.registered if self._matches(value, host, path)]
        feed = self._first(matches, lambda value: value.source_type == "rss" or
                           (value.source_type == "cert" and str(value.configuration.get("method", "")).lower() == "rss"))
        cert = self._first(matches, lambda value: value.source_type == "cert")
        if feed: return URLRoute("rss", source_id=feed.source_id)
        if cert: return URLRoute("cert", source_id=cert.source_id)
        if detected_feed or self._looks_like_feed(path):
            return URLRoute("rss")
        telegram = self._first(matches, lambda value: value.source_type == "telegram")
        if telegram: return URLRoute("telegram", source_id=telegram.source_id)
        if self._telegram_path(host, path): return URLRoute("telegram")
        reddit = self._first(matches, lambda value: value.source_type == "reddit")
        if reddit: return URLRoute("reddit", source_id=reddit.source_id)
        if self._reddit_path(host, path): return URLRoute("reddit")
        if matches: return URLRoute("registered_source", source_id=matches[0].source_id)
        return URLRoute("generic_web")

    @staticmethod
    def _registered_urls(registry: Mapping[str, Any]) -> tuple[_RegisteredURL, ...]:
        values = []
        for source_id, source in sorted(registry.items()):
            configuration = dict(getattr(source, "configuration", {}) or {})
            source_type = str(getattr(source, "source_type", "") or "").lower()
            urls = [configuration.get("url"), configuration.get("base_url")]
            if source_type == "telegram" and configuration.get("channel"):
                channel = str(configuration["channel"]).strip().lstrip("@")
                urls.extend((f"https://t.me/s/{channel}", f"https://t.me/{channel}"))
            for raw in urls:
                if not raw: continue
                try: parts = urlsplit(canonicalize_url(str(raw)))
                except ValueError: continue
                values.append(_RegisteredURL(str(source_id), source_type, configuration,
                                             (parts.hostname or "").lower(), ManualURLRouter._path(parts.path)))
        return tuple(values)

    @staticmethod
    def _matches(registered: _RegisteredURL, host: str, path: str) -> bool:
        candidate = ManualURLRouter._path(path)
        if host != registered.host: return False
        if candidate == registered.path: return True
        if registered.source_type in {"rss", "telegram", "reddit"}: return False
        return registered.path != "/" and candidate.startswith(registered.path + "/")

    @staticmethod
    def _looks_like_feed(path: str) -> bool:
        normalized = ManualURLRouter._path(path)
        segments = {value for value in normalized.split("/") if value}
        return normalized.endswith(FEED_SUFFIXES) or bool(segments & FEED_SEGMENTS)

    @staticmethod
    def _telegram_path(host: str, path: str) -> bool:
        segments = [value for value in path.split("/") if value]
        return host in TELEGRAM_HOSTS and bool(segments) and (segments[0] == "s" and len(segments) >= 2 or segments[0] != "s")

    @staticmethod
    def _reddit_path(host: str, path: str) -> bool:
        segments = [value.lower() for value in path.split("/") if value]
        return host in REDDIT_HOSTS and len(segments) >= 2 and segments[0] == "r"

    @staticmethod
    def _path(value: str) -> str:
        normalized = "/" + "/".join(part for part in value.split("/") if part)
        return normalized.lower() if normalized != "" else "/"

    @staticmethod
    def _first(values: list[_RegisteredURL], predicate) -> _RegisteredURL | None:
        return next((value for value in values if predicate(value)), None)

    def _source(self, predicate) -> _RegisteredURL | None:
        return next((value for value in self.registered if predicate(value)), None)
