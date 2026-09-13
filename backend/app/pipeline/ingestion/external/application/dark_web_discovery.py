from __future__ import annotations

import hashlib
import html
import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Literal
from urllib.parse import parse_qsl, quote_plus, urlencode, urlsplit, urlunsplit

from bs4 import BeautifulSoup
import requests

from backend.app.pipeline.ingestion.external.dark_web_connector import (
    DarkWebRequestError, DarkWebSource, TorHttpClient, TorUnavailableError, V3_ONION_LABEL,
)

TRACKING_KEYS = frozenset({"utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "fbclid", "gclid"})
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class DiscoveryConfigurationError(ValueError): pass
class DiscoveryUnavailable(RuntimeError): pass


def normalize_keywords(values: Iterable[str]) -> tuple[str, ...]:
    from backend.app.pipeline.ingestion.external.application.dark_web_watch_service import normalize_keyword
    normalized: list[str] = []
    folded: set[str] = set()
    for value in values:
        item = normalize_keyword(value); key = item.casefold()
        if key in folded: raise ValueError("duplicate_keyword")
        folded.add(key); normalized.append(item)
    if not 1 <= len(normalized) <= 10: raise ValueError("keyword_count")
    return tuple(normalized)


def canonical_onion_url(value: str) -> str:
    if not isinstance(value, str) or len(value) > 2048: raise ValueError("invalid_candidate")
    value = html.unescape(value).strip()
    try: parsed = urlsplit(value)
    except ValueError as exc: raise ValueError("invalid_candidate") from exc
    if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password or parsed.fragment or parsed.port is not None:
        raise ValueError("invalid_candidate")
    host = (parsed.hostname or "").lower()
    if not host.endswith(".onion") or not V3_ONION_LABEL.fullmatch(host[:-6]): raise ValueError("invalid_candidate")
    path = "/" + "/".join(segment for segment in (parsed.path or "/").split("/") if segment not in {"", "."})
    if any(segment == ".." for segment in parsed.path.split("/")): raise ValueError("invalid_candidate")
    query = urlencode([(key, val) for key, val in parse_qsl(parsed.query, keep_blank_values=True) if key.casefold() not in TRACKING_KEYS])
    return urlunsplit((parsed.scheme, host, path or "/", query, ""))


@dataclass(frozen=True, slots=True)
class DiscoveryProvider:
    provider_id: str
    enabled: bool
    provider_type: Literal["ahmia_html"]
    search_endpoint: str
    through_tor: bool
    allowed_hostname: str
    max_query_chars: int = 300
    max_result_pages: int = 2
    max_candidates: int = 20
    timeout_seconds: float = 15
    rate_limit_seconds: float = 2

    def validate(self) -> None:
        parsed = urlsplit(self.search_endpoint)
        if not SAFE_ID.fullmatch(self.provider_id) or self.provider_type != "ahmia_html" or parsed.scheme not in {"http", "https"}:
            raise DiscoveryConfigurationError("invalid_provider")
        if parsed.username or parsed.password or parsed.hostname != self.allowed_hostname or "{query}" not in self.search_endpoint:
            raise DiscoveryConfigurationError("invalid_provider_endpoint")
        if not 2 <= self.max_query_chars <= 1000 or not 1 <= self.max_result_pages <= 3 or not 1 <= self.max_candidates <= 20:
            raise DiscoveryConfigurationError("invalid_provider_bounds")
        if not 1 <= self.timeout_seconds <= 30 or not 0 <= self.rate_limit_seconds <= 60:
            raise DiscoveryConfigurationError("invalid_provider_bounds")


def load_discovery_providers(path: Path) -> tuple[DiscoveryProvider, ...]:
    if path.is_symlink() or not path.is_file(): raise DiscoveryConfigurationError("provider_config_unavailable")
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or raw.get("schema_version") != "1.0" or not isinstance(raw.get("providers"), list):
        raise DiscoveryConfigurationError("invalid_provider_config")
    providers = tuple(DiscoveryProvider(**item) for item in raw["providers"] if isinstance(item, dict))
    if len(providers) > 10 or len({item.provider_id for item in providers}) != len(providers): raise DiscoveryConfigurationError("invalid_provider_config")
    for provider in providers: provider.validate()
    return providers


class ProviderHttpClient:
    def __init__(self, tor_proxy_url: str, session: requests.Session | None = None):
        self.tor_proxy_url=tor_proxy_url; self.session=session or requests.Session(); self.session.trust_env=False

    def fetch(self, endpoint: str, through_tor: bool, timeout: float) -> bytes:
        parsed=urlsplit(endpoint); current=endpoint
        proxies={"http":self.tor_proxy_url,"https":self.tor_proxy_url} if through_tor else {"http":None,"https":None}
        for _ in range(4):
            cookie_jar=getattr(self.session,"cookies",None)
            if cookie_jar is not None: cookie_jar.clear()
            response=self.session.get(current,headers={"Accept":"text/html"},proxies=proxies,timeout=(5,min(timeout,15)),stream=True,allow_redirects=False)
            if response.status_code in {301,302,303,307,308}:
                from urllib.parse import urljoin
                destination=urljoin(current,response.headers.get("Location","")); response.close()
                target=urlsplit(destination)
                if target.scheme not in {"http","https"} or target.hostname!=parsed.hostname or target.username or target.password: raise DiscoveryUnavailable("provider_redirect_blocked")
                current=destination; continue
            if response.status_code==429: response.close(); raise DiscoveryUnavailable("provider_rate_limited")
            if response.status_code!=200 or response.headers.get("Content-Type","").split(";",1)[0].lower()!="text/html": response.close(); raise DiscoveryUnavailable("provider_unavailable")
            chunks=[]; size=0
            for chunk in response.iter_content(65536):
                size+=len(chunk)
                if size>1_048_576: response.close(); raise DiscoveryUnavailable("provider_response_too_large")
                chunks.append(chunk)
            response.close(); return b"".join(chunks)
        raise DiscoveryUnavailable("provider_redirect_limit")


class AhmiaHTMLDiscovery:
    """Discovery-only parser. Returned titles/snippets are deliberately discarded."""
    def __init__(self, provider: DiscoveryProvider, fetch: Callable[[str, bool, float], bytes], *, sleeper: Callable[[float], None] = time.sleep):
        provider.validate(); self.provider, self.fetch, self.sleeper = provider, fetch, sleeper

    def discover(self, keywords: tuple[str, ...]) -> list[str]:
        query = " ".join(keywords)
        if len(query) > self.provider.max_query_chars: raise DiscoveryUnavailable("query_bound")
        candidates: dict[str, None] = {}
        for page in range(1, self.provider.max_result_pages + 1):
            endpoint = self.provider.search_endpoint.replace("{query}", quote_plus(query)).replace("{page}", str(page))
            try: payload = self.fetch(endpoint, self.provider.through_tor, self.provider.timeout_seconds)
            except Exception as exc: raise DiscoveryUnavailable("provider_unavailable") from exc
            if len(payload) > 1_048_576: raise DiscoveryUnavailable("provider_response_too_large")
            soup = BeautifulSoup(payload, "html.parser")
            for anchor in soup.find_all("a", href=True):
                try: candidate = canonical_onion_url(str(anchor["href"]))
                except ValueError: continue
                candidates.setdefault(candidate, None)
                if len(candidates) >= self.provider.max_candidates: return list(candidates)
            if page < self.provider.max_result_pages: self.sleeper(self.provider.rate_limit_seconds)
        return list(candidates)


class CandidateVerifier:
    def __init__(self, client: TorHttpClient, privacy: Callable[[str], tuple[str, str, list[str]]] | None = None):
        self.client = client; self.privacy = privacy or (lambda value: (value, "reviewed", []))

    def verify(self, url: str, keywords: tuple[str, ...], mode: Literal["any", "all"], provider_id: str) -> dict | None:
        canonical = canonical_onion_url(url); parsed = urlsplit(canonical)
        source = DarkWebSource("discovered", provider_id, canonical, ("/",), True, max_items=1)
        try: response = self.client.get(source, canonical)
        except (TorUnavailableError, DarkWebRequestError): return None
        if response.status_code != 200 or response.content_type not in {"text/html", "text/plain"} or len(response.content) > 1_048_576: return None
        text = response.content.decode("utf-8", errors="replace")
        if response.content_type == "text/html":
            soup = BeautifulSoup(text, "html.parser")
            for tag in soup(["script", "style", "form", "nav", "header", "footer"]): tag.decompose()
            title = " ".join((soup.title.get_text(" ", strip=True) if soup.title else provider_id).split())
            text = " ".join(soup.get_text(" ", strip=True).split())
        else: title, text = provider_id, " ".join(text.split())
        filtered, privacy_status, reasons = self.privacy(text)
        folded = filtered.casefold(); matched = tuple(keyword for keyword in keywords if keyword.casefold() in folded)
        if (mode == "all" and len(matched) != len(keywords)) or (mode == "any" and not matched): return None
        positions = [folded.index(item.casefold()) for item in matched]; position = min(positions)
        excerpt = filtered[max(0, position - 100):position + max(map(len, matched)) + 100]
        canonical_hash = hashlib.sha256(canonical.encode()).hexdigest(); content_hash = hashlib.sha256(filtered.encode()).hexdigest()
        occurrence_hash = hashlib.sha256((canonical_hash + "\0" + content_hash + "\0" + "\0".join(item.casefold() for item in matched)).encode()).hexdigest()
        return {"result_id": "dwr-" + occurrence_hash[:32], "canonical_hash": occurrence_hash, "content_sha256": content_hash,
                "onion_reference": "onion-ref:" + canonical_hash, "title": _safe(title, 200), "excerpt": _safe(excerpt, 240),
                "provider": provider_id, "privacy_status": privacy_status, "review_reasons": reasons,
                "matched_keywords": list(matched), "collected_at": _utc_now(), "protected_url": canonical}


class DynamicDiscoveryScanner:
    def __init__(self, discoveries: dict[str, AhmiaHTMLDiscovery], verifier: CandidateVerifier):
        self.discoveries, self.verifier = discoveries, verifier

    def readiness(self) -> list[dict]:
        return [{"provider_id": key, "enabled": value.provider.enabled, "ready": value.provider.enabled,
                 "through_tor": value.provider.through_tor} for key, value in sorted(self.discoveries.items())]

    def scan(self, watch: dict, tracked_urls: list[str]) -> tuple[list[dict], bool, dict[str, int]]:
        provider_id=watch["provider_id"]; discovery=self.discoveries.get(provider_id)
        if discovery is None or not discovery.provider.enabled: raise DiscoveryUnavailable("provider_unconfigured")
        keywords=tuple(watch.get("keywords") or [watch["keyword"]]); mode=watch.get("match_mode","any")
        candidates=discovery.discover(keywords)
        unique=list(dict.fromkeys([*candidates,*tracked_urls]))[:20]
        matches=[]; unreachable=errors=0
        for candidate in unique:
            try: verified=self.verifier.verify(candidate,keywords,mode,provider_id)
            except Exception: errors+=1; continue
            if verified is None: unreachable+=1
            else: matches.append(verified)
        counts={"discovered":len(candidates),"rejected":max(0,len(candidates)-len(unique)),"unreachable":unreachable,
                "verified":len(unique)-unreachable-errors,"matched":len(matches),"new":len(matches),"unchanged":0,
                "privacy_blocked":0,"errors":errors}
        return matches, bool(unreachable or errors), counts


def _safe(value: str, limit: int) -> str:
    return re.sub(r"https?://\S+|\b\S*\.onion\b", "[redacted]", " ".join(value.split()), flags=re.I)[:limit]


def _utc_now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
