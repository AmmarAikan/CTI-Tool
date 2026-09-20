from __future__ import annotations

import hashlib
import html
import json
import random
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Literal
from urllib.parse import parse_qs, parse_qsl, quote_plus, urlencode, urlsplit, urlunsplit

from bs4 import BeautifulSoup
import requests

from backend.app.pipeline.ingestion.external.application.job_errors import SafeJobFailure

from backend.app.pipeline.ingestion.external.dark_web_connector import (
    DarkWebRequestError, DarkWebSource, TorHttpClient, TorUnavailableError, V3_ONION_LABEL,
)

TRACKING_KEYS = frozenset({"utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "fbclid", "gclid"})
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
PROVIDER_USER_AGENT = "CTI-Tool-DarkWeb-Monitor/1.0"


class DiscoveryConfigurationError(ValueError): pass
class DiscoveryFailure(SafeJobFailure): pass

class ProviderMissing(DiscoveryFailure):
    def __init__(self) -> None: super().__init__("provider_missing", "configured discovery provider is unavailable", retryable=False)

class ProviderDisabled(DiscoveryFailure):
    def __init__(self) -> None: super().__init__("provider_disabled", "configured discovery provider is disabled", retryable=False)

class DiscoveryUnavailable(DiscoveryFailure):
    def __init__(self, reason: str = "provider_failure", *, retryable: bool = False) -> None:
        code = "provider_temporarily_unavailable" if retryable else "provider_failure"
        message = "discovery provider is temporarily unavailable" if retryable else "discovery provider request was rejected safely"
        super().__init__(code, message, retryable=retryable); self.reason = reason


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
        if not SAFE_ID.fullmatch(self.provider_id) or self.provider_type != "ahmia_html" or parsed.scheme != "https":
            raise DiscoveryConfigurationError("invalid_provider")
        if (parsed.username or parsed.password or parsed.hostname != self.allowed_hostname or parsed.path != "/search/"
                or parsed.fragment or "{query}" not in self.search_endpoint or "{page}" not in self.search_endpoint
                or not self.through_tor):
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
    def __init__(self, tor_proxy_url: str, session: requests.Session | None = None, *,
                 sleeper: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.monotonic,
                 jitter: Callable[[float, float], float] = random.SystemRandom().uniform,
                 max_attempts: int = 3, total_deadline_seconds: float = 30):
        if not 1 <= max_attempts <= 3 or not 1 <= total_deadline_seconds <= 30:
            raise ValueError("invalid_provider_retry_bounds")
        self.tor_proxy_url=tor_proxy_url; self.session=session or requests.Session(); self.session.trust_env=False
        self.sleeper=sleeper; self.clock=clock; self.jitter=jitter
        self.max_attempts=max_attempts; self.total_deadline_seconds=total_deadline_seconds

    def fetch(self, endpoint: str, through_tor: bool, timeout: float) -> bytes:
        parsed=urlsplit(endpoint)
        proxies={"http":self.tor_proxy_url,"https":self.tor_proxy_url} if through_tor else {"http":None,"https":None}
        cookie_jar=getattr(self.session,"cookies",None)
        if cookie_jar is not None: cookie_jar.clear()
        deadline=self.clock()+min(timeout,self.total_deadline_seconds)
        response=None
        for attempt in range(1,self.max_attempts+1):
            remaining=deadline-self.clock()
            if remaining<=0: raise DiscoveryUnavailable("provider_server_failure",retryable=True)
            try: response=self.session.get(endpoint,headers={"Accept":"text/html","User-Agent":PROVIDER_USER_AGENT},proxies=proxies,
                    timeout=(min(5,remaining),min(timeout,15,remaining)),stream=True,allow_redirects=False)
            except (requests.ConnectionError,requests.Timeout) as exc: raise DiscoveryUnavailable("provider_network_failure",retryable=True) from exc
            if not 500<=response.status_code<=599: break
            response.close()
            if attempt==self.max_attempts: raise DiscoveryUnavailable("provider_server_failure",retryable=True)
            delay=min(.25*(2**(attempt-1))+self.jitter(0,.1),1.0)
            if delay>=deadline-self.clock(): raise DiscoveryUnavailable("provider_server_failure",retryable=True)
            self.sleeper(delay)
        assert response is not None
        if response.status_code in {301,302,303,307,308}:
            response.close(); raise DiscoveryUnavailable("provider_redirect_blocked")
        if response.status_code==429: response.close(); raise DiscoveryUnavailable("provider_rate_limited",retryable=True)
        final=urlsplit(getattr(response,"url",endpoint))
        if (response.status_code!=200 or final.scheme!="https" or final.hostname!=parsed.hostname or final.path!=parsed.path
                or response.headers.get("Content-Type","").split(";",1)[0].strip().lower()!="text/html"):
            response.close(); raise DiscoveryUnavailable("provider_response_invalid")
        chunks=[]; size=0
        for chunk in response.iter_content(65536):
            size+=len(chunk)
            if size>1_048_576: response.close(); raise DiscoveryUnavailable("provider_response_too_large")
            chunks.append(chunk)
        response.close(); return b"".join(chunks)


class AhmiaHTMLDiscovery:
    """Discovery-only parser. Returned titles/snippets are deliberately discarded."""
    def __init__(self, provider: DiscoveryProvider, fetch: Callable[[str, bool, float], bytes], *, sleeper: Callable[[float], None] = time.sleep):
        provider.validate(); self.provider, self.fetch, self.sleeper = provider, fetch, sleeper

    def discover(self, keywords: tuple[str, ...]) -> list[str]:
        query = " ".join(keywords)
        if len(query) > self.provider.max_query_chars: raise DiscoveryUnavailable("query_bound")
        candidates: dict[str, None] = {}
        token_name,token_value=self._search_token()
        for page in range(0, self.provider.max_result_pages):
            endpoint = self.provider.search_endpoint.replace("{query}", quote_plus(query)).replace("{page}", str(page))
            parts=urlsplit(endpoint);endpoint=urlunsplit((parts.scheme,parts.netloc,parts.path,parts.query+"&"+urlencode({token_name:token_value}),""))
            try: payload = self.fetch(endpoint, self.provider.through_tor, self.provider.timeout_seconds)
            except DiscoveryFailure: raise
            except (requests.ConnectionError,requests.Timeout,OSError) as exc: raise DiscoveryUnavailable("provider_network_failure",retryable=True) from exc
            except Exception as exc: raise DiscoveryUnavailable("provider_failure") from exc
            if len(payload) > 1_048_576: raise DiscoveryUnavailable("provider_response_too_large")
            soup = BeautifulSoup(payload, "html.parser")
            results=soup.select_one("#ahmiaResultsPage")
            if results is None or (results.select_one("ol.searchResults") is None and results.select_one("#noResults") is None):
                raise DiscoveryUnavailable("provider_page_invalid")
            for anchor in results.select("li.result h4 a[href]"):
                href=urlsplit(str(anchor["href"]));values=parse_qs(href.query,keep_blank_values=True)
                if href.path!="/search/redirect" or len(values.get("redirect_url",()))!=1:continue
                try: candidate = canonical_onion_url(str(anchor["href"]))
                except ValueError:
                    try:candidate=canonical_onion_url(values["redirect_url"][0])
                    except ValueError:continue
                candidates.setdefault(candidate, None)
                if len(candidates) >= self.provider.max_candidates: return list(candidates)
            if page + 1 < self.provider.max_result_pages: self.sleeper(self.provider.rate_limit_seconds)
        return list(candidates)

    def _search_token(self)->tuple[str,str]:
        parts=urlsplit(self.provider.search_endpoint);home=urlunsplit((parts.scheme,parts.netloc,"/","",""))
        payload=self.fetch(home,self.provider.through_tor,self.provider.timeout_seconds)
        if len(payload)>1_048_576:raise DiscoveryUnavailable("provider_response_too_large")
        soup=BeautifulSoup(payload,"html.parser");form=soup.select_one('form#searchForm[action="/search/"][method="get"]')
        hidden=form.select_one('input[type="hidden"][name][value]') if form else None
        if hidden is None:raise DiscoveryUnavailable("provider_token_missing")
        name,value=str(hidden.get("name","")),str(hidden.get("value",""))
        if not re.fullmatch(r"[0-9a-f]{6}",name) or not re.fullmatch(r"[0-9a-f]{6}",value):raise DiscoveryUnavailable("provider_token_invalid")
        return name,value


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

    def require_provider(self, provider_id: str) -> AhmiaHTMLDiscovery:
        discovery=self.discoveries.get(provider_id)
        if discovery is None: raise ProviderMissing()
        if not discovery.provider.enabled: raise ProviderDisabled()
        return discovery

    def scan(self, watch: dict, tracked_urls: list[str]) -> tuple[list[dict], bool, dict[str, int]]:
        provider_id=watch["provider_id"]; discovery=self.require_provider(provider_id)
        keywords=tuple(watch.get("keywords") or [watch["keyword"]]); mode=watch.get("match_mode","any")
        provider_failed=False
        try: candidates=discovery.discover(keywords)
        except DiscoveryFailure:
            if not tracked_urls: raise
            candidates=[];provider_failed=True
        unique=list(dict.fromkeys([*candidates,*tracked_urls]))[:20]
        matches=[]; unreachable=errors=0
        for candidate in unique:
            try: verified=self.verifier.verify(candidate,keywords,mode,provider_id)
            except Exception: errors+=1; continue
            if verified is None: unreachable+=1
            else: matches.append(verified)
        counts={"discovered":len(candidates),"rejected":max(0,len(candidates)-len(unique)),"unreachable":unreachable,
                "verified":len(unique)-unreachable-errors,"matched":len(matches),"new":len(matches),"unchanged":0,
                "privacy_blocked":0,"errors":errors+int(provider_failed)}
        return matches, bool(provider_failed or unreachable or errors), counts


def _safe(value: str, limit: int) -> str:
    return re.sub(r"https?://\S+|\b\S*\.onion\b", "[redacted]", " ".join(value.split()), flags=re.I)[:limit]


def _utc_now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
