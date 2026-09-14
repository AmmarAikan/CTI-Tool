from __future__ import annotations

import os
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

import feedparser
import requests
from bs4 import BeautifulSoup

from backend.app.pipeline.ingestion.external.common.canonical_url import canonicalize_url
from backend.app.pipeline.ingestion.external.common.hashing import sha256_bytes, sha256_json
from backend.app.pipeline.ingestion.external.common.http_client import HttpClientSettings, ResponseTooLargeError
from backend.app.pipeline.ingestion.external.manual_source.safe_http_client import SSRFProtectedHttpClient
from backend.app.pipeline.ingestion.external.social_common import PlatformURLPolicy, SocialCandidate, SocialCollectionResult, SocialConnector, SocialError, SocialItemProcessor

SOURCE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
SUBREDDIT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_]{1,20}$")
XML_TYPES = frozenset({"application/atom+xml", "application/rss+xml", "application/xml", "text/xml"})


@dataclass(frozen=True, slots=True)
class RedditSource:
    source_id: str
    name: str
    subreddit: str
    enabled: bool = False
    limit: int = 30
    transport: str = "reddit_oauth"
    request_timeout_seconds: float = 20.0
    rate_limit_delay_seconds: float = 1.0
    fetch_linked_articles: bool = True
    max_response_bytes: int = 2 * 1024 * 1024
    max_redirects: int = 3

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> "RedditSource":
        allowed = {"source_id", "name", "source_type", "transport", "enabled", "subreddit", "max_items", "limit",
                   "request_timeout_seconds", "rate_limit_delay_seconds", "fetch_linked_articles", "max_response_bytes", "max_redirects"}
        if set(value) - allowed: raise ValueError("unsupported Reddit source configuration")
        source_id, name, subreddit = (str(value.get(key) or "").strip() for key in ("source_id", "name", "subreddit"))
        transport, limit = str(value.get("transport") or "reddit_oauth"), int(value.get("max_items", value.get("limit", 30)))
        timeout, delay = float(value.get("request_timeout_seconds", 20)), float(value.get("rate_limit_delay_seconds", 1))
        max_bytes, redirects = int(value.get("max_response_bytes", 2 * 1024 * 1024)), int(value.get("max_redirects", 3))
        if (not SOURCE_ID_RE.fullmatch(source_id) or not name or str(value.get("source_type") or "reddit") != "reddit"
                or transport not in {"reddit_public_rss", "reddit_oauth"} or not SUBREDDIT_RE.fullmatch(subreddit)
                or not 1 <= limit <= 100 or not 1 <= timeout <= 60 or not 0 <= delay <= 30
                or not 1024 <= max_bytes <= 5 * 1024 * 1024 or not 0 <= redirects <= 5):
            raise ValueError("invalid Reddit source configuration")
        return cls(source_id, name, subreddit, bool(value.get("enabled", False)), limit, transport, timeout, delay,
                   bool(value.get("fetch_linked_articles", True)), max_bytes, redirects)


class RedditAccessError(RuntimeError):
    def __init__(self, category: str, *, retryable: bool) -> None:
        super().__init__(category); self.category, self.retryable = category, retryable


def _status_error(status: int) -> RedditAccessError:
    if status in {401, 403}: return RedditAccessError("source_access_unavailable", retryable=False)
    if status == 429: return RedditAccessError("rate_limited", retryable=True)
    if 500 <= status <= 599: return RedditAccessError("upstream_temporarily_unavailable", retryable=True)
    return RedditAccessError("malformed_response", retryable=False)


class RedditPublicRSSClient:
    def __init__(self, source: RedditSource, *, http_client: Any | None = None) -> None:
        self.source = source
        settings = HttpClientSettings(connect_timeout_seconds=min(5, source.request_timeout_seconds),
            read_timeout_seconds=source.request_timeout_seconds, max_response_bytes=source.max_response_bytes,
            max_redirects=source.max_redirects, user_agent="CTI-Tool-External-Sources/1.0 (public Reddit RSS reader)")
        expected = f"/r/{source.subreddit}/.rss"
        self.http_client = http_client or SSRFProtectedHttpClient(
            PlatformURLPolicy("www.reddit.com", lambda path: path.lower() == expected.lower()), settings=settings)

    def listing(self):
        url = f"https://www.reddit.com/r/{self.source.subreddit}/.rss"
        try: response = self.http_client.get(url, headers={"Accept": ",".join(sorted(XML_TYPES))})
        except ResponseTooLargeError as exc: raise RedditAccessError("malformed_response", retryable=False) from exc
        except requests.Timeout as exc: raise RedditAccessError("network_timeout", retryable=True) from exc
        except requests.HTTPError as exc: raise _status_error(exc.response.status_code if exc.response is not None else 500) from exc
        except requests.RequestException as exc: raise RedditAccessError("upstream_temporarily_unavailable", retryable=True) from exc
        except Exception as exc: raise RedditAccessError("source_access_unavailable", retryable=False) from exc
        parts, expected = urlsplit(response.url), f"/r/{self.source.subreddit}/.rss"
        media = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if parts.scheme != "https" or parts.hostname != "www.reddit.com" or parts.port is not None or parts.path.lower() != expected.lower():
            raise RedditAccessError("source_access_unavailable", retryable=False)
        if media not in XML_TYPES or b"<!DOCTYPE" in response.body.upper() or b"<!ENTITY" in response.body.upper():
            raise RedditAccessError("malformed_response", retryable=False)
        return response


class RedditOAuthClient:
    """Optional application-only OAuth adapter; separate from public RSS."""
    def __init__(self, *, client_id=None, client_secret=None, user_agent=None, session=None, timeout: float = 20) -> None:
        self.client_id, self.client_secret = client_id or os.getenv("REDDIT_CLIENT_ID"), client_secret or os.getenv("REDDIT_CLIENT_SECRET")
        self.user_agent, self.session, self.timeout, self._token = user_agent or os.getenv("REDDIT_USER_AGENT"), session or requests.Session(), timeout, None
        self.session.trust_env = False
    @property
    def configured(self) -> bool: return bool(self.client_id and self.client_secret and self.user_agent)
    def listing(self, subreddit: str, *, limit: int, after=None) -> dict[str, Any]:
        if not self.configured: raise RedditAccessError("source_configuration", retryable=False)
        try:
            if self._token is None:
                response = self.session.post("https://www.reddit.com/api/v1/access_token", auth=(self.client_id, self.client_secret), data={"grant_type":"client_credentials"}, headers={"User-Agent":self.user_agent}, timeout=self.timeout)
                if not 200 <= response.status_code <= 299: raise _status_error(response.status_code)
                self._token = response.json().get("access_token")
                if not self._token: raise RedditAccessError("source_configuration", retryable=False)
            response = self.session.get(f"https://oauth.reddit.com/r/{subreddit}/new", params={"limit":limit,"raw_json":1,**({"after":after} if after else {})}, headers={"Authorization":f"Bearer {self._token}","User-Agent":self.user_agent}, timeout=self.timeout)
            if not 200 <= response.status_code <= 299: raise _status_error(response.status_code)
            value = response.json()
        except (requests.ConnectionError, requests.Timeout) as exc: raise RedditAccessError("network_timeout", retryable=True) from exc
        except ValueError as exc: raise RedditAccessError("malformed_response", retryable=False) from exc
        if not isinstance(value, dict): raise RedditAccessError("malformed_response", retryable=False)
        return value


class RedditConnector(SocialConnector):
    def __init__(self, source: RedditSource, *, api_client=None, rss_client=None, processor=None) -> None:
        self.source, self.source_name, self.api_client = source, source.name, api_client or RedditOAuthClient()
        self.rss_client, self.processor = rss_client, processor or SocialItemProcessor()
    def collect_result(self) -> SocialCollectionResult:
        result = SocialCollectionResult(self.source.source_id)
        if not self.source.enabled: result.status = "disabled"; return result
        state = self.processor.state["sources"].setdefault(self.source.source_id, {})
        try:
            candidates, raw_hash = self._public() if self.source.transport == "reddit_public_rss" else self._oauth()
            state["raw_content_hash"] = raw_hash
            for candidate in candidates[:self.source.limit]:
                try: self.add(result, self.processor.process(candidate))
                except Exception: result.errors.append(SocialError(self.source.source_id, "internal_failure"))
            state.update({"source_config_hash":sha256_json(asdict(self.source)),"last_checked":self.processor._now_iso()})
        except RedditAccessError as error: result.status="failed"; result.errors.append(SocialError(self.source.source_id,error.category,error.retryable))
        except Exception: result.status="failed"; result.errors.append(SocialError(self.source.source_id,"internal_failure"))
        if result.errors and result.all_items: result.status="partial"
        state["last_status"] = result.status
        return result
    def _public(self):
        response = (self.rss_client or RedditPublicRSSClient(self.source)).listing(); parsed = feedparser.parse(response.body)
        if getattr(parsed,"bozo",False) and not parsed.entries: raise RedditAccessError("parsing_contract",retryable=False)
        return [value for entry in list(parsed.entries)[:self.source.limit] if (value:=self._rss_candidate(entry))], sha256_bytes(response.body)
    def _rss_candidate(self, entry):
        title,item_id=str(entry.get("title") or "").strip(),str(entry.get("id") or "").strip(); links=entry.get("links") or []
        post=next((str(x.get("href")) for x in links if "reddit.com" in str(x.get("href"))),"")
        if not title or not item_id or not post:return None
        canonical=canonicalize_url(post); parts=urlsplit(canonical)
        if parts.scheme!="https" or parts.hostname!="www.reddit.com" or not parts.path.lower().startswith(f"/r/{self.source.subreddit.lower()}/"):return None
        raw=str(entry.get("content",[{}])[0].get("value") if entry.get("content") else entry.get("summary") or ""); soup=BeautifulSoup(raw,"lxml"); body=soup.get_text("\n",strip=True)
        external=next((str(x.get("href")) for x in links if "reddit.com" not in str(x.get("href"))),None)
        if external is None:
            external=next((str(anchor.get("href")) for anchor in soup.select("a[href]") if "reddit.com" not in str(anchor.get("href"))),None)
        try: external=canonicalize_url(external) if external and self.source.fetch_linked_articles else None
        except ValueError: external=None
        return SocialCandidate(self.source.source_id,self.source.name,"reddit",item_id,title,canonical,body,external,str(entry.get("published") or entry.get("updated") or "") or None,None,{"subreddit":self.source.subreddit,"public_reference":canonical,"linked_article_present":bool(external),"transport":self.source.transport})
    def _oauth(self):
        data=self.api_client.listing(self.source.subreddit,limit=self.source.limit,after=None); listing=data.get("data") if isinstance(data.get("data"),dict) else None; children=listing.get("children") if listing else None
        if not isinstance(children,list):raise RedditAccessError("malformed_response",retryable=False)
        return [value for child in children if isinstance(child,dict) and isinstance(child.get("data"),dict) and (value:=self._oauth_candidate(child["data"]))],sha256_json(data)
    def _oauth_candidate(self,post):
        item_id,title,permalink=(str(post.get(k) or "").strip() for k in ("name","title","permalink"))
        if not item_id or not title or not permalink:return None
        external=str(post.get("url_overridden_by_dest") or "").strip() or None
        try: external=canonicalize_url(external) if external and "reddit.com" not in external.lower() and self.source.fetch_linked_articles else None
        except ValueError: external=None
        published=datetime.fromtimestamp(float(post["created_utc"]),tz=timezone.utc).isoformat().replace("+00:00","Z") if post.get("created_utc") is not None else None; canonical=canonicalize_url(f"https://www.reddit.com{permalink}")
        return SocialCandidate(self.source.source_id,self.source.name,"reddit",item_id,title,canonical,str(post.get("selftext") or ""),external,published,None,{"subreddit":self.source.subreddit,"public_reference":canonical,"linked_article_present":bool(external),"transport":self.source.transport})
