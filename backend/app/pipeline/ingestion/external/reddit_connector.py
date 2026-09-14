from __future__ import annotations

import os
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Protocol
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
POST_ID_RE = re.compile(r"^(?:t3_)?[A-Za-z0-9]{3,16}$")
XML_TYPES = frozenset({"application/atom+xml", "application/rss+xml", "application/xml", "text/xml"})
REDDIT_TRANSPORTS = frozenset({"reddit_public_rss", "rss_with_browser_fallback", "reddit_oauth"})


@dataclass(frozen=True, slots=True)
class RedditSource:
    source_id: str; name: str; subreddit: str; enabled: bool = False; limit: int = 30
    transport: str = "reddit_oauth"; request_timeout_seconds: float = 20.0; rate_limit_delay_seconds: float = 1.0
    fetch_linked_articles: bool = True; max_response_bytes: int = 2 * 1024 * 1024; max_redirects: int = 3
    fallback_enabled: bool = False; minimum_usable_posts: int = 1; target_count: int = 30
    max_scrolls: int = 6; max_stale_scrolls: int = 2; navigation_timeout_seconds: float = 20.0
    overall_fallback_timeout_seconds: float = 45.0

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> "RedditSource":
        allowed = {"source_id","name","source_type","transport","enabled","subreddit","max_items","limit","request_timeout_seconds","rate_limit_delay_seconds","fetch_linked_articles","max_response_bytes","max_redirects","fallback_enabled","minimum_usable_posts","target_count","max_scrolls","max_stale_scrolls","navigation_timeout_seconds","overall_fallback_timeout_seconds"}
        if set(value)-allowed: raise ValueError("unsupported Reddit source configuration")
        try:
            source_id,name,subreddit=(str(value.get(k) or "").strip() for k in ("source_id","name","subreddit")); transport=str(value.get("transport") or "reddit_oauth")
            limit=int(value.get("max_items",value.get("limit",30))); timeout=float(value.get("request_timeout_seconds",20)); delay=float(value.get("rate_limit_delay_seconds",1)); max_bytes=int(value.get("max_response_bytes",2*1024*1024)); redirects=int(value.get("max_redirects",3))
            minimum=int(value.get("minimum_usable_posts",1)); target=int(value.get("target_count",limit)); scrolls=int(value.get("max_scrolls",6)); stale=int(value.get("max_stale_scrolls",2)); navigation=float(value.get("navigation_timeout_seconds",20)); overall=float(value.get("overall_fallback_timeout_seconds",45))
        except (TypeError,ValueError) as exc: raise ValueError("invalid Reddit source configuration") from exc
        fallback=bool(value.get("fallback_enabled",transport=="rss_with_browser_fallback"))
        if (not SOURCE_ID_RE.fullmatch(source_id) or not name or str(value.get("source_type") or "reddit")!="reddit" or transport not in REDDIT_TRANSPORTS or not SUBREDDIT_RE.fullmatch(subreddit) or not 1<=limit<=100 or not 1<=timeout<=60 or not 0<=delay<=30 or not 1024<=max_bytes<=5*1024*1024 or not 0<=redirects<=5 or not 1<=minimum<=limit or not minimum<=target<=100 or not 0<=scrolls<=20 or not 1<=stale<=5 or stale>max(1,scrolls) or not 5<=navigation<=60 or not navigation<=overall<=120 or (transport!="rss_with_browser_fallback" and fallback)):
            raise ValueError("invalid Reddit source configuration")
        return cls(source_id,name,subreddit,bool(value.get("enabled",False)),limit,transport,timeout,delay,bool(value.get("fetch_linked_articles",True)),max_bytes,redirects,fallback,minimum,target,scrolls,stale,navigation,overall)


@dataclass(frozen=True, slots=True)
class RedditPost:
    post_id: str; title: str; permalink: str; body: str = ""; external_url: str|None = None; published: str|None = None
    author: str|None = None; score: str|None = None; comment_count: str|None = None; subreddit_name: str|None = None


class RedditAccessError(RuntimeError):
    def __init__(self,category:str,*,retryable:bool)->None: super().__init__(category);self.category,self.retryable=category,retryable


class RedditBrowser(Protocol):
    def collect(self)->list[RedditPost]: ...


def _status_error(status:int)->RedditAccessError:
    if status in {401,403}: return RedditAccessError("rss_http_failure",retryable=False)
    if status==429:return RedditAccessError("rate_limited",retryable=True)
    if 500<=status<=599:return RedditAccessError("rss_http_failure",retryable=True)
    return RedditAccessError("rss_http_failure",retryable=False)


def _oauth_status_error(status:int)->RedditAccessError:
    if status in {401,403}:return RedditAccessError("authorization_failed",retryable=False)
    if status==429:return RedditAccessError("rate_limited",retryable=True)
    if 500<=status<=599:return RedditAccessError("upstream_temporarily_unavailable",retryable=True)
    return RedditAccessError("malformed_response",retryable=False)


class RedditPublicRSSClient:
    def __init__(self,source:RedditSource,*,http_client:Any|None=None)->None:
        self.source=source;settings=HttpClientSettings(connect_timeout_seconds=min(5,source.request_timeout_seconds),read_timeout_seconds=source.request_timeout_seconds,max_response_bytes=source.max_response_bytes,max_redirects=source.max_redirects,user_agent="CTI-Tool-External-Sources/1.0 (public Reddit RSS reader)");expected=f"/r/{source.subreddit}/.rss"
        self.http_client=http_client or SSRFProtectedHttpClient(PlatformURLPolicy("www.reddit.com",lambda path:path.lower()==expected.lower()),settings=settings)
    def listing(self):
        url=f"https://www.reddit.com/r/{self.source.subreddit}/.rss"
        try:response=self.http_client.get(url,headers={"Accept":",".join(sorted(XML_TYPES))})
        except ResponseTooLargeError as exc:raise RedditAccessError("rss_parsing_failure",retryable=False) from exc
        except requests.Timeout as exc:raise RedditAccessError("rss_timeout",retryable=True) from exc
        except requests.HTTPError as exc:raise _status_error(exc.response.status_code if exc.response is not None else 500) from exc
        except requests.RequestException as exc:raise RedditAccessError("rss_network_failure",retryable=True) from exc
        except Exception as exc:raise RedditAccessError("rss_http_failure",retryable=False) from exc
        parts=urlsplit(response.url);expected=f"/r/{self.source.subreddit}/.rss";media=response.headers.get("Content-Type","").split(";",1)[0].strip().lower()
        if parts.scheme!="https" or parts.hostname!="www.reddit.com" or parts.port is not None or parts.path.lower()!=expected.lower():raise RedditAccessError("rss_http_failure",retryable=False)
        if media not in XML_TYPES or b"<!DOCTYPE" in response.body.upper() or b"<!ENTITY" in response.body.upper():raise RedditAccessError("rss_parsing_failure",retryable=False)
        return response


class RedditOAuthClient:
    """Optional application-only OAuth adapter; separate from RSS/fallback collection."""
    def __init__(self,*,client_id=None,client_secret=None,user_agent=None,session=None,timeout:float=20)->None:
        self.client_id,self.client_secret=client_id or os.getenv("REDDIT_CLIENT_ID"),client_secret or os.getenv("REDDIT_CLIENT_SECRET");self.user_agent,self.session,self.timeout,self._token=user_agent or os.getenv("REDDIT_USER_AGENT"),session or requests.Session(),timeout,None;self.session.trust_env=False
    @property
    def configured(self)->bool:return bool(self.client_id and self.client_secret and self.user_agent)
    def listing(self,subreddit:str,*,limit:int,after=None)->dict[str,Any]:
        if not self.configured:raise RedditAccessError("source_configuration",retryable=False)
        try:
            if self._token is None:
                response=self.session.post("https://www.reddit.com/api/v1/access_token",auth=(self.client_id,self.client_secret),data={"grant_type":"client_credentials"},headers={"User-Agent":self.user_agent},timeout=self.timeout)
                if not 200<=response.status_code<=299:raise _oauth_status_error(response.status_code)
                self._token=response.json().get("access_token")
                if not self._token:raise RedditAccessError("source_configuration",retryable=False)
            response=self.session.get(f"https://oauth.reddit.com/r/{subreddit}/new",params={"limit":limit,"raw_json":1,**({"after":after} if after else {})},headers={"Authorization":f"Bearer {self._token}","User-Agent":self.user_agent},timeout=self.timeout)
            if not 200<=response.status_code<=299:raise _oauth_status_error(response.status_code)
            value=response.json()
        except (requests.ConnectionError,requests.Timeout) as exc:raise RedditAccessError("network_timeout",retryable=True) from exc
        except ValueError as exc:raise RedditAccessError("malformed_response",retryable=False) from exc
        if not isinstance(value,dict):raise RedditAccessError("malformed_response",retryable=False)
        return value


class RedditConnector(SocialConnector):
    def __init__(self,source:RedditSource,*,api_client=None,rss_client=None,browser:RedditBrowser|None=None,processor=None)->None:self.source,self.source_name,self.api_client=source,source.name,api_client or RedditOAuthClient();self.rss_client,self.browser,self.processor=rss_client,browser,processor or SocialItemProcessor()
    def collect_result(self)->SocialCollectionResult:
        result=SocialCollectionResult(self.source.source_id)
        if not self.source.enabled:result.status="disabled";return result
        state=self.processor.state["sources"].setdefault(self.source.source_id,{})
        try:
            posts,raw_hash,method,warning=self._collect_posts();state.update({"raw_content_hash":raw_hash,"collection_method":method})
            for post in posts[:self.source.limit]:
                try:self.add(result,self.processor.process(self._candidate(post,method)))
                except Exception:result.errors.append(SocialError(self.source.source_id,"internal_failure"))
            if warning:result.errors.append(warning)
            state.update({"source_config_hash":sha256_json(asdict(self.source)),"last_checked":self.processor._now_iso()})
        except RedditAccessError as error:result.status="failed";result.errors.append(SocialError(self.source.source_id,error.category,error.retryable))
        except Exception:result.status="failed";result.errors.append(SocialError(self.source.source_id,"internal_failure"))
        if result.errors and result.all_items:result.status="partial"
        state["last_status"]=result.status;return result
    def _collect_posts(self):
        if self.source.transport=="reddit_oauth":posts,raw_hash=self._oauth();return posts,raw_hash,"reddit_oauth",None
        rss_error=None
        try:
            posts,raw_hash=self._public()
            if len(posts)>=self.source.minimum_usable_posts:return posts,raw_hash,"reddit_public_rss",None
            rss_error=RedditAccessError("rss_insufficient_results",retryable=True)
        except RedditAccessError as error:rss_error=error;posts,raw_hash=[],sha256_json({"rss":"unavailable"})
        if not self.source.fallback_enabled or self.source.transport!="rss_with_browser_fallback":raise rss_error
        browser=self.browser
        if browser is None:
            from backend.app.pipeline.ingestion.external.reddit_playwright import RedditPlaywrightCollector
            browser=RedditPlaywrightCollector(self.source)
        browser_posts=[post for value in browser.collect() if (post:=self._validated_post(value))]
        if not browser_posts:raise RedditAccessError("browser_insufficient_results",retryable=True)
        combined={post.post_id:post for post in posts};combined.update({post.post_id:post for post in browser_posts});selected=list(combined.values())[:self.source.target_count]
        return selected,sha256_json([asdict(post) for post in selected]),"reddit_browser_fallback",None
    def _public(self):
        response=(self.rss_client or RedditPublicRSSClient(self.source)).listing();parsed=feedparser.parse(response.body)
        if getattr(parsed,"bozo",False) and not parsed.entries:raise RedditAccessError("rss_parsing_failure",retryable=False)
        return [post for entry in list(parsed.entries)[:self.source.limit] if (post:=self._rss_post(entry))],sha256_bytes(response.body)
    def _rss_post(self,entry):
        title,item_id=str(entry.get("title") or "").strip(),str(entry.get("id") or "").strip();links=entry.get("links") or [];post=next((str(link.get("href")) for link in links if urlsplit(str(link.get("href"))).hostname=="www.reddit.com"),"")
        raw=str(entry.get("content",[{}])[0].get("value") if entry.get("content") else entry.get("summary") or "");soup=BeautifulSoup(raw,"lxml");body=soup.get_text("\n",strip=True);external=next((str(link.get("href")) for link in links if urlsplit(str(link.get("href"))).hostname!="www.reddit.com"),None)
        if external is None:external=next((str(anchor.get("href")) for anchor in soup.select("a[href]") if urlsplit(str(anchor.get("href"))).hostname!="www.reddit.com"),None)
        return self._validated_post(RedditPost(item_id,title,post,body,external,str(entry.get("published") or entry.get("updated") or "") or None))
    def _candidate(self,post:RedditPost,method:str)->SocialCandidate:
        external=None
        try:external=canonicalize_url(post.external_url) if post.external_url and self.source.fetch_linked_articles else None
        except ValueError:pass
        canonical=canonicalize_url(post.permalink);metadata={"subreddit":self.source.subreddit,"public_reference":canonical,"linked_article_present":bool(external),"transport":self.source.transport,"collection_method":method}
        if post.score is not None:metadata["score"]=post.score
        if post.comment_count is not None:metadata["comment_count"]=post.comment_count
        return SocialCandidate(self.source.source_id,self.source.name,"reddit",post.post_id,post.title,canonical,post.body,external,post.published,None,metadata)
    def _validated_post(self,post:RedditPost)->RedditPost|None:
        if not post.title or not POST_ID_RE.fullmatch(post.post_id):return None
        permalink=f"https://www.reddit.com{post.permalink}" if post.permalink.startswith("/") else post.permalink
        try:canonical=canonicalize_url(permalink)
        except ValueError:return None
        parts=urlsplit(canonical)
        if parts.scheme!="https" or parts.hostname!="www.reddit.com" or not parts.path.lower().startswith(f"/r/{self.source.subreddit.lower()}/"):return None
        if not post.body.strip() and not post.external_url:return None
        return RedditPost(post.post_id,post.title,canonical,post.body.strip(),post.external_url,post.published,post.author,post.score,post.comment_count,post.subreddit_name)
    def _oauth(self):
        data=self.api_client.listing(self.source.subreddit,limit=self.source.limit,after=None);listing=data.get("data") if isinstance(data.get("data"),dict) else None;children=listing.get("children") if listing else None
        if not isinstance(children,list):raise RedditAccessError("malformed_response",retryable=False)
        return [post for child in children if isinstance(child,dict) and isinstance(child.get("data"),dict) and (post:=self._oauth_post(child["data"]))],sha256_json(data)
    def _oauth_post(self,value):
        item_id,title,permalink=(str(value.get(k) or "").strip() for k in ("name","title","permalink"));published=datetime.fromtimestamp(float(value["created_utc"]),tz=timezone.utc).isoformat().replace("+00:00","Z") if value.get("created_utc") is not None else None
        return self._validated_post(RedditPost(item_id,title,f"https://www.reddit.com{permalink}",str(value.get("selftext") or ""),str(value.get("url_overridden_by_dest") or "") or None,published))
