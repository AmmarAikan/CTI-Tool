from __future__ import annotations

import re
import time
from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import urlsplit

import requests
from bs4 import BeautifulSoup

from backend.app.pipeline.ingestion.external.common.canonical_url import canonicalize_url
from backend.app.pipeline.ingestion.external.common.hashing import sha256_bytes, sha256_json
from backend.app.pipeline.ingestion.external.common.http_client import HttpClientSettings, ResponseTooLargeError
from backend.app.pipeline.ingestion.external.manual_source.safe_http_client import SSRFProtectedHttpClient
from backend.app.pipeline.ingestion.external.social_common import PlatformURLPolicy, SocialCandidate, SocialCollectionResult, SocialConnector, SocialError, SocialItemProcessor

SOURCE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
CHANNEL_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{4,31}$")


@dataclass(frozen=True, slots=True)
class TelegramSource:
    source_id: str
    name: str
    channel: str
    enabled: bool = True
    max_pages: int = 3
    transport: str = "telegram_public_preview"
    max_messages: int = 50
    request_timeout_seconds: float = 20.0
    rate_limit_delay_seconds: float = 1.0
    fetch_linked_articles: bool = True
    max_response_bytes: int = 2 * 1024 * 1024
    max_redirects: int = 3

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> "TelegramSource":
        allowed={"source_id","name","source_type","transport","enabled","channel","max_pages","max_messages","request_timeout_seconds","rate_limit_delay_seconds","fetch_linked_articles","max_response_bytes","max_redirects"}
        if set(value)-allowed: raise ValueError("unsupported Telegram source configuration")
        source_id,name,channel=(str(value.get(k) or "").strip() for k in ("source_id","name","channel")); transport=str(value.get("transport") or "telegram_public_preview")
        pages,messages=int(value.get("max_pages",3)),int(value.get("max_messages",50)); timeout,delay=float(value.get("request_timeout_seconds",20)),float(value.get("rate_limit_delay_seconds",1)); max_bytes,redirects=int(value.get("max_response_bytes",2*1024*1024)),int(value.get("max_redirects",3))
        if (not SOURCE_ID_RE.fullmatch(source_id) or not name or str(value.get("source_type") or "telegram")!="telegram" or transport!="telegram_public_preview" or not CHANNEL_RE.fullmatch(channel)
                or not 1<=pages<=5 or not 1<=messages<=100 or not 1<=timeout<=60 or not 0<=delay<=30 or not 1024<=max_bytes<=5*1024*1024 or not 0<=redirects<=5): raise ValueError("invalid Telegram source configuration")
        return cls(source_id,name,channel,bool(value.get("enabled",True)),pages,transport,messages,timeout,delay,bool(value.get("fetch_linked_articles",True)),max_bytes,redirects)


class TelegramAccessError(RuntimeError):
    def __init__(self,category:str,*,retryable:bool)->None: super().__init__(category);self.category,self.retryable=category,retryable


class TelegramPublicClient:
    def __init__(self,source:TelegramSource,*,http_client:Any|None=None)->None:
        self.source=source; prefix=f"/s/{source.channel}"
        settings=HttpClientSettings(connect_timeout_seconds=min(5,source.request_timeout_seconds),read_timeout_seconds=source.request_timeout_seconds,max_response_bytes=source.max_response_bytes,max_redirects=source.max_redirects,user_agent="CTI-Tool-External-Sources/1.0 (public Telegram preview reader)")
        self.http_client=http_client or SSRFProtectedHttpClient(PlatformURLPolicy("t.me",lambda path:path.lower()==prefix.lower()),settings=settings)
    def get(self,before:int|None=None):
        url=f"https://t.me/s/{self.source.channel}"+(f"?before={before}" if before else "")
        try: response=self.http_client.get(url,headers={"Accept":"text/html,application/xhtml+xml"})
        except ResponseTooLargeError as exc: raise TelegramAccessError("malformed_response",retryable=False) from exc
        except requests.Timeout as exc: raise TelegramAccessError("network_timeout",retryable=True) from exc
        except requests.HTTPError as exc:
            status=exc.response.status_code if exc.response is not None else 500
            category="source_access_unavailable" if status in {401,403} else "rate_limited" if status==429 else "upstream_temporarily_unavailable" if 500<=status<=599 else "malformed_response"
            raise TelegramAccessError(category,retryable=status==429 or 500<=status<=599) from exc
        except requests.RequestException as exc: raise TelegramAccessError("upstream_temporarily_unavailable",retryable=True) from exc
        except Exception as exc: raise TelegramAccessError("source_access_unavailable",retryable=False) from exc
        parts=urlsplit(response.url); media=response.headers.get("Content-Type","").split(";",1)[0].lower()
        if parts.scheme!="https" or parts.hostname!="t.me" or parts.port is not None or parts.path.lower()!=f"/s/{self.source.channel.lower()}" or media not in {"text/html","application/xhtml+xml"}: raise TelegramAccessError("malformed_response",retryable=False)
        return response


class TelegramConnector(SocialConnector):
    def __init__(self,source:TelegramSource,*,http_client=None,public_client=None,processor=None,sleeper=time.sleep)->None:
        self.source,self.source_name=source,source.name; self.client=public_client or TelegramPublicClient(source,http_client=http_client);self.processor=processor or SocialItemProcessor();self.sleeper=sleeper
    def collect_result(self)->SocialCollectionResult:
        result=SocialCollectionResult(self.source.source_id)
        if not self.source.enabled:result.status="disabled";return result
        state=self.processor.state["sources"].setdefault(self.source.source_id,{});newest_known,before,seen=int(state.get("checkpoint_message_id",0)),None,set();newest_seen=newest_known;seen_cursors=set()
        try:
            for page in range(self.source.max_pages):
                if before in seen_cursors:break
                seen_cursors.add(before)
                if page:self.sleeper(self.source.rate_limit_delay_seconds)
                response=self.client.get(before);state.setdefault("pages",{})[str(page)]={"raw_content_hash":sha256_bytes(response.body)};soup=BeautifulSoup(response.body,"lxml");messages=soup.select(".tgme_widget_message[data-post]");ids=[];added=0
                for message in messages:
                    data_post=str(message.get("data-post") or "");match=re.fullmatch(re.escape(self.source.channel)+r"/(\d+)",data_post,re.I)
                    if not match or data_post in seen:continue
                    seen.add(data_post);message_id=int(match.group(1));ids.append(message_id);newest_seen=max(newest_seen,message_id)
                    if message_id<=newest_known or len(result.all_items)>=self.source.max_messages:continue
                    candidate=self._candidate(message,data_post,message_id)
                    if candidate:
                        try:self.add(result,self.processor.process(candidate));added+=1
                        except Exception:result.errors.append(SocialError(self.source.source_id,"internal_failure"))
                if len(result.all_items)>=self.source.max_messages or not ids or min(ids)<=newest_known or added==0:break
                cursor=min(ids)
                if cursor<=0 or cursor==before:break
                before=cursor
        except TelegramAccessError as error:result.status="failed";result.errors.append(SocialError(self.source.source_id,error.category,error.retryable))
        except Exception:result.status="failed";result.errors.append(SocialError(self.source.source_id,"internal_failure"))
        if result.status!="failed" and not result.errors:state["checkpoint_message_id"]=newest_seen
        if result.errors and result.all_items:result.status="partial"
        state.update({"source_config_hash":sha256_json(asdict(self.source)),"last_checked":self.processor._now_iso(),"last_status":result.status})
        return result
    def _candidate(self,message,data_post:str,message_id:int):
        text=message.select_one(".tgme_widget_message_text");body=text.get_text("\n",strip=True) if text else "";preview=message.select_one("a.tgme_widget_message_link_preview[href]");external=str(preview.get("href")) if preview else None
        if external:
            try:
                parsed=urlsplit(external)
                if parsed.scheme not in {"http","https"} or parsed.hostname in {"t.me","telegram.me"} or "/joinchat/" in parsed.path or parsed.path.startswith("/+"):external=None
                else:external=canonicalize_url(external) if self.source.fetch_linked_articles else None
            except ValueError:external=None
        if not body and not external:return None
        timestamp=message.select_one("time[datetime]");views=message.select_one(".tgme_widget_message_views");canonical=canonicalize_url(f"https://t.me/{data_post}")
        return SocialCandidate(self.source.source_id,self.source.name,"telegram",str(message_id),(body or f"Public channel post {message_id}")[:120],canonical,body,external,str(timestamp.get("datetime")) if timestamp else None,None,{"channel":self.source.channel,"views":views.get_text(strip=True) if views else None,"public_reference":canonical,"linked_article_present":bool(external),"transport":self.source.transport})
