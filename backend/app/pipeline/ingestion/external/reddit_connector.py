from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from typing import Any

import requests

from backend.app.pipeline.ingestion.external.common.canonical_url import canonicalize_url
from backend.app.pipeline.ingestion.external.common.hashing import sha256_json
from backend.app.pipeline.ingestion.external.social_common import SocialCandidate, SocialCollectionResult, SocialConnector, SocialError, SocialItemProcessor


@dataclass(frozen=True, slots=True)
class RedditSource:
    source_id: str
    name: str
    subreddit: str
    enabled: bool = False
    limit: int = 30

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> "RedditSource":
        source_id, name = (str(value.get(key) or "").strip() for key in ("source_id", "name"))
        subreddit = str(value.get("subreddit") or "").strip()
        limit = int(value.get("limit", value.get("target_count", 30)))
        if not source_id or not name or not subreddit.replace("_", "").isalnum() or not 1 <= limit <= 100: raise ValueError("invalid Reddit source")
        return cls(source_id, name, subreddit, bool(value.get("enabled", False)), limit)


class RedditOAuthClient:
    """Minimal application-only Reddit Data API client; never uses user login."""

    def __init__(self, *, client_id: str | None = None, client_secret: str | None = None, user_agent: str | None = None, session: requests.Session | None = None, timeout: float = 20) -> None:
        self.client_id = client_id or os.getenv("REDDIT_CLIENT_ID")
        self.client_secret = client_secret or os.getenv("REDDIT_CLIENT_SECRET")
        self.user_agent = user_agent or os.getenv("REDDIT_USER_AGENT")
        self.session, self.timeout, self._token = session or requests.Session(), timeout, None

    @property
    def configured(self) -> bool: return bool(self.client_id and self.client_secret and self.user_agent)

    def listing(self, subreddit: str, *, limit: int, after: str | None = None) -> dict[str, Any]:
        if not self.configured: raise RuntimeError("reddit_credentials_missing")
        if self._token is None:
            response = self.session.post("https://www.reddit.com/api/v1/access_token", auth=(self.client_id, self.client_secret), data={"grant_type": "client_credentials"}, headers={"User-Agent": self.user_agent}, timeout=self.timeout)
            response.raise_for_status(); data = response.json(); self._token = data.get("access_token")
            if not self._token: raise RuntimeError("reddit_token_missing")
        params = {"limit": limit, "raw_json": 1}
        if after: params["after"] = after
        response = self.session.get(f"https://oauth.reddit.com/r/{subreddit}/new", params=params,
            headers={"Authorization": f"Bearer {self._token}", "User-Agent": self.user_agent}, timeout=self.timeout)
        response.raise_for_status(); value = response.json()
        if not isinstance(value, dict): raise ValueError("invalid Reddit response")
        return value


class RedditConnector(SocialConnector):
    def __init__(self, source: RedditSource, *, api_client: RedditOAuthClient | None = None, processor: SocialItemProcessor | None = None) -> None:
        self.source, self.source_name = source, source.name
        self.api_client, self.processor = api_client or RedditOAuthClient(), processor or SocialItemProcessor()

    def collect_result(self) -> SocialCollectionResult:
        result = SocialCollectionResult(self.source.source_id)
        if not self.source.enabled: result.status = "disabled"; return result
        source_state = self.processor.state["sources"].setdefault(self.source.source_id, {})
        try:
            data = self.api_client.listing(self.source.subreddit, limit=self.source.limit, after=None)
            listing = data.get("data") if isinstance(data.get("data"), dict) else None
            children = listing.get("children") if listing else None
            if not isinstance(children, list): raise ValueError("invalid Reddit listing")
            source_state["raw_content_hash"] = sha256_json(data)
            for child in children:
                post = child.get("data") if isinstance(child, dict) and isinstance(child.get("data"), dict) else None
                candidate = self._candidate(post) if post else None
                if candidate:
                    try: self.add(result, self.processor.process(candidate))
                    except Exception: result.errors.append(SocialError(self.source.source_id, "item_processing_failed"))
            if not result.errors: source_state["after"] = listing.get("after")
            source_state.update({"source_config_hash": sha256_json(asdict(self.source)), "last_checked": self.processor._now_iso()})
        except Exception as error:
            category = "credentials_missing" if str(error) == "reddit_credentials_missing" else "source_failed"
            result.status = "failed"; result.errors.append(SocialError(self.source.source_id, category, category != "credentials_missing"))
        if result.errors and result.all_items: result.status = "partial"
        source_state["last_status"] = result.status
        return result

    def _candidate(self, post: dict[str, Any]) -> SocialCandidate | None:
        item_id, title, permalink = (str(post.get(key) or "").strip() for key in ("name", "title", "permalink"))
        if not item_id or not title or not permalink: return None
        body = str(post.get("selftext") or "").strip()
        destination = str(post.get("url_overridden_by_dest") or "").strip()
        external = None
        if destination and "reddit.com" not in destination.lower() and "redd.it" not in destination.lower():
            external = canonicalize_url(destination)
        published = None
        if post.get("created_utc") is not None:
            from datetime import datetime, timezone
            published = datetime.fromtimestamp(float(post["created_utc"]), tz=timezone.utc).isoformat().replace("+00:00", "Z")
        return SocialCandidate(self.source.source_id, self.source.name, "reddit", item_id, title,
            canonicalize_url(f"https://www.reddit.com{permalink}"), body, external, published,
            str(post.get("author") or "") or None, {"subreddit": post.get("subreddit"), "score": post.get("score"), "num_comments": post.get("num_comments")})
