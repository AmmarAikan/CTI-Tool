from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

from bs4 import BeautifulSoup

from backend.app.pipeline.ingestion.external.common.canonical_url import canonicalize_url
from backend.app.pipeline.ingestion.external.common.hashing import sha256_bytes, sha256_json
from backend.app.pipeline.ingestion.external.common.http_client import ExternalHttpClient
from backend.app.pipeline.ingestion.external.social_common import SocialCandidate, SocialCollectionResult, SocialConnector, SocialError, SocialItemProcessor


ALGOLIA_SEARCH_BY_DATE = "https://hn.algolia.com/api/v1/search_by_date"


@dataclass(frozen=True, slots=True)
class HackerNewsSource:
    source_id: str
    name: str
    query: str
    enabled: bool = True
    limit: int = 30
    max_pages: int = 3

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> "HackerNewsSource":
        source_id, name, query = (str(value.get(key) or "").strip() for key in ("source_id", "name", "query"))
        limit, pages = int(value.get("limit", 30)), int(value.get("max_pages", 3))
        if not source_id or not name or not query or not 1 <= limit <= 1000 or pages <= 0: raise ValueError("invalid Hacker News source")
        return cls(source_id, name, query, bool(value.get("enabled", True)), limit, pages)


class HackerNewsConnector(SocialConnector):
    def __init__(self, source: HackerNewsSource, *, http_client: ExternalHttpClient | None = None, processor: SocialItemProcessor | None = None) -> None:
        self.source, self.source_name = source, source.name
        self.http_client, self.processor = http_client or ExternalHttpClient(), processor or SocialItemProcessor()

    def collect_result(self) -> SocialCollectionResult:
        result = SocialCollectionResult(self.source.source_id)
        if not self.source.enabled: result.status = "disabled"; return result
        source_state = self.processor.state["sources"].setdefault(self.source.source_id, {})
        since = int(source_state.get("checkpoint_created_at_i", 0)); completed = False
        for page in range(self.source.max_pages):
            params = {"query": self.source.query, "tags": "story", "numericFilters": f"created_at_i>{since}", "hitsPerPage": self.source.limit, "page": page}
            try:
                response = self.http_client.get(f"{ALGOLIA_SEARCH_BY_DATE}?{urlencode(params)}", headers={"Accept": "application/json"})
                data = json.loads(response.body)
                hits = data.get("hits") if isinstance(data, dict) else None
                if not isinstance(hits, list): raise ValueError("invalid Algolia response")
                source_state.setdefault("pages", {})[str(page)] = {"raw_content_hash": sha256_bytes(response.body)}
                for hit in hits:
                    if not isinstance(hit, dict): continue
                    candidate = self._candidate(hit)
                    if candidate:
                        try: self.add(result, self.processor.process(candidate))
                        except Exception: result.errors.append(SocialError(self.source.source_id, "item_processing_failed"))
                if page + 1 >= int(data.get("nbPages", 1)): completed = True; break
            except Exception:
                result.errors.append(SocialError(self.source.source_id, "source_failed", True)); result.status = "failed"
                source_state.update({"last_checked": self.processor._now_iso(), "last_status": "failed"})
                return result
        if completed and not result.errors:
            newest = max([since, *[int(item.metadata.get("created_at_i", 0)) for item in result.all_items]])
            source_state["checkpoint_created_at_i"] = newest
        if result.errors: result.status = "partial" if result.all_items else "failed"
        source_state.update({"source_config_hash": sha256_json({k: getattr(self.source, k) for k in self.source.__slots__}), "last_checked": self.processor._now_iso(), "last_status": result.status})
        return result

    def _candidate(self, hit: dict[str, Any]) -> SocialCandidate | None:
        item_id, title = str(hit.get("objectID") or "").strip(), str(hit.get("title") or "").strip()
        if not item_id or not title: return None
        body = BeautifulSoup(str(hit.get("story_text") or ""), "lxml").get_text("\n", strip=True)
        external = str(hit.get("url") or "").strip() or None
        return SocialCandidate(self.source.source_id, self.source.name, "hackernews", item_id, title,
            canonicalize_url(f"https://news.ycombinator.com/item?id={item_id}"), body,
            canonicalize_url(external) if external else None, str(hit.get("created_at") or "") or None,
            str(hit.get("author") or "") or None, {"points": hit.get("points"), "num_comments": hit.get("num_comments"), "created_at_i": hit.get("created_at_i")})
