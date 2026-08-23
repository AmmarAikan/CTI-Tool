from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Any

from bs4 import BeautifulSoup

from backend.app.pipeline.ingestion.external.common.canonical_url import canonicalize_url
from backend.app.pipeline.ingestion.external.common.hashing import sha256_bytes, sha256_json
from backend.app.pipeline.ingestion.external.common.http_client import ExternalHttpClient
from backend.app.pipeline.ingestion.external.social_common import SocialCandidate, SocialCollectionResult, SocialConnector, SocialError, SocialItemProcessor


CHANNEL_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{4,31}$")


@dataclass(frozen=True, slots=True)
class TelegramSource:
    source_id: str
    name: str
    channel: str
    enabled: bool = True
    max_pages: int = 3

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> "TelegramSource":
        source_id, name, channel = (str(value.get(key) or "").strip() for key in ("source_id", "name", "channel"))
        pages = int(value.get("max_pages", 3))
        if not source_id or not name or not CHANNEL_RE.fullmatch(channel) or pages <= 0: raise ValueError("invalid public Telegram source")
        return cls(source_id, name, channel, bool(value.get("enabled", True)), pages)


class TelegramConnector(SocialConnector):
    def __init__(self, source: TelegramSource, *, http_client: ExternalHttpClient | None = None, processor: SocialItemProcessor | None = None) -> None:
        self.source, self.source_name = source, source.name
        self.http_client, self.processor = http_client or ExternalHttpClient(), processor or SocialItemProcessor()

    def collect_result(self) -> SocialCollectionResult:
        result = SocialCollectionResult(self.source.source_id)
        if not self.source.enabled: result.status = "disabled"; return result
        source_state = self.processor.state["sources"].setdefault(self.source.source_id, {})
        newest_known, before, seen = int(source_state.get("checkpoint_message_id", 0)), None, set()
        newest_seen, completed = newest_known, False
        for page in range(self.source.max_pages):
            url = f"https://t.me/s/{self.source.channel}" + (f"?before={before}" if before else "")
            try:
                response = self.http_client.get(url, headers={"Accept": "text/html"})
                source_state.setdefault("pages", {})[str(page)] = {"raw_content_hash": sha256_bytes(response.body)}
                soup = BeautifulSoup(response.body, "lxml")
                messages = soup.select(".tgme_widget_message[data-post]")
                ids = []
                for message in messages:
                    data_post = str(message.get("data-post") or "")
                    match = re.fullmatch(re.escape(self.source.channel) + r"/(\d+)", data_post, re.IGNORECASE)
                    if not match or data_post in seen: continue
                    seen.add(data_post); message_id = int(match.group(1)); ids.append(message_id); newest_seen = max(newest_seen, message_id)
                    if message_id <= newest_known: continue
                    candidate = self._candidate(message, data_post, message_id)
                    if candidate:
                        try: self.add(result, self.processor.process(candidate))
                        except Exception: result.errors.append(SocialError(self.source.source_id, "item_processing_failed"))
                if not ids or min(ids) <= newest_known: completed = True; break
                before = min(ids)
            except Exception:
                result.errors.append(SocialError(self.source.source_id, "source_failed", True)); result.status = "failed"
                source_state.update({"last_checked": self.processor._now_iso(), "last_status": "failed"})
                return result
        if (completed or newest_known == 0) and not result.errors: source_state["checkpoint_message_id"] = newest_seen
        if result.errors: result.status = "partial" if result.all_items else "failed"
        source_state.update({"source_config_hash": sha256_json(asdict(self.source)), "last_checked": self.processor._now_iso(), "last_status": result.status})
        return result

    def _candidate(self, message, data_post: str, message_id: int) -> SocialCandidate | None:
        text = message.select_one(".tgme_widget_message_text")
        body = text.get_text("\n", strip=True) if text else ""
        preview = message.select_one("a.tgme_widget_message_link_preview[href]")
        external = str(preview.get("href")) if preview else None
        if not body and not external: return None
        time = message.select_one("time[datetime]")
        views = message.select_one(".tgme_widget_message_views")
        return SocialCandidate(self.source.source_id, self.source.name, "telegram", str(message_id), (body or f"Telegram post {message_id}")[:120],
            canonicalize_url(f"https://t.me/{data_post}"), body, canonicalize_url(external) if external else None,
            str(time.get("datetime")) if time else None, None, {"channel": self.source.channel, "views": views.get_text(strip=True) if views else None})
