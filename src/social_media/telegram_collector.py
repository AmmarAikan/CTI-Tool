"""
Phase 6 (continued) — Telegram Sources.

Collects posts from public Telegram channels. Deliberately NOT built
with Playwright: a public channel's web preview at
`https://t.me/s/{channel}` is plain, server-rendered static HTML — no
JavaScript rendering or login required — so `requests` + BeautifulSoup
(the same stack already used by Phase 2's crawler and Phase 4's CERT
scrape path) is the correct, lighter-weight tool here, not a browser.

`content` vs `summary`: many channel posts are just a short caption
plus a link to the actual article (Telegram renders this as a "link
preview" card). Using only that caption as `content` left it nearly
identical to `summary`. When a post has a link preview, `content` is
now the linked article's full body — fetched and extracted via the
same reused Phase 2 `WebCrawler` already used by Phase 4's CERT
collector and Reddit's link-post handling — while `summary` stays the
short Telegram caption. Posts with no link (pure text posts) are
unaffected: `content` is just the caption, same as before.

Telegram is a general-purpose source (a channel's content isn't
guaranteed to be CTI-relevant post-by-post), so `run()` filters
collected posts through the shared content classifier
(`src.classification.classifier`) before saving — same as
Reddit/Mastodon/GitHub.

Only public channels are supported (this is what the web preview
exposes); private channels/groups would require the MTProto API
(Telethon/Pyrogram) with a phone-number login, a materially different
and heavier integration that isn't needed for public OSINT monitoring.

Default channels are deliberately limited to verified, clearly
legitimate cybersecurity news/research channels (an official outlet's
own channel, and a channel that auto-relays published CVEs) — not
threat-actor-operated channels. Plenty of those exist and are used by
professional CTI teams for OSINT, but this project defaults to safe,
unambiguous sources; add others by channel username in config as needed.
"""

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests
from bs4 import BeautifulSoup

from src.classification.classifier import filter_cti_relevant
from src.collectors.base_collector import BaseCollector
from src.crawler.web_crawler import WebCrawler
from src.utils.config_loader import get_telegram_sources
from src.utils.logger import get_logger
from src.utils.schema import CTIItem
from src.utils.storage import save_json, timestamped_filename

logger = get_logger(__name__)

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36 CTI-Tool-TelegramCollector/1.0"
    )
}


class TelegramCollector(BaseCollector):
    """Collects posts from public Telegram channels via their static web preview."""

    name = "telegram_collector"

    def __init__(
        self,
        sources: Optional[List[Dict[str, Any]]] = None,
        timeout: int = 15,
    ):
        """
        Args:
            sources: Optional explicit list of source dicts
                (`{"name", "channel", "category", "max_pages"}`). If not
                provided, sources are loaded from `config/sources.json`.
            timeout: Per-request timeout in seconds.
        """
        self.sources = sources if sources is not None else get_telegram_sources()
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)
        # Reused (not duplicated) from Phase 2 to fetch and extract the
        # full body of articles that a post's link preview points to —
        # same pattern already used by Phase 4's CERT collector and
        # Reddit's link-post handling.
        self._crawler = WebCrawler(timeout=timeout)

    def collect(self) -> List[CTIItem]:
        """
        Collect posts from every configured Telegram channel.

        A single channel failing (network error, channel doesn't exist,
        page structure changed) is logged and skipped, never
        interrupting collection from the remaining channels.

        Returns:
            A list of `CTIItem` objects collected across all channels.
        """
        all_items: List[CTIItem] = []

        if not self.sources:
            logger.warning("No Telegram sources configured; nothing to collect.")
            return all_items

        for source in self.sources:
            channel = source.get("channel")
            source_name = source.get("name", channel or "unknown")

            if not channel:
                logger.warning("Skipping Telegram source '%s': missing 'channel'.", source_name)
                continue

            try:
                items = self._collect_channel(source)
                logger.info("Collected %d posts from %s", len(items), source_name)
                all_items.extend(items)
            except Exception as e:  # noqa: BLE001 - one channel must never abort the run
                logger.error("Failed to collect Telegram channel '%s': %s", source_name, e)
                continue

        return all_items

    def _collect_channel(self, source: Dict[str, Any]) -> List[CTIItem]:
        """
        Fetch a public channel's web preview, paginating backwards via
        Telegram's `?before={message_id}` pattern to pull more than just
        the most recent ~20 posts a single page shows.
        """
        channel = source["channel"]
        source_name = source.get("name", channel)
        category = source.get("category", "social")
        max_pages = source.get("max_pages", 3)

        items: List[CTIItem] = []
        seen_ids = set()
        before_id: Optional[int] = None
        base_url = f"https://t.me/s/{channel}"

        for _ in range(max_pages):
            url = base_url if before_id is None else f"{base_url}?before={before_id}"
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()

            soup = BeautifulSoup(response.text, "lxml")
            message_wraps = soup.select(".tgme_widget_message_wrap")

            if not message_wraps:
                break  # empty/nonexistent channel, or end of history reached

            page_min_id: Optional[int] = None
            new_on_this_page = 0

            for wrap in message_wraps:
                message = wrap.select_one(".tgme_widget_message")
                if message is None:
                    continue

                data_post = message.get("data-post")  # e.g. "channelname/12345"
                if not data_post or data_post in seen_ids:
                    continue
                seen_ids.add(data_post)

                msg_id = self._extract_message_id(data_post)
                if msg_id is not None:
                    page_min_id = msg_id if page_min_id is None else min(page_min_id, msg_id)

                item = self._parse_message(message, data_post, source_name, category)
                if item is not None:
                    items.append(item)
                    new_on_this_page += 1

            if page_min_id is None or new_on_this_page == 0:
                break  # nothing new — avoid looping on an unchanging page

            before_id = page_min_id

        return items

    @staticmethod
    def _extract_message_id(data_post: str) -> Optional[int]:
        """Parse the numeric message ID from a 'channel/12345' data-post value."""
        match = re.search(r"/(\d+)$", data_post)
        return int(match.group(1)) if match else None

    def _parse_message(
        self, message, data_post: str, source_name: str, category: str
    ) -> Optional[CTIItem]:
        """Convert a single `.tgme_widget_message` element into a unified CTIItem."""
        text_element = message.select_one(".tgme_widget_message_text")
        caption = text_element.get_text(separator="\n", strip=True) if text_element else ""

        link_preview_href = self._extract_link_preview_href(message)

        if not caption and not link_preview_href:
            # Media-only post (photo/video, no caption, no link) —
            # nothing useful to hand downstream; skip rather than emit
            # an empty-content item.
            return None

        content = self._extract_post_content(caption, link_preview_href, data_post)
        if not content:
            # Neither a caption nor a successfully fetched linked
            # article — same "nothing useful" case as above.
            return None

        time_element = message.select_one(".tgme_widget_message_date time")
        published = time_element.get("datetime") if time_element else None

        views_element = message.select_one(".tgme_widget_message_views")
        views = views_element.get_text(strip=True) if views_element else None

        link = f"https://t.me/{data_post}"
        title = (caption or content)[:120]
        summary = caption[:300].strip() if caption else content[:300].strip()

        return CTIItem(
            title=title,
            link=link,
            source=source_name,
            category=category,
            content=content,
            summary=summary,
            published=published,
            collected_at=datetime.now(timezone.utc).isoformat(),
            metadata={
                "platform": "telegram",
                "collection_method": "scrape",
                "views": views,
                "linked_article_url": link_preview_href,
            },
        )

    @staticmethod
    def _extract_link_preview_href(message) -> Optional[str]:
        """
        Return the external URL from a post's Telegram "link preview"
        card, if present. The whole card is wrapped in a single
        `<a class="tgme_widget_message_link_preview" href="...">`.
        """
        preview = message.select_one("a.tgme_widget_message_link_preview")
        return preview.get("href") if preview else None

    def _extract_post_content(
        self, caption: str, link_preview_href: Optional[str], data_post: str
    ) -> str:
        """
        Build the post's `content`: the linked article's full body when
        a link preview is present (reusing the Phase 2 `WebCrawler`,
        same pattern as Phase 4's CERT collector and Reddit's link-post
        handling), falling back to the short caption otherwise — or to
        the caption if fetching/extracting the link fails, so a network
        hiccup never turns a perfectly good text post into an empty one.
        """
        if not link_preview_href:
            return caption

        html = self._crawler.fetch_html(link_preview_href)
        if html is None:
            logger.warning(
                "Could not fetch linked article for Telegram post %s; "
                "falling back to caption only.", data_post,
            )
            return caption

        article = self._crawler.extract_article(html, link_preview_href)
        if article is None or not article["content"]:
            logger.warning(
                "No article content extracted for Telegram post %s; "
                "falling back to caption only.", data_post,
            )
            return caption

        return article["content"]


def run() -> str:
    """
    Convenience entry point: collect all configured Telegram sources,
    filter to CTI-relevant posts, and persist the results to a
    timestamped JSON file.

    Telegram is a general-purpose source per the classification
    integration requirement — filtered via the shared
    `filter_cti_relevant()` before saving, same as
    Reddit/Mastodon/GitHub.

    Returns:
        Path to the written JSON file, or an empty string if nothing
        was collected, nothing passed classification, or saving failed.
    """
    collector = TelegramCollector()
    items = collector.collect()

    if not items:
        logger.warning("Telegram collection produced no items.")
        return ""

    item_dicts = [item.to_dict() for item in items]
    item_dicts = filter_cti_relevant(item_dicts)

    if not item_dicts:
        logger.warning("Telegram collection produced no CTI-relevant items after classification.")
        return ""

    filename = timestamped_filename("telegram_posts")
    return save_json(item_dicts, filename)


if __name__ == "__main__":
    output_path = run()
    if output_path:
        print(f"Telegram collection complete. Output saved to: {output_path}")
    else:
        print("Telegram collection finished with no output.")
