"""
Phase 1 — RSS Feed Collector.

Collects cybersecurity article metadata from trusted RSS feeds defined in
`config/sources.json`, and normalizes each entry into a `CTIItem`.

This module is intentionally scoped to *metadata only* (title, link,
summary, published date, source, category). Fetching full article bodies
is the responsibility of the Phase 2 web crawler, which consumes the
JSON output produced here.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import feedparser

from src.collectors.base_collector import BaseCollector
from src.utils.config_loader import get_rss_sources
from src.utils.logger import get_logger
from src.utils.schema import CTIItem
from src.utils.storage import save_json, timestamped_filename

logger = get_logger(__name__)


class RSSCollector(BaseCollector):
    """Collects article metadata from a configured list of RSS feeds."""

    name = "rss_collector"

    def __init__(self, sources: Optional[List[Dict[str, Any]]] = None):
        """
        Args:
            sources: Optional explicit list of source dicts
                (`{"name": ..., "url": ..., "category": ...}`). If not
                provided, sources are loaded from `config/sources.json`.
        """
        self.sources = sources if sources is not None else get_rss_sources()

    def collect(self) -> List[CTIItem]:
        """
        Fetch and parse every configured RSS feed.

        Returns:
            A list of `CTIItem` objects collected across all feeds.
            A failure on one feed is logged and skipped; it does not
            interrupt collection from the remaining feeds.
        """
        all_items: List[CTIItem] = []

        if not self.sources:
            logger.warning("No RSS sources configured; nothing to collect.")
            return all_items

        for source in self.sources:
            source_name = source.get("name", "unknown")
            url = source.get("url")
            category = source.get("category", "uncategorized")

            if not url:
                logger.warning("Skipping source '%s': missing 'url'.", source_name)
                continue

            try:
                items = self._collect_feed(url, source_name, category)
                logger.info("Collected %d items from %s", len(items), source_name)
                all_items.extend(items)
            except Exception as e:  # noqa: BLE001 - a single feed must never abort the run
                logger.error("Failed to collect feed '%s' (%s): %s", source_name, url, e)
                continue

        return all_items

    def _collect_feed(self, url: str, source_name: str, category: str) -> List[CTIItem]:
        """Parse a single RSS feed URL and convert its entries to CTIItems."""
        parsed = feedparser.parse(url)

        if parsed.bozo and not parsed.entries:
            # bozo=True with no entries usually means the feed was
            # unreachable or malformed beyond recovery.
            raise ValueError(f"Unparseable or unreachable feed: {parsed.bozo_exception}")

        items: List[CTIItem] = []
        for entry in parsed.entries:
            items.append(self._entry_to_item(entry, source_name, category))

        return items

    @staticmethod
    def _entry_to_item(entry: Dict[str, Any], source_name: str, category: str) -> CTIItem:
        """Convert a single feedparser entry into a unified CTIItem."""
        published = entry.get("published") or entry.get("updated")

        return CTIItem(
            title=entry.get("title", "").strip(),
            link=entry.get("link", "").strip(),
            source=source_name,
            category=category,
            summary=entry.get("summary", "").strip(),
            published=published,
            author=entry.get("author"),
            tags=[tag.get("term") for tag in entry.get("tags", []) if tag.get("term")],
            collected_at=datetime.now(timezone.utc).isoformat(),
            metadata={
                "feed_id": entry.get("id", ""),
            },
        )


def run() -> str:
    """
    Convenience entry point: collect all configured RSS feeds and persist
    the results to a timestamped JSON file.

    Returns:
        Path to the written JSON file, or an empty string if nothing
        was collected or saving failed.
    """
    collector = RSSCollector()
    items = collector.collect()

    if not items:
        logger.warning("RSS collection produced no items.")
        return ""

    filename = timestamped_filename("rss_articles")
    return save_json([item.to_dict() for item in items], filename)


if __name__ == "__main__":
    output_path = run()
    if output_path:
        print(f"RSS collection complete. Output saved to: {output_path}")
    else:
        print("RSS collection finished with no output.")
