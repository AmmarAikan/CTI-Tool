"""
Phase 6 (continued) — Hacker News Sources.

Replaces Lobsters in this project. Reasoning: Lobsters' plain `.json`
suffix convention, while genuinely real and unauthenticated, comes with
no documented reliability/rate-limit guarantees (it's an informal
convention on a small community site, not a maintained public API
product) — and in practice, requests to it were failing even with
generous retries and increased timeouts.

Hacker News' Algolia Search API (`https://hn.algolia.com/api/v1/`) is
instead a genuinely maintained, heavily used, explicitly documented
public API product — confirmed (not assumed) via extensive independent
sources: dozens of production tools, CLIs, and MCP servers build on it
specifically because it's stable, free, requires no authentication, and
documents a generous 10,000 requests/hour limit. This is a categorically
different reliability tier than an informal `.json`-suffix convention.

Two endpoints exist: `/search` (relevance-ranked) and `/search_by_date`
(chronological, newest first) — this collector uses the latter, since
"most recent CTI-relevant discussion" is the actual goal, not "most
popular ever."

Uses `requests` only — no Playwright needed, same reasoning as
Telegram/GitHub: a stable, public JSON API doesn't need a browser.

A hit's `story_text` is populated only for genuine self-text ("Ask HN"
style) posts; the far more common case is a link post, where HN itself
has no body text — just a title and an external `url`. For those, the
linked article's full body is fetched and extracted via the reused
Phase 2 `WebCrawler` (same pattern as Reddit's link posts, Telegram's
link previews, and Phase 4's CERT collector), so `content` carries real
text for the classifier and NER rather than being left empty.

Hacker News is a general-purpose source (a keyword match isn't
guaranteed CTI-relevant — "CVE" can appear in an unrelated joke thread,
"breach" in a non-security context, etc.), so `run()` filters through
the shared content classifier (`src.classification.classifier`) before
saving — same as Reddit/Telegram/GitHub.
"""

import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests

from src.classification.classifier import filter_cti_relevant
from src.collectors.base_collector import BaseCollector
from src.crawler.web_crawler import WebCrawler
from src.utils.config_loader import get_hackernews_sources
from src.utils.logger import get_logger
from src.utils.schema import CTIItem
from src.utils.storage import save_json, timestamped_filename

logger = get_logger(__name__)

SEARCH_BY_DATE_URL = "https://hn.algolia.com/api/v1/search_by_date"

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36 CTI-Tool-HackerNewsCollector/1.0"
    ),
    "Accept": "application/json",
}


class HackerNewsCollector(BaseCollector):
    """Collects keyword-matched stories from Hacker News via the public Algolia Search API."""

    name = "hackernews_collector"

    def __init__(
        self,
        sources: Optional[List[Dict[str, Any]]] = None,
        timeout: int = 20,
        max_retries: int = 2,
        retry_delay: float = 3.0,
    ):
        """
        Args:
            sources: Optional explicit list of source dicts
                (`{"name", "query", "category", "limit"}`). If not
                provided, sources are loaded from `config/sources.json`.
            timeout: Per-request timeout in seconds.
            max_retries: Retry attempts for a transient failure
                (timeout, connection error, or a 5xx) before giving up
                on a given query. Never retries a 4xx.
            retry_delay: Seconds to wait between retry attempts.
        """
        self.sources = sources if sources is not None else get_hackernews_sources()
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.session = requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)
        # Reused (not duplicated) from Phase 2 to fetch and extract the
        # full body of the external article a link post points to —
        # same pattern already used by Reddit, Telegram, and CERT.
        self._crawler = WebCrawler(timeout=timeout)

    def collect(self) -> List[CTIItem]:
        """
        Collect stories for every configured search query.

        A single query failing (network error, malformed response) is
        logged and skipped, never interrupting collection from the
        remaining queries.

        Returns:
            A list of `CTIItem` objects collected across all queries.
        """
        all_items: List[CTIItem] = []

        if not self.sources:
            logger.warning("No Hacker News sources configured; nothing to collect.")
            return all_items

        for source in self.sources:
            query = source.get("query")
            source_name = source.get("name", f"Hacker News - {query}" if query else "unknown")

            if not query:
                logger.warning("Skipping Hacker News source '%s': missing 'query'.", source_name)
                continue

            try:
                items = self._collect_query(source)
                logger.info("Collected %d posts from %s", len(items), source_name)
                all_items.extend(items)
            except requests.exceptions.HTTPError as e:
                status = e.response.status_code if e.response is not None else "?"
                logger.error("Source '%s' returned HTTP %s.", source_name, status)
            except requests.exceptions.RequestException as e:
                logger.error("Failed to collect Hacker News source '%s': %s", source_name, e)
            except Exception as e:  # noqa: BLE001 - one source must never abort the run
                logger.error("Failed to collect Hacker News source '%s': %s", source_name, e)

        return all_items

    def _get_with_retry(self, params: Dict[str, Any], source_name: str) -> requests.Response:
        """
        GET with retry-on-transient-failure: connection errors, timeouts,
        and 5xx responses are retried; a 4xx is not, since retrying an
        identical request won't produce a different result.
        """
        last_exception: Optional[Exception] = None

        for attempt in range(1, self.max_retries + 2):  # +1 initial + retries
            try:
                response = self.session.get(SEARCH_BY_DATE_URL, params=params, timeout=self.timeout)
                if response.status_code >= 500:
                    raise requests.exceptions.HTTPError(
                        f"{response.status_code} Server Error", response=response
                    )
                response.raise_for_status()
                return response
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
                last_exception = e
                logger.warning(
                    "Attempt %d/%d failed for '%s' (%s); %s",
                    attempt, self.max_retries + 1, source_name, e,
                    "retrying..." if attempt <= self.max_retries else "giving up.",
                )
            except requests.exceptions.HTTPError as e:
                status = e.response.status_code if e.response is not None else None
                if status is not None and status >= 500:
                    last_exception = e
                    logger.warning(
                        "Attempt %d/%d failed for '%s' (HTTP %s from the server); %s",
                        attempt, self.max_retries + 1, source_name, status,
                        "retrying..." if attempt <= self.max_retries else "giving up.",
                    )
                else:
                    raise

            if attempt <= self.max_retries:
                time.sleep(self.retry_delay)

        raise last_exception

    def _collect_query(self, source: Dict[str, Any]) -> List[CTIItem]:
        """Fetch stories matching one search query, newest first."""
        query = source["query"]
        source_name = source.get("name", f"Hacker News - {query}")
        category = source.get("category", "social")
        limit = min(source.get("limit", 30), 1000)  # Algolia's own documented max hitsPerPage

        params = {"query": query, "tags": "story", "hitsPerPage": limit}
        response = self._get_with_retry(params, source_name)

        data = response.json()
        hits = data.get("hits") if isinstance(data, dict) else None
        if hits is None:
            logger.warning("Unexpected response shape from %s; skipping.", source_name)
            return []

        logger.info("%s: received %d raw hits from the API.", source_name, len(hits))

        items = []
        for hit in hits:
            item = self._parse_hit(hit, source_name, category)
            if item is not None:
                items.append(item)

        return items

    def _parse_hit(self, hit: Dict[str, Any], source_name: str, category: str) -> Optional[CTIItem]:
        """
        Convert a single Algolia HN search hit into a unified CTIItem.

        `content` comes from the self-text body if the story has one
        (`story_text`, populated for "Ask HN"/text posts), or — for the
        far more common link-post case — from fetching and extracting
        the linked article via the reused Phase 2 `WebCrawler`. A story
        with neither is skipped rather than emitted with empty content.
        """
        title = (hit.get("title") or "").strip()
        object_id = hit.get("objectID")
        external_url = hit.get("url") or ""

        story_text_html = hit.get("story_text") or ""
        story_text = self._strip_html(story_text_html) if story_text_html else ""

        if story_text:
            content = story_text
        elif external_url:
            content = self._fetch_external_content(external_url, title or str(object_id))
        else:
            content = ""

        if not title or not content:
            return None

        link = f"https://news.ycombinator.com/item?id={object_id}" if object_id else external_url

        return CTIItem(
            title=title,
            link=link,
            source=source_name,
            category=category,
            content=content,
            summary=content[:300].strip(),
            author=hit.get("author"),
            published=hit.get("created_at"),
            collected_at=datetime.now(timezone.utc).isoformat(),
            metadata={
                "platform": "hackernews",
                "collection_method": "api",
                "points": hit.get("points"),
                "num_comments": hit.get("num_comments"),
                "external_url": external_url or None,
            },
        )

    @staticmethod
    def _strip_html(html: str) -> str:
        """HN's story_text field contains basic HTML — strip it before use."""
        from bs4 import BeautifulSoup

        return BeautifulSoup(html, "lxml").get_text(separator="\n", strip=True)

    def _fetch_external_content(self, external_url: str, context_label: str) -> str:
        """
        Fetch and extract the full body of a link post's external
        article via the reused Phase 2 `WebCrawler`. A fetch/extraction
        failure is logged and results in empty content rather than
        raising, consistent with the rest of the pipeline.
        """
        html = self._crawler.fetch_html(external_url)
        if html is None:
            logger.warning("Could not fetch linked article for Hacker News story %s", context_label)
            return ""

        article = self._crawler.extract_article(html, external_url)
        if article is None or not article["content"]:
            logger.warning("No article content extracted for Hacker News story %s", context_label)
            return ""

        return article["content"]


def run() -> str:
    """
    Convenience entry point: collect all configured Hacker News sources,
    filter to CTI-relevant posts, and persist the results to a
    timestamped JSON file.

    Hacker News is a general-purpose source per the classification
    integration requirement — filtered via the shared
    `filter_cti_relevant()` before saving, same as
    Reddit/Telegram/GitHub.

    Returns:
        Path to the written JSON file, or an empty string if nothing
        was collected, nothing passed classification, or saving failed.
    """
    collector = HackerNewsCollector()
    items = collector.collect()

    if not items:
        logger.warning("Hacker News collection produced no items.")
        return ""

    item_dicts = [item.to_dict() for item in items]
    item_dicts = filter_cti_relevant(item_dicts)

    if not item_dicts:
        logger.warning("Hacker News collection produced no CTI-relevant items after classification.")
        return ""

    filename = timestamped_filename("hackernews_posts")
    return save_json(item_dicts, filename)


if __name__ == "__main__":
    output_path = run()
    if output_path:
        print(f"Hacker News collection complete. Output saved to: {output_path}")
    else:
        print("Hacker News collection finished with no output.")