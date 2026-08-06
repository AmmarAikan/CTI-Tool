"""
Phase 6 — Social Media Sources (Reddit).

Collects cybersecurity-related posts from social media platforms using
Playwright (not Selenium, per the project spec). New platforms are
added by implementing one `_collect_<platform>` method and registering
it in `self._handlers` — nothing else in this module needs to change.

Note: X/Twitter support was removed from this collector (see prior
integration notes) — Mastodon and GitHub Security Advisories replaced
it, both with real, stable, public REST APIs.

Reddit is a general-purpose source (a subreddit's content isn't
guaranteed to be CTI-relevant just because the subreddit is
security-themed), so `run()` filters collected posts through the
shared content classifier (`src.classification.classifier`) before
saving — same as Telegram/Mastodon/GitHub.

- **Reddit**: public subreddits render without login. New Reddit's
  listing page uses `<shreddit-post>` custom elements with clean data
  attributes (`post-title`, `permalink`, `score`, `comment-count`,
  `author`, `created-timestamp`) — no fragile nested-div scraping needed.
  Each listing only renders a first batch of posts and lazy-loads more
  on scroll, so this collector scrolls the page (configurable per
  source) to pull a larger, more useful volume of posts. `content` is
  populated either from the post's inline self-text slot, or — for
  link posts pointing at an external article — by reusing the Phase 2
  `WebCrawler` to fetch and extract that article's body, exactly the
  way Phase 4's CERT collector reuses it.
"""

from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urljoin

from src.classification.classifier import filter_cti_relevant
from src.collectors.base_collector import BaseCollector
from src.crawler.web_crawler import WebCrawler
from src.utils.config_loader import get_social_media_sources
from src.utils.logger import get_logger
from src.utils.schema import CTIItem
from src.utils.storage import save_json, timestamped_filename

logger = get_logger(__name__)

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36 CTI-Tool-SocialMediaCollector/1.0"
)


class SocialMediaCollector(BaseCollector):
    """Collects cybersecurity-related posts from social media platforms via Playwright."""

    name = "social_media_collector"

    def __init__(
        self,
        sources: Optional[List[Dict[str, Any]]] = None,
        headless: bool = True,
        nav_timeout_ms: int = 30000,
    ):
        """
        Args:
            sources: Optional explicit list of source dicts. If not
                provided, sources are loaded from `config/sources.json`.
            headless: Whether to run the browser headless.
            nav_timeout_ms: Navigation/selector wait timeout in milliseconds.
        """
        self.sources = sources if sources is not None else get_social_media_sources()
        self.headless = headless
        self.nav_timeout_ms = nav_timeout_ms
        # Reused (not duplicated) from Phase 2 to fetch and extract the
        # body of external articles that Reddit "link posts" point to —
        # same pattern Phase 4's CERT collector uses.
        self._crawler = WebCrawler(timeout=max(nav_timeout_ms // 1000, 10))

        # Platform → handler registry. Adding a new platform later means
        # implementing one `_collect_<platform>` method and adding one
        # line here — no other code in this module changes.
        self._handlers: Dict[str, Callable] = {
            "reddit": self._collect_reddit,
        }

    def collect(self) -> List[CTIItem]:
        """
        Launch a single Playwright browser instance and collect posts
        from every configured source, dispatching by `platform`.

        A failure on one source (or an unknown platform) is logged and
        skipped, never interrupting collection from the remaining
        sources. The browser is always closed via `finally`, even if a
        source raises.

        Returns:
            A list of `CTIItem` objects collected across all sources.
        """
        all_items: List[CTIItem] = []

        if not self.sources:
            logger.warning("No social media sources configured; nothing to collect.")
            return all_items

        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            logger.error(
                "Playwright is not installed. Run `pip install playwright` and "
                "`playwright install chromium` before using this collector."
            )
            return all_items

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=self.headless)
                try:
                    for source in self.sources:
                        platform = source.get("platform")
                        source_name = source.get("name", "unknown")
                        handler = self._handlers.get(platform)

                        if handler is None:
                            logger.warning(
                                "Unknown social media platform '%s' for source '%s'; skipping.",
                                platform, source_name,
                            )
                            continue

                        try:
                            items = handler(browser, source)
                            logger.info("Collected %d posts from %s", len(items), source_name)
                            all_items.extend(items)
                        except Exception as e:  # noqa: BLE001 - one source must never abort the run
                            logger.error(
                                "Failed to collect social media source '%s': %s", source_name, e
                            )
                            continue
                finally:
                    browser.close()
        except Exception as e:  # noqa: BLE001 - e.g. browser binaries not installed
            logger.error(
                "Failed to launch Playwright browser (is it installed? "
                "run `playwright install chromium`): %s", e,
            )
            return all_items

        return all_items

    @staticmethod
    def _scroll_to_load_more(
        page,
        item_selector: str,
        max_scrolls: int = 6,
        target_count: int = 30,
        pause_ms: int = 1200,
    ) -> None:
        """
        Scroll the page to trigger lazy-loading of additional posts.

        Reddit's listing only renders an initial batch and loads more as
        the user scrolls. Without this, collection is limited to
        whatever happened to be in the first paint. Stops early once
        `target_count` elements are present, once scrolling stops
        producing new elements (end of feed), or after `max_scrolls`
        attempts, whichever comes first.
        """
        previous_count = -1

        for _ in range(max_scrolls):
            current_count = len(page.query_selector_all(item_selector))
            if current_count >= target_count or current_count == previous_count:
                break
            previous_count = current_count

            page.keyboard.press("End")
            page.wait_for_timeout(pause_ms)

    # ------------------------------------------------------------------
    # Reddit — public subreddits render without login; new Reddit uses
    # <shreddit-post> custom elements with clean data attributes.
    # ------------------------------------------------------------------

    def _collect_reddit(self, browser, source: Dict[str, Any]) -> List[CTIItem]:
        """
        Collect posts from a public subreddit listing page, scrolling to
        load more than just the first paint, and populating `content`
        for each post (inline self-text, or the linked external article).
        """
        url = source["url"]
        source_name = source.get("name", "Reddit")
        category = source.get("category", "social")
        max_scrolls = source.get("max_scrolls", 6)
        target_count = source.get("target_count", 30)

        context = browser.new_context(user_agent=DEFAULT_USER_AGENT)
        page = context.new_page()
        items: List[CTIItem] = []

        try:
            page.goto(url, timeout=self.nav_timeout_ms, wait_until="domcontentloaded")

            try:
                page.wait_for_selector("shreddit-post", timeout=self.nav_timeout_ms)
            except Exception:
                logger.warning(
                    "No posts rendered for '%s' within timeout; the subreddit may be "
                    "empty, private, or Reddit's markup may have changed.", source_name,
                )
                return items

            self._scroll_to_load_more(
                page, "shreddit-post", max_scrolls=max_scrolls, target_count=target_count
            )

            post_elements = page.query_selector_all("shreddit-post")

            for post in post_elements:
                title = post.get_attribute("post-title")
                permalink = post.get_attribute("permalink")

                if not title or not permalink:
                    continue

                link = urljoin("https://www.reddit.com", permalink)
                content = self._extract_reddit_content(post, link)

                items.append(
                    CTIItem(
                        title=title,
                        link=link,
                        source=source_name,
                        category=category,
                        content=content,
                        summary=content[:300].strip() if content else "",
                        author=post.get_attribute("author"),
                        published=post.get_attribute("created-timestamp"),
                        collected_at=datetime.now(timezone.utc).isoformat(),
                        metadata={
                            "platform": "reddit",
                            "score": post.get_attribute("score"),
                            "comment_count": post.get_attribute("comment-count"),
                            "subreddit": post.get_attribute("subreddit-prefixed-name"),
                        },
                    )
                )
        finally:
            context.close()

        return items

    def _extract_reddit_content(self, post, permalink_url: str) -> str:
        """
        Populate a Reddit post's body text.

        Self-text posts render their (possibly truncated) body inline in
        a `[slot="text-body"]` element within the listing page itself —
        read directly, no extra navigation needed. Link posts point at
        an external article instead; for those, `content-href` is
        fetched and extracted via the reused Phase 2 `WebCrawler`, the
        same pattern Phase 4's CERT collector uses for advisory pages.
        A failure here is logged and results in empty content rather
        than raising, consistent with the rest of the pipeline.
        """
        text_body = post.query_selector('[slot="text-body"]')
        if text_body:
            text = text_body.inner_text().strip()
            if text:
                return text

        content_href = post.get_attribute("content-href")
        if not content_href or "reddit.com" in content_href:
            # No self-text and no external link (or the link just points
            # back to the discussion itself) — nothing further to fetch.
            return ""

        html = self._crawler.fetch_html(content_href)
        if html is None:
            logger.warning("Could not fetch linked article for Reddit post %s", permalink_url)
            return ""

        article = self._crawler.extract_article(html, content_href)
        if article is None or not article["content"]:
            logger.warning("No article content extracted for Reddit post %s", permalink_url)
            return ""

        return article["content"]


def run() -> str:
    """
    Convenience entry point: collect all configured social media
    sources, filter to CTI-relevant posts, and persist the results to a
    timestamped JSON file.

    Reddit is a general-purpose source per the classification
    integration requirement — filtered via the shared
    `filter_cti_relevant()` before saving, same as
    Telegram/Mastodon/GitHub.

    Returns:
        Path to the written JSON file, or an empty string if nothing
        was collected, nothing passed classification, or saving failed.
    """
    collector = SocialMediaCollector()
    items = collector.collect()

    if not items:
        logger.warning("Social media collection produced no items.")
        return ""

    item_dicts = [item.to_dict() for item in items]
    item_dicts = filter_cti_relevant(item_dicts)

    if not item_dicts:
        logger.warning("Social media collection produced no CTI-relevant items after classification.")
        return ""

    filename = timestamped_filename("social_media_posts")
    return save_json(item_dicts, filename)


if __name__ == "__main__":
    output_path = run()
    if output_path:
        print(f"Social media collection complete. Output saved to: {output_path}")
    else:
        print("Social media collection finished with no output.")
