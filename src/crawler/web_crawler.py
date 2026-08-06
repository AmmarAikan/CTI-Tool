"""
Phase 2 — General Web Crawler.

Visits each article URL collected in Phase 1 and extracts the main
article body, discarding menus, navigation, ads, comments, and sidebars.

This is a *generic* crawler: it relies on `readability-lxml` to identify
the main content region of an arbitrary article page rather than writing
per-website parsers. A BeautifulSoup pass then strips any residual
markup/scripts and produces clean text ready for Phase 3 preprocessing.

Site-specific parsers are deliberately avoided per the project spec;
only add one if a specific source proves unworkable with the generic
approach, and keep it isolated rather than modifying this module's
default path.
"""

import time
from typing import Any, Dict, List, Optional

import requests
from bs4 import BeautifulSoup
from readability import Document

from src.utils.logger import get_logger
from src.utils.storage import latest_file, load_json, save_json, timestamped_filename

logger = get_logger(__name__)

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36 CTI-Tool-Crawler/1.0"
    )
}

# Tags that never contain article body content and should be stripped
# outright regardless of what readability already discarded.
NOISE_TAGS = ["script", "style", "nav", "footer", "header", "aside", "form", "iframe"]


class WebCrawler:
    """Fetches article pages and extracts clean main-content text."""

    def __init__(
        self,
        timeout: int = 15,
        max_retries: int = 2,
        retry_delay: float = 2.0,
        headers: Optional[Dict[str, str]] = None,
    ):
        """
        Args:
            timeout: Per-request timeout in seconds.
            max_retries: Number of retry attempts on transient failures.
            retry_delay: Seconds to wait between retries.
            headers: Optional override for request headers.
        """
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.session = requests.Session()
        self.session.headers.update(headers or DEFAULT_HEADERS)

    def fetch_html(self, url: str) -> Optional[str]:
        """
        Download the raw HTML for a URL, retrying on transient errors.

        Returns:
            The HTML body as a string, or None if all attempts failed.
        """
        last_error: Optional[Exception] = None

        for attempt in range(1, self.max_retries + 2):  # +1 initial + retries
            try:
                response = self.session.get(url, timeout=self.timeout)
                response.raise_for_status()
                return response.text
            except requests.RequestException as e:
                last_error = e
                logger.warning(
                    "Attempt %d/%d failed for %s: %s",
                    attempt, self.max_retries + 1, url, e,
                )
                if attempt <= self.max_retries:
                    time.sleep(self.retry_delay)

        logger.error("Giving up on %s after %d attempts: %s", url, self.max_retries + 1, last_error)
        return None

    def extract_article(self, html: str, url: str) -> Optional[Dict[str, str]]:
        """
        Extract the main article title and body text from raw HTML.

        Uses readability-lxml to isolate the main content region (working
        across arbitrary sites without a site-specific parser), then a
        BeautifulSoup pass to strip residual noise tags and collapse the
        result to clean text.

        Returns:
            {"title": ..., "content": ...} or None if extraction failed
            or produced no usable content.
        """
        try:
            doc = Document(html)
            summary_html = doc.summary(html_partial=True)
            extracted_title = doc.title()
        except Exception as e:  # noqa: BLE001 - malformed pages must not abort the crawl
            logger.error("Readability extraction failed for %s: %s", url, e)
            return None

        soup = BeautifulSoup(summary_html, "lxml")

        for tag in soup.find_all(NOISE_TAGS):
            tag.decompose()

        # Also drop common non-article containers that survive readability
        # on some sites (comment widgets, share bars, related-post blocks).
        for selector in ["[class*=comment]", "[id*=comment]", "[class*=share]",
                         "[class*=related]", "[class*=sidebar]", "[class*=advert]"]:
            for tag in soup.select(selector):
                tag.decompose()

        text = soup.get_text(separator="\n", strip=True)
        # Collapse runs of blank lines left behind after stripping tags.
        lines = [line for line in (l.strip() for l in text.splitlines()) if line]
        clean_text = "\n".join(lines)

        if not clean_text:
            logger.warning("No content extracted for %s", url)
            return None

        return {"title": extracted_title.strip(), "content": clean_text}

    def crawl_items(self, items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Fetch and extract full article content for each item's `link`.

        Each item's `content` field is populated in place. A single
        item's failure (network error, unparseable page, empty result)
        is logged and skipped — the item is kept with `content` left as
        an empty string so downstream stages still see it, rather than
        being dropped from the dataset.

        Args:
            items: List of unified CTI item dicts (as produced by Phase 1),
                each expected to contain a `link` field.

        Returns:
            The same list of items with `content` populated where
            extraction succeeded.
        """
        enriched: List[Dict[str, Any]] = []

        for item in items:
            url = item.get("link")
            if not url:
                logger.warning("Skipping item with no link: %s", item.get("title", "untitled"))
                enriched.append(item)
                continue

            html = self.fetch_html(url)
            if html is None:
                enriched.append(item)
                continue

            article = self.extract_article(html, url)
            if article is None:
                enriched.append(item)
                continue

            item["content"] = article["content"]
            # Only fill title from the page if we didn't already have one
            # (RSS feeds almost always provide a title already).
            if not item.get("title") and article["title"]:
                item["title"] = article["title"]

            logger.info("Crawled article: %s (%d chars)", url, len(article["content"]))
            enriched.append(item)

        return enriched


def run(input_path: Optional[str] = None) -> str:
    """
    Convenience entry point for Phase 2.

    Loads the most recent Phase 1 RSS output (or an explicit input file),
    crawls every article link, and saves the enriched items to a new
    timestamped JSON file.

    Args:
        input_path: Optional explicit path to a Phase 1 JSON file. If
            omitted, the newest `rss_articles_*.json` file is used.

    Returns:
        Path to the written output file, or an empty string if there
        was nothing to process or saving failed.
    """
    if input_path is None:
        input_path = latest_file("rss_articles")

    if not input_path:
        logger.warning("No RSS output file found; run Phase 1 first.")
        return ""

    items = load_json(input_path)
    if not items:
        logger.warning("No items to crawl in %s", input_path)
        return ""

    crawler = WebCrawler()
    enriched_items = crawler.crawl_items(items)

    filename = timestamped_filename("crawled_articles")
    return save_json(enriched_items, filename)


if __name__ == "__main__":
    output_path = run()
    if output_path:
        print(f"Crawling complete. Output saved to: {output_path}")
    else:
        print("Crawling finished with no output.")
