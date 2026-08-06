"""
Phase 4 — CERT Security Advisories.

Collects official cybersecurity advisories from national/regional CERTs
(e.g. CISA, CERT-EU, CERT-AT). Per each source's `method` in
`config/sources.json`:

- "rss": parsed with feedparser, same library as Phase 1 but implemented
  independently here (no dependency on `src.collectors.rss_collector`),
  per the project spec's requirement to build this module independently.
- "scrape": fetched with requests and parsed with BeautifulSoup, since
  not every CERT publishes a feed (e.g. CISA retired its advisory RSS
  feeds in May 2025 in favor of a web-only Alerts & Advisories page).

Note on the "scrape" path: unlike the Phase 2 generic crawler, a
site-specific scraper is unavoidable here because advisory listing pages
have no common structure to exploit generically. The selectors below use
a pattern-matching heuristic (advisory-like URL paths) rather than exact
CSS classes, but should still be spot-checked against the live page
before relying on it in production, since government sites occasionally
restructure their markup without notice.
"""

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import feedparser
import requests
from bs4 import BeautifulSoup

from src.collectors.base_collector import BaseCollector
from src.crawler.web_crawler import WebCrawler
from src.utils.config_loader import get_cert_sources
from src.utils.logger import get_logger
from src.utils.schema import CTIItem
from src.utils.storage import save_json, timestamped_filename

logger = get_logger(__name__)

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36 CTI-Tool-CERTCollector/1.0"
    )
}

# Heuristic pattern used by the scrape path to recognize advisory-like
# *detail page* links on a CERT listing page (e.g. CISA's individual
# advisory URLs). Requires an actual slug segment after the category
# (e.g. ".../cybersecurity-advisories/aa26-197a") so it does NOT match
# the bare listing page or its filter links (e.g.
# ".../cybersecurity-advisories?f[0]=advisory_type:65"), which share
# the same path prefix but carry no slug and only a query string.
# Adjust per-site if a new scrape source is added.
_ADVISORY_LINK_PATTERN = re.compile(
    r"/news-events/(cybersecurity-advisories|ics-advisories|ics-medical-advisories|alerts)/"
    r"[a-z0-9][a-z0-9\-]*",
    re.IGNORECASE,
)

# Generic category/definition labels that sometimes appear as link text
# even after URL filtering (e.g. a "Cybersecurity Advisory" type-filter
# link with a slug-like anchor); used as a second safety net.
_GENERIC_LABELS = {
    "alert", "alerts", "analysis report", "cybersecurity advisory",
    "ics advisory", "ics medical advisory", "advisory definitions",
    "read more", "view all", "view all alerts & advisories",
}


class CERTCollector(BaseCollector):
    """Collects official security advisories from CERT/government sources."""

    name = "cert_collector"

    def __init__(
        self,
        sources: Optional[List[Dict[str, Any]]] = None,
        timeout: int = 15,
    ):
        """
        Args:
            sources: Optional explicit list of source dicts
                (`{"name", "url", "category", "method"}`). If not
                provided, sources are loaded from `config/sources.json`.
            timeout: Per-request timeout in seconds for the scrape path.
        """
        self.sources = sources if sources is not None else get_cert_sources()
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)
        # Reused (not duplicated) from Phase 2 to fetch and extract the
        # full body of each individual advisory page found by the scrape
        # path — the listing page only gives title + link.
        self._crawler = WebCrawler(timeout=timeout)

    def collect(self) -> List[CTIItem]:
        """
        Collect advisories from every configured CERT source.

        Returns:
            A list of `CTIItem` objects collected across all sources.
            A failure on one source is logged and skipped, never
            interrupting collection from the remaining sources.
        """
        all_items: List[CTIItem] = []

        if not self.sources:
            logger.warning("No CERT sources configured; nothing to collect.")
            return all_items

        for source in self.sources:
            source_name = source.get("name", "unknown")
            url = source.get("url")
            category = source.get("category", "advisory")
            method = source.get("method", "rss")

            if not url:
                logger.warning("Skipping CERT source '%s': missing 'url'.", source_name)
                continue

            try:
                if method == "rss":
                    items = self._collect_rss(url, source_name, category)
                elif method == "scrape":
                    items = self._collect_scrape(url, source_name, category)
                else:
                    logger.warning(
                        "Unknown collection method '%s' for source '%s'; skipping.",
                        method, source_name,
                    )
                    continue

                logger.info("Collected %d advisories from %s", len(items), source_name)
                all_items.extend(items)
            except Exception as e:  # noqa: BLE001 - one source must never abort the run
                logger.error("Failed to collect CERT source '%s' (%s): %s", source_name, url, e)
                continue

        return all_items

    # ------------------------------------------------------------------
    # RSS path (independent implementation from src.collectors.rss_collector)
    # ------------------------------------------------------------------

    def _collect_rss(self, url: str, source_name: str, category: str) -> List[CTIItem]:
        """
        Parse a CERT RSS/Atom feed for title/link/date/summary, then
        visit each entry's link and extract the full advisory body —
        the feed's <description> is only ever a short summary, never
        the complete advisory text.
        """
        parsed = feedparser.parse(url)

        if parsed.bozo and not parsed.entries:
            raise ValueError(f"Unparseable or unreachable CERT feed: {parsed.bozo_exception}")

        items = []
        for entry in parsed.entries:
            published = entry.get("published") or entry.get("updated")
            link = entry.get("link", "").strip()

            content = self._fetch_full_content(link) if link else ""

            items.append(
                CTIItem(
                    title=entry.get("title", "").strip(),
                    link=link,
                    source=source_name,
                    category=category,
                    content=content,
                    summary=entry.get("summary", "").strip(),
                    published=published,
                    author=entry.get("author"),
                    tags=[tag.get("term") for tag in entry.get("tags", []) if tag.get("term")],
                    collected_at=datetime.now(timezone.utc).isoformat(),
                    metadata={"collection_method": "rss", "feed_id": entry.get("id", "")},
                )
            )
        return items

    # ------------------------------------------------------------------
    # Scrape path (used when a CERT source has no RSS feed available)
    # ------------------------------------------------------------------

    def _collect_scrape(self, url: str, source_name: str, category: str) -> List[CTIItem]:
        """
        Fetch a CERT advisory listing page, extract links to individual
        advisory pages (not the listing page's own filter/category
        links), then visit each advisory page to pull its real title
        and full content — the listing page only gives a title/link,
        never the advisory body itself.
        """
        response = self.session.get(url, timeout=self.timeout)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, "lxml")

        # Prefer scoping to the main content region if the page defines
        # one, so nav/footer links (which sometimes also match the URL
        # pattern, e.g. pagination links) aren't mistaken for advisories.
        search_scope = soup.find("main") or soup

        candidates = []
        seen_links = set()

        for link_tag in search_scope.find_all("a", href=True):
            href = link_tag["href"]

            # Filter/category links share the listing page's path prefix
            # but only add a query string (e.g. "?f[0]=advisory_type:65")
            # with no further path segment — exclude those outright.
            path_only = href.split("?", 1)[0].split("#", 1)[0]
            if not _ADVISORY_LINK_PATTERN.search(path_only):
                continue

            link_text = link_tag.get_text(strip=True)
            if not link_text or len(link_text) < 5:
                continue
            if link_text.strip().lower() in _GENERIC_LABELS:
                # Safety net: catches type/definition labels even if a
                # future page structure makes them slip past the path check.
                continue

            full_link = urljoin(url, path_only)
            if full_link in seen_links:
                continue
            seen_links.add(full_link)

            published = self._find_nearby_date(link_tag)
            candidates.append(
                {"title": link_text, "link": full_link, "published": published}
            )

        if not candidates:
            logger.warning(
                "Scrape of '%s' produced no advisory-like links; the page "
                "structure may have changed and the link pattern may need updating.",
                source_name,
            )
            return []

        return self._enrich_with_full_content(candidates, source_name, category)

    def _enrich_with_full_content(
        self, candidates: List[Dict[str, Any]], source_name: str, category: str
    ) -> List[CTIItem]:
        """
        Visit each candidate advisory's own page and extract its real
        title and full body text via the shared WebCrawler. A single
        advisory page failing to fetch/parse is logged and kept with
        empty content rather than dropped, consistent with the rest of
        the pipeline's failure handling.
        """
        items = []

        for candidate in candidates:
            link = candidate["link"]
            title = candidate["title"]

            content, extracted_title = self._fetch_full_content(link, return_title=True)
            # The listing page's link text is normally the real advisory
            # title already (unlike a bare category label, which was
            # filtered out earlier), so keep it and only fall back to the
            # page's own <title> if the listing gave us nothing usable.
            if not title and extracted_title:
                title = extracted_title

            summary = content[:300].strip() if content else ""

            items.append(
                CTIItem(
                    title=title,
                    link=link,
                    source=source_name,
                    category=category,
                    content=content,
                    summary=summary,
                    published=candidate["published"],
                    collected_at=datetime.now(timezone.utc).isoformat(),
                    metadata={"collection_method": "scrape"},
                )
            )

        return items

    def _fetch_full_content(self, link: str, return_title: bool = False):
        """
        Shared helper (used by both the RSS and scrape paths) that visits
        an advisory's own page and extracts its full body text via the
        Phase 2 `WebCrawler`. This is the "open link → extract full text"
        step every advisory goes through regardless of how it was
        discovered (feed entry or listing-page link).

        A fetch or extraction failure is logged and results in empty
        content rather than raising, so one bad advisory page never
        aborts the batch.

        Args:
            link: URL of the individual advisory page.
            return_title: If True, returns `(content, extracted_title)`;
                otherwise returns just `content`. The RSS path doesn't
                need the extracted title (feeds already provide one) but
                the scrape path uses it as a fallback.

        Returns:
            `content` string, or `(content, title)` tuple if
            `return_title=True`. Content is `""` on any failure.
        """
        if not link:
            return ("", "") if return_title else ""

        html = self._crawler.fetch_html(link)
        if html is None:
            logger.warning("Could not fetch advisory page %s", link)
            return ("", "") if return_title else ""

        article = self._crawler.extract_article(html, link)
        if article is None or not article["content"]:
            logger.warning("No article content extracted for %s", link)
            return ("", "") if return_title else ""

        if return_title:
            return article["content"], article["title"]
        return article["content"]

    @staticmethod
    def _find_nearby_date(link_tag) -> Optional[str]:
        """
        Best-effort attempt to find a publication date near an advisory
        link: checks a sibling/parent <time> tag first, then falls back
        to a simple date-like text pattern in the parent element.
        """
        parent = link_tag.find_parent()
        if parent is None:
            return None

        time_tag = parent.find("time")
        if time_tag:
            return time_tag.get("datetime") or time_tag.get_text(strip=True)

        date_pattern = re.compile(
            r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\w*\.?\s+\d{1,2},?\s+\d{4}\b"
        )
        match = date_pattern.search(parent.get_text())
        return match.group(0) if match else None


def run() -> str:
    """
    Convenience entry point: collect all configured CERT sources and
    persist the results to a timestamped JSON file.

    Returns:
        Path to the written JSON file, or an empty string if nothing
        was collected or saving failed.
    """
    collector = CERTCollector()
    items = collector.collect()

    if not items:
        logger.warning("CERT collection produced no items.")
        return ""

    filename = timestamped_filename("cert_advisories")
    return save_json([item.to_dict() for item in items], filename)


if __name__ == "__main__":
    output_path = run()
    if output_path:
        print(f"CERT collection complete. Output saved to: {output_path}")
    else:
        print("CERT collection finished with no output.")
