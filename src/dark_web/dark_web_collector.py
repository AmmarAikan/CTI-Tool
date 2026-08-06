"""
Dark Web external-source collector.

Purpose: defensive Cyber Threat Intelligence collection ONLY, from a
small, explicitly curated list of approved onion sources
(`config/dark_web_sources.json`) — never automatic discovery.

Collection model:
    Approved/curated onion sources
        -> Tor network (SOCKS5 proxy)
        -> HTTP GET requests
        -> HTML extraction (BeautifulSoup)
        -> Text cleaning (reuses Phase 3's TextPreprocessor)
        -> Normalized CTIItem
        -> src/data/ (reuses existing storage.py)

Strict security boundaries — this module does, and will only ever do,
a plain HTTP GET against sources the operator has explicitly listed and
enabled in config. It does NOT and must never:
    - discover or follow onion links found on a page
    - create accounts, log in, or register
    - send messages or interact with any threat actor
    - purchase anything or handle any transaction
    - submit forms, upload files, or download arbitrary files
    - bypass CAPTCHAs or any authentication/access control
    - perform any exploitation or credential collection

If Tor isn't running, this collector fails gracefully (logs it clearly
and returns no items) — it never crashes the rest of the pipeline, and
no other collector in this project depends on Tor being available.
"""

import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests
from bs4 import BeautifulSoup

from src.collectors.base_collector import BaseCollector
from src.dark_web.onion_sources import (
    get_dark_web_sources,
    get_default_request_delay,
    get_default_timeout,
    get_tor_proxy_config,
)
from src.preprocessing.text_cleaner import TextPreprocessor
from src.utils.logger import get_logger
from src.utils.schema import CTIItem
from src.utils.storage import save_json, timestamped_filename

logger = get_logger(__name__)

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36 CTI-Tool-DarkWebCollector/1.0"
    )
}

# Tags that never contain meaningful article/post content and should be
# stripped before extracting text — same intent as Phase 2's crawler.
NOISE_TAGS = ["script", "style", "nav", "footer", "header", "aside", "form", "iframe"]

# A placeholder URL is unmistakably not a real, verified source — never
# attempt to connect to one, even if accidentally left "enabled".
_PLACEHOLDER_MARKERS = ("REPLACE", "PLACEHOLDER", "EXAMPLE.ONION")


class DarkWebCollector(BaseCollector):
    """Collects CTI content from a curated, operator-approved list of onion sources via Tor."""

    name = "dark_web_collector"

    def __init__(
        self,
        sources: Optional[List[Dict[str, Any]]] = None,
        tor_proxy: Optional[Dict[str, Any]] = None,
        default_timeout: Optional[int] = None,
        default_request_delay: Optional[int] = None,
    ):
        """
        Args:
            sources: Optional explicit list of source dicts. If not
                provided, sources are loaded from
                `config/dark_web_sources.json`.
            tor_proxy: Optional explicit `{"host":..., "port":...}`. If
                not provided, resolved from `TOR_PROXY_HOST`/
                `TOR_PROXY_PORT` env vars, then the config file, then
                Tor's own standard default (127.0.0.1:9050).
            default_timeout: Fallback per-request timeout (seconds) for
                sources that don't set their own.
            default_request_delay: Fallback delay (seconds) between
                requests for sources that don't set their own.
        """
        self.sources = sources if sources is not None else get_dark_web_sources()
        self.tor_proxy = tor_proxy if tor_proxy is not None else get_tor_proxy_config()
        self.default_timeout = default_timeout if default_timeout is not None else get_default_timeout()
        self.default_request_delay = (
            default_request_delay if default_request_delay is not None else get_default_request_delay()
        )
        # Reused (not duplicated) from Phase 3 — same boilerplate-stripping/
        # whitespace-normalizing logic every other collector's text goes
        # through, applied here to the raw text pulled from onion pages.
        self._preprocessor = TextPreprocessor()

    def is_tor_available(self) -> bool:
        """
        Quick, cheap check for whether something is listening on the
        configured Tor SOCKS5 proxy port — lets the collector fail
        gracefully with one clear log message instead of repeated
        per-source connection errors when Tor isn't running at all.
        """
        import socket

        host = self.tor_proxy["host"]
        port = self.tor_proxy["port"]
        try:
            with socket.create_connection((host, port), timeout=5):
                return True
        except OSError:
            return False

    def _build_session(self) -> requests.Session:
        """Build a requests Session routed entirely through the Tor SOCKS5 proxy."""
        session = requests.Session()
        proxy_url = f"socks5h://{self.tor_proxy['host']}:{self.tor_proxy['port']}"
        # socks5h (not socks5): DNS resolution also happens through Tor,
        # not locally — avoids leaking the .onion hostname outside Tor.
        session.proxies = {"http": proxy_url, "https": proxy_url}
        session.headers.update(DEFAULT_HEADERS)
        return session

    @staticmethod
    def _is_placeholder(url: str) -> bool:
        """Detect an unverified placeholder URL so it's never actually requested."""
        if not url or ".onion" not in url:
            return True
        return any(marker in url.upper() for marker in _PLACEHOLDER_MARKERS)

    def collect(self) -> List[CTIItem]:
        """
        Collect from every enabled, non-placeholder Dark Web source.

        Only ever issues plain HTTP GET requests, one source at a time
        (never concurrent), with a configurable delay between them. A
        single source failing (Tor down, timeout, connection refused,
        bad HTTP status, unparseable page) is logged clearly and never
        stops collection of the remaining sources.

        Returns:
            A list of `CTIItem` objects. Empty if Tor is unavailable,
            no sources are configured/enabled, or every source failed.
        """
        if not self.sources:
            logger.warning("No Dark Web sources configured; nothing to collect.")
            return []

        enabled_sources = [s for s in self.sources if s.get("enabled", False)]
        if not enabled_sources:
            logger.warning(
                "No enabled Dark Web sources (all disabled or still placeholders); "
                "nothing to collect. Add a verified source to "
                "config/dark_web_sources.json and set enabled: true."
            )
            return []

        if not self.is_tor_available():
            logger.error(
                "Tor connection unavailable (%s:%s). Skipping Dark Web collection "
                "for this run — no other collector in this project depends on Tor, "
                "so the rest of the pipeline is unaffected.",
                self.tor_proxy["host"], self.tor_proxy["port"],
            )
            return []

        try:
            session = self._build_session()
        except Exception as e:  # noqa: BLE001 - e.g. PySocks not installed
            logger.error(
                "Failed to set up the Tor SOCKS5 session (is PySocks installed? "
                "`pip install PySocks`): %s", e,
            )
            return []

        items: List[CTIItem] = []

        for index, source in enumerate(enabled_sources):
            name = source.get("name", "unknown")
            url = source.get("url", "")

            if self._is_placeholder(url):
                logger.warning(
                    "Skipping Dark Web source '%s': URL is missing, invalid, or still "
                    "a placeholder. Replace it with a manually verified onion address.",
                    name,
                )
                continue

            try:
                item = self._collect_source(session, source)
                if item is not None:
                    logger.info("Source collected successfully: %s", name)
                    items.append(item)
            except requests.exceptions.ConnectTimeout:
                logger.error("Source unavailable (connection timed out): %s", name)
            except requests.exceptions.ConnectionError:
                logger.error("Source unavailable (connection refused/failed): %s", name)
            except requests.exceptions.Timeout:
                logger.error("Source unavailable (request timed out): %s", name)
            except requests.exceptions.RequestException as e:
                logger.error("Source unavailable (%s): %s", name, e)
            except Exception as e:  # noqa: BLE001 - one source must never abort the run
                logger.error("Failed to collect Dark Web source '%s': %s", name, e)

            is_last = index == len(enabled_sources) - 1
            if not is_last:
                delay = source.get("request_delay", self.default_request_delay)
                time.sleep(delay)

        return items

    def _collect_source(self, session: requests.Session, source: Dict[str, Any]) -> Optional[CTIItem]:
        """
        Fetch and parse exactly one configured onion page.

        Only ever a single GET to the exact configured URL — this does
        NOT follow any link found on the page, paginate automatically,
        or discover related pages. `max_pages` in config is accepted for
        forward compatibility with manually-curated multi-page sources
        later, but is not used to drive any automatic crawling today.
        """
        name = source.get("name", "unknown")
        url = source["url"]
        category = source.get("category", "dark_web")
        timeout = source.get("timeout", self.default_timeout)

        response = session.get(url, timeout=timeout)

        if response.status_code != 200:
            logger.warning("Source returned HTTP status %s: %s", response.status_code, name)
            return None

        try:
            soup = BeautifulSoup(response.text, "lxml")
        except Exception as e:
            logger.error("Failed to parse source '%s': %s", name, e)
            return None

        content = self._extract_content(soup)
        if not content:
            logger.warning("Source '%s' returned an empty or unparseable page.", name)
            return None

        title = self._extract_title(soup) or name
        published = self._extract_published(soup)
        author = self._extract_author(soup)

        return CTIItem(
            title=title,
            link=url,
            source=name,
            category=category,
            content=content,
            summary=content[:300].strip(),
            published=published,
            author=author,
            collected_at=datetime.now(timezone.utc).isoformat(),
            metadata={
                "collection_method": "tor_http",
                "network": "tor",
                "source_type": "onion_service",
            },
        )

    @staticmethod
    def _extract_title(soup: BeautifulSoup) -> Optional[str]:
        """Best-effort title: <title> tag, else the first <h1>."""
        if soup.title and soup.title.string:
            title = soup.title.string.strip()
            if title:
                return title

        h1 = soup.find("h1")
        if h1:
            text = h1.get_text(strip=True)
            if text:
                return text

        return None

    @staticmethod
    def _extract_published(soup: BeautifulSoup) -> Optional[str]:
        """Best-effort published date: common meta tags, else a <time datetime>."""
        meta = soup.find("meta", attrs={"property": "article:published_time"})
        if meta and meta.get("content"):
            return meta["content"]

        meta = soup.find("meta", attrs={"name": "date"})
        if meta and meta.get("content"):
            return meta["content"]

        time_tag = soup.find("time")
        if time_tag and time_tag.get("datetime"):
            return time_tag["datetime"]

        return None

    @staticmethod
    def _extract_author(soup: BeautifulSoup) -> Optional[str]:
        """Best-effort author: a standard <meta name="author"> tag."""
        meta = soup.find("meta", attrs={"name": "author"})
        if meta and meta.get("content"):
            return meta["content"].strip()
        return None

    def _extract_content(self, soup: BeautifulSoup) -> str:
        """
        Extract and clean the page's main textual content.

        Strips script/style/nav/header/footer/aside/form elements (never
        saves menus, ads, or navigation chrome), pulls plain text, then
        runs it through the existing Phase 3 `TextPreprocessor` — reusing
        the same boilerplate-stripping and whitespace-normalizing logic
        every other collector's text already goes through, rather than
        duplicating that logic here.
        """
        for tag in soup.find_all(NOISE_TAGS):
            tag.decompose()

        raw_text = soup.get_text(separator="\n", strip=True)
        return self._preprocessor.clean(raw_text)


def run() -> str:
    """
    Convenience entry point, matching every other collector's `run()`
    pattern: collect from all configured sources, save via the existing
    storage layer.

    Returns:
        Path to the written JSON file, or an empty string if nothing
        was collected (no sources enabled, Tor unavailable, or every
        source failed) or saving failed.
    """
    collector = DarkWebCollector()
    items = collector.collect()

    if not items:
        logger.warning("Dark Web collection produced no items.")
        return ""

    filename = timestamped_filename("dark_web_posts")
    return save_json([item.to_dict() for item in items], filename)


if __name__ == "__main__":
    output_path = run()
    if output_path:
        print(f"Dark Web collection complete. Output saved to: {output_path}")
    else:
        print("Dark Web collection finished with no output.")
