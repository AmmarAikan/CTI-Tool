"""
Test suite for the Dark Web collector.

Deliberately does NOT require a live Tor connection or a real onion
site — everything here runs against local config, a mocked session, and
a local HTML fixture (`tests/fixtures/sample_dark_web_page.html`).

Run with:
    python -m tests.test_dark_web_collector

Uses plain asserts with clear PASS/FAIL output rather than pytest,
matching this project's existing "no test framework dependency" stance
(no test framework currently appears in requirements.txt).
"""

import os
import sys
import socket
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.dark_web.dark_web_collector import DarkWebCollector
from src.dark_web.onion_sources import get_dark_web_sources, get_tor_proxy_config

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "sample_dark_web_page.html"

_passed = 0
_failed = 0


def check(description: str, condition: bool) -> None:
    global _passed, _failed
    if condition:
        print(f"  PASS: {description}")
        _passed += 1
    else:
        print(f"  FAIL: {description}")
        _failed += 1


def test_config_loads_correctly():
    print("\n[1] Configuration loads correctly")
    sources = get_dark_web_sources()
    check("dark_web_sources.json is readable and returns a list", isinstance(sources, list))
    check("at least the placeholder source entry is present", len(sources) >= 1)
    if sources:
        check("source entries have a 'url' field", "url" in sources[0])
        check("source entries have an 'enabled' field", "enabled" in sources[0])


def test_tor_proxy_config_read_correctly():
    print("\n[2] Tor proxy configuration is read correctly")
    proxy = get_tor_proxy_config()
    check("proxy config has a 'host' key", "host" in proxy)
    check("proxy config has a 'port' key", "port" in proxy)
    check("proxy port is an int", isinstance(proxy.get("port"), int))

    # Environment variables should override the config file.
    os.environ["TOR_PROXY_HOST"] = "192.0.2.1"  # TEST-NET-1, never routable
    os.environ["TOR_PROXY_PORT"] = "9150"
    overridden = get_tor_proxy_config()
    check("TOR_PROXY_HOST env var overrides config", overridden["host"] == "192.0.2.1")
    check("TOR_PROXY_PORT env var overrides config", overridden["port"] == 9150)
    del os.environ["TOR_PROXY_HOST"]
    del os.environ["TOR_PROXY_PORT"]


def test_detects_tor_unavailable():
    print("\n[3] Collector detects when Tor is unavailable")
    # Port 1 is a reserved/unassigned low port essentially guaranteed to
    # have nothing listening on it in any normal environment.
    collector = DarkWebCollector(tor_proxy={"host": "127.0.0.1", "port": 1})
    available = collector.is_tor_available()
    check("is_tor_available() returns False for a closed port", available is False)

    # collect() should fail gracefully (no items, no exception) when Tor
    # is unavailable, even with an enabled, well-formed source configured.
    fake_sources = [{
        "name": "Test Source", "url": "http://validlooking3fakeaddress.onion/",
        "enabled": True, "category": "dark_web_cti",
    }]
    collector2 = DarkWebCollector(sources=fake_sources, tor_proxy={"host": "127.0.0.1", "port": 1})
    items = collector2.collect()
    check("collect() returns an empty list (not an exception) when Tor is down", items == [])


def test_processes_sample_html_without_live_site():
    print("\n[4] Collector can process a sample HTML page without a live onion site")
    check("fixture file exists", FIXTURE_PATH.exists())

    html = FIXTURE_PATH.read_text(encoding="utf-8")
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(html, "lxml")

    collector = DarkWebCollector(sources=[])

    title = collector._extract_title(soup)
    check("title extracted from <title> tag", title == "Sample CTI Research Forum - Post #4821")

    published = collector._extract_published(soup)
    check("published date extracted from meta tag", published == "2026-07-23T10:00:00Z")

    author = collector._extract_author(soup)
    check("author extracted from meta tag", author == "research_contributor")

    content = collector._extract_content(soup)
    check("content is non-empty", bool(content))
    check("content includes the real article text", "Data Exfiltration Toolkit" in content)
    check("content excludes nav chrome", "Home" not in content.split("\n")[:2])
    check("content excludes script content", "console.log" not in content)
    check("content excludes footer boilerplate text", "Forum footer text" not in content)


def test_output_matches_existing_schema():
    print("\n[5] Output JSON follows the project's existing structure")
    html = FIXTURE_PATH.read_text(encoding="utf-8")
    from bs4 import BeautifulSoup
    import requests

    soup = BeautifulSoup(html, "lxml")
    collector = DarkWebCollector(sources=[])

    fake_response = mock.Mock()
    fake_response.status_code = 200
    fake_response.text = html

    fake_session = mock.Mock(spec=requests.Session)
    fake_session.get.return_value = fake_response

    source = {
        "name": "Test Source", "url": "http://validlooking3fakeaddress.onion/",
        "category": "dark_web_cti", "timeout": 30,
    }
    item = collector._collect_source(fake_session, source)
    check("an item was produced", item is not None)

    if item is not None:
        item_dict = item.to_dict()
        expected_keys = {
            "title", "link", "source", "category", "content", "summary",
            "published", "author", "tags", "collected_at", "metadata",
        }
        check("output has all expected unified-schema keys", expected_keys.issubset(item_dict.keys()))
        check("metadata.collection_method == 'tor_http'", item_dict["metadata"].get("collection_method") == "tor_http")
        check("metadata.network == 'tor'", item_dict["metadata"].get("network") == "tor")
        check("metadata.source_type == 'onion_service'", item_dict["metadata"].get("source_type") == "onion_service")
        check("category matches configured source", item_dict["category"] == "dark_web_cti")


def test_one_failed_source_does_not_stop_others():
    print("\n[6] One failed source does not stop other sources")
    import requests

    good_html = FIXTURE_PATH.read_text(encoding="utf-8")
    good_response = mock.Mock()
    good_response.status_code = 200
    good_response.text = good_html

    def fake_get(url, timeout=None):
        if "broken" in url:
            raise requests.exceptions.ConnectionError("simulated connection failure")
        return good_response

    fake_session = mock.Mock(spec=requests.Session)
    fake_session.get.side_effect = fake_get

    sources = [
        {"name": "Broken Source", "url": "http://brokenfakeaddress3xyz.onion/", "enabled": True, "category": "dark_web_cti"},
        {"name": "Good Source", "url": "http://goodfakeaddress3xyz.onion/", "enabled": True, "category": "dark_web_cti"},
    ]
    collector = DarkWebCollector(sources=sources, default_request_delay=0)

    with mock.patch.object(collector, "is_tor_available", return_value=True), \
         mock.patch.object(collector, "_build_session", return_value=fake_session):
        items = collector.collect()

    check("exactly one item collected despite one broken source", len(items) == 1)
    if items:
        check("the successful item is from the good source", items[0].source == "Good Source")


def test_existing_collectors_still_importable():
    print("\n[7] Existing RSS/Web/CERT/Vulnerability/Social Media collectors still work")
    try:
        from src.collectors.rss_collector import RSSCollector  # noqa: F401
        from src.crawler.web_crawler import WebCrawler  # noqa: F401
        from src.cert.cert_collector import CERTCollector  # noqa: F401
        from src.vulnerabilities.vulnerability_collector import VulnerabilityCollector  # noqa: F401
        from src.social_media.social_media_collector import SocialMediaCollector  # noqa: F401
        from src.social_media.telegram_collector import TelegramCollector  # noqa: F401
        from src.preprocessing.text_cleaner import TextPreprocessor  # noqa: F401
        check("all existing collectors still import without error", True)
    except Exception as e:
        check(f"all existing collectors still import without error (error: {e})", False)


def main():
    print("=" * 70)
    print("Dark Web Collector Test Suite (no live Tor/onion site required)")
    print("=" * 70)

    test_config_loads_correctly()
    test_tor_proxy_config_read_correctly()
    test_detects_tor_unavailable()
    test_processes_sample_html_without_live_site()
    test_output_matches_existing_schema()
    test_one_failed_source_does_not_stop_others()
    test_existing_collectors_still_importable()

    print("\n" + "=" * 70)
    print(f"Results: {_passed} passed, {_failed} failed")
    print("=" * 70)
    sys.exit(1 if _failed else 0)


if __name__ == "__main__":
    main()
