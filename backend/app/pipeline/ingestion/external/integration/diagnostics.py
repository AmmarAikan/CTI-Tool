"""Canonical bounded diagnostics exposed by External collection jobs."""

from __future__ import annotations


EXTERNAL_COLLECTION_METHODS = frozenset(
    {
        "cert",
        "configured_onion_get",
        "dark_web",
        "hackernews",
        "official_csaf",
        "official_listing",
        "official_rss",
        "reddit",
        "reddit_browser_fallback",
        "reddit_oauth",
        "reddit_public_rss",
        "rss",
        "telegram",
        "vulnerability",
    }
)

DIAGNOSTIC_IDENTIFIER_PATTERN = r"^[A-Za-z][A-Za-z0-9_]{0,99}$"
COLLECTION_STAGE_PATTERN = r"^[a-z][a-z0-9_]{0,63}$"
