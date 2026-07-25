from __future__ import annotations

import urllib.request
import xml.etree.ElementTree as ET
from collections.abc import Iterable

from backend.app.pipeline.common.cti_schema import RawRecord, utc_now_iso
from backend.app.pipeline.ingestion.base_connector import ExternalConnector


class RSSConnector(ExternalConnector):
    """Minimal RSS/Atom connector using only the Python standard library."""

    def __init__(self, feed_url: str, source_name: str = "rss_feed", timeout: int = 20) -> None:
        self.feed_url = feed_url
        self.source_name = source_name
        self.timeout = timeout

    def collect(self) -> Iterable[RawRecord]:
        with urllib.request.urlopen(self.feed_url, timeout=self.timeout) as response:
            payload = response.read()

        root = ET.fromstring(payload)
        entries = root.findall(".//item") or root.findall("{http://www.w3.org/2005/Atom}entry")
        for entry in entries:
            title = self._child_text(entry, "title") or "Untitled RSS item"
            link = self._child_text(entry, "link") or self._atom_link(entry)
            content = (
                self._child_text(entry, "description")
                or self._child_text(entry, "{http://www.w3.org/2005/Atom}summary")
                or title
            )
            published = self._child_text(entry, "pubDate") or self._child_text(
                entry, "{http://www.w3.org/2005/Atom}updated"
            )
            yield RawRecord(
                external_id=link or title,
                source_name=self.source_name,
                source_type="rss",
                title=title,
                content=content,
                url=link,
                published_at=published,
                collected_at=utc_now_iso(),
                raw_data={"feed_url": self.feed_url, "title": title, "link": link},
            )

    def _child_text(self, entry: ET.Element, tag: str) -> str | None:
        child = entry.find(tag)
        if child is None or child.text is None:
            return None
        return child.text.strip()

    def _atom_link(self, entry: ET.Element) -> str | None:
        link = entry.find("{http://www.w3.org/2005/Atom}link")
        if link is None:
            return None
        href = link.attrib.get("href")
        return href.strip() if href else None
