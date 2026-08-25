from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, field
import re
from typing import Any, Literal
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

from backend.app.pipeline.ingestion.external.common.canonical_url import canonicalize_url


PageType = Literal["article", "listing", "unknown"]
CONTAINER_TOKENS = ("card", "post", "article", "story", "item", "entry", "result", "teaser")
UTILITY_TOKENS = ("menu", "nav", "footer", "header", "cookie", "consent", "utility", "account", "breadcrumb", "sidebar")
UTILITY_SEGMENTS = frozenset({"contact", "login", "signin", "signup", "account", "privacy", "terms", "legal", "tag", "tags", "category", "categories", "page", "pagination"})


@dataclass(frozen=True, slots=True)
class PageTypeResult:
    page_type: PageType
    confidence: float
    candidate_links: tuple[str, ...] = ()
    signals: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["candidate_links"] = list(self.candidate_links)
        return value


class PageTypeDetector:
    """Classify a page with explainable article/listing signals."""

    def __init__(self, *, max_candidate_links: int = 100, decision_threshold: float = 0.5) -> None:
        if max_candidate_links <= 0:
            raise ValueError("max_candidate_links must be positive")
        if not 0 < decision_threshold <= 1:
            raise ValueError("decision_threshold must be between 0 and 1")
        self.max_candidate_links = max_candidate_links
        self.decision_threshold = decision_threshold

    def detect(self, html: str, url: str, extracted_text: str = "") -> PageTypeResult:
        soup = BeautifulSoup(html, "lxml")
        candidates = self._candidate_links(soup, url)
        article_count = len(soup.find_all("article"))
        repeated_cards = self._repeated_card_count(soup)
        h1_count = len(soup.find_all("h1"))
        heading_count = len(soup.find_all(["h1", "h2", "h3"]))
        metadata_article = self._has_article_metadata(soup)
        visible_text = soup.get_text(" ", strip=True)
        text_density = len(extracted_text.strip()) / max(1, len(visible_text))
        link_text_total = sum(len(anchor.get_text(" ", strip=True)) for anchor in soup.find_all("a"))
        link_text_ratio = link_text_total / max(1, len(visible_text))

        article_score = 0.0
        article_score += 0.35 if metadata_article else 0.0
        article_score += 0.18 if article_count == 1 else 0.0
        article_score += 0.17 if h1_count == 1 else 0.0
        article_score += 0.2 if len(extracted_text.strip()) >= 300 else (0.1 if len(extracted_text.strip()) >= 120 else 0.0)
        article_score += 0.1 if text_density >= 0.55 else 0.0

        listing_score = 0.0
        listing_score += 0.3 if article_count >= 3 else (0.15 if article_count == 2 else 0.0)
        listing_score += 0.25 if repeated_cards >= 3 else (0.12 if repeated_cards == 2 else 0.0)
        listing_score += 0.3 if len(candidates) >= 4 else (0.15 if len(candidates) >= 2 else 0.0)
        listing_score += 0.15 if link_text_ratio >= 0.25 else 0.0

        article_score = min(1.0, article_score)
        listing_score = min(1.0, listing_score)
        best_score = max(article_score, listing_score)
        if best_score < self.decision_threshold or abs(article_score - listing_score) < 0.1:
            page_type: PageType = "unknown"
        elif article_score > listing_score:
            page_type = "article"
        else:
            page_type = "listing"

        signals = {
            "article_score": round(article_score, 4),
            "listing_score": round(listing_score, 4),
            "article_elements": article_count,
            "repeated_card_elements": repeated_cards,
            "h1_count": h1_count,
            "heading_count": heading_count,
            "article_metadata": metadata_article,
            "extraction_yield": len(extracted_text.strip()),
            "text_density": round(text_density, 4),
            "headline_link_count": len(candidates),
            "link_text_ratio": round(link_text_ratio, 4),
        }
        return PageTypeResult(page_type, round(best_score, 4), tuple(candidates), signals)

    def _candidate_links(self, soup: BeautifulSoup, base_url: str) -> list[str]:
        base_host = (urlsplit(base_url).hostname or "").lower()
        base_path = self._segments(urlsplit(base_url).path)
        signatures: Counter[str] = Counter()
        for tag in soup.find_all(["article", "section", "div", "li"]):
            signature = self._container_signature(tag)
            if signature: signatures[signature] += 1
        ranked: dict[str, tuple[float, int]] = {}
        base_canonical = canonicalize_url(base_url)
        for order, anchor in enumerate(soup.find_all("a", href=True)):
            text = anchor.get_text(" ", strip=True)
            if self._inside_utility(anchor):
                continue
            absolute = urljoin(base_url, str(anchor["href"]))
            if (urlsplit(absolute).hostname or "").lower() != base_host:
                continue
            try:
                canonical = canonicalize_url(absolute)
            except ValueError:
                continue
            if canonical == base_canonical or self._utility_path(urlsplit(canonical).path):
                continue
            context = self._context(anchor, signatures)
            headline = len(text) >= 18 and len(text.split()) >= 3
            if not headline and context < 2:
                continue
            score = context + self._path_score(base_path, self._segments(urlsplit(canonical).path))
            current = ranked.get(canonical)
            if current is None or score > current[0]: ranked[canonical] = (score, order)
        ordered = sorted(ranked, key=lambda value: (-ranked[value][0], ranked[value][1], value))
        return ordered[:self.max_candidate_links]

    @staticmethod
    def _inside_utility(anchor) -> bool:
        for parent in [anchor, *anchor.parents]:
            if getattr(parent, "name", None) in {"header", "nav", "footer", "form", "aside"}: return True
            role = str(parent.get("role") or "").lower() if hasattr(parent, "get") else ""
            if role in {"navigation", "banner", "contentinfo", "form"}: return True
            marker = " ".join(str(value).lower() for value in [*(parent.get("class") or []), parent.get("id") or ""] if value) if hasattr(parent, "get") else ""
            if any(token in marker for token in UTILITY_TOKENS): return True
        return False

    @staticmethod
    def _context(anchor, signatures: Counter[str]) -> float:
        score = 0.0
        if anchor.find_parent("main"): score += 1.0
        if anchor.find_parent("article"): score += 4.0
        if anchor.find_parent(["h1", "h2", "h3", "h4"]): score += 3.0
        for parent in anchor.parents:
            if getattr(parent, "name", None) not in {"article", "section", "div", "li"}: continue
            signature = PageTypeDetector._container_signature(parent)
            if signature:
                score += 2.0
                if signatures[signature] >= 2: score += 2.0
                break
        return score

    @staticmethod
    def _container_signature(tag) -> str | None:
        for class_name in tag.get("class") or []:
            lowered = str(class_name).lower()
            if any(token in lowered for token in CONTAINER_TOKENS): return f"{tag.name}.{lowered}"
        return None

    @staticmethod
    def _utility_path(path: str) -> bool:
        segments = PageTypeDetector._segments(path)
        if any(segment in UTILITY_SEGMENTS for segment in segments): return True
        if len(segments) == 3 and segments[:2] == ("blog", "products"): return True
        if segments and re.fullmatch(r"page-?\d+", segments[-1]): return True
        return False

    @staticmethod
    def _path_score(base: tuple[str, ...], child: tuple[str, ...]) -> float:
        common = 0
        for left, right in zip(base, child):
            if left != right: break
            common += 1
        score = min(common, 4) * 0.75
        if base and common == len(base) and len(child) > len(base): score += 2.5
        elif common == 0: score -= 1.0
        return score

    @staticmethod
    def _segments(path: str) -> tuple[str, ...]:
        return tuple(value.lower() for value in path.split("/") if value)

    @staticmethod
    def _has_article_metadata(soup: BeautifulSoup) -> bool:
        for tag in soup.find_all("meta"):
            key = str(tag.get("property") or tag.get("name") or "").lower()
            content = str(tag.get("content") or "").lower()
            if key in {"og:type", "twitter:card"} and ("article" in content or "summary_large_image" in content):
                return True
            if key in {"article:published_time", "datepublished", "author"} and content:
                return True
        return bool(soup.find(attrs={"itemtype": lambda value: value and "Article" in str(value)}))

    @staticmethod
    def _repeated_card_count(soup: BeautifulSoup) -> int:
        signatures: Counter[str] = Counter()
        for tag in soup.find_all(["article", "section", "div", "li"]):
            classes = tag.get("class") or []
            for class_name in classes:
                lowered = str(class_name).lower()
                if any(token in lowered for token in CONTAINER_TOKENS):
                    signatures[f"{tag.name}.{lowered}"] += 1
        return max(signatures.values(), default=0)
