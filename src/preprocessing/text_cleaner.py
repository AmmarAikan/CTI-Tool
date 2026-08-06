"""
Phase 3 — Text Preprocessing.

Cleans article text produced by the Phase 2 crawler: removes leftover
HTML entities, boilerplate lines (share bars, cookie notices, newsletter
prompts, comment counts), duplicate whitespace, and stray symbols, while
preserving paragraph breaks, headings, and the actual article text.

This stage does NOT do content understanding (that's Classification/NER/
IOC Extraction, owned by the rest of the team) — it only normalizes and
cleans text so those downstream stages get consistent input.
"""

import html
import re
import unicodedata
from typing import Any, Dict, List

from src.utils.config_loader import get_boilerplate_patterns
from src.utils.logger import get_logger
from src.utils.storage import latest_file, load_json, save_json, timestamped_filename

logger = get_logger(__name__)

# Characters that occasionally survive HTML extraction but carry no
# semantic value in plain text (zero-width spaces, byte-order marks,
# soft hyphens, various invisible formatting marks).
_INVISIBLE_CHARS_PATTERN = re.compile(
    "[\u200b\u200c\u200d\u200e\u200f\ufeff\xad]"
)

# Runs of 3+ blank lines collapse to a single blank line between paragraphs.
_MULTI_BLANK_LINES_PATTERN = re.compile(r"\n{3,}")

# Runs of horizontal whitespace (spaces/tabs) collapse to a single space.
_MULTI_SPACE_PATTERN = re.compile(r"[ \t]{2,}")

# Stray repeated punctuation/symbol noise (e.g. "-----", "*****", "====")
# left over from ASCII dividers, but NOT touching normal punctuation.
_REPEATED_SYMBOL_PATTERN = re.compile(r"([\-=_*~#]){4,}")


class TextPreprocessor:
    """Cleans raw article text into normalized, boilerplate-free text."""

    def __init__(self, boilerplate_patterns: List[str] = None):
        """
        Args:
            boilerplate_patterns: Optional explicit list of regex patterns
                for boilerplate lines to strip. If not provided, patterns
                are loaded from `config/preprocessing_rules.json`.
        """
        patterns = (
            boilerplate_patterns
            if boilerplate_patterns is not None
            else get_boilerplate_patterns()
        )
        self._compiled_patterns = self._compile_patterns(patterns)

    @staticmethod
    def _compile_patterns(patterns: List[str]) -> List[re.Pattern]:
        """Compile regex patterns, skipping and logging any invalid ones."""
        compiled = []
        for pattern in patterns:
            try:
                compiled.append(re.compile(pattern))
            except re.error as e:
                logger.error("Skipping invalid boilerplate pattern '%s': %s", pattern, e)
        return compiled

    def clean(self, text: str) -> str:
        """
        Run the full cleaning pipeline over a block of text.

        Preserves paragraph breaks (blank lines) and heading lines;
        removes HTML entity remnants, invisible characters, boilerplate
        lines, repeated symbol dividers, and duplicate whitespace.

        Args:
            text: Raw text (e.g. from the Phase 2 crawler's `content`
                or `summary` fields).

        Returns:
            Cleaned text. Empty string in, empty string out.
        """
        if not text:
            return ""

        text = self._decode_html_entities(text)
        text = self._normalize_unicode(text)
        text = self._strip_invisible_chars(text)
        text = self._strip_boilerplate_lines(text)
        text = self._strip_repeated_symbols(text)
        text = self._collapse_whitespace(text)

        return text.strip()

    @staticmethod
    def _decode_html_entities(text: str) -> str:
        """Convert leftover entities like &amp; or &#39; to real characters."""
        return html.unescape(text)

    @staticmethod
    def _normalize_unicode(text: str) -> str:
        """Normalize to NFKC form (e.g. fold odd quote/dash variants consistently)."""
        return unicodedata.normalize("NFKC", text)

    @staticmethod
    def _strip_invisible_chars(text: str) -> str:
        """Remove zero-width and other invisible formatting characters."""
        return _INVISIBLE_CHARS_PATTERN.sub("", text)

    def _strip_boilerplate_lines(self, text: str) -> str:
        """Drop any line that matches a configured boilerplate pattern."""
        kept_lines = []
        for line in text.split("\n"):
            stripped = line.strip()
            if not stripped:
                kept_lines.append("")  # preserve paragraph breaks
                continue

            if any(p.match(stripped) for p in self._compiled_patterns):
                logger.debug("Dropped boilerplate line: %s", stripped[:60])
                continue

            kept_lines.append(stripped)

        return "\n".join(kept_lines)

    @staticmethod
    def _strip_repeated_symbols(text: str) -> str:
        """Remove ASCII divider noise like '-----' or '*****' left over from source formatting."""
        return _REPEATED_SYMBOL_PATTERN.sub("", text)

    @staticmethod
    def _collapse_whitespace(text: str) -> str:
        """Collapse duplicate spaces/tabs and excessive blank lines."""
        text = _MULTI_SPACE_PATTERN.sub(" ", text)
        text = _MULTI_BLANK_LINES_PATTERN.sub("\n\n", text)
        # Trim trailing whitespace on each line without disturbing blank
        # lines that separate paragraphs.
        lines = [line.rstrip() for line in text.split("\n")]
        return "\n".join(lines)

    def process_items(self, items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Clean the `content` and `summary` fields of every item in place.

        A cleaning failure on a single item is logged and the item is
        kept with its original (uncleaned) text rather than being
        dropped from the dataset.

        Args:
            items: List of unified CTI item dicts (as produced by
                Phase 2), each with `content` and/or `summary` fields.

        Returns:
            The same list of items with cleaned text.
        """
        cleaned_items = []

        for item in items:
            try:
                if item.get("content"):
                    item["content"] = self.clean(item["content"])
                if item.get("summary"):
                    item["summary"] = self.clean(item["summary"])
            except Exception as e:  # noqa: BLE001 - one bad item must not abort the batch
                logger.error(
                    "Failed to clean item '%s': %s", item.get("title", "untitled"), e
                )
            cleaned_items.append(item)

        return cleaned_items


def run(input_path: str = None) -> str:
    """
    Convenience entry point for Phase 3.

    Loads the most recent Phase 2 crawler output (or an explicit input
    file), cleans every item's text, and saves the result to a new
    timestamped JSON file.

    Args:
        input_path: Optional explicit path to a Phase 2 JSON file. If
            omitted, the newest `crawled_articles_*.json` file is used.

    Returns:
        Path to the written output file, or an empty string if there
        was nothing to process or saving failed.
    """
    if input_path is None:
        input_path = latest_file("crawled_articles")

    if not input_path:
        logger.warning("No crawler output file found; run Phase 2 first.")
        return ""

    items = load_json(input_path)
    if not items:
        logger.warning("No items to preprocess in %s", input_path)
        return ""

    preprocessor = TextPreprocessor()
    cleaned_items = preprocessor.process_items(items)

    filename = timestamped_filename("clean_articles")
    return save_json(cleaned_items, filename)


if __name__ == "__main__":
    output_path = run()
    if output_path:
        print(f"Preprocessing complete. Output saved to: {output_path}")
    else:
        print("Preprocessing finished with no output.")
