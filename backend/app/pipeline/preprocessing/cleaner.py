from __future__ import annotations

import html
import re


TAG_RE = re.compile(r"<[^>]+>")
CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
WHITESPACE_RE = re.compile(r"\s+")


class TextCleaner:
    """Clean external document text before classification and extraction."""

    def clean(self, text: str | None) -> str:
        if not text:
            return ""
        value = html.unescape(str(text))
        value = TAG_RE.sub(" ", value)
        value = CONTROL_RE.sub(" ", value)
        value = WHITESPACE_RE.sub(" ", value)
        return value.strip()
