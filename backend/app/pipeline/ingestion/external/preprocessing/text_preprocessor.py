from __future__ import annotations

import html
import re
import unicodedata
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from bs4 import BeautifulSoup, Comment

from backend.app.pipeline.ingestion.external.common.config_loader import load_config
from backend.app.pipeline.ingestion.external.common.hashing import sha256_json, sha256_text
from backend.app.pipeline.preprocessing.cleaner import TextCleaner


IMPLEMENTATION_VERSION = "external_text_preprocessor_v1"
SPACE_RE = re.compile(r"[\t \f\v]+")
HTML_TAG_RE = re.compile(r"</?[a-zA-Z][^>]*>")


@dataclass(frozen=True, slots=True)
class PreprocessingResult:
    text: str
    input_hash: str
    output_hash: str
    rules_hash: str
    rules_version: str
    implementation_version: str = IMPLEMENTATION_VERSION
    removed_boilerplate_lines: int = 0

    @property
    def stage_hash(self) -> str:
        return sha256_json(
            {
                "input_hash": self.input_hash,
                "implementation_version": self.implementation_version,
                "rules_hash": self.rules_hash,
            }
        )

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["stage_hash"] = self.stage_hash
        return value


class TextPreprocessor:
    """Clean External text without changing CTI tokens or fenced code content."""

    def __init__(self, rules_path: str | Path, cleaner: TextCleaner | None = None) -> None:
        self.rules_path = Path(rules_path)
        self.rules = load_config(self.rules_path)
        self.rules_version = str(self.rules.get("rules_version") or "")
        if not self.rules_version:
            raise ValueError("preprocessing rules_version is required")
        normalization = str(self.rules.get("unicode_normalization") or "NFC")
        if normalization not in {"NFC", "NFD", "NFKC", "NFKD"}:
            raise ValueError("unsupported Unicode normalization form")
        self.normalization = normalization
        patterns = self.rules.get("boilerplate_patterns")
        if not isinstance(patterns, list) or not all(isinstance(item, str) for item in patterns):
            raise ValueError("boilerplate_patterns must be a list of strings")
        self.boilerplate_patterns = tuple(re.compile(item) for item in patterns)
        self.preserve_fenced_code = bool(self.rules.get("preserve_fenced_code_blocks", True))
        self.rules_hash = sha256_json(self.rules)
        self.cleaner = cleaner or TextCleaner()

    def process(self, text: str | None) -> PreprocessingResult:
        original = "" if text is None else str(text)
        normalized = unicodedata.normalize(self.normalization, original.replace("\r\n", "\n").replace("\r", "\n"))
        normalized = self._remove_invisible_controls(normalized)
        normalized = html.unescape(normalized)
        normalized = self._strip_html_remnants(normalized)

        output_lines: list[str] = []
        in_code_block = False
        removed = 0
        for raw_line in normalized.split("\n"):
            if self.preserve_fenced_code and raw_line.lstrip().startswith("```"):
                in_code_block = not in_code_block
                output_lines.append(raw_line.rstrip())
                continue
            if in_code_block:
                output_lines.append(raw_line.rstrip())
                continue

            line = self.cleaner.clean(raw_line)
            if line and any(pattern.search(line) for pattern in self.boilerplate_patterns):
                removed += 1
                continue
            output_lines.append(SPACE_RE.sub(" ", line).strip())

        cleaned = self._collapse_blank_lines(output_lines)
        return PreprocessingResult(
            text=cleaned,
            input_hash=sha256_text(original),
            output_hash=sha256_text(cleaned),
            rules_hash=self.rules_hash,
            rules_version=self.rules_version,
            removed_boilerplate_lines=removed,
        )

    @staticmethod
    def _remove_invisible_controls(value: str) -> str:
        preserved = {"\n", "\t"}
        return "".join(
            character
            for character in value
            if character in preserved or unicodedata.category(character) not in {"Cc", "Cf"}
        )

    @staticmethod
    def _strip_html_remnants(value: str) -> str:
        if not HTML_TAG_RE.search(value):
            return value
        soup = BeautifulSoup(value, "lxml")
        for comment in soup.find_all(string=lambda item: isinstance(item, Comment)):
            comment.extract()
        for element in soup.find_all(["script", "style", "noscript", "template"]):
            element.decompose()
        for break_tag in soup.find_all("br"):
            break_tag.replace_with("\n")
        for block in soup.find_all(["p", "div", "article", "section", "h1", "h2", "h3", "li", "pre", "blockquote"]):
            block.append("\n")
        return soup.get_text()

    @staticmethod
    def _collapse_blank_lines(lines: list[str]) -> str:
        output: list[str] = []
        previous_blank = True
        for line in lines:
            blank = not line.strip()
            if blank and previous_blank:
                continue
            output.append(line)
            previous_blank = blank
        while output and not output[-1].strip():
            output.pop()
        return "\n".join(output).strip()
