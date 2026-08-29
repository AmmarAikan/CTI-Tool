from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from backend.app.pipeline.ingestion.external.common.hashing import sha256_text
from backend.app.pipeline.ingestion.external.preprocessing.text_preprocessor import TextPreprocessor


ROOT = Path(__file__).resolve().parents[3]
FIXTURES = ROOT / "tests" / "external_sources" / "fixtures"
RULES = ROOT / "config" / "preprocessing_rules.json"


class TextPreprocessorTests(unittest.TestCase):
    def test_cleans_html_boilerplate_and_controls_without_altering_iocs(self) -> None:
        source = (FIXTURES / "preprocessing_input.txt").read_text(encoding="utf-8") + "\u200b\x00"
        result = TextPreprocessor(RULES).process(source)
        self.assertIn("CVE-2026-12345", result.text)
        self.assertIn("https://evil.example/path?q=1", result.text)
        self.assertIn("203.0.113.42", result.text)
        self.assertIn("a" * 64, result.text)
        self.assertNotIn("Share this article", result.text)
        self.assertNotIn("Subscribe to our newsletter", result.text)
        self.assertNotIn("Copyright 2026", result.text)
        self.assertNotIn("<article>", result.text)
        self.assertNotIn("\u200b", result.text)
        self.assertNotIn("\x00", result.text)
        self.assertEqual(result.input_hash, sha256_text(source))
        self.assertEqual(result.output_hash, sha256_text(result.text))
        self.assertGreaterEqual(result.removed_boilerplate_lines, 3)

    def test_preserves_paragraphs_and_fenced_code_spacing(self) -> None:
        source = "Heading\n\nFirst   paragraph.\n\n```text\n  key =  value\n```\n\nSecond paragraph."
        result = TextPreprocessor(RULES).process(source)
        self.assertIn("Heading\n\nFirst paragraph.", result.text)
        self.assertIn("```text\n  key =  value\n```", result.text)
        self.assertIn("\n\nSecond paragraph.", result.text)

    def test_rule_change_invalidates_rules_and_stage_hashes(self) -> None:
        original = json.loads(RULES.read_text(encoding="utf-8"))
        changed = dict(original)
        changed["rules_version"] = "1.1"
        changed["boilerplate_patterns"] = [*original["boilerplate_patterns"], "(?i)^remove me$"]
        with tempfile.TemporaryDirectory() as directory:
            changed_path = Path(directory) / "rules.json"
            changed_path.write_text(json.dumps(changed), encoding="utf-8")
            first = TextPreprocessor(RULES).process("Keep me")
            second = TextPreprocessor(changed_path).process("Keep me")
        self.assertNotEqual(first.rules_hash, second.rules_hash)
        self.assertNotEqual(first.stage_hash, second.stage_hash)

    def test_repeated_processing_is_deterministic(self) -> None:
        preprocessor = TextPreprocessor(RULES)
        first = preprocessor.process("Alpha\r\n\r\nBeta &amp; Gamma")
        second = preprocessor.process("Alpha\r\n\r\nBeta &amp; Gamma")
        self.assertEqual(first, second)

    def test_truncates_configured_trailing_boilerplate_and_keeps_article_substantial(self) -> None:
        source = (FIXTURES / "cpu_article_with_trailing_boilerplate.txt").read_text(encoding="utf-8")
        result = TextPreprocessor(RULES).process(source)
        self.assertIn("CPU diagnostic evidence", result.text)
        self.assertIn("References", result.text)
        self.assertIn("CVE-2026-12345", result.text)
        self.assertNotIn("Recent Posts", result.text)
        self.assertNotIn("Want more?", result.text)
        self.assertNotIn("Unrelated story card", result.text)
        self.assertGreater(len(result.text), 300)
        self.assertGreaterEqual(result.removed_boilerplate_lines, 1)


if __name__ == "__main__":
    unittest.main()
