from __future__ import annotations

import unittest
from pathlib import Path

from backend.app.pipeline.ingestion.external.preprocessing.content_processor import ExternalContentProcessor
from backend.app.pipeline.ingestion.external.preprocessing.text_preprocessor import TextPreprocessor
from backend.app.pipeline.ingestion.external.privacy.privacy_filter import PrivacyFilter


ROOT = Path(__file__).resolve().parents[3]


class ContentProcessingTests(unittest.TestCase):
    @staticmethod
    def processor() -> ExternalContentProcessor:
        return ExternalContentProcessor(
            TextPreprocessor(ROOT / "config" / "preprocessing_rules.json"),
            PrivacyFilter(ROOT / "config" / "privacy_rules.json"),
        )

    def test_cleaning_always_precedes_privacy_and_stage_hashes_are_linked(self) -> None:
        processor = self.processor()
        source = "<p>Incident details</p>\nSubscribe to our newsletter today\nPersonal phone: +1 202-555-0142"
        result = processor.process(source)
        self.assertNotIn("Subscribe", result.cleaned_content)
        self.assertIn("+1 202-555-0142", result.cleaned_content)
        self.assertNotIn("+1 202-555-0142", result.export_content)
        self.assertEqual(result.preprocessing.output_hash, result.privacy.input_hash)
        self.assertEqual(result.metadata["processing"]["privacy_output_hash"], result.privacy.output_hash)

    def test_cpu_article_uses_shared_cleanup_and_technical_privacy_policy(self) -> None:
        source = (ROOT / "tests" / "external_sources" / "fixtures" /
                  "cpu_article_with_trailing_boilerplate.txt").read_text(encoding="utf-8")
        result = self.processor().process(source)
        self.assertNotIn("Recent Posts", result.export_content)
        self.assertNotIn("Want more?", result.export_content)
        self.assertIn("cpu MHz : 3192.004", result.export_content)
        self.assertIn("processor id: 0000-00A1", result.export_content)
        self.assertNotIn("[REDACTED:phone_number]", result.export_content)
        preserved = set(result.metadata["privacy"]["cti_value_types_preserved"])
        self.assertTrue({"diagnostic_output", "processor_hardware_id", "cvss_value",
                         "network_port", "ipv4", "hash", "cve"}.issubset(preserved))
        self.assertGreater(len(result.export_content), 300)


if __name__ == "__main__":
    unittest.main()
