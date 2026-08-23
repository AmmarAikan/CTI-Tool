from __future__ import annotations

import unittest
from pathlib import Path

from backend.app.pipeline.ingestion.external.preprocessing.content_processor import ExternalContentProcessor
from backend.app.pipeline.ingestion.external.preprocessing.text_preprocessor import TextPreprocessor
from backend.app.pipeline.ingestion.external.privacy.privacy_filter import PrivacyFilter


ROOT = Path(__file__).resolve().parents[3]


class ContentProcessingTests(unittest.TestCase):
    def test_cleaning_always_precedes_privacy_and_stage_hashes_are_linked(self) -> None:
        processor = ExternalContentProcessor(
            TextPreprocessor(ROOT / "config" / "preprocessing_rules.json"),
            PrivacyFilter(ROOT / "config" / "privacy_rules.json"),
        )
        source = "<p>Incident details</p>\nSubscribe to our newsletter today\nPersonal phone: +1 202-555-0142"
        result = processor.process(source)
        self.assertNotIn("Subscribe", result.cleaned_content)
        self.assertIn("+1 202-555-0142", result.cleaned_content)
        self.assertNotIn("+1 202-555-0142", result.export_content)
        self.assertEqual(result.preprocessing.output_hash, result.privacy.input_hash)
        self.assertEqual(result.metadata["processing"]["privacy_output_hash"], result.privacy.output_hash)


if __name__ == "__main__":
    unittest.main()
