from __future__ import annotations

import unittest
from pathlib import Path

from backend.app.pipeline.ingestion.external.common.hashing import sha256_text
from backend.app.pipeline.ingestion.external.privacy.privacy_filter import PrivacyFilter


ROOT = Path(__file__).resolve().parents[3]
RULES = ROOT / "config" / "privacy_rules.json"


class PrivacyFilterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.filter = PrivacyFilter(RULES)

    def test_redacts_high_confidence_secret_and_phone_without_audit_value(self) -> None:
        secret = "AKIAABCDEFGHIJKLMNOP"
        phone = "+1 202-555-0142"
        text = f"Leaked credential {secret}. Personal phone: {phone}."
        result = self.filter.apply(text)
        serialized = result.to_dict()
        self.assertNotIn(secret, result.content)
        self.assertNotIn(phone, result.content)
        self.assertIn("[REDACTED:possible_api_token]", result.content)
        self.assertIn("[REDACTED:phone_number]", result.content)
        self.assertEqual(result.metadata["privacy"]["redactions_count"], 2)
        self.assertNotIn(secret, str(result.metadata))
        self.assertNotIn(secret, str(serialized["findings"]))
        self.assertEqual(result.output_hash, sha256_text(result.content))

    def test_preserves_cti_indicators(self) -> None:
        values = [
            "CVE-2026-12345",
            "https://evil.example/callback",
            "203.0.113.42",
            "d41d8cd98f00b204e9800998ecf8427e",
            "sender@evil.example",
        ]
        text = "Observed malicious indicators and phishing sender: " + " ".join(values)
        result = self.filter.apply(text)
        for value in values:
            self.assertIn(value, result.content)
        preserved = result.metadata["privacy"]["cti_value_types_preserved"]
        self.assertTrue({"cve", "url", "ipv4", "hash", "email"}.issubset(set(preserved)))
        self.assertEqual(result.metadata["privacy"]["redactions_count"], 0)

    def test_ambiguous_email_and_username_require_review_without_redaction(self) -> None:
        text = "The document mentions person@example.test and @unverified_handle without context."
        result = self.filter.apply(text)
        self.assertEqual(result.status, "review_required")
        self.assertEqual(result.content, text)
        self.assertEqual(result.metadata["privacy"]["finding_categories"]["unknown"], 2)

    def test_public_attribution_email_is_preserved(self) -> None:
        text = "Security researcher contact: analyst@example.test"
        result = self.filter.apply(text)
        self.assertEqual(result.status, "reviewed")
        self.assertIn("analyst@example.test", result.content)
        self.assertEqual(result.metadata["privacy"]["finding_categories"]["public_attribution"], 1)

    def test_clean_and_privacy_hashes_remain_distinct(self) -> None:
        text = "Personal phone: +1 202-555-0142"
        result = self.filter.apply(text)
        self.assertEqual(result.input_hash, sha256_text(text))
        self.assertNotEqual(result.input_hash, result.output_hash)
        self.assertRegex(result.rules_hash, r"^sha256:[a-f0-9]{64}$")
        self.assertRegex(result.stage_hash, r"^sha256:[a-f0-9]{64}$")


if __name__ == "__main__":
    unittest.main()
