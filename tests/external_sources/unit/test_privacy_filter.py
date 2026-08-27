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

    def test_preserves_technical_numbers_and_records_their_types(self) -> None:
        text = """CPU MHz: 3192.004
processor : 12
processor id: 0000-00A1
microcode : 0x2f
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
port 9050
203.0.113.42
d41d8cd98f00b204e9800998ecf8427e
CVE-2026-12345"""
        result = self.filter.apply(text)
        self.assertEqual(result.content, text)
        self.assertNotIn("[REDACTED:phone_number]", result.content)
        preserved = set(result.metadata["privacy"]["cti_value_types_preserved"])
        self.assertTrue({"diagnostic_output", "processor_hardware_id", "cvss_value", "network_port",
                         "ipv4", "hash", "cve"}.issubset(preserved))

    def test_genuine_phone_is_redacted_but_uncontextual_number_is_not(self) -> None:
        text = "Personal phone: +1 202-555-0142. Diagnostic counter 12345678."
        result = self.filter.apply(text)
        self.assertIn("[REDACTED:phone_number]", result.content)
        self.assertIn("Diagnostic counter 12345678", result.content)
        self.assertEqual(result.metadata["privacy"]["redactions_count"], 1)

    def test_disclosure_timeline_dates_are_not_phone_numbers(self) -> None:
        values = (
            "June 10",
            "June 10-18",
            "June 20, 2021",
            "December 1-28 2021",
            "2020-2021",
        )
        text = "Disclosure timeline\n" + "\n".join(values)
        result = self.filter.apply(text)
        self.assertEqual(result.content, text)
        self.assertNotIn("[REDACTED:phone_number]", result.content)
        self.assertEqual(result.metadata["privacy"]["redactions_count"], 0)
        self.assertTrue({"calendar_date", "year_range"}.issubset(
            set(result.metadata["privacy"]["cti_value_types_preserved"])))

    def test_international_and_contextual_local_phone_numbers_are_redacted(self) -> None:
        international = "+44 20 7946 0958"
        local = "202-555-0142"
        text = f"Emergency line: {international}. Contact phone: {local}."
        result = self.filter.apply(text)
        self.assertNotIn(international, result.content)
        self.assertNotIn(local, result.content)
        self.assertEqual(result.content.count("[REDACTED:phone_number]"), 2)
        self.assertEqual(result.metadata["privacy"]["redactions_count"], 2)

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

    def test_attacker_email_indicators_are_preserved_but_personal_email_is_reviewed(self) -> None:
        attacker = self.filter.apply(
            "IOC table: attacker email used to register attacker infrastructure: operator@bad.example"
        )
        self.assertEqual(attacker.status, "reviewed")
        self.assertIn("operator@bad.example", attacker.content)
        self.assertIn("email", attacker.metadata["privacy"]["cti_value_types_preserved"])
        personal = self.filter.apply("Meeting attendee address: person@example.test")
        self.assertEqual(personal.status, "review_required")

    def test_python_decorators_are_technical_but_social_handles_remain_ambiguous(self) -> None:
        code = "import functions_framework\n@functions_framework.http\ndef handler(request):\n    return 'ok'"
        result = self.filter.apply(code)
        self.assertEqual(result.status, "reviewed")
        self.assertIn("@functions_framework.http", result.content)
        self.assertIn("programming_decorator", result.metadata["privacy"]["cti_value_types_preserved"])
        social = self.filter.apply("The public profile uses @security_researcher.")
        self.assertEqual(social.status, "review_required")

    def test_clean_and_privacy_hashes_remain_distinct(self) -> None:
        text = "Personal phone: +1 202-555-0142"
        result = self.filter.apply(text)
        self.assertEqual(result.input_hash, sha256_text(text))
        self.assertNotEqual(result.input_hash, result.output_hash)
        self.assertRegex(result.rules_hash, r"^sha256:[a-f0-9]{64}$")
        self.assertRegex(result.stage_hash, r"^sha256:[a-f0-9]{64}$")


if __name__ == "__main__":
    unittest.main()
