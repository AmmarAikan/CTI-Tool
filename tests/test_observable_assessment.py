from __future__ import annotations

import unittest
from types import SimpleNamespace

from backend.app.pipeline.enrichment.observable_assessor import ObservableAssessor
from backend.app.pipeline.extraction.ioc_extractor import IoCExtractor
from backend.app.services.attack_mapping_service import AttackMappingService


def item(value_type: str, value: str, enrichments=None):
    return SimpleNamespace(
        indicator_type=value_type,
        value=value,
        enrichments=enrichments or [],
    )


class ObservableAssessmentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.assessor = ObservableAssessor()

    def test_reference_url_and_cve_are_not_malicious_indicators(self) -> None:
        url = self.assessor.assess(item("url", "https://nvd.nist.gov/vuln/detail/CVE-2026-1234"))
        cve = self.assessor.assess(item("cve", "CVE-2026-1234"))
        self.assertEqual((url.semantic_role, url.assessment, url.actionable), ("external_reference", "reference", False))
        self.assertEqual((cve.semantic_role, cve.assessment, cve.actionable), ("vulnerability", "reference", False))

    def test_all_supported_types_are_validated_conservatively(self) -> None:
        values = {
            "domain": "malware.example.com",
            "email": "actor@example.com",
            "md5": "a" * 32,
            "sha1": "b" * 40,
            "sha256": "c" * 64,
            "ipv4": "8.8.8.8",
            "ipv6": "2606:4700:4700::1111",
            "asn": "AS13335",
            "mac": "00:11:22:33:44:55",
        }
        for value_type, value in values.items():
            with self.subTest(value_type=value_type):
                result = self.assessor.assess(item(value_type, value))
                self.assertEqual(result.validation_status, "valid")
                self.assertNotIn(result.assessment, {"malicious", "suspicious"})

    def test_non_global_ip_is_non_actionable(self) -> None:
        result = self.assessor.assess(item("ipv4", "203.0.113.7"))
        self.assertEqual(result.assessment, "non_actionable")
        self.assertEqual(result.reason_code, "non_global_ip")
        local_url = self.assessor.assess(item("url", "http://127.0.0.1:6808/status"))
        self.assertEqual(local_url.assessment, "non_actionable")
        self.assertEqual(local_url.reason_code, "non_global_url_host")

    def test_explicit_enrichment_verdict_is_required_for_promotion(self) -> None:
        enrichment = SimpleNamespace(provider="TEST", status="success", data={"verdict": "malicious"})
        result = self.assessor.assess(item("domain", "evil.example.com", [enrichment]))
        self.assertEqual(result.semantic_role, "indicator")
        self.assertEqual(result.assessment, "malicious")
        self.assertTrue(result.actionable)

    def test_hash_inside_url_is_reference_and_future_extraction_drops_overlap(self) -> None:
        digest = "a" * 40
        url = item("url", f"https://github.com/example/project/commit/{digest}")
        digest_item = item("sha1", digest)
        event = SimpleNamespace(indicators=[url, digest_item])
        result = self.assessor.assess(digest_item, event)
        self.assertEqual(result.reason_code, "embedded_in_url")
        extracted = IoCExtractor().extract(f"See https://github.com/example/project/commit/{digest}")
        self.assertEqual([entry.type for entry in extracted], ["url"])

    def test_invalid_values_are_visible_but_not_actionable(self) -> None:
        result = self.assessor.assess(item("sha256", "not-a-hash"))
        self.assertEqual(result.validation_status, "invalid")
        self.assertFalse(result.actionable)


class AttackMappingTests(unittest.TestCase):
    def test_explicit_id_wins_over_rule_candidate(self) -> None:
        event = SimpleNamespace(title="T1059.001", summary="PowerShell execution", normalized_text="")
        result = AttackMappingService().map_event(event)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["technique_id"], "T1059.001")
        self.assertEqual(result[0]["mapping_source"], "explicit_id")

    def test_rule_mapping_is_labeled_candidate_with_evidence(self) -> None:
        event = SimpleNamespace(title="Incident", summary="Mimikatz performed credential dumping", normalized_text="")
        result = AttackMappingService().map_event(event)
        self.assertEqual(result[0]["technique_id"], "T1003")
        self.assertEqual(result[0]["mapping_source"], "rule_based_candidate")
        self.assertTrue(result[0]["evidence"])


if __name__ == "__main__":
    unittest.main()
