from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend.app.pipeline.ingestion.external.classification.classification_service import ClassificationService
from backend.app.pipeline.ingestion.external.classification.classifier import (
    MODEL_PATH,
    MODEL_SHA256,
    MODEL_VERSION,
    ClassificationResult,
    CTIRelevanceClassifier,
    preprocess_for_model,
)
from backend.app.pipeline.ingestion.external.common.hashing import sha256_text
from backend.app.pipeline.ingestion.external.common.models import ExternalCTIItem, ExternalClassification


APPROVED_MODEL_SHA256 = "0e929dfebd36c46498047a6f93d3b5d08ba9aad81d48f8f3f68070c6e21d7d8c"


def item(*, source_type: str = "manual", status: str = "not_run", content: str | None = None) -> ExternalCTIItem:
    text = content or (
        "A detailed public report describes activity affecting several systems, "
        "including technical evidence and remediation information for administrators."
    )
    return ExternalCTIItem(
        record_id="classification-test-record-001",
        source="Sanitized fixture",
        source_type=source_type,
        category="general",
        title="Sanitized report",
        link="https://example.test/report",
        content=text,
        summary="",
        collected_at="2026-08-23T12:00:00Z",
        content_hash=sha256_text(text),
        classification=ExternalClassification(status=status),
    )


class FakeModel:
    def __init__(self, prediction=1, error: Exception | None = None) -> None:
        self.prediction = prediction
        self.error = error
        self.inputs = []

    def predict(self, values):
        self.inputs.append(values)
        if self.error:
            raise self.error
        return [self.prediction]


class ClassificationTests(unittest.TestCase):
    def setUp(self) -> None:
        CTIRelevanceClassifier.clear_cache_for_tests()

    def tearDown(self) -> None:
        CTIRelevanceClassifier.clear_cache_for_tests()

    def test_canonical_model_matches_approved_immutable_hash(self) -> None:
        canonical_hash = hashlib.sha256(MODEL_PATH.read_bytes()).hexdigest()
        self.assertEqual(canonical_hash, APPROVED_MODEL_SHA256)
        self.assertEqual(canonical_hash, MODEL_SHA256)
        self.assertEqual(MODEL_VERSION, f"cti-svm-sha256:{MODEL_SHA256}")

    def test_training_preprocessing_parity_for_varied_examples(self) -> None:
        examples = {
            "CVE-2026-12345 reached 8.8.8.8": "specifiedcve reached specifiedip",
            "Mixed CASE and CVE-1999-0001": "mixed case and specifiedcve",
            "Invalid CVE-26-1 and 999.999.999.999": "invalid cve-26-1 and specifiedip",
            "No indicators — Café": "no indicators — café",
        }
        for source, expected in examples.items():
            with self.subTest(source=source):
                self.assertEqual(preprocess_for_model(source), expected)

    def test_model_is_loaded_once_and_label_mapping_is_exact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "model.pkl"
            path.write_bytes(b"test placeholder; mocked loader")
            model = FakeModel(1)
            with patch("joblib.load", return_value=model) as loader:
                classifier = CTIRelevanceClassifier(path, minimum_characters=1)
                first = classifier.classify("CVE-2026-12345 contacted 8.8.8.8")
                second = classifier.classify("A second sufficiently detailed security report")

        self.assertEqual(loader.call_count, 1)
        self.assertEqual(first.status, "accepted")
        self.assertEqual(first.label, "cti_related")
        self.assertIsNone(first.score)
        self.assertEqual(model.inputs[0], ["specifiedcve contacted specifiedip"])
        self.assertEqual(second.status, "accepted")

    def test_empty_short_missing_and_prediction_failure_route_safely(self) -> None:
        classifier = CTIRelevanceClassifier(Path("missing-model.pkl"))
        self.assertEqual(classifier.classify("").status, "not_run")
        self.assertEqual(classifier.classify("short text").error_category, "short_input")
        missing = classifier.classify("x" * 100)
        self.assertEqual((missing.status, missing.error_category), ("error", "model_missing"))

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "model.pkl"
            path.write_bytes(b"test placeholder; mocked loader")
            with patch("joblib.load", return_value=FakeModel(error=RuntimeError("safe"))):
                failed = CTIRelevanceClassifier(path, minimum_characters=1).classify("long enough")
        self.assertEqual((failed.status, failed.error_category), ("error", "prediction_failed"))

    def test_service_bypasses_all_trusted_types_without_invoking_model(self) -> None:
        class MustNotRun:
            def classify(self, text):
                raise AssertionError("trusted source reached classifier")

        service = ClassificationService(MustNotRun())
        for source_type in ("rss", "cert", "nvd", "cve", "mitre", "github_advisories", "cisa_kev", "vulnerability"):
            with self.subTest(source_type=source_type):
                result = service.classify_item(item(source_type=source_type))
                self.assertEqual(result.disposition, "accepted")
                self.assertEqual(result.item.classification.status, "not_required")

    def test_service_routes_general_source_results_without_silent_acceptance(self) -> None:
        class StubClassifier:
            def __init__(self, status): self.status = status
            def classify(self, text):
                label = "cti_related" if self.status == "accepted" else "not_cti_related" if self.status == "rejected" else None
                return ClassificationResult(self.status, label, None, MODEL_VERSION, MODEL_SHA256, "prediction_failed" if self.status == "error" else None)

        accepted = ClassificationService(StubClassifier("accepted")).classify_item(item())
        rejected = ClassificationService(StubClassifier("rejected")).classify_item(item())
        failed = ClassificationService(StubClassifier("error")).classify_item(item())
        self.assertEqual((accepted.disposition, rejected.disposition, failed.disposition), ("accepted", "rejected", "review"))
        self.assertEqual(failed.review_reason, "prediction_failed")
        self.assertEqual(failed.item.classification.status, "error")
        self.assertEqual(failed.item.metadata["classification_stage"]["model_sha256"], MODEL_SHA256)

    def test_approved_model_reproduces_representative_predictions(self) -> None:
        classifier = CTIRelevanceClassifier()
        cti = (
            "A critical remote code execution vulnerability CVE-2024-1234 was disclosed today affecting a widely "
            "deployed VPN appliance, allowing unauthenticated attackers to execute arbitrary code on affected systems."
        )
        non_cti = (
            "The stock market rallied today as major technology companies reported strong quarterly earnings that "
            "beat analyst expectations across the board, sending the Nasdaq composite index to its best single-day "
            "performance in months."
        )
        self.assertEqual(classifier.classify(cti).status, "accepted")
        self.assertEqual(classifier.classify(non_cti).status, "rejected")


if __name__ == "__main__":
    unittest.main()
