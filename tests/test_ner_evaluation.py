from __future__ import annotations

import unittest

from ml.common.dnrti import BioSplit, audit_split_integrity, unique_unseen_split
from ml.common.metrics import detailed_entity_metrics, entity_metrics_by_type
from ml.evaluation.compare_ner_runtimes import compare


class NEREvaluationTests(unittest.TestCase):
    def test_runtime_comparison_requires_quality_and_speed_gates(self) -> None:
        def report(f1: float, samples_per_second: float) -> dict[str, object]:
            return {
                "scope": "unseen",
                "evaluated_sentences": 10,
                "runtime": "test",
                "model_name": "model",
                "runtime_seconds": 1.0,
                "samples_per_second": samples_per_second,
                "metrics": {
                    "micro": {
                        "entity_f1": f1,
                        "entity_precision": f1,
                        "entity_recall": f1,
                    }
                },
            }

        result = compare(
            {
                "pytorch": report(0.75, 10.0),
                "onnx_fp32": report(0.75, 13.0),
                "onnx_int8": report(0.742, 16.0),
            },
            maximum_f1_drop=0.01,
            minimum_speedup=1.5,
        )

        self.assertEqual(result["selected_runtime"], "onnx_int8")
        self.assertFalse(result["variants"]["onnx_fp32"]["activation_gate_passed"])
        self.assertTrue(result["variants"]["onnx_int8"]["activation_gate_passed"])

    def test_integrity_audit_detects_leakage_duplicates_and_conflicts(self) -> None:
        splits = {
            "train": BioSplit(
                "train",
                [["APT28"], ["APT28"], ["X-Agent"]],
                [["B-HackOrg"], ["B-Org"], ["B-Tool"]],
                1,
                [],
            ),
            "valid": BioSplit("valid", [["Other"]], [["O"]], 0, []),
            "test": BioSplit(
                "test",
                [["APT28"], ["Novel"], ["Novel"]],
                [["B-HackOrg"], ["B-Tool"], ["B-Tool"]],
                0,
                [],
            ),
        }

        report = audit_split_integrity(splits)

        self.assertEqual(report["splits"]["train"]["duplicate_rows"], 1)
        self.assertEqual(
            report["splits"]["train"]["texts_with_conflicting_label_sequences"], 1
        )
        self.assertEqual(
            report["cross_split_overlaps"]["train_test"]["shared_unique_sentences"], 1
        )
        self.assertFalse(report["all_quality_gates_passed"])
        self.assertEqual(unique_unseen_split(splits).tokens, [["Novel"]])

    def test_detailed_metrics_report_exact_span_per_type_and_macro(self) -> None:
        truth = [["B-HackOrg", "O", "B-Tool", "I-Tool"]]
        predictions = [["B-HackOrg", "O", "B-Tool", "O"]]

        per_type = entity_metrics_by_type(truth, predictions)
        detailed = detailed_entity_metrics(truth, predictions)

        self.assertEqual(per_type["HackOrg"]["f1"], 1.0)
        self.assertEqual(per_type["Tool"]["f1"], 0.0)
        self.assertEqual(detailed["micro"]["entity_true_positives"], 1)
        self.assertEqual(detailed["macro"]["entity_types_with_support"], 2)
        self.assertAlmostEqual(detailed["macro"]["entity_macro_f1"], 0.5)


if __name__ == "__main__":
    unittest.main()
