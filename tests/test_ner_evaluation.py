from __future__ import annotations

import unittest

from ml.common.dnrti import BioSplit, audit_split_integrity, unique_unseen_split
from ml.common.metrics import detailed_entity_metrics, entity_metrics_by_type
from ml.evaluation.compare_ner_runtimes import compare
from ml.evaluation.compare_clean_ner_models import compare as compare_clean_models
from ml.preprocessing.clean_dnrti import build_clean_splits


class NEREvaluationTests(unittest.TestCase):
    def test_clean_model_comparison_requires_micro_and_macro_improvement(self) -> None:
        current = {
            "metrics": {
                "micro": {
                    "entity_precision": 0.75,
                    "entity_recall": 0.75,
                    "entity_f1": 0.75,
                },
                "macro": {"entity_macro_f1": 0.60},
                "token_accuracy": 0.93,
            }
        }

        def candidate(micro_f1: float, macro_f1: float) -> dict[str, object]:
            return {
                "eval_precision": micro_f1,
                "eval_recall": micro_f1,
                "eval_f1": micro_f1,
                "eval_macro_f1": macro_f1,
                "eval_accuracy": 0.94,
            }

        result = compare_clean_models(
            {
                "current": current,
                "clean_v1_stage1": candidate(0.76, 0.59),
                "clean_v1_stage2": candidate(0.755, 0.61),
            }
        )

        self.assertEqual(result["selected_model"], "clean_v1_stage2")
        self.assertFalse(result["variants"]["clean_v1_stage1"]["activation_gate_passed"])
        self.assertTrue(result["variants"]["clean_v1_stage2"]["activation_gate_passed"])

    def test_clean_splits_remove_conflicts_duplicates_and_cross_split_leakage(self) -> None:
        source = {
            "train": BioSplit(
                "train",
                [["APT28"], ["APT28"], ["Conflict"]],
                [["B-HackOrg"], ["B-HackOrg"], ["B-Org"]],
                1,
                [],
                1,
            ),
            "valid": BioSplit(
                "valid",
                [["APT28"], ["ValidOnly"]],
                [["B-HackOrg"], ["B-Tool"]],
                0,
                [],
            ),
            "test": BioSplit(
                "test",
                [["Conflict"], ["TestOnly"]],
                [["B-Tool"], ["O"]],
                0,
                [],
            ),
        }

        cleaned, report = build_clean_splits(source)

        self.assertEqual(cleaned["train"].tokens, [["APT28"]])
        self.assertEqual(cleaned["valid"].tokens, [["ValidOnly"]])
        self.assertEqual(cleaned["test"].tokens, [["TestOnly"]])
        self.assertEqual(report["grouping"]["conflicting_text_groups_excluded"], 1)
        self.assertEqual(report["grouping"]["duplicate_occurrences_removed"], 2)
        self.assertTrue(report["integrity"]["all_quality_gates_passed"])

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
