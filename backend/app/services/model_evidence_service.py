from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from backend.app.pipeline.extraction.ner_extractor import (
    ROOT,
    get_runtime_ner_extractor,
)


class ModelEvidenceService:
    """Expose reproducible local evidence without publishing model files or paths."""

    BERT_REPORT = ROOT / "ml/reports/ner_test_metrics.json"
    BERT_UNSEEN_REPORT = ROOT / "ml/reports/ner_unseen_test_metrics.json"
    INTEGRITY_REPORT = ROOT / "ml/reports/dnrti_integrity_report.json"
    SKLEARN_REPORT = ROOT / "ml/reports/sklearn_ner_metrics.json"
    BERT_MODEL = ROOT / "ml/models/dnrti_bert_ner/model.safetensors"
    SKLEARN_MODEL = ROOT / "ml/models/dnrti_sklearn_ner/model.joblib"

    @classmethod
    def status(cls) -> dict[str, Any]:
        bert_metrics = cls._read_json(cls.BERT_REPORT)
        unseen_report = cls._read_json(cls.BERT_UNSEEN_REPORT)
        integrity_report = cls._read_json(cls.INTEGRITY_REPORT)
        sklearn_metrics = cls._read_json(cls.SKLEARN_REPORT)
        sklearn_test = sklearn_metrics.get("test", {}) if isinstance(sklearn_metrics, dict) else {}

        bert_f1 = cls._number(bert_metrics.get("eval_f1"))
        bert_accuracy = cls._number(bert_metrics.get("eval_accuracy"))
        sklearn_f1 = cls._number(sklearn_test.get("entity_f1"))
        unseen_metrics = unseen_report.get("metrics", {}) if isinstance(unseen_report, dict) else {}
        unseen_micro = unseen_metrics.get("micro", {}) if isinstance(unseen_metrics, dict) else {}
        unseen_macro = unseen_metrics.get("macro", {}) if isinstance(unseen_metrics, dict) else {}
        unseen_f1 = cls._number(unseen_micro.get("entity_f1"))
        integrity_gates = (
            integrity_report.get("quality_gates", {})
            if isinstance(integrity_report, dict)
            else {}
        )
        quality_gates = {
            "bert_artifact_present": cls.BERT_MODEL.is_file(),
            "secondary_artifact_present": cls.SKLEARN_MODEL.is_file(),
            "bert_test_f1_at_least_0_75": bert_f1 is not None and bert_f1 >= 0.75,
            "bert_test_accuracy_at_least_0_90": (
                bert_accuracy is not None and bert_accuracy >= 0.90
            ),
            "primary_outperforms_secondary_entity_f1": (
                bert_f1 is not None and sklearn_f1 is not None and bert_f1 > sklearn_f1
            ),
            "bert_unique_unseen_f1_at_least_0_73": (
                unseen_f1 is not None and unseen_f1 >= 0.73
            ),
            "dataset_cross_split_overlap_zero": (
                integrity_gates.get("cross_split_overlap_zero") is True
            ),
            "dataset_label_conflicts_zero": (
                integrity_gates.get("within_split_label_conflicts_zero") is True
            ),
            "dataset_malformed_lines_zero": (
                integrity_gates.get("malformed_lines_zero") is True
            ),
        }
        return {
            "runtime": get_runtime_ner_extractor().diagnostics(),
            "model_priority": {
                "primary": "dnrti_bert_ner",
                "secondary_fallback": "dnrti_sklearn_ner",
            },
            "held_out_test": {
                "bert": {
                    "precision": cls._number(bert_metrics.get("eval_precision")),
                    "recall": cls._number(bert_metrics.get("eval_recall")),
                    "f1": bert_f1,
                    "accuracy": bert_accuracy,
                    "reported_epoch": cls._number(bert_metrics.get("epoch")),
                },
                "sklearn_secondary": {
                    "entity_precision": cls._number(sklearn_test.get("entity_precision")),
                    "entity_recall": cls._number(sklearn_test.get("entity_recall")),
                    "entity_f1": sklearn_f1,
                    "token_accuracy": cls._number(sklearn_test.get("token_accuracy")),
                },
                "bert_unique_unseen": {
                    "precision": cls._number(unseen_micro.get("entity_precision")),
                    "recall": cls._number(unseen_micro.get("entity_recall")),
                    "f1": unseen_f1,
                    "macro_f1": cls._number(unseen_macro.get("entity_macro_f1")),
                    "token_accuracy": cls._number(unseen_metrics.get("token_accuracy")),
                    "evaluated_sentences": unseen_report.get("evaluated_sentences"),
                },
            },
            "dataset_integrity": {
                "unique_unseen_test_sentences": integrity_report.get(
                    "unique_unseen_test_sentences"
                ),
                "quality_gates": integrity_gates,
            },
            "quality_gates": quality_gates,
            "all_quality_gates_passed": all(quality_gates.values()),
            "metric_scope": (
                "saved DNRTI reports include the original split and a unique test subset "
                "absent from train; neither is live production accuracy"
            ),
        }

    @staticmethod
    def _read_json(path: Path) -> dict[str, Any]:
        if not path.is_file():
            return {}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    @staticmethod
    def _number(value: object) -> float | None:
        try:
            return float(value) if value is not None else None
        except (TypeError, ValueError):
            return None
