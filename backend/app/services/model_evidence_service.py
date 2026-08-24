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
    SKLEARN_REPORT = ROOT / "ml/reports/sklearn_ner_metrics.json"
    BERT_MODEL = ROOT / "ml/models/dnrti_bert_ner/model.safetensors"
    SKLEARN_MODEL = ROOT / "ml/models/dnrti_sklearn_ner/model.joblib"

    @classmethod
    def status(cls) -> dict[str, Any]:
        bert_metrics = cls._read_json(cls.BERT_REPORT)
        sklearn_metrics = cls._read_json(cls.SKLEARN_REPORT)
        sklearn_test = sklearn_metrics.get("test", {}) if isinstance(sklearn_metrics, dict) else {}

        bert_f1 = cls._number(bert_metrics.get("eval_f1"))
        bert_accuracy = cls._number(bert_metrics.get("eval_accuracy"))
        sklearn_f1 = cls._number(sklearn_test.get("entity_f1"))
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
            },
            "quality_gates": quality_gates,
            "all_quality_gates_passed": all(quality_gates.values()),
            "metric_scope": "saved held-out DNRTI test reports; not live production accuracy",
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
