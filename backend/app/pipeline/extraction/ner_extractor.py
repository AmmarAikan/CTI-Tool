from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def project_root() -> Path:
    current = Path(__file__).resolve()
    for parent in current.parents:
        if (parent / "ml").exists():
            return parent
    return Path.cwd()


ROOT = project_root()
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ml.common.token_features import sentence_to_feature_dicts, simple_word_tokenize  # noqa: E402


class NERExtractor:
    """Runtime NER extractor for the CTI pipeline.

    It prefers a fine-tuned transformer model when available. If the transformer
    stack or model is missing, it falls back to the local scikit-learn baseline.
    """

    def __init__(
        self,
        transformer_model_path: str | Path | None = None,
        sklearn_model_path: str | Path | None = None,
    ) -> None:
        self.backend = "none"
        self.ner_pipeline: Any | None = None
        self.sklearn_model: Any | None = None

        transformer_path = Path(transformer_model_path or ROOT / "ml/models/dnrti_bert_ner")
        sklearn_path = Path(sklearn_model_path or ROOT / "ml/models/dnrti_sklearn_ner/model.joblib")

        if self._load_transformer(transformer_path):
            return
        self._load_sklearn(sklearn_path)

    def extract_entities(self, text: str) -> list[dict[str, object]]:
        if not text:
            return []

        if self.backend == "transformer" and self.ner_pipeline is not None:
            return self._extract_with_transformer(text)

        if self.backend == "sklearn" and self.sklearn_model is not None:
            return self._extract_with_sklearn(text)

        return []

    def _load_transformer(self, model_path: Path) -> bool:
        if not (model_path / "config.json").exists():
            return False
        try:
            from transformers import pipeline

            self.ner_pipeline = pipeline(
                task="token-classification",
                model=str(model_path),
                tokenizer=str(model_path),
                aggregation_strategy="simple",
            )
            self.backend = "transformer"
            return True
        except Exception:
            self.ner_pipeline = None
            return False

    def _load_sklearn(self, model_path: Path) -> bool:
        if not model_path.exists():
            return False
        try:
            from joblib import load

            self.sklearn_model = load(model_path)
            metadata_path = model_path.parent / "metadata.json"
            if metadata_path.exists():
                with metadata_path.open("r", encoding="utf-8") as file:
                    self.metadata = json.load(file)
            else:
                self.metadata = {}
            self.backend = "sklearn"
            return True
        except Exception:
            self.sklearn_model = None
            return False

    def _extract_with_transformer(self, text: str) -> list[dict[str, object]]:
        results = self.ner_pipeline(text)
        entities = []
        for item in results:
            entity_type = item.get("entity_group") or item.get("entity")
            value = item.get("word")
            score = item.get("score", 0.0)
            if not entity_type or not value:
                continue
            entities.append(
                {
                    "type": self._normalize_entity_type(str(entity_type)),
                    "value": str(value).strip(),
                    "confidence": round(float(score) * 100, 2),
                    "source": "dnrti_bert_ner",
                }
            )
        return self._deduplicate_entities(entities)

    def _extract_with_sklearn(self, text: str) -> list[dict[str, object]]:
        tokens = simple_word_tokenize(text)
        if not tokens:
            return []

        features = sentence_to_feature_dicts(tokens)
        labels = list(self.sklearn_model.predict(features))
        confidences = self._predict_confidences(features, labels)
        return self._labels_to_entities(tokens, labels, confidences)

    def _predict_confidences(self, features: list[dict[str, object]], labels: list[str]) -> list[float]:
        classifier = self.sklearn_model.named_steps.get("classifier")
        if not classifier or not hasattr(self.sklearn_model, "predict_proba"):
            return [0.75 for _ in labels]

        probabilities = self.sklearn_model.predict_proba(features)
        class_to_index = {label: index for index, label in enumerate(classifier.classes_)}
        confidences = []
        for probability, label in zip(probabilities, labels):
            index = class_to_index.get(label)
            confidences.append(float(probability[index]) if index is not None else float(max(probability)))
        return confidences

    def _labels_to_entities(
        self,
        tokens: list[str],
        labels: list[str],
        confidences: list[float],
    ) -> list[dict[str, object]]:
        entities: list[dict[str, object]] = []
        current_type: str | None = None
        current_tokens: list[str] = []
        current_scores: list[float] = []

        def flush() -> None:
            nonlocal current_type, current_tokens, current_scores
            if current_type and current_tokens:
                entities.append(
                    {
                        "type": self._normalize_entity_type(current_type),
                        "value": self._join_tokens(current_tokens),
                        "confidence": round((sum(current_scores) / len(current_scores)) * 100, 2),
                        "source": "dnrti_sklearn_ner",
                    }
                )
            current_type = None
            current_tokens = []
            current_scores = []

        for token, label, confidence in zip(tokens, labels, confidences):
            if label == "O":
                flush()
                continue

            if "-" in label:
                prefix, entity_type = label.split("-", 1)
            else:
                prefix, entity_type = "B", label

            if prefix == "B" or current_type != entity_type:
                flush()
                current_type = entity_type
                current_tokens = [token]
                current_scores = [confidence]
            else:
                current_tokens.append(token)
                current_scores.append(confidence)

        flush()
        return self._deduplicate_entities(entities)

    def _normalize_entity_type(self, entity_type: str) -> str:
        clean_type = entity_type.replace("B-", "").replace("I-", "")
        mapping = {
            "HackOrg": "threat_actor",
            "Tool": "tool_or_malware",
            "Org": "organization",
            "Area": "location",
            "SecTeam": "security_team",
            "Idus": "industry_sector",
            "OffAct": "attack_method",
            "SamFile": "sample_file",
            "Exp": "exploit",
            "Way": "attack_method",
            "Features": "technical_feature",
            "Time": "time",
            "Purp": "objective",
        }
        return mapping.get(clean_type, clean_type.lower())

    def _join_tokens(self, tokens: list[str]) -> str:
        value = " ".join(tokens)
        for punctuation in [".", ",", ":", ";", ")", "]", "}"]:
            value = value.replace(f" {punctuation}", punctuation)
        for punctuation in ["(", "[", "{"]:
            value = value.replace(f"{punctuation} ", punctuation)
        return value.strip().rstrip(".,;:")

    def _deduplicate_entities(self, entities: list[dict[str, object]]) -> list[dict[str, object]]:
        seen = set()
        unique_entities = []
        for entity in entities:
            key = (entity["type"], str(entity["value"]).lower())
            if key in seen:
                continue
            seen.add(key)
            unique_entities.append(entity)
        return unique_entities
