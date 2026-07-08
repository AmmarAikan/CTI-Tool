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
        entities: list[dict[str, object]] = []

        def coerce_offset(value: object) -> int | None:
            if value is None:
                return None
            try:
                return int(value)
            except (TypeError, ValueError):
                return None

        def clean_value(value: str) -> str:
            value = value.replace(" ##", "").replace("##", "")
            value = " ".join(value.split())
            while " - " in value or " -" in value or "- " in value:
                value = value.replace(" - ", "-").replace(" -", "-").replace("- ", "-")
            return value.strip().rstrip(".,;:")

        def has_valid_offsets(start: int | None, end: int | None) -> bool:
            return start is not None and end is not None and 0 <= start < end <= len(text)

        def is_entity_token_char(character: str) -> bool:
            return character.isalnum() or character in "-_"

        def expand_offsets_to_token(start: int, end: int) -> tuple[int, int]:
            while start > 0 and is_entity_token_char(text[start - 1]) and is_entity_token_char(text[start]):
                start -= 1
            while end < len(text) and is_entity_token_char(text[end - 1]) and is_entity_token_char(text[end]):
                end += 1
            return start, end

        spans: list[dict[str, object]] = []
        for item in results:
            entity_type = item.get("entity_group") or item.get("entity")
            raw_value = item.get("word")
            score = item.get("score", 0.0)
            if not entity_type or not raw_value:
                continue

            start = coerce_offset(item.get("start"))
            end = coerce_offset(item.get("end"))
            if has_valid_offsets(start, end):
                start, end = expand_offsets_to_token(start, end)
                value = text[start:end]
            else:
                start = None
                end = None
                value = str(raw_value)

            value = clean_value(value)
            if not value:
                continue

            spans.append(
                {
                    "type": self._normalize_entity_type(str(entity_type)),
                    "value": value,
                    "score": float(score),
                    "start": start,
                    "end": end,
                    "raw_value": str(raw_value),
                    "scores": [float(score)],
                }
            )

        merged_spans: list[dict[str, object]] = []
        for span in spans:
            if not merged_spans:
                merged_spans.append(span)
                continue

            previous = merged_spans[-1]
            previous_start = previous.get("start")
            previous_end = previous.get("end")
            span_start = span.get("start")
            span_end = span.get("end")
            same_type = previous["type"] == span["type"]
            adjacent_offsets = (
                isinstance(previous_start, int)
                and isinstance(previous_end, int)
                and isinstance(span_start, int)
                and isinstance(span_end, int)
                and (
                    previous_end >= span_start
                    or (previous_end <= span_start and not text[previous_end:span_start].strip())
                )
            )
            wordpiece_continuation = str(span.get("raw_value", "")).startswith("##")

            if same_type and (adjacent_offsets or wordpiece_continuation):
                if (
                    isinstance(previous_start, int)
                    and isinstance(previous_end, int)
                    and isinstance(span_start, int)
                    and isinstance(span_end, int)
                ):
                    previous["start"] = min(previous_start, span_start)
                    span_end = max(previous_end, span_end)
                    previous["end"] = span_end
                    previous["value"] = clean_value(text[previous["start"]:span_end])
                else:
                    separator = "" if wordpiece_continuation else " "
                    previous["value"] = clean_value(f"{previous['value']}{separator}{span['value']}")
                previous_scores = previous.setdefault("scores", [])
                if isinstance(previous_scores, list):
                    previous_scores.extend(span["scores"])
                continue

            merged_spans.append(span)

        for span in merged_spans:
            scores = span.get("scores", [span["score"]])
            if not isinstance(scores, list):
                scores = [float(span["score"])]
            confidence = sum(float(score) for score in scores) / len(scores)
            entities.append(
                {
                    "type": span["type"],
                    "value": span["value"],
                    "confidence": round(confidence * 100, 2),
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
