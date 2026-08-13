from __future__ import annotations

import re
from dataclasses import dataclass
from itertools import combinations
from typing import Any


@dataclass(slots=True)
class CorrelationCandidate:
    event_a_id: str
    event_b_id: str
    correlation_type: str
    score: float
    reason: str
    evidence: dict[str, Any]


class SimpleCorrelator:
    """MISP-style exact-value correlation across normalized indicators."""

    def correlate(self, events) -> list[CorrelationCandidate]:
        results: list[CorrelationCandidate] = []
        for event_a, event_b in combinations(events, 2):
            values_a = self._values(event_a)
            values_b = self._values(event_b)
            shared_types = sorted(set(values_a) & set(values_b))
            for indicator_type in shared_types:
                shared = sorted(values_a[indicator_type] & values_b[indicator_type])
                if not shared:
                    continue
                results.append(
                    CorrelationCandidate(
                        event_a_id=event_a.id,
                        event_b_id=event_b.id,
                        correlation_type="simple_indicator_match",
                        score=1.0,
                        reason=f"same_{indicator_type}",
                        evidence={"indicator_type": indicator_type, "values": shared[:20]},
                    )
                )
        return results

    def _values(self, event) -> dict[str, set[str]]:
        values: dict[str, set[str]] = {}
        for indicator in event.indicators:
            values.setdefault(indicator.indicator_type, set()).add(indicator.value.strip().lower())
        return values


class SimilarityCorrelator:
    def __init__(self, threshold: float = 0.35) -> None:
        self.threshold = threshold

    def correlate(self, events) -> list[CorrelationCandidate]:
        events = list(events)
        if len(events) < 2:
            return []
        texts = [f"{event.title}\n{event.normalized_text or event.description}" for event in events]
        try:
            scores = self._tfidf_scores(texts)
            backend = "tfidf_cosine"
        except (ImportError, ValueError):
            scores = self._jaccard_scores(texts)
            backend = "token_jaccard_fallback"
        results = []
        for i, j in combinations(range(len(events)), 2):
            score = float(scores[i][j])
            if score < self.threshold:
                continue
            results.append(
                CorrelationCandidate(
                    event_a_id=events[i].id,
                    event_b_id=events[j].id,
                    correlation_type="text_similarity",
                    score=round(score, 6),
                    reason="similar_text",
                    evidence={"backend": backend, "threshold": self.threshold},
                )
            )
        return results

    def _tfidf_scores(self, texts: list[str]):
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.metrics.pairwise import cosine_similarity

        matrix = TfidfVectorizer(stop_words="english", ngram_range=(1, 2), min_df=1).fit_transform(texts)
        return cosine_similarity(matrix)

    def _jaccard_scores(self, texts: list[str]) -> list[list[float]]:
        tokens = [set(re.findall(r"[a-z0-9_.:/-]{3,}", text.lower())) for text in texts]
        matrix = [[0.0 for _ in texts] for _ in texts]
        for i in range(len(texts)):
            matrix[i][i] = 1.0
            for j in range(i + 1, len(texts)):
                union = tokens[i] | tokens[j]
                score = len(tokens[i] & tokens[j]) / len(union) if union else 0.0
                matrix[i][j] = matrix[j][i] = score
        return matrix
