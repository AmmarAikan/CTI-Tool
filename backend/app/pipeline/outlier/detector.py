from __future__ import annotations

from dataclasses import dataclass

from backend.app.pipeline.outlier.feature_extractor import SessionFeatureExtractor
from backend.app.pipeline.outlier.sessionizer import InternalSession


@dataclass(slots=True)
class OutlierDetection:
    session: InternalSession
    features: dict[str, float]
    is_outlier: bool
    anomaly_score: float
    backend: str


class InternalOutlierDetector:
    """Isolation Forest with an explicit small-batch fallback for demo/sample files."""

    def __init__(self, contamination: float = 0.1, random_state: int = 42) -> None:
        self.contamination = contamination
        self.random_state = random_state

    def detect(
        self,
        sessions: list[InternalSession],
        feature_sets: list[dict[str, float]],
    ) -> list[OutlierDetection]:
        if not sessions:
            return []
        if len(sessions) < 4:
            return [self._heuristic(session, features) for session, features in zip(sessions, feature_sets)]
        try:
            from sklearn.ensemble import IsolationForest
        except ImportError:
            return [self._heuristic(session, features) for session, features in zip(sessions, feature_sets)]

        contamination = min(0.25, max(1 / len(sessions), self.contamination))
        matrix = [SessionFeatureExtractor.vector(features) for features in feature_sets]
        model = IsolationForest(
            n_estimators=200,
            contamination=contamination,
            random_state=self.random_state,
        )
        predictions = model.fit_predict(matrix)
        decisions = model.decision_function(matrix)
        results = []
        for session, features, prediction, decision in zip(sessions, feature_sets, predictions, decisions):
            results.append(
                OutlierDetection(
                    session=session,
                    features=features,
                    is_outlier=bool(prediction == -1),
                    anomaly_score=round(float(-decision), 6),
                    backend="isolation_forest",
                )
            )
        return results

    def _heuristic(self, session: InternalSession, features: dict[str, float]) -> OutlierDetection:
        score = (
            features.get("max_rule_level", 0.0) / 15.0 * 0.35
            + min(1.0, features.get("alerts_count", 0.0) / 20.0) * 0.15
            + min(1.0, features.get("distinct_rules", 0.0) / 8.0) * 0.1
            + min(1.0, features.get("failed_actions", 0.0) / 10.0) * 0.1
            + min(1.0, (features.get("cve_count", 0.0) + features.get("domain_count", 0.0)) / 5.0) * 0.1
            + min(1.0, features.get("credential_attempts", 0.0) / 5.0) * 0.2
        )
        is_outlier = (
            score >= 0.6
            or features.get("max_rule_level", 0.0) >= 12
            or features.get("credential_attempts", 0.0) >= 5
        )
        return OutlierDetection(
            session=session,
            features=features,
            is_outlier=is_outlier,
            anomaly_score=round(score, 6),
            backend="documented_small_batch_heuristic",
        )
