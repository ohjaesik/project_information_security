from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class AnomalyResult:
    """
    Data structure representing the result of anomaly detection.
    """
    id: str
    is_anomaly: bool
    score: float
    reasons: List[str]


class RuleBasedAnomalyDetector:
    """
    Simple rule-based anomaly detector based on:
    - Repeated authentication failures
    - Short-term abnormal event frequency

    The detector primarily uses Event.raw_payload["failed_attempts"].
    """

    def detect(self, events: List[Any]) -> List[AnomalyResult]:
        results: List[AnomalyResult] = []
        for e in events:
            reasons: List[str] = []
            score = 0.0

            # Prefer raw_payload if available
            raw: Dict[str, Any] = getattr(e, "raw_payload", {}) or {}

            failed = raw.get("failed_attempts")
            if failed is None:
                # Fallback for alternative field structures
                failed = getattr(e, "failed_attempts", None)

            # High number of repeated authentication failures
            if isinstance(failed, int) and failed >= 5:
                score += 0.7
                reasons.append(f"High number of failed attempts ({failed})")

            category = getattr(e, "category", raw.get("category", ""))
            if category == "auth" and isinstance(failed, int) and failed >= 3:
                score += 0.2
                reasons.append("Authentication category with multiple failures")

            is_anomaly = score >= 0.7
            results.append(
                AnomalyResult(
                    id=getattr(e, "id", ""),
                    is_anomaly=is_anomaly,
                    score=score,
                    reasons=reasons,
                )
            )
        return results


class IsolationForestAnomalyDetector:
    """
    Machine-learning-based anomaly detector using the Isolation Forest algorithm.
    If scikit-learn is not available, the detector runs in disabled mode.
    """

    def __init__(self) -> None:
        try:
            from sklearn.ensemble import IsolationForest  # type: ignore
        except Exception:
            self._model = None
        else:
            self._model = IsolationForest(
                n_estimators=100,
                contamination=0.05,
                random_state=42,
            )

    def _vectorize(self, event: Any) -> List[float]:
        """
        Convert a security event into a numerical feature vector.
        Version 2 features:
        - Severity level
        - Event category
        - Event ID
        - Failed login attempts
        - Hour of occurrence
        """
        # Severity feature
        sev = str(
            getattr(
                getattr(event, "severity", ""),
                "value",
                getattr(event, "severity", "") or "",
            )
        ).lower()

        # Category feature
        category = str(getattr(event, "category", "")).lower()

        raw: Dict[str, Any] = getattr(event, "raw_payload", {}) or {}
        failed = raw.get("failed_attempts", 0)
        if not isinstance(failed, (int, float)):
            failed = 0

        event_id = raw.get("event_id", 0)
        if not isinstance(event_id, (int, float)):
            event_id = 0

        # Temporal feature (hour of the day)
        ts = getattr(event, "timestamp", None)
        hour = getattr(ts, "hour", 0)

        sev_map = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        cat_map = {"auth": 1, "network": 2, "system": 3}

        return [
            float(sev_map.get(sev, 0)),
            float(cat_map.get(category, 0)),
            float(event_id) / 5000.0,   # Rough normalization
            float(failed),
            float(hour) / 24.0,
        ]

    def fit(self, events: List[Any]) -> None:
        """
        Train the Isolation Forest model using the given event feature vectors.
        """
        if self._model is None or not events:
            return
        X = [self._vectorize(e) for e in events]
        self._model.fit(X)

    def detect(self, events: List[Any]) -> List[AnomalyResult]:
        """
        Perform anomaly detection using the trained Isolation Forest model.
        """
        if self._model is None or not events:
            # If the model is unavailable, return all events as normal
            return [
                AnomalyResult(
                    id=getattr(e, "id", ""),
                    is_anomaly=False,
                    score=0.0,
                    reasons=["model_not_available"],
                )
                for e in events
            ]

        X = [self._vectorize(e) for e in events]
        scores = self._model.decision_function(X)  # Lower value => higher anomaly
        preds = self._model.predict(X)             # -1: anomaly, +1: normal

        results: List[AnomalyResult] = []
        for e, s, p in zip(events, scores, preds):
            is_anomaly = p == -1
            reasons: List[str] = []
            if is_anomaly:
                reasons.append("Isolation Forest flagged this event as anomalous")

            results.append(
                AnomalyResult(
                    id=getattr(e, "id", ""),
                    is_anomaly=is_anomaly,
                    score=float(-s),  # Inverted to make higher value = higher risk
                    reasons=reasons,
                )
            )
        return results
