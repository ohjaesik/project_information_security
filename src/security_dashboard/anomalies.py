# security_dashboard/anomalies.py
from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class AnomalyResult:
    id: str
    is_anomaly: bool
    score: float
    reasons: List[str]


class RuleBasedAnomalyDetector:
    """
    간단한 규칙 기반 이상 탐지 (로그인 실패 횟수, 단시간 이벤트 폭증 등).
    """

    def detect(self, events: List[Any]) -> List[AnomalyResult]:
        results: List[AnomalyResult] = []
        for e in events:
            reasons: List[str] = []
            score = 0.0

            failed = getattr(e, "metadata", {}).get("failed_attempts")
            if failed is None:
                # event dict에서 직접 가져오는 fallback
                failed = getattr(e, "failed_attempts", None)

            if isinstance(failed, int) and failed >= 5:
                score += 0.7
                reasons.append(f"High number of failed attempts ({failed})")

            category = getattr(e, "category", "")
            if category == "auth" and failed and failed >= 3:
                score += 0.2
                reasons.append("Auth category with multiple failures")

            is_anomaly = score >= 0.7
            results.append(AnomalyResult(
                id=getattr(e, "id", ""),
                is_anomaly=is_anomaly,
                score=score,
                reasons=reasons,
            ))
        return results


class IsolationForestAnomalyDetector:
    """
    Isolation Forest 기반 이상 탐지.
    scikit-learn이 설치되어 있지 않으면 비활성 모드로 동작.
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
        이벤트를 간단한 feature vector로 변환.
        v1: severity / category 정도만 사용.
        """
        sev = str(getattr(getattr(event, "severity", ""), "value", getattr(event, "severity", "") or "")).lower()
        category = str(getattr(event, "category", "")).lower()

        sev_map = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        cat_map = {"auth": 1, "network": 2, "system": 3}

        return [
            float(sev_map.get(sev, 0)),
            float(cat_map.get(category, 0)),
        ]

    def fit(self, events: List[Any]) -> None:
        if self._model is None or not events:
            return
        X = [self._vectorize(e) for e in events]
        self._model.fit(X)

    def detect(self, events: List[Any]) -> List[AnomalyResult]:
        if self._model is None or not events:
            # 모델 없으면 전부 정상으로 반환
            return [
                AnomalyResult(id=getattr(e, "id", ""), is_anomaly=False, score=0.0, reasons=["model_not_available"])
                for e in events
            ]
        X = [self._vectorize(e) for e in events]
        scores = self._model.decision_function(X)  # 값이 작을수록 이상
        preds = self._model.predict(X)  # -1: 이상, 1: 정상

        results: List[AnomalyResult] = []
        for e, s, p in zip(events, scores, preds):
            is_anomaly = (p == -1)
            reasons = []
            if is_anomaly:
                reasons.append("IsolationForest flagged this event")
            results.append(AnomalyResult(
                id=getattr(e, "id", ""),
                is_anomaly=is_anomaly,
                score=float(-s),  # score는 양수일수록 위험하도록 반전
                reasons=reasons,
            ))
        return results
