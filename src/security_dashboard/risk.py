# security_dashboard/risk.py
from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, Any, List


@dataclass
class RiskScore:
    id: str
    score: int          # 0 ~ 100
    reasons: List[str]


class RiskScorer:
    """
    이벤트 / 알림 / 인시던트에 대해 0~100 RiskScore 산출.
    v1: 규칙 기반 + 간단 가중치 합산.
    """

    def score_event(self, event: Any) -> RiskScore:
        reasons: List[str] = []
        score = 0

        sev = getattr(event, "severity", None)
        asset = getattr(event, "asset_id", "unknown")
        category = getattr(event, "category", "unknown")

        # severity 기반 기본 가중치
        if sev:
            sev_val = str(getattr(sev, "value", sev)).lower()
            if sev_val == "critical":
                score += 60
                reasons.append("Critical severity")
            elif sev_val == "high":
                score += 40
                reasons.append("High severity")
            elif sev_val == "medium":
                score += 20
                reasons.append("Medium severity")
            else:
                score += 5
                reasons.append("Low severity")

        # 인증/계정 관련 이벤트
        if category in ("auth", "identity"):
            score += 15
            reasons.append("Authentication related event")

        # Windows / auth 로그에서 failed_attempts 반영
        raw = getattr(event, "raw_payload", {}) or {}
        failed = raw.get("failed_attempts")
        if isinstance(failed, int) and failed >= 5:
            score += 20
            reasons.append(f"High number of failed attempts ({failed})")

        # 프로덕션 자산
        if isinstance(asset, str) and "prod" in asset.lower():
            score += 10
            reasons.append("Production asset")

        score = int(max(0, min(100, score)))
        return RiskScore(id=getattr(event, "id", ""), score=score, reasons=reasons)

    def score_alert(self, alert: Any) -> RiskScore:
        reasons: List[str] = []
        score = 0

        sev = getattr(alert, "severity", None)
        if sev:
            sev_val = str(getattr(sev, "value", sev)).lower()
            if sev_val == "critical":
                score += 70
                reasons.append("Critical alert")
            elif sev_val == "high":
                score += 50
                reasons.append("High alert")
            elif sev_val == "medium":
                score += 30
                reasons.append("Medium alert")
            else:
                score += 10
                reasons.append("Low alert")

        # 인시던트와 연계되면 추가 가중치 줄 수도 있음 (v2)
        score = int(max(0, min(100, score)))
        return RiskScore(id=getattr(alert, "id", ""), score=score, reasons=reasons)

    def score_incident(self, incident: Any) -> RiskScore:
        """
        Incident.priority 는 Severity(low/medium/high/critical)이므로
        그 기준으로 점수 매핑.
        """
        reasons: List[str] = []
        score = 0

        priority = getattr(incident, "priority", None)
        if priority:
            p_val = str(getattr(priority, "value", priority)).lower()
            if p_val == "critical":
                score += 80
                reasons.append("Critical incident")
            elif p_val == "high":
                score += 60
                reasons.append("High priority incident")
            elif p_val == "medium":
                score += 40
                reasons.append("Medium priority incident")
            else:
                score += 20
                reasons.append("Low priority incident")

        if getattr(incident, "assignee", None):
            score += 5
            reasons.append("Assigned to operator")

        score = int(max(0, min(100, score)))
        return RiskScore(id=getattr(incident, "id", ""), score=score, reasons=reasons)

    def build_risk_summary(self, incident_scores: List[RiskScore]) -> Dict[str, Any]:
        """
        요약 카드 / 위험 지도 등에 쓸 집계 정보.
        """
        if not incident_scores:
            return {
                "max_score": 0,
                "avg_score": 0,
                "high_risk_incidents": [],
            }

        max_score = max(s.score for s in incident_scores)
        avg_score = sum(s.score for s in incident_scores) / len(incident_scores)
        high_risk = [s.id for s in incident_scores if s.score >= 70]

        return {
            "max_score": int(max_score),
            "avg_score": round(avg_score, 1),
            "high_risk_incidents": high_risk,
        }
