from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, Any, List


@dataclass
class RiskScore:
    """
    Data structure representing a risk score result.
    """
    id: str
    score: int          # Risk score in the range 0 ~ 100
    reasons: List[str] # Explanatory reasons for the score


class RiskScorer:
    """
    Risk scoring engine for Events, Alerts, and Incidents.
    Version 1: Rule-based weighted aggregation model.
    """

    def score_event(self, event: Any) -> RiskScore:
        """
        Calculate a RiskScore for a single security event based on:
        - Severity level
        - Event category
        - Authentication failure frequency
        - Asset criticality
        """
        reasons: List[str] = []
        score = 0

        sev = getattr(event, "severity", None)
        asset = getattr(event, "asset_id", "unknown")
        category = getattr(event, "category", "unknown")

        # Base weight derived from severity level
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

        # Additional weight for authentication or identity-related events
        if category in ("auth", "identity"):
            score += 15
            reasons.append("Authentication related event")

        # Reflect failed login attempts from raw event payload
        raw = getattr(event, "raw_payload", {}) or {}
        failed = raw.get("failed_attempts")
        if isinstance(failed, int) and failed >= 5:
            score += 20
            reasons.append(f"High number of failed attempts ({failed})")

        # Additional weight for production assets
        if isinstance(asset, str) and "prod" in asset.lower():
            score += 10
            reasons.append("Production asset")

        score = int(max(0, min(100, score)))
        return RiskScore(id=getattr(event, "id", ""), score=score, reasons=reasons)

    def score_alert(self, alert: Any) -> RiskScore:
        """
        Calculate a RiskScore for a security alert.
        The primary factor is the alert severity level.
        """
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

        # Future extension: Add correlation-based weighting with incidents
        score = int(max(0, min(100, score)))
        return RiskScore(id=getattr(alert, "id", ""), score=score, reasons=reasons)

    def score_incident(self, incident: Any) -> RiskScore:
        """
        Calculate a RiskScore for an Incident object based on:
        - Incident priority (low, medium, high, critical)
        - Operator assignment status
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

        # Additional weight if the incident is actively assigned to an operator
        if getattr(incident, "assignee", None):
            score += 5
            reasons.append("Assigned to operator")

        score = int(max(0, min(100, score)))
        return RiskScore(id=getattr(incident, "id", ""), score=score, reasons=reasons)

    def build_risk_summary(self, incident_scores: List[RiskScore]) -> Dict[str, Any]:
        """
        Generate aggregated risk metrics for dashboard visualization:
        - Maximum risk score
        - Average risk score
        - List of high-risk incident IDs
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
