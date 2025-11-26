from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class Recommendation:
    title: str
    description: str
    actions: List[str]


def build_recommendations(incident: Any, risk_score: int) -> Recommendation:
    """
    Generate response recommendations based on risk score and incident properties
    (v1: rule-based).
    """
    title = "Review incident"
    actions: List[str] = []

    sev_text = str(getattr(getattr(incident, "priority", ""), "value", "")).lower()
    if risk_score >= 80 or sev_text in ("p1", "p2"):
        title = "Immediate response required"
        actions.append("Escalate to on-call security engineer")
        actions.append("Isolate affected asset if possible")
    elif risk_score >= 60:
        title = "High risk incident"
        actions.append("Review logs for lateral movement")
    else:
        title = "Monitor incident"
        actions.append("Add to watchlist and monitor")

    return Recommendation(
        title=title,
        description=f"Incident {getattr(incident, 'id', '')} has risk score {risk_score}.",
        actions=actions,
    )


# Slack / Email notifications require webhook/SMTP configuration in a real environment.
# Here, they are implemented as logging/print-based stubs.
def send_slack_alert(webhook_url: str, payload: Dict[str, Any]) -> None:
    """
    In a real implementation, use requests.post(webhook_url, json=payload).
    This is currently a stub.
    """
    print("[SLACK] would send:", payload)


def send_email_alert(to: str, subject: str, body: str) -> None:
    """
    In a real implementation, use smtplib.
    This is currently a stub.
    """
    print(f"[EMAIL] to={to}, subject={subject}")
    print(body)
