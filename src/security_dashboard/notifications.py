# security_dashboard/notifications.py
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
    위험도 + 인시던트 속성 기반 대응 권고 텍스트 생성 (v1: 규칙 기반).
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


# Slack / Email 알림은 실제 환경에 맞게 webhook/SMTP 설정 필요.
# 여기서는 로깅/프린트 기반 stub.
def send_slack_alert(webhook_url: str, payload: Dict[str, Any]) -> None:
    """
    실제 구현 시 requests.post(webhook_url, json=payload) 사용.
    현재는 stub.
    """
    print("[SLACK] would send:", payload)


def send_email_alert(to: str, subject: str, body: str) -> None:
    """
    실제 구현 시 smtplib 사용.
    현재는 stub.
    """
    print(f"[EMAIL] to={to}, subject={subject}")
    print(body)
