"""Incident management utilities."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from typing import Dict, Iterable, List, Optional

from .models import Alert, Incident, Severity, pick_highest_severity


@dataclass
class IncidentPolicy:
    """Define how incidents should be created and escalated."""

    sla_per_severity: Dict[Severity, timedelta]

    def response_time(self, severity: Severity) -> timedelta:
        return self.sla_per_severity.get(severity, timedelta(hours=4))


@dataclass
class IncidentService:
    """Service that groups alerts into incidents and tracks their lifecycle."""

    policy: IncidentPolicy
    incidents: Dict[str, Incident] = field(default_factory=dict)

    def create_incident(self, incident_id: str, alerts: Iterable[Alert]) -> Incident:
        alerts_list = list(alerts)
        severity = pick_highest_severity(alert.severity for alert in alerts_list)
        incident = Incident(
            id=incident_id,
            alert_ids={alert.id for alert in alerts_list},
            priority=severity,
        )
        self.incidents[incident_id] = incident
        incident.add_timeline_entry(
            f"Incident created with alerts: {', '.join(alert.id for alert in alerts_list)}"
        )
        incident.assign(
            assignee="soc_on_call",
            response_time=self.policy.response_time(severity),
        )
        return incident

    def resolve_incident(self, incident_id: str, resolution: str) -> Optional[Incident]:
        incident = self.incidents.get(incident_id)
        if incident:
            incident.resolve(resolution)
        return incident

    def open_incidents(self) -> List[Incident]:
        return [incident for incident in self.incidents.values() if incident.resolution is None]