"""Reporting utilities for the security dashboard."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Iterable, List

from .models import Alert, Event, Incident, Report, Severity, group_events_by_asset


@dataclass
class ReportBuilder:
    """Build reports from dashboard data."""

    generated_by: str

    def build_event_summary(self, events: Iterable[Event]) -> Report:
        event_list = list(events)
        grouped = group_events_by_asset(event_list)
        per_asset = {
            asset: {
                "count": len(asset_events),
                "severities": {severity.value: 0 for severity in Severity},
            }
            for asset, asset_events in grouped.items()
        }
        for asset, asset_events in grouped.items():
            for event in asset_events:
                per_asset[asset]["severities"][event.severity.value] += 1
        findings = {
            "total_events": len(event_list),
            "assets": per_asset,
        }
        period_start = min((event.timestamp for event in event_list), default=datetime.now(timezone.utc))
        period_end = max((event.timestamp for event in event_list), default=period_start)
        return Report(
            id="event-summary",
            type="event-summary",
            period_start=period_start,
            period_end=period_end,
            filters={},
            generated_by=self.generated_by,
            findings=findings,
        )

    def build_incident_summary(self, incidents: Iterable[Incident], alerts: Iterable[Alert]) -> Report:
        incident_list = list(incidents)
        alert_lookup: Dict[str, Alert] = {alert.id: alert for alert in alerts}
        by_status: Dict[str, int] = {"open": 0, "acknowledged": 0, "resolved": 0}
        for incident in incident_list:
            if incident.resolution:
                by_status["resolved"] += 1
            elif any(alert_lookup.get(alert_id, Alert("", "", [], Severity.LOW)).status == "acknowledged" for alert_id in incident.alert_ids):
                by_status["acknowledged"] += 1
            else:
                by_status["open"] += 1
        findings = {
            "total_incidents": len(incident_list),
            "by_status": by_status,
        }
        period_start = min((incident.created_at for incident in incident_list), default=datetime.now(timezone.utc))
        period_end = max((incident.created_at for incident in incident_list), default=period_start)
        return Report(
            id="incident-summary",
            type="incident-summary",
            period_start=period_start,
            period_end=period_end,
            filters={},
            generated_by=self.generated_by,
            findings=findings,
        )