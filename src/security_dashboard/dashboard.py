"""High level orchestration for the security dashboard pipeline."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from typing import Iterable, List

from .automation import LoggingActionExecutor, PlaybookEngine
from .incidents import IncidentPolicy, IncidentService
from .ingestion import EventNormalizer, EventSource, stream_events
from .models import Alert, Event, Playbook, PlaybookAction, Severity
from .reporting import ReportBuilder
from .rules import CorrelationRule, DetectionRule, RuleEngine


@dataclass
class DashboardPipeline:
    """End-to-end pipeline that ingests events and produces alerts and incidents."""

    event_source: EventSource
    normalizer: EventNormalizer
    detection_rules: Iterable[DetectionRule]
    correlation_rules: Iterable[CorrelationRule]
    incident_policy: IncidentPolicy
    playbooks: Iterable[Playbook]
    report_builder: ReportBuilder
    executed_actions: List[str] = field(default_factory=list)

    def run(self) -> dict:
        events = list(stream_events(self.event_source, self.normalizer))
        engine = RuleEngine(
            detection_rules=list(self.detection_rules),
            correlation_rules=list(self.correlation_rules),
        )
        alerts = engine.evaluate(events)
        incident_service = IncidentService(self.incident_policy)
        incidents = []
        if alerts:
            incident = incident_service.create_incident("INC-1", alerts)
            incidents.append(incident)
        playbook_engine = PlaybookEngine(
            playbooks=list(self.playbooks),
            executor_factory=lambda playbook: LoggingActionExecutor(self.executed_actions),
        )
        for alert in alerts:
            playbook_engine.run(alert, {"incident_id": "INC-1", "alert_id": alert.id})
        event_report = self.report_builder.build_event_summary(events)
        incident_report = self.report_builder.build_incident_summary(incidents, alerts)
        return {
            "events": events,
            "alerts": alerts,
            "incidents": incidents,
            "reports": [event_report, incident_report],
            "executed_actions": list(self.executed_actions),
        }


def default_pipeline(event_source: EventSource) -> DashboardPipeline:
    normalizer = EventNormalizer(id_factory=lambda event: str(event.get("id")))
    detection_rules = [
        DetectionRule(
            id="RULE-1",
            name="Critical severity alert",
            severity=Severity.CRITICAL,
            condition=lambda event: event.severity == Severity.CRITICAL,
        ),
        DetectionRule(
            id="RULE-2",
            name="Suspicious login",
            severity=Severity.HIGH,
            condition=lambda event: event.category == "auth" and event.raw_payload.get("failed_attempts", 0) > 5,
        ),
    ]
    correlation_rules = [
        CorrelationRule(
            id="CORR-1",
            name="Multiple alerts per asset",
            severity=Severity.HIGH,
            group_key=lambda event: event.asset_id,
            threshold=3,
        )
    ]
    incident_policy = IncidentPolicy(
        sla_per_severity={
            Severity.CRITICAL: timedelta(minutes=15),
            Severity.HIGH: timedelta(minutes=30),
            Severity.MEDIUM: timedelta(hours=2),
            Severity.LOW: timedelta(hours=4),
        }
    )
    playbooks = [
        Playbook(
            id="PB-1",
            name="Critical containment",
            trigger_condition="critical",
            actions=[
                PlaybookAction(type="isolate-host", parameters={"method": "network"}),
                PlaybookAction(type="notify", parameters={"channel": "slack"}),
            ],
            approval_required=True,
        ),
        Playbook(
            id="PB-2",
            name="Suspicious login investigation",
            trigger_condition="RULE-2",
            actions=[
                PlaybookAction(type="disable-account", parameters={}),
                PlaybookAction(type="force-password-reset", parameters={}),
            ],
        ),
    ]
    report_builder = ReportBuilder(generated_by="dashboard-system")
    return DashboardPipeline(
        event_source=event_source,
        normalizer=normalizer,
        detection_rules=detection_rules,
        correlation_rules=correlation_rules,
        incident_policy=incident_policy,
        playbooks=playbooks,
        report_builder=report_builder,
    )