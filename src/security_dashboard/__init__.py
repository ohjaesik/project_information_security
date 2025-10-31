"""Security dashboard simulation package."""
from .automation import LoggingActionExecutor, PlaybookEngine
from .dashboard import DashboardPipeline, default_pipeline
from .incidents import IncidentPolicy, IncidentService
from .ingestion import EventNormalizer, InMemoryEventSource, stream_events
from .models import (
    Alert,
    Event,
    Incident,
    Playbook,
    PlaybookAction,
    Report,
    Severity,
    group_events_by_asset,
    pick_highest_severity,
)
from .reporting import ReportBuilder
from .rules import CorrelationRule, DetectionRule, RuleEngine

__all__ = [
    "Alert",
    "DashboardPipeline",
    "DetectionRule",
    "CorrelationRule",
    "Event",
    "Incident",
    "IncidentPolicy",
    "IncidentService",
    "LoggingActionExecutor",
    "Playbook",
    "PlaybookAction",
    "PlaybookEngine",
    "Report",
    "ReportBuilder",
    "Severity",
    "default_pipeline",
    "EventNormalizer",
    "InMemoryEventSource",
    "stream_events",
    "group_events_by_asset",
    "pick_highest_severity",
    "RuleEngine",
]