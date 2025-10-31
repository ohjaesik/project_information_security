"""Core data models for the security dashboard domain."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Dict, Iterable, List, Optional, Sequence, Set


class Severity(str, Enum):
    """Represents severity levels for security events and alerts."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class Event:
    """Represents a normalized security event."""

    id: str
    source: str
    asset_id: str
    severity: Severity
    category: str
    timestamp: datetime
    raw_payload: Dict[str, object]


def utcnow() -> datetime:
    """Return a timezone-aware UTC timestamp."""

    return datetime.now(timezone.utc)


@dataclass
class Alert:
    """Represents an alert triggered by a detection rule."""

    id: str
    rule_id: str
    event_ids: List[str]
    severity: Severity
    status: str = "open"
    owner: Optional[str] = None
    created_at: datetime = field(default_factory=utcnow)
    acknowledged_at: Optional[datetime] = None

    def acknowledge(self, owner: str) -> None:
        """Mark the alert as acknowledged by an owner."""
        self.status = "acknowledged"
        self.owner = owner
        self.acknowledged_at = utcnow()


@dataclass
class Incident:
    """Represents an incident composed of one or more alerts."""

    id: str
    alert_ids: Set[str]
    priority: Severity
    assignee: Optional[str] = None
    sla_due_at: Optional[datetime] = None
    resolution: Optional[str] = None
    timeline: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=utcnow)

    def add_timeline_entry(self, entry: str) -> None:
        self.timeline.append(f"{utcnow().isoformat()} {entry}")

    def assign(self, assignee: str, response_time: timedelta) -> None:
        self.assignee = assignee
        self.sla_due_at = utcnow() + response_time
        self.add_timeline_entry(f"Incident assigned to {assignee}")

    def resolve(self, resolution: str) -> None:
        self.resolution = resolution
        self.add_timeline_entry(f"Incident resolved: {resolution}")


@dataclass(frozen=True)
class PlaybookAction:
    """Represents a single action inside an automation playbook."""

    type: str
    parameters: Dict[str, object]


@dataclass
class Playbook:
    """Represents a SOAR playbook definition."""

    id: str
    name: str
    trigger_condition: str
    actions: Sequence[PlaybookAction]
    approval_required: bool = False


@dataclass
class Report:
    """Represents an aggregated report of security posture."""

    id: str
    type: str
    period_start: datetime
    period_end: datetime
    filters: Dict[str, object]
    generated_by: str
    findings: Dict[str, object]


def group_events_by_asset(events: Iterable[Event]) -> Dict[str, List[Event]]:
    """Utility to group events by the affected asset."""

    groups: Dict[str, List[Event]] = {}
    for event in events:
        groups.setdefault(event.asset_id, []).append(event)
    return groups


def pick_highest_severity(severities: Iterable[Severity]) -> Severity:
    """Return the highest severity value in the iterable."""

    order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    index = {severity: position for position, severity in enumerate(order)}
    highest = Severity.LOW
    for severity in severities:
        if index[severity] > index[highest]:
            highest = severity
    return highest