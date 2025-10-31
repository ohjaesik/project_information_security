"""Detection rule engine for the security dashboard."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Sequence

from .models import Alert, Event, Severity


@dataclass
class DetectionRule:
    """A rule that produces alerts when the condition evaluates to true."""

    id: str
    name: str
    severity: Severity
    condition: Callable[[Event], bool]

    def matches(self, event: Event) -> bool:
        return self.condition(event)


@dataclass
class CorrelationRule:
    """A rule that correlates multiple events into a single alert."""

    id: str
    name: str
    severity: Severity
    group_key: Callable[[Event], str]
    threshold: int

    def correlate(self, events: Iterable[Event]) -> List[List[Event]]:
        buckets: Dict[str, List[Event]] = {}
        for event in events:
            key = self.group_key(event)
            buckets.setdefault(key, []).append(event)
        return [bucket for bucket in buckets.values() if len(bucket) >= self.threshold]


@dataclass
class RuleEngine:
    """Applies detection and correlation rules to events."""

    detection_rules: Sequence[DetectionRule]
    correlation_rules: Sequence[CorrelationRule]

    def evaluate(self, events: Iterable[Event]) -> List[Alert]:
        event_list = list(events)
        alerts: List[Alert] = []
        for event in event_list:
            for rule in self.detection_rules:
                if rule.matches(event):
                    alerts.append(
                        Alert(
                            id=f"{rule.id}:{event.id}",
                            rule_id=rule.id,
                            event_ids=[event.id],
                            severity=rule.severity,
                        )
                    )
        for rule in self.correlation_rules:
            for group in rule.correlate(event_list):
                alerts.append(
                    Alert(
                        id=f"{rule.id}:{group[0].id}",
                        rule_id=rule.id,
                        event_ids=[event.id for event in group],
                        severity=rule.severity,
                    )
                )
        return alerts