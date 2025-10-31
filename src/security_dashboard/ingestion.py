"""Event ingestion utilities for the security dashboard."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Dict, Iterable, Iterator, List, Protocol

from .models import Event, Severity


class EventSource(Protocol):
    """A protocol for event sources."""

    def fetch(self) -> Iterable[Dict[str, object]]:
        """Return raw events as dictionaries."""


@dataclass
class InMemoryEventSource:
    """Simple event source backed by an in-memory list."""

    events: List[Dict[str, object]]

    def fetch(self) -> Iterable[Dict[str, object]]:
        return list(self.events)


@dataclass
class EventNormalizer:
    """Convert raw event dictionaries into :class:`Event` instances."""

    id_factory: Callable[[Dict[str, object]], str]
    timestamp_field: str = "timestamp"

    def normalize(self, raw_event: Dict[str, object]) -> Event:
        timestamp_value = raw_event.get(self.timestamp_field)
        if isinstance(timestamp_value, str):
            timestamp = datetime.fromisoformat(timestamp_value)
        elif isinstance(timestamp_value, datetime):
            timestamp = timestamp_value
        else:
            timestamp = datetime.now(timezone.utc)
        severity = Severity(raw_event.get("severity", Severity.LOW))
        return Event(
            id=self.id_factory(raw_event),
            source=str(raw_event.get("source", "unknown")),
            asset_id=str(raw_event.get("asset_id", "unknown")),
            severity=severity,
            category=str(raw_event.get("category", "unknown")),
            timestamp=timestamp,
            raw_payload=dict(raw_event),
        )


def stream_events(source: EventSource, normalizer: EventNormalizer) -> Iterator[Event]:
    """Yield normalized events from the event source."""

    for raw_event in source.fetch():
        yield normalizer.normalize(raw_event)