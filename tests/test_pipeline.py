from datetime import UTC, datetime, timedelta

from security_dashboard import InMemoryEventSource, Severity, default_pipeline
from security_dashboard.pretty import render_rich_dashboard

def test_default_pipeline_generates_alerts_and_reports(rich_dashboard):
    now = datetime.now(UTC)
    events = [
        {
            "id": "evt-1",
            "source": "ids",
            "asset_id": "srv-1",
            "severity": "critical",
            "category": "network",
            "timestamp": (now - timedelta(minutes=1)).isoformat(),
        },
        {
            "id": "evt-2",
            "source": "auth",
            "asset_id": "srv-1",
            "severity": "medium",
            "category": "auth",
            "timestamp": (now - timedelta(minutes=2)).isoformat(),
            "failed_attempts": 6,
        },
        {
            "id": "evt-3",
            "source": "auth",
            "asset_id": "srv-1",
            "severity": "medium",
            "category": "auth",
            "timestamp": (now - timedelta(minutes=3)).isoformat(),
            "failed_attempts": 7,
        },
        {
            "id": "evt-4",
            "source": "ids",
            "asset_id": "srv-1",
            "severity": "high",
            "category": "network",
            "timestamp": (now - timedelta(minutes=4)).isoformat(),
        },
    ]
    pipeline = default_pipeline(InMemoryEventSource(events))
    result = pipeline.run()

    assert len(result["alerts"]) >= 2
    assert len(result["incidents"]) == 1
    assert {report.type for report in result["reports"]} == {"event-summary", "incident-summary"}
    assert result["executed_actions"], "Expected automation actions to run"

    if rich_dashboard:
        from rich.console import Console
        console = Console()
        console.print() 
        render_rich_dashboard(result)

def test_pipeline_event_normalization_handles_missing_fields():
    now = datetime.now(UTC)
    events = [
        {
            "id": "evt-1",
            "asset_id": "srv-99",
            "severity": "critical",
            "category": "network",
            "timestamp": (now - timedelta(minutes=1)).isoformat(),
        }
    ]
    pipeline = default_pipeline(InMemoryEventSource(events))
    result = pipeline.run()

    assert result["events"][0].source == "unknown"
    assert result["alerts"][0].severity == Severity.CRITICAL
