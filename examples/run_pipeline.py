"""Run the default security dashboard pipeline with sample data."""
from datetime import UTC, datetime, timedelta

from security_dashboard import InMemoryEventSource, default_pipeline


def main() -> None:
    now = datetime.now(UTC)
    events = [
        {
            "id": "evt-1",
            "source": "ids",
            "asset_id": "srv-1",
            "severity": "critical",
            "category": "network",
            "timestamp": (now - timedelta(minutes=1)).isoformat(),
            "details": "Malware beacon detected",
        },
        {
            "id": "evt-2",
            "source": "auth",
            "asset_id": "srv-1",
            "severity": "medium",
            "category": "auth",
            "timestamp": (now - timedelta(minutes=2)).isoformat(),
            "failed_attempts": 10,
        },
        {
            "id": "evt-3",
            "source": "auth",
            "asset_id": "srv-2",
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
            "details": "Suspicious lateral movement",
        },
    ]
    pipeline = default_pipeline(InMemoryEventSource(events))
    result = pipeline.run()
    print(f"Generated {len(result['alerts'])} alerts and {len(result['incidents'])} incidents")
    for report in result["reports"]:
        print(f"Report {report.id}: {report.findings}")
    print(f"Executed actions: {result['executed_actions']}")


if __name__ == "__main__":
    main()