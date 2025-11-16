from datetime import UTC, datetime, timedelta

from security_dashboard import InMemoryEventSource, default_pipeline


def build_sample_events():
    now = datetime.now(UTC)
    return [
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
            "asset_id": "srv-2",
            "severity": "high",
            "category": "auth",
            "timestamp": (now - timedelta(minutes=3)).isoformat(),
            "failed_attempts": 8,
        },
    ]


def print_events(events):
    print("\n=== EVENTS ===")
    print("id      asset   severity   category   source")
    print("-----------------------------------------------")
    for e in events:
        print(
            f"{e.id:7} {e.asset_id:7} {e.severity.value:9} "
            f"{e.category:9} {e.source}"
        )


def print_alerts(alerts):
    print("\n=== ALERTS ===")
    print("id                 rule     severity   events")
    print("-----------------------------------------------------")
    for a in alerts:
        ev_ids = ",".join(a.event_ids)
        print(
            f"{a.id:18} {a.rule_id:8} {a.severity.value:9} {ev_ids}"
        )


def print_incidents(incidents):
    print("\n=== INCIDENTS ===")
    if not incidents:
        print("(none)")
        return
    for inc in incidents:
        print(
            f"- {inc.id} | priority={inc.priority.value} "
            f"| assignee={inc.assignee} | resolution={inc.resolution}"
        )
        print("  timeline:")
        for line in inc.timeline:
            print("   ·", line)


def print_reports(reports):
    print("\n=== REPORTS ===")
    for rep in reports:
        print(f"- {rep.type} ({rep.id})")
        print(f"  period: {rep.period_start} ~ {rep.period_end}")
        print("  findings:")
        for k, v in rep.findings.items():
            print(f"    {k}: {v}")


def print_actions(actions):
    print("\n=== EXECUTED ACTIONS ===")
    if not actions:
        print("(none)")
    else:
        for a in actions:
            print(" -", a)


def main():
    events = build_sample_events()
    source = InMemoryEventSource(events)
    pipeline = default_pipeline(source)

    result = pipeline.run()

    print_events(result["events"])
    print_alerts(result["alerts"])
    print_incidents(result["incidents"])
    print_reports(result["reports"])
    print_actions(result["executed_actions"])


if __name__ == "__main__":
    main()