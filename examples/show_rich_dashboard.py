from datetime import UTC, datetime, timedelta

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

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


def main():
    console = Console()

    source = InMemoryEventSource(build_sample_events())
    pipeline = default_pipeline(source)
    result = pipeline.run()

    # Alerts table
    alerts_table = Table(title="" \
    " Alerts")
    alerts_table.add_column("ID")
    alerts_table.add_column("Rule")
    alerts_table.add_column("Severity")
    alerts_table.add_column("Events")

    for a in result["alerts"]:
        alerts_table.add_row(
            a.id, a.rule_id, a.severity.value, ", ".join(a.event_ids)
        )

    # Incidents table
    inc_table = Table(title=" Incidents")
    inc_table.add_column("ID")
    inc_table.add_column("Priority")
    inc_table.add_column("Assignee")
    inc_table.add_column("Resolution")

    for inc in result["incidents"]:
        inc_table.add_row(
            inc.id,
            inc.priority.value,
            inc.assignee or "-",
            inc.resolution or "-",
        )

    # Reports panel
    reports_panels = []
    for rep in result["reports"]:
        body_lines = [f"type: {rep.type}"]
        for k, v in rep.findings.items():
            body_lines.append(f"{k}: {v}")
        body = "\n".join(body_lines)
        reports_panels.append(Panel(body, title=f" {rep.id}"))

    # Executed actions
    actions_text = "\n".join(result["executed_actions"]) or "(none)"
    actions_panel = Panel(actions_text, title=" Executed Actions")

    console.print(alerts_table)
    console.print(inc_table)
    for p in reports_panels:
        console.print(p)
    console.print(actions_panel)


if __name__ == "__main__":
    main()