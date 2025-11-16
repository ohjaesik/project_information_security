from rich.console import Console
from rich.table import Table
from rich.panel import Panel


def render_rich_dashboard(result: dict) -> None:
    """
    security_dashboard.DashboardPipeline.run() 결과 dict를
    rich를 이용해서 예쁘게 출력해준다.
    """
    console = Console()

    alerts = result.get("alerts", [])
    incidents = result.get("incidents", [])
    reports = result.get("reports", [])
    actions = result.get("executed_actions", [])

    # 🚨 Alerts 테이블
    alerts_table = Table(title=" Alerts")
    alerts_table.add_column("ID")
    alerts_table.add_column("Rule")
    alerts_table.add_column("Severity")
    alerts_table.add_column("Events")

    for a in alerts:
        alerts_table.add_row(
            a.id,
            a.rule_id,
            a.severity.value,
            ", ".join(a.event_ids),
        )

    # 🧩 Incidents 테이블
    inc_table = Table(title=" Incidents")
    inc_table.add_column("ID")
    inc_table.add_column("Priority")
    inc_table.add_column("Assignee")
    inc_table.add_column("Resolution")
    inc_table.add_column("Alerts")

    for inc in incidents:
        inc_table.add_row(
            inc.id,
            inc.priority.value,
            inc.assignee or "-",
            inc.resolution or "-",
            ", ".join(sorted(inc.alert_ids)),
        )

    # 📊 Reports 패널
    report_panels = []
    for rep in reports:
        lines = [f"type: {rep.type}"]
        for k, v in rep.findings.items():
            lines.append(f"{k}: {v}")
        body = "\n".join(lines)
        report_panels.append(Panel(body, title=f" {rep.id}"))

    # 🤖 Executed Actions 패널
    actions_text = "\n".join(actions) if actions else "(none)"
    actions_panel = Panel(actions_text, title=" Executed Actions")

    # 실제 출력
    console.rule("[bold cyan]Security Dashboard Result[/bold cyan]")
    console.print(alerts_table)
    console.print(inc_table)
    for p in report_panels:
        console.print(p)
    console.print(actions_panel)
    console.rule()