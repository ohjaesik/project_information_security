# security_dashboard/automation.py

"""SOAR automation helpers."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Protocol

from .models import Alert, Playbook, PlaybookAction


class ActionExecutor(Protocol):
    """Protocol for executing playbook actions."""

    def execute(self, action: PlaybookAction, context: Dict[str, object]) -> None:
        """Execute a single action."""


@dataclass
class LoggingActionExecutor:
    """
    실제 액션을 수행하고, 사람이 읽을 수 있는 로그를 executed_actions에 쌓는 실행기.

    DashboardPipeline.run() 에서 self.executed_actions 리스트를 공유해 주입하므로,
    여기서 append() 하면 최종 result["executed_actions"] 에 그대로 반영된다.
    """

    executed_actions: List[str]

    def execute(self, action: PlaybookAction, context: Dict[str, object]) -> None:
        action_type = action.type
        params = action.parameters or {}

        # 공통 컨텍스트 (incident_id, alert_id 등)
        incident_id = context.get("incident_id", "-")
        alert_id = context.get("alert_id", "-")

        # 실제 환경에 연동하려면 아래 분기 안에 API 호출 / 스크립트 실행을 넣으면 된다.
        if action_type == "isolate-host":
            self._isolate_host(params, context)
            msg = f"[isolate-host] Isolated host (incident={incident_id}, alert={alert_id}, params={params})"

        elif action_type == "disable-account":
            self._disable_account(params, context)
            msg = f"[disable-account] Disabled account (incident={incident_id}, alert={alert_id}, params={params})"

        elif action_type == "force-password-reset":
            self._force_password_reset(params, context)
            msg = f"[force-password-reset] Forced password reset (incident={incident_id}, alert={alert_id}, params={params})"

        elif action_type == "notify":
            self._notify(params, context)
            msg = f"[notify] Sent notification (incident={incident_id}, alert={alert_id}, params={params})"

        else:
            # 알 수 없는 타입은 그냥 로깅만
            msg = f"[unknown-action] type={action_type}, incident={incident_id}, alert={alert_id}, params={params}"

        # UI에 보여줄 실행 내역 추가
        self.executed_actions.append(msg)

    # --- 아래 메서드들에 실제 액션(API, 스크립트)을 붙이면 된다. ---

    def _isolate_host(self, params: Dict[str, object], context: Dict[str, object]) -> None:
        """
        호스트 격리 액션.
        예: 방화벽 API, netsh, EDR API 등을 호출해서 IP/호스트를 차단.

        지금은 안전하게 'TODO' 자리 + print만 둔다.
        """
        host = params.get("asset_id") or context.get("asset_id") or "unknown-host"
        method = params.get("method", "network")

        # TODO: 실제 환경에서는 여기서 방화벽 / NAC / EDR API 호출
        # 예시(Windows 방화벽):
        #   import subprocess
        #   subprocess.run(
        #       ["netsh", "advfirewall", "firewall", "add", "rule",
        #        "name=BlockHost", "dir=in", f"remoteip={host}", "action=block"],
        #       check=False,
        #   )
        print(f"[ACTION] isolate-host: host={host}, method={method}")

    def _disable_account(self, params: Dict[str, object], context: Dict[str, object]) -> None:
        """
        계정 비활성화 액션.
        예: AD/LDAP API 호출해서 계정 disabled 처리.
        """
        account = params.get("account") or context.get("username") or "unknown-user"
        print(f"[ACTION] disable-account: account={account}")
        # TODO: 실제 환경 계정 시스템과 연동

    def _force_password_reset(self, params: Dict[str, object], context: Dict[str, object]) -> None:
        """
        비밀번호 초기화/교체 강제.
        """
        account = params.get("account") or context.get("username") or "unknown-user"
        print(f"[ACTION] force-password-reset: account={account}")
        # TODO: 비밀번호 재설정 워크플로우 연동

    def _notify(self, params: Dict[str, object], context: Dict[str, object]) -> None:
        """
        Slack / Email / Teams 등 알림 전송.
        """
        channel = params.get("channel", "slack")
        print(f"[ACTION] notify via {channel}: context={context}")
        # TODO: 웹훅, SMTP 등 실제 알림 연동
        # 예시 (Slack Webhook):
        #   import os, requests
        #   url = os.environ.get("SLACK_WEBHOOK_URL")
        #   if url:
        #       requests.post(url, json={"text": f"Security alert: {context}"})


class PlaybookEngine:
    """
    Run security playbooks for alerts.
    """

    def __init__(self, playbooks: Iterable[Playbook], executor_factory):
        self.playbooks = playbooks
        self.executor_factory = executor_factory

    def run(self, alert: Alert, context: Dict[str, object]) -> List[str]:
        executed: List[str] = []

        for pb in self.playbooks:
            # playbook.trigger_condition이 rule_id 또는 severity 값과 매칭되면 실행
            if pb.trigger_condition in {alert.rule_id, alert.severity.value, "*"}:
                executor = self.executor_factory(pb)

                for action in pb.actions:
                    executor.execute(action, context)
                    executed.append(action.type)

        return executed
