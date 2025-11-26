"""SOAR automation helpers."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Protocol

from .models import Alert, Playbook, PlaybookAction


class ActionExecutor(Protocol):
    """
    Protocol interface for executing playbook actions.
    """

    def execute(self, action: PlaybookAction, context: Dict[str, object]) -> None:
        """
        Execute a single playbook action with the given execution context.
        """
        ...


@dataclass
class LoggingActionExecutor:
    """
    Action executor that records human-readable execution logs.

    The executed action messages are appended to the shared executed_actions list
    injected by DashboardPipeline.run(), and reflected in the final API result.
    """

    executed_actions: List[str]

    def execute(self, action: PlaybookAction, context: Dict[str, object]) -> None:
        action_type = action.type
        params = action.parameters or {}

        # Common execution context (incident_id, alert_id, etc.)
        incident_id = context.get("incident_id", "-")
        alert_id = context.get("alert_id", "-")

        # In a production environment, actual API calls or system commands
        # should be implemented inside each branch below.
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
            # Unknown or unsupported action type
            msg = f"[unknown-action] type={action_type}, incident={incident_id}, alert={alert_id}, params={params}"

        # Append the execution log for UI visualization
        self.executed_actions.append(msg)

    # --- The following methods can be connected to real APIs or scripts in production ---

    def _isolate_host(self, params: Dict[str, object], context: Dict[str, object]) -> None:
        """
        Host isolation action.
        Example use cases:
        - Firewall API
        - Network Access Control (NAC)
        - Endpoint Detection & Response (EDR) platform

        Currently implemented as a safe placeholder.
        """
        host = params.get("asset_id") or context.get("asset_id") or "unknown-host"
        method = params.get("method", "network")

        # TODO: Integrate real firewall / NAC / EDR API calls here
        print(f"[ACTION] isolate-host: host={host}, method={method}")

    def _disable_account(self, params: Dict[str, object], context: Dict[str, object]) -> None:
        """
        User account deactivation action.
        Example use cases:
        - Active Directory (AD)
        - LDAP
        """
        account = params.get("account") or context.get("username") or "unknown-user"
        print(f"[ACTION] disable-account: account={account}")

        # TODO: Integrate with real identity management systems

    def _force_password_reset(self, params: Dict[str, object], context: Dict[str, object]) -> None:
        """
        Force password reset action.
        """
        account = params.get("account") or context.get("username") or "unknown-user"
        print(f"[ACTION] force-password-reset: account={account}")

        # TODO: Integrate with password reset workflows

    def _notify(self, params: Dict[str, object], context: Dict[str, object]) -> None:
        """
        Notification action for Slack, Email, Teams, etc.
        """
        channel = params.get("channel", "slack")
        print(f"[ACTION] notify via {channel}: context={context}")

        # TODO: Integrate with webhooks, SMTP servers, or messaging APIs
        # Example (Slack webhook):
        #   import os, requests
        #   url = os.environ.get("SLACK_WEBHOOK_URL")
        #   if url:
        #       requests.post(url, json={"text": f"Security alert: {context}"})


class PlaybookEngine:
    """
    Playbook execution engine for handling security alerts.
    """

    def __init__(self, playbooks: Iterable[Playbook], executor_factory):
        self.playbooks = playbooks
        self.executor_factory = executor_factory

    def run(self, alert: Alert, context: Dict[str, object]) -> List[str]:
        """
        Execute all playbooks whose trigger conditions match the given alert.
        """
        executed: List[str] = []

        for pb in self.playbooks:
            # The playbook is triggered if its condition matches:
            # - alert.rule_id
            # - alert.severity
            # - wildcard ("*")
            if pb.trigger_condition in {alert.rule_id, alert.severity.value, "*"}:
                executor = self.executor_factory(pb)

                for action in pb.actions:
                    executor.execute(action, context)
                    executed.append(action.type)

        return executed
