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
    """Simple executor that records executed actions for verification."""

    executed: List[str]

    def execute(self, action: PlaybookAction, context: Dict[str, object]) -> None:
        self.executed.append(f"{action.type}:{context.get('incident_id', 'unknown')}")


@dataclass
class PlaybookEngine:
    """Run playbooks that match an alert."""

    playbooks: Iterable[Playbook]
    executor_factory: Callable[[Playbook], ActionExecutor]

    def run(self, alert: Alert, context: Dict[str, object]) -> List[str]:
        executed: List[str] = []
        for playbook in self.playbooks:
            if playbook.trigger_condition in {alert.rule_id, alert.severity.value, "*"}:
                executor = self.executor_factory(playbook)
                for action in playbook.actions:
                    executor.execute(action, context)
                    executed.append(action.type)
        return executed