#!/usr/bin/env python3
"""Autonomous agent Circuit Breaker & Emergency Kill-Switch for PENT-20.

Tracks consecutive scope and prompt-injection violations and trips into an
``OPEN (LOCKED)`` state when ``max_violations`` (default: 3) is reached,
freezing the subagent via ``EmergencyKillSwitchError`` until an operator
performs an audited ``reset_with_human_token(operator, reason)`` unlock.
Uses only Python standard library modules.
"""
from __future__ import annotations

import hashlib
from typing import Any

VIOLATION_STATUSES = ("REFUSED_OUT_OF_SCOPE", "REFUSED_PROMPT_INJECTION")
RESET_STATUSES = ("EXECUTED", "ALLOWED", "CIRCUIT_RESET")


class EmergencyKillSwitchError(RuntimeError):
    """Raised when the subagent circuit breaker trips or is invoked while OPEN (LOCKED)."""

    def __init__(
        self,
        reason: str,
        *,
        consecutive_violations: int,
        max_violations: int,
        state: str = "OPEN (LOCKED)",
        last_violation_status: str = "",
    ) -> None:
        super().__init__(reason)
        self.reason = reason
        self.consecutive_violations = consecutive_violations
        self.max_violations = max_violations
        self.state = state
        self.last_violation_status = last_violation_status

    def to_dict(self) -> dict[str, Any]:
        return {
            "error": "EmergencyKillSwitchError",
            "state": self.state,
            "consecutive_violations": self.consecutive_violations,
            "max_violations": self.max_violations,
            "last_violation_status": self.last_violation_status,
            "reason": self.reason,
        }


class SubagentCircuitBreaker:
    """Consecutive-violation circuit breaker protecting against runaway subagent abuse."""

    def __init__(self, max_violations: int = 3, *, audit_logger: Any | None = None) -> None:
        if int(max_violations) < 1:
            raise ValueError("max_violations must be at least 1.")
        self.max_violations: int = int(max_violations)
        self._audit_logger = audit_logger
        self.consecutive_violations: int = 0
        self.total_violations: int = 0
        self.total_trips: int = 0
        self._locked: bool = False
        self.last_violation_status: str = ""
        self.last_violation_reason: str = ""
        self.unlock_history: list[dict[str, Any]] = []

    @property
    def is_locked(self) -> bool:
        return self._locked

    @property
    def state(self) -> str:
        return "OPEN (LOCKED)" if self._locked else "CLOSED (ARMED)"

    def check_before_step(self) -> None:
        """Raise ``EmergencyKillSwitchError`` immediately if the breaker is locked."""
        if self._locked:
            raise EmergencyKillSwitchError(
                (
                    f"Subagent frozen by Emergency Kill-Switch ({self.state}): "
                    f"{self.consecutive_violations}/{self.max_violations} consecutive violations. "
                    "Call reset_with_human_token(operator, reason) to resume."
                ),
                consecutive_violations=self.consecutive_violations,
                max_violations=self.max_violations,
                state=self.state,
                last_violation_status=self.last_violation_status,
            )

    def record_outcome(self, status: str, reason: str = "") -> bool:
        """Update violation counter from a step outcome; returns True if circuit is OPEN (LOCKED)."""
        if status in VIOLATION_STATUSES:
            self.consecutive_violations += 1
            self.total_violations += 1
            self.last_violation_status = status
            self.last_violation_reason = reason
            if self.consecutive_violations >= self.max_violations:
                if not self._locked:
                    self.total_trips += 1
                self._locked = True
                return True
            return False

        if status in RESET_STATUSES:
            self.consecutive_violations = 0
            return False

        return self._locked

    def reset_with_human_token(
        self,
        operator: str,
        reason: str,
        *,
        audit_logger: Any | None = None,
    ) -> dict[str, Any]:
        """Unlock an OPEN circuit breaker after verified human operator override."""
        if not isinstance(operator, str) or not operator.strip():
            raise ValueError("Operator identity must be a non-empty string to reset circuit breaker.")
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("Override reason must be a non-empty string to reset circuit breaker.")

        clean_op = operator.strip()
        clean_reason = reason.strip()

        self._locked = False
        self.consecutive_violations = 0

        unlock_event: dict[str, Any] = {
            "operator": clean_op,
            "reason": clean_reason,
            "state": self.state,
            "total_trips": self.total_trips,
        }

        target_logger = audit_logger if audit_logger is not None else self._audit_logger
        if target_logger is not None:
            prompt_hash = hashlib.sha256(f"circuit-unlock:{clean_op}:{clean_reason}".encode("utf-8")).hexdigest()
            entry = target_logger.log_step(
                target="localhost",
                port=None,
                command=f"circuit-breaker reset --operator {clean_op}",
                status="CIRCUIT_RESET",
                duration_ms=0.0,
                output_summary=f"HUMAN_OVERRIDE_UNLOCK operator={clean_op}: {clean_reason}",
                matched_rule="human_operator_override",
                ai_disclosure={
                    "agent_id": f"human-operator:{clean_op}",
                    "model": "human-in-the-loop",
                    "reasoning": clean_reason,
                    "human_approved": True,
                    "tool_name": "circuit_breaker",
                    "prompt_hash": prompt_hash,
                    "prompt_summary": f"Reset circuit breaker by operator {clean_op}",
                },
            )
            unlock_event["seq"] = entry["seq"]
            unlock_event["entry_hash"] = entry["entry_hash"]
            unlock_event["timestamp"] = entry["timestamp"]

        self.unlock_history.append(unlock_event)
        return unlock_event

    def summary(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "is_locked": self._locked,
            "consecutive_violations": self.consecutive_violations,
            "max_violations": self.max_violations,
            "total_violations": self.total_violations,
            "total_trips": self.total_trips,
            "last_violation_status": self.last_violation_status,
            "last_violation_reason": self.last_violation_reason,
            "unlock_history": list(self.unlock_history),
        }
