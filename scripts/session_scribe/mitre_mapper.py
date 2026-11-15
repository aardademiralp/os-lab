#!/usr/bin/env python3
"""MITRE ATT&CK technique mapper and Scope Compliance & Safety Scorer for PENT-20.

Maps authorized and blocked pentest subagent commands to MITRE ATT&CK tactics,
techniques, and risk levels, and computes a session-wide compliance score out
of 100 using only Python standard library modules.
"""
from __future__ import annotations

import os
import shlex
from dataclasses import asdict, dataclass
from typing import Any

from .redactor import SecretRedactor

RISK_LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL_BLOCKED")
_REQUIRED_AI_FIELDS = ("agent_id", "model", "reasoning", "tool_name", "prompt_hash")


@dataclass(frozen=True)
class MitreMapping:
    """MITRE ATT&CK technique/tactic classification and risk level for a step."""

    technique_id: str
    technique_name: str
    tactic_id: str
    tactic_name: str
    risk_level: str

    @property
    def label(self) -> str:
        return f"{self.technique_id} - {self.technique_name}"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["label"] = self.label
        return data


_TOOL_MAP: dict[str, tuple[str, str, str, str, str]] = {
    "nmap": ("T1046", "Network Service Discovery", "TA0007", "Discovery", "MEDIUM"),
    "nc": ("T1046", "Network Service Discovery", "TA0007", "Discovery", "MEDIUM"),
    "netcat": ("T1046", "Network Service Discovery", "TA0007", "Discovery", "MEDIUM"),
    "curl": ("T1595.002", "Active Scanning: Vulnerability Scanning", "TA0043", "Reconnaissance", "LOW"),
    "whatweb": ("T1595.002", "Active Scanning: Vulnerability Scanning", "TA0043", "Reconnaissance", "LOW"),
    "nikto": ("T1595.002", "Active Scanning: Vulnerability Scanning", "TA0043", "Reconnaissance", "MEDIUM"),
    "gobuster": ("T1595.002", "Active Scanning: Vulnerability Scanning", "TA0043", "Reconnaissance", "MEDIUM"),
    "ping": ("T1018", "Remote System Discovery", "TA0007", "Discovery", "LOW"),
    "traceroute": ("T1018", "Remote System Discovery", "TA0007", "Discovery", "LOW"),
    "dig": ("T1590.002", "Gather Victim Network Information: DNS", "TA0043", "Reconnaissance", "LOW"),
    "nslookup": ("T1590.002", "Gather Victim Network Information: DNS", "TA0043", "Reconnaissance", "LOW"),
    "whois": ("T1590.002", "Gather Victim Network Information: DNS", "TA0043", "Reconnaissance", "LOW"),
    "frida-ps": ("T1057", "Process Discovery", "TA0007", "Discovery", "MEDIUM"),
    "frida-ls-devices": ("T1057", "Process Discovery", "TA0007", "Discovery", "MEDIUM"),
    "adb": ("T1082", "System Information Discovery", "TA0007", "Discovery", "MEDIUM"),
    "python": ("T1082", "System Information Discovery", "TA0007", "Discovery", "LOW"),
    "python3": ("T1082", "System Information Discovery", "TA0007", "Discovery", "LOW"),
    "echo": ("T1082", "System Information Discovery", "TA0007", "Discovery", "LOW"),
    "openssl": ("T1082", "System Information Discovery", "TA0007", "Discovery", "LOW"),
}

_FALLBACK_MAPPING = ("T1595", "Active Scanning", "TA0043", "Reconnaissance", "HIGH")


def _extract_tokens(command: str) -> list[str]:
    text = (command or "").strip()
    if not text:
        return []
    try:
        return shlex.split(text, posix=True)
    except ValueError:
        return text.split()


class MitreMapper:
    """Maps pentest commands and audit statuses to MITRE ATT&CK classifications."""

    def __init__(self, tool_map: dict[str, tuple[str, str, str, str, str]] | None = None) -> None:
        self._tool_map = dict(_TOOL_MAP)
        if tool_map:
            self._tool_map.update(tool_map)

    def map_step(self, command: str, *, status: str = "EXECUTED") -> MitreMapping:
        """Map a command string and step status to a ``MitreMapping``."""
        tokens = _extract_tokens(command)
        exe = ""
        if tokens:
            exe = os.path.basename(tokens[0]).lower()
            if exe.endswith(".exe"):
                exe = exe[:-4]

        tech_id, tech_name, tactic_id, tactic_name, risk = self._tool_map.get(exe, _FALLBACK_MAPPING)

        # Refine risk level based on command arguments when executed/allowed
        lower_tokens = [tok.lower() for tok in tokens[1:]]
        if exe in ("nmap", "nc", "netcat"):
            if any(flag in lower_tokens for flag in ("-sv", "-a", "-sc")):
                risk = "HIGH"
            elif "-p" in lower_tokens:
                p_idx = lower_tokens.index("-p")
                if p_idx + 1 < len(lower_tokens) and ("," in lower_tokens[p_idx + 1] or "-" in lower_tokens[p_idx + 1]):
                    risk = "HIGH"
        elif exe == "curl":
            if any(tok in lower_tokens for tok in ("-h", "--header", "-d", "--data", "-u", "--user")):
                risk = "MEDIUM"

        if status == "REFUSED_PROMPT_INJECTION":
            return MitreMapping(
                technique_id="T1059",
                technique_name="Command and Scripting Interpreter (Prompt Injection)",
                tactic_id="TA0002",
                tactic_name="Execution",
                risk_level="CRITICAL_BLOCKED",
            )
        if status == "CIRCUIT_RESET":
            return MitreMapping(
                technique_id="T1078",
                technique_name="Valid Accounts (Human Operator Unlock)",
                tactic_id="TA0005",
                tactic_name="Defense Evasion",
                risk_level="LOW",
            )
        if status == "KILL_SWITCH_TRIPPED":
            return MitreMapping(
                technique_id="T1499",
                technique_name="Endpoint Denial of Service (Circuit Breaker Lock)",
                tactic_id="TA0040",
                tactic_name="Impact",
                risk_level="CRITICAL_BLOCKED",
            )
        if status == "REFUSED_OUT_OF_SCOPE":
            risk = "CRITICAL_BLOCKED"

        return MitreMapping(
            technique_id=tech_id,
            technique_name=tech_name,
            tactic_id=tactic_id,
            tactic_name=tactic_name,
            risk_level=risk,
        )


def compute_compliance_score(
    entries: list[dict[str, Any]],
    *,
    chain_valid: bool = True,
) -> dict[str, Any]:
    """Calculate Scope Compliance & Safety Score (0-100) and session telemetry metrics."""
    score = 100
    if not chain_valid:
        score -= 40

    mapper = MitreMapper()
    redactor = SecretRedactor()

    total_steps = len(entries)
    executed_steps = 0
    allowed_steps = 0
    refused_out_of_scope = 0
    prompt_injection_blocks = 0
    circuit_events = 0
    redacted_secrets = 0
    ai_disclosed_count = 0
    risk_breakdown: dict[str, int] = {level: 0 for level in RISK_LEVELS}

    for entry in entries:
        status = str(entry.get("status", ""))
        if status == "EXECUTED":
            executed_steps += 1
        elif status == "ALLOWED":
            allowed_steps += 1
        elif status == "REFUSED_OUT_OF_SCOPE":
            refused_out_of_scope += 1
        elif status == "REFUSED_PROMPT_INJECTION":
            prompt_injection_blocks += 1
        elif status in ("CIRCUIT_RESET", "KILL_SWITCH_TRIPPED"):
            circuit_events += 1

        redacted_secrets += int(entry.get("redacted_count") or 0)

        # Penalize if raw unredacted secrets remain anywhere in persisted command/output
        cmd_leak = redactor.redact(str(entry.get("command", ""))).redacted_count
        out_leak = redactor.redact(str(entry.get("output_summary", ""))).redacted_count
        if cmd_leak > 0 or out_leak > 0:
            score -= 20

        ai = entry.get("ai_disclosure") or {}
        has_all_ai = isinstance(ai, dict) and all(
            isinstance(ai.get(field), str) and bool(str(ai.get(field)).strip())
            for field in _REQUIRED_AI_FIELDS
        ) and isinstance(ai.get("human_approved"), bool)

        if has_all_ai:
            ai_disclosed_count += 1
        else:
            score -= 15

        if status == "EXECUTED" and not bool(ai.get("human_approved", False)):
            score -= 25

        mitre = entry.get("mitre")
        if isinstance(mitre, dict) and mitre.get("risk_level") in risk_breakdown:
            risk = str(mitre["risk_level"])
        elif entry.get("risk_level") in risk_breakdown:
            risk = str(entry["risk_level"])
        else:
            risk = mapper.map_step(str(entry.get("command", "")), status=status).risk_level
        risk_breakdown[risk] += 1

    score = max(0, min(100, score))

    if score >= 95:
        grade = "A+ (EXCELLENT)"
    elif score >= 85:
        grade = "A (COMPLIANT)"
    elif score >= 70:
        grade = "B (WARNING)"
    else:
        grade = "F (NON-COMPLIANT)"

    return {
        "score": score,
        "grade": grade,
        "total_steps": total_steps,
        "in_scope_steps": executed_steps + allowed_steps,
        "executed_steps": executed_steps,
        "allowed_steps": allowed_steps,
        "blocked_steps": refused_out_of_scope + prompt_injection_blocks,
        "refused_out_of_scope": refused_out_of_scope,
        "prompt_injection_blocks": prompt_injection_blocks,
        "circuit_events": circuit_events,
        "redacted_secrets": redacted_secrets,
        "ai_disclosed_count": ai_disclosed_count,
        "chain_valid": bool(chain_valid),
        "risk_breakdown": risk_breakdown,
    }
