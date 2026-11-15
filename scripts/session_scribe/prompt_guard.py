#!/usr/bin/env python3
"""AI Prompt Injection & Jailbreak detection shield for PENT-20 Session Scribe.

Inspects subagent prompts, reasoning rationales, commands, and simulated or live
target output for direct/indirect prompt injection, scope-bypass jailbreaks,
obfuscated payloads (Base64 / Hex / ROT13), and secret/environment exfiltration
attempts using only the Python standard library.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import re
from dataclasses import asdict, dataclass
from typing import Any

REFUSED_PROMPT_INJECTION = "REFUSED_PROMPT_INJECTION"

_OVERRIDE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "INSTRUCTION_OVERRIDE",
        re.compile(
            r"(?i)\bignore\s+(?:all\s+|any\s+)?(?:previous|prior|above|system)\s+"
            r"(?:instructions|prompts|rules|constraints|policies)\b"
        ),
    ),
    (
        "SCOPE_OVERRIDE_ATTEMPT",
        re.compile(r"(?i)\boverride\s+(?:the\s+|all\s+)?scope(?:\.json|\s+policy|\s+rules|\s+manifest)?\b"),
    ),
    (
        "GUARD_BYPASS_ATTEMPT",
        re.compile(r"(?i)\bbypass\s+(?:the\s+|all\s+)?(?:scope\s*)?(?:guard|filter|policy|check|restrictions)\b"),
    ),
    (
        "SYSTEM_PROMPT_EXPOSURE",
        re.compile(r"(?i)\bsystem\s+prompt\b"),
    ),
    (
        "JAILBREAK_PERSONA",
        re.compile(
            r"(?i)\b(?:disregard\s+(?:all\s+)?(?:scope|safety|authorization|previous|rules)|"
            r"(?:enter|switch\s+to|act\s+as|you\s+are\s+now\s+in)\s+"
            r"(?:dan|jailbreak|unrestricted|developer|god)\s+mode)\b"
        ),
    ),
)

_EXFIL_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "ENV_SECRET_EXFILTRATION",
        re.compile(
            r"(?i)(?:\$|\$\{)(?:AWS_SECRET(?:_ACCESS_KEY)?|AWS_ACCESS_KEY_ID|"
            r"AWS_SESSION_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY|SECRET_KEY|"
            r"GITHUB_TOKEN|PENT20_SIGNING_KEY|PASSWORD|DB_PASS)\b"
        ),
    ),
    (
        "SENSITIVE_FILE_EXFILTRATION",
        re.compile(
            r"(?i)(?:\b(?:cat|head|tail|less|more|type|grep|awk|sed)\s+[^\n]*?)?"
            r"(?:/etc/shadow|/etc/passwd|~/\.ssh/id_rsa|\bid_rsa\b|session_signing\.key)\b"
        ),
    ),
    (
        "ENV_DUMP_ATTEMPT",
        re.compile(r"(?:(?:^|[;\s|&])\b(?:env|printenv)\b(?=\s*$|\s+[A-Z_-]+|\s*[|;>&])|(?i:\b(?:printenv|os\.environ|process\.env)\b))"),
    ),
)

_EXPLICIT_ENCODING_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "ENCODED_PAYLOAD",
        re.compile(
            r"(?i)\b(?:base64\s+-d|base64\s+--decode|codecs\.decode\(|bytes\.fromhex\(|"
            r"fromhex\(|eval\s*\(\s*compile\b|(?:rot13|b64|base64_payload|hex_payload)\s*:)"
        ),
    ),
    (
        "ENCODED_PAYLOAD",
        re.compile(r"(?:\\x[0-9a-fA-F]{2}){6,}"),
    ),
)

_BASE64_CANDIDATE_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])")
_HEX_CANDIDATE_RE = re.compile(r"\b(?:0x)?([0-9a-fA-F]{24,})\b")

_DECODED_SUSPICIOUS_RE = re.compile(
    r"(?i)\b(?:ignore|override|bypass|scope\.json|system\s+prompt|shadow|passwd|"
    r"aws_secret|printenv|os\.environ|jailbreak|disregard|rm\s+-rf|bash\s+-c)\b"
)


@dataclass(frozen=True)
class PromptThreatResult:
    """Result of scanning prompt, reasoning, command, or output for injection threats."""

    safe: bool
    status: str
    matched_rules: tuple[str, ...]
    reason: str
    severity: str = "NONE"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class PromptInjectionError(PermissionError):
    """Raised when prompt injection, jailbreak, or exfiltration payload is detected."""

    def __init__(self, result: PromptThreatResult) -> None:
        super().__init__(result.reason)
        self.result = result

    def to_dict(self) -> dict[str, Any]:
        return {
            "error": "PromptInjectionError",
            **self.result.to_dict(),
        }


def _is_mostly_printable_ascii(raw: bytes) -> bool:
    if not raw:
        return False
    printable = sum(1 for b in raw if 32 <= b <= 126 or b in (9, 10, 13))
    return (printable / len(raw)) >= 0.85


class PromptInjectionGuard:
    """Detects direct/indirect prompt injections, obfuscated payloads, and secret exfiltration."""

    def _scan_plain_patterns(self, text: str) -> list[tuple[str, str]]:
        hits: list[tuple[str, str]] = []
        for rule_name, pattern in _OVERRIDE_PATTERNS + _EXFIL_PATTERNS + _EXPLICIT_ENCODING_PATTERNS:
            m = pattern.search(text)
            if m:
                hits.append((rule_name, m.group(0).strip()))
        return hits

    def _scan_obfuscations(self, text: str) -> list[tuple[str, str]]:
        hits: list[tuple[str, str]] = []

        # Check suspicious Base64 blobs whose decoded ASCII contains threat indicators
        for m in _BASE64_CANDIDATE_RE.finditer(text):
            token = m.group(0)
            if len(token) % 4 != 0:
                continue
            try:
                decoded_bytes = base64.b64decode(token, validate=True)
            except (binascii.Error, ValueError):
                continue
            if _is_mostly_printable_ascii(decoded_bytes):
                decoded_text = decoded_bytes.decode("ascii", errors="ignore")
                if _DECODED_SUSPICIOUS_RE.search(decoded_text) or self._scan_plain_patterns(decoded_text):
                    hits.append(("ENCODED_BASE64_PAYLOAD", decoded_text[:80]))

        # Check suspicious hex-encoded ASCII payloads (skip random hashes unless printable ASCII threats decode)
        for m in _HEX_CANDIDATE_RE.finditer(text):
            hex_part = m.group(1)
            if len(hex_part) % 2 != 0:
                continue
            try:
                decoded_bytes = bytes.fromhex(hex_part)
            except ValueError:
                continue
            if _is_mostly_printable_ascii(decoded_bytes):
                decoded_text = decoded_bytes.decode("ascii", errors="ignore")
                if _DECODED_SUSPICIOUS_RE.search(decoded_text) or self._scan_plain_patterns(decoded_text):
                    hits.append(("ENCODED_HEX_PAYLOAD", decoded_text[:80]))

        # Check ROT13-obfuscated jailbreak / exfiltration instructions
        rot_decoded = codecs.decode(text, "rot_13")
        for rule_name, pattern in _OVERRIDE_PATTERNS + _EXFIL_PATTERNS:
            m = pattern.search(rot_decoded)
            if m:
                hits.append(("ENCODED_ROT13_PAYLOAD", f"ROT13->{m.group(0).strip()}"))

        return hits

    def inspect_text(self, text: str | None, *, context: str = "input") -> PromptThreatResult:
        """Scan a single string for prompt injection, obfuscation, or exfiltration."""
        if not text or not str(text).strip():
            return PromptThreatResult(
                safe=True,
                status="SAFE",
                matched_rules=(),
                reason="No threat patterns detected.",
                severity="NONE",
            )

        sample = str(text)
        hits = self._scan_plain_patterns(sample)
        hits.extend(self._scan_obfuscations(sample))

        if not hits:
            return PromptThreatResult(
                safe=True,
                status="SAFE",
                matched_rules=(),
                reason="No threat patterns detected.",
                severity="NONE",
            )

        unique_rules: list[str] = []
        snippets: list[str] = []
        for rule_name, snippet in hits:
            if rule_name not in unique_rules:
                unique_rules.append(rule_name)
            if snippet and snippet not in snippets and len(snippets) < 3:
                snippets.append(snippet)

        reason = (
            f"Prompt Injection / Jailbreak blocked in {context}: "
            f"rules=[{', '.join(unique_rules)}], matched={snippets!r}"
        )
        return PromptThreatResult(
            safe=False,
            status=REFUSED_PROMPT_INJECTION,
            matched_rules=tuple(unique_rules),
            reason=reason,
            severity="CRITICAL_BLOCKED",
        )

    def inspect_prompt(
        self,
        *,
        prompt: str = "",
        reasoning: str = "",
        command: str = "",
    ) -> PromptThreatResult:
        """Inspect prompt text, reasoning rationale, and command string together."""
        for ctx, value in (
            ("prompt", prompt),
            ("reasoning", reasoning),
            ("command", command),
        ):
            res = self.inspect_text(value, context=ctx)
            if not res.safe:
                return res
        return PromptThreatResult(
            safe=True,
            status="SAFE",
            matched_rules=(),
            reason="Prompt, reasoning, and command passed PromptInjectionGuard.",
            severity="NONE",
        )
