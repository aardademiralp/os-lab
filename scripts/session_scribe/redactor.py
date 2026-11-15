#!/usr/bin/env python3
"""DLP-style sensitive data and secret redactor for PENT-20 Session Scribe.

Detects and masks sensitive credentials (API keys, Bearer tokens, JWTs,
AWS access/secret keys, passwords, and SSH/PEM private key blocks) before
commands or outputs are persisted to audit logs or rendered in reports.
Uses only Python standard library modules.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class RedactionResult:
    """Outcome of scanning and redacting text for sensitive values."""

    redacted_text: str
    redacted_count: int
    matched_types: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "redacted_text": self.redacted_text,
            "redacted_count": self.redacted_count,
            "matched_types": list(self.matched_types),
        }


@dataclass(frozen=True)
class _RedactionRule:
    secret_type: str
    pattern: re.Pattern[str]
    replacement: str


_DEFAULT_RULES: tuple[_RedactionRule, ...] = (
    # 1. Private key blocks (multiline PEM/OpenSSH)
    _RedactionRule(
        secret_type="PRIVATE_KEY",
        pattern=re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----"
        ),
        replacement="[REDACTED:PRIVATE_KEY]",
    ),
    # 2. JSON Web Tokens
    _RedactionRule(
        secret_type="JWT",
        pattern=re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
        replacement="[REDACTED:JWT]",
    ),
    # 3. HTTP Authorization Bearer tokens
    _RedactionRule(
        secret_type="BEARER_TOKEN",
        pattern=re.compile(r"(?i)\b(Bearer\s+)(?!\[REDACTED:)[A-Za-z0-9._\-+/=]{8,}"),
        replacement=r"\1[REDACTED:BEARER_TOKEN]",
    ),
    # 4. AWS Access Key IDs & Secret Access Keys
    _RedactionRule(
        secret_type="AWS_SECRET",
        pattern=re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        replacement="[REDACTED:AWS_SECRET]",
    ),
    _RedactionRule(
        secret_type="AWS_SECRET",
        pattern=re.compile(
            r"(?i)\b(aws[_-]?secret(?:[_-]?access[_-]?key)?['\"]?\s*[=:]\s*['\"]?)"
            r"(?!\[REDACTED:)[^\s'\";,}]{8,}(['\"]?)"
        ),
        replacement=r"\1[REDACTED:AWS_SECRET]\2",
    ),
    # 5. Prefixed API keys & key-value API tokens
    _RedactionRule(
        secret_type="API_KEY",
        pattern=re.compile(r"\b(?:sk|pk|rk|ghp|gho|glpat|xoxb|xoxp)-[A-Za-z0-9_\-]{10,}\b"),
        replacement="[REDACTED:API_KEY]",
    ),
    _RedactionRule(
        secret_type="API_KEY",
        pattern=re.compile(
            r"(?i)\b((?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|"
            r"client[_-]?secret|x-api-key)['\"]?\s*[=:]\s*['\"]?)"
            r"(?!\[REDACTED:)[A-Za-z0-9._\-+/=]{6,}(['\"]?)"
        ),
        replacement=r"\1[REDACTED:API_KEY]\2",
    ),
    # 6. Plaintext passwords
    _RedactionRule(
        secret_type="PASSWORD",
        pattern=re.compile(
            r"(?i)\b((?:password|passwd|pwd|db_pass)['\"]?\s*[=:]\s*['\"]?)"
            r"(?!\[REDACTED:)[^\s'\";,}]{3,}(['\"]?)"
        ),
        replacement=r"\1[REDACTED:PASSWORD]\2",
    ),
)


class SecretRedactor:
    """Regex-based secret detector and DLP masker for commands and tool output."""

    def __init__(self, rules: tuple[_RedactionRule, ...] = _DEFAULT_RULES) -> None:
        self.rules = rules

    def redact(self, text: str | None) -> RedactionResult:
        """Scan ``text`` and replace matching secrets with ``[REDACTED:<TYPE>]``."""
        if not text:
            return RedactionResult(redacted_text="", redacted_count=0, matched_types=())

        current = str(text)
        total_count = 0
        found_types: list[str] = []

        for rule in self.rules:
            current, n = rule.pattern.subn(rule.replacement, current)
            if n > 0:
                total_count += n
                if rule.secret_type not in found_types:
                    found_types.append(rule.secret_type)

        return RedactionResult(
            redacted_text=current,
            redacted_count=total_count,
            matched_types=tuple(found_types),
        )

    def redact_text(self, text: str | None) -> tuple[str, int]:
        """Return ``(redacted_text, redacted_count)`` tuple for convenience."""
        res = self.redact(text)
        return res.redacted_text, res.redacted_count
