"""PENT-20: Pentest Session Scribe — Scoped, Logged, AI-Disclosed (Subagent).

Standard-library-only modular package providing:
- scope_guard: CIDR, domain, port, and command allowlist enforcement.
- redactor: DLP-style regex redactor for sensitive tokens, keys, and passwords.
- mitre_mapper: MITRE ATT&CK technique/tactic mapping and compliance scorer.
- audit_logger: tamper-evident SHA-256 hash-chained JSONL audit logging.
- subagent: AI-disclosed pentest execution layer with refusal logging.
- prompt_guard: direct/indirect prompt injection, jailbreak & exfiltration shield.
- circuit_breaker: autonomous kill-switch & human-token recovery control.
- forensic_exporter: binary Merkle-tree root, SARIF v2.1.0 & evidence manifest exporter.
- report_signer: Markdown session reporting with SHA-256 + HMAC-SHA256 signatures.
- html_dashboard: self-contained 4-tab dark-mode cybersecurity HTML command center.
- cli: command-line interface, live demo, and 10-stage video showcase mode.
"""

from .audit_logger import AuditLogger, ChainVerificationResult, GENESIS_HASH, verify_log_chain
from .circuit_breaker import EmergencyKillSwitchError, SubagentCircuitBreaker
from .forensic_exporter import ForensicExporter, build_merkle_tree, compute_merkle_root
from .html_dashboard import HTMLDashboard, generate_html_dashboard
from .mitre_mapper import MitreMapper, MitreMapping, compute_compliance_score
from .prompt_guard import (
    REFUSED_PROMPT_INJECTION,
    PromptInjectionError,
    PromptInjectionGuard,
    PromptThreatResult,
)
from .redactor import RedactionResult, SecretRedactor
from .report_signer import (
    ReportVerificationResult,
    generate_session_report,
    sign_report,
    verify_report,
)
from .scope_guard import ScopeCheckResult, ScopeGuard, ScopeViolationError
from .subagent import AIDisclosure, AIDisclosureError, PentestSubagent, SubagentStepResult

__all__ = [
    "AIDisclosure",
    "AIDisclosureError",
    "AuditLogger",
    "ChainVerificationResult",
    "EmergencyKillSwitchError",
    "ForensicExporter",
    "GENESIS_HASH",
    "HTMLDashboard",
    "MitreMapper",
    "MitreMapping",
    "PentestSubagent",
    "PromptInjectionError",
    "PromptInjectionGuard",
    "PromptThreatResult",
    "REFUSED_PROMPT_INJECTION",
    "RedactionResult",
    "ReportVerificationResult",
    "ScopeCheckResult",
    "ScopeGuard",
    "ScopeViolationError",
    "SecretRedactor",
    "SubagentCircuitBreaker",
    "SubagentStepResult",
    "build_merkle_tree",
    "compute_compliance_score",
    "compute_merkle_root",
    "generate_html_dashboard",
    "generate_session_report",
    "sign_report",
    "verify_log_chain",
    "verify_report",
]
