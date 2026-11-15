#!/usr/bin/env python3
"""Cryptographic Markdown session report generator & verifier for PENT-20.

Generates ``SESSION_REPORT.md`` from the tamper-evident audit log and scope
manifest—including blocked out-of-scope attempts, SHA-256 hash-chain proof,
and a full AI-Use Disclosure appendix—and signs/verifies it with SHA-256 +
HMAC-SHA256 (``SESSION_REPORT.md.sig``).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .audit_logger import GENESIS_HASH, AuditLogger, utc_now_iso, verify_log_chain
from .forensic_exporter import ForensicExporter
from .html_dashboard import generate_html_dashboard
from .mitre_mapper import MitreMapper, compute_compliance_score
from .redactor import SecretRedactor
from .scope_guard import ScopeGuard

KEY_ENV_VAR = "PENT20_SIGNING_KEY"
DEFAULT_KEY_FILENAME = "session_signing.key"


@dataclass(frozen=True)
class ReportVerificationResult:
    """Result of verifying SESSION_REPORT.md against SESSION_REPORT.md.sig."""

    valid: bool
    status: str
    report_path: str
    sig_path: str
    expected_sha256: str | None
    actual_sha256: str | None
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "status": self.status,
            "report_path": self.report_path,
            "sig_path": self.sig_path,
            "expected_sha256": self.expected_sha256,
            "actual_sha256": self.actual_sha256,
            "reason": self.reason,
        }


def _coerce_key_bytes(secret_key: bytes | str) -> bytes:
    if isinstance(secret_key, bytes):
        raw = secret_key
    elif isinstance(secret_key, str):
        raw = secret_key.encode("utf-8")
    else:
        raise ValueError("Signing key must be bytes or str.")
    if not raw:
        raise ValueError("Signing key must not be empty.")
    return raw


def _resolve_or_create_signing_key(
    *,
    secret_key: bytes | str | None,
    key_path: str | Path | None,
    base_dir: Path,
    create_if_missing: bool,
) -> tuple[bytes, Path | None]:
    if secret_key is not None:
        return _coerce_key_bytes(secret_key), None

    env_val = os.environ.get(KEY_ENV_VAR)
    if env_val:
        return _coerce_key_bytes(env_val), None

    resolved_key_path = Path(key_path) if key_path is not None else base_dir / DEFAULT_KEY_FILENAME
    if resolved_key_path.exists():
        text = resolved_key_path.read_text(encoding="utf-8").strip()
        if not text:
            raise ValueError(f"Signing key file is empty: {resolved_key_path}")
        return text.encode("utf-8"), resolved_key_path

    if not create_if_missing:
        raise FileNotFoundError(
            f"Signing key not provided and key file not found at {resolved_key_path}. "
            f"Pass --key, --key-file, or set {KEY_ENV_VAR}."
        )

    resolved_key_path.parent.mkdir(parents=True, exist_ok=True)
    generated = secrets.token_hex(32)
    resolved_key_path.write_text(generated + "\n", encoding="utf-8")
    try:
        os.chmod(resolved_key_path, 0o600)
    except OSError:
        pass
    return generated.encode("utf-8"), resolved_key_path


def _md_escape(value: Any) -> str:
    text = str(value if value is not None else "")
    return text.replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def sign_report(
    report_path: str | Path,
    sig_path: str | Path | None = None,
    secret_key: bytes | str | None = None,
    key_path: str | Path | None = None,
) -> dict[str, Any]:
    """Compute SHA-256 and HMAC-SHA256 signature over ``report_path`` and write ``.sig`` JSON."""
    rpath = Path(report_path)
    if not rpath.exists() or not rpath.is_file():
        raise FileNotFoundError(f"Report file not found: {rpath}")

    spath = Path(sig_path) if sig_path is not None else Path(f"{rpath}.sig")
    report_bytes = rpath.read_bytes()
    content_sha256 = hashlib.sha256(report_bytes).hexdigest()

    key_bytes, used_key_file = _resolve_or_create_signing_key(
        secret_key=secret_key,
        key_path=key_path,
        base_dir=spath.parent,
        create_if_missing=True,
    )
    signature_hex = hmac.new(key_bytes, report_bytes, hashlib.sha256).hexdigest()
    key_fingerprint = hashlib.sha256(key_bytes).hexdigest()[:16]

    sig_payload: dict[str, Any] = {
        "version": 1,
        "algorithm": "HMAC-SHA256",
        "hash_algorithm": "SHA-256",
        "report_file": rpath.name,
        "report_bytes": len(report_bytes),
        "content_sha256": content_sha256,
        "hmac_sha256": signature_hex,
        "key_fingerprint": key_fingerprint,
        "signed_at": utc_now_iso(),
    }
    if used_key_file is not None:
        sig_payload["key_file"] = used_key_file.name

    spath.parent.mkdir(parents=True, exist_ok=True)
    spath.write_text(json.dumps(sig_payload, indent=2) + "\n", encoding="utf-8")
    return sig_payload


def verify_report(
    report_path: str | Path,
    sig_path: str | Path | None = None,
    secret_key: bytes | str | None = None,
    key_path: str | Path | None = None,
) -> ReportVerificationResult:
    """Verify ``report_path`` integrity and HMAC-SHA256 signature against ``.sig`` file."""
    rpath = Path(report_path)
    spath = Path(sig_path) if sig_path is not None else Path(f"{rpath}.sig")

    if not rpath.exists() or not rpath.is_file():
        return ReportVerificationResult(
            valid=False,
            status="SIGNATURE INVALID / TAMPER DETECTED",
            report_path=str(rpath),
            sig_path=str(spath),
            expected_sha256=None,
            actual_sha256=None,
            reason=f"Report file missing: {rpath}",
        )

    if not spath.exists() or not spath.is_file():
        actual_sha = hashlib.sha256(rpath.read_bytes()).hexdigest()
        return ReportVerificationResult(
            valid=False,
            status="SIGNATURE INVALID / TAMPER DETECTED",
            report_path=str(rpath),
            sig_path=str(spath),
            expected_sha256=None,
            actual_sha256=actual_sha,
            reason=f"Signature file missing: {spath}",
        )

    try:
        sig_data = json.loads(spath.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return ReportVerificationResult(
            valid=False,
            status="SIGNATURE INVALID / TAMPER DETECTED",
            report_path=str(rpath),
            sig_path=str(spath),
            expected_sha256=None,
            actual_sha256=None,
            reason=f"Corrupted signature JSON: {exc}",
        )

    if not isinstance(sig_data, dict):
        return ReportVerificationResult(
            valid=False,
            status="SIGNATURE INVALID / TAMPER DETECTED",
            report_path=str(rpath),
            sig_path=str(spath),
            expected_sha256=None,
            actual_sha256=None,
            reason="Signature file must contain a JSON object.",
        )

    report_bytes = rpath.read_bytes()
    actual_sha = hashlib.sha256(report_bytes).hexdigest()
    expected_sha = sig_data.get("content_sha256")
    expected_hmac = sig_data.get("hmac_sha256")

    if not isinstance(expected_sha, str) or not isinstance(expected_hmac, str):
        return ReportVerificationResult(
            valid=False,
            status="SIGNATURE INVALID / TAMPER DETECTED",
            report_path=str(rpath),
            sig_path=str(spath),
            expected_sha256=expected_sha if isinstance(expected_sha, str) else None,
            actual_sha256=actual_sha,
            reason="Signature file missing content_sha256 or hmac_sha256.",
        )

    if not hmac.compare_digest(actual_sha, expected_sha):
        return ReportVerificationResult(
            valid=False,
            status="SIGNATURE INVALID / TAMPER DETECTED",
            report_path=str(rpath),
            sig_path=str(spath),
            expected_sha256=expected_sha,
            actual_sha256=actual_sha,
            reason=(
                f"SHA-256 content mismatch: expected {expected_sha[:16]}..., "
                f"got {actual_sha[:16]}... (report content was modified)."
            ),
        )

    inferred_key_path = key_path
    if inferred_key_path is None and isinstance(sig_data.get("key_file"), str):
        candidate = spath.parent / Path(sig_data["key_file"]).name
        if candidate.exists():
            inferred_key_path = candidate

    try:
        key_bytes, _ = _resolve_or_create_signing_key(
            secret_key=secret_key,
            key_path=inferred_key_path,
            base_dir=spath.parent,
            create_if_missing=False,
        )
    except (FileNotFoundError, ValueError) as exc:
        return ReportVerificationResult(
            valid=False,
            status="SIGNATURE INVALID / TAMPER DETECTED",
            report_path=str(rpath),
            sig_path=str(spath),
            expected_sha256=expected_sha,
            actual_sha256=actual_sha,
            reason=str(exc),
        )

    actual_hmac = hmac.new(key_bytes, report_bytes, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(actual_hmac, expected_hmac):
        return ReportVerificationResult(
            valid=False,
            status="SIGNATURE INVALID / TAMPER DETECTED",
            report_path=str(rpath),
            sig_path=str(spath),
            expected_sha256=expected_sha,
            actual_sha256=actual_sha,
            reason="HMAC-SHA256 verification failed (wrong signing key or forged signature).",
        )

    return ReportVerificationResult(
        valid=True,
        status="SIGNATURE VALID",
        report_path=str(rpath),
        sig_path=str(spath),
        expected_sha256=expected_sha,
        actual_sha256=actual_sha,
        reason="SHA-256 digest and HMAC-SHA256 cryptographic signature verified successfully.",
    )


def generate_session_report(
    *,
    log_path: str | Path,
    scope_path: str | Path,
    report_path: str | Path,
    sig_path: str | Path | None = None,
    html_path: str | Path | None = None,
    sarif_path: str | Path | None = None,
    manifest_path: str | Path | None = None,
    signing_key: bytes | str | None = None,
    key_path: str | Path | None = None,
    circuit_breaker_info: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build ``SESSION_REPORT.md``, ``SESSION_DASHBOARD.html``, SARIF v2.1.0 & Evidence Manifest, and sign ``.sig``."""
    lpath = Path(log_path)
    spath = Path(scope_path)
    rpath = Path(report_path)
    resolved_sig_path = Path(sig_path) if sig_path is not None else Path(f"{rpath}.sig")
    resolved_html_path = Path(html_path) if html_path is not None else rpath.parent / "SESSION_DASHBOARD.html"
    resolved_sarif_path = Path(sarif_path) if sarif_path is not None else rpath.parent / "SESSION_FINDINGS.sarif.json"
    resolved_manifest_path = Path(manifest_path) if manifest_path is not None else rpath.parent / "EVIDENCE_MANIFEST.json"

    guard = ScopeGuard.from_file(spath)
    chain_result = verify_log_chain(lpath)
    logger = AuditLogger(lpath, session_id=guard.session_id) if lpath.exists() else None
    entries = logger.read_entries() if (logger and chain_result.status != "TAMPER_DETECTED") else []

    if not entries and lpath.exists():
        # Best-effort parse for visibility even if chain was tampered
        for raw in lpath.read_text(encoding="utf-8").splitlines():
            if raw.strip():
                try:
                    parsed = json.loads(raw)
                    if isinstance(parsed, dict):
                        entries.append(parsed)
                except json.JSONDecodeError:
                    pass

    redactor = SecretRedactor()
    mapper = MitreMapper()
    forensic = ForensicExporter()

    executed_entries = [e for e in entries if e.get("status") == "EXECUTED"]
    allowed_entries = [e for e in entries if e.get("status") == "ALLOWED"]
    scope_refused_entries = [e for e in entries if e.get("status") == "REFUSED_OUT_OF_SCOPE"]
    prompt_injection_entries = [e for e in entries if e.get("status") == "REFUSED_PROMPT_INJECTION"]
    refused_entries = [
        e for e in entries if e.get("status") in ("REFUSED_OUT_OF_SCOPE", "REFUSED_PROMPT_INJECTION")
    ]
    circuit_entries = [e for e in entries if e.get("status") in ("KILL_SWITCH_TRIPPED", "CIRCUIT_RESET")]

    entry_hashes = [str(e.get("entry_hash", "")) for e in entries if e.get("entry_hash")]
    merkle_info = forensic.build_merkle_tree(entry_hashes)
    merkle_root = str(merkle_info["merkle_root"])

    cb_info = circuit_breaker_info
    if cb_info is None:
        trips = [e for e in circuit_entries if e.get("status") == "KILL_SWITCH_TRIPPED"]
        resets = [e for e in circuit_entries if e.get("status") == "CIRCUIT_RESET"]
        locked_now = bool(circuit_entries and circuit_entries[-1].get("status") == "KILL_SWITCH_TRIPPED")
        cb_info = {
            "state": "OPEN (LOCKED)" if locked_now else "CLOSED (ARMED)",
            "total_trips": len(trips),
            "resets_count": len(resets),
            "consecutive_violations": 0,
            "max_violations": 3,
        }

    compliance = compute_compliance_score(entries, chain_valid=chain_result.valid)
    scope_info = guard.summary()
    generated_at = utc_now_iso()

    lines: list[str] = [
        "# PENT-20 Pentest Session Report",
        "",
        "## 1. Session Summary & Integrity Status",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| **Session ID** | `{_md_escape(scope_info['session_id'])}` |",
        f"| **Scope Name** | {_md_escape(scope_info['name'])} |",
        f"| **Authorization** | {_md_escape(scope_info['authorization'])} |",
        f"| **Generated (UTC)** | `{generated_at}` |",
        f"| **Total Logged Steps** | {len(entries)} |",
        f"| **Executed (In-Scope)** | {len(executed_entries)} |",
        f"| **Allowed (Scope-Check / Dry-Run)** | {len(allowed_entries)} |",
        f"| **Refused (Out-of-Scope)** | {len(scope_refused_entries)} |",
        f"| **Refused (Prompt Injection)** | {len(prompt_injection_entries)} |",
        f"| **Masked Secrets (DLP)** | {compliance['redacted_secrets']} |",
        f"| **Circuit Breaker Status** | `{_md_escape(cb_info.get('state', 'CLOSED (ARMED)'))}` ({int(cb_info.get('total_trips', 0))} trip(s)) |",
        f"| **Compliance & Safety Score** | **{compliance['score']}/100** ({_md_escape(compliance['grade'])}) |",
        f"| **Audit Chain Status** | **{chain_result.status}** (`{chain_result.verified_entries}/{chain_result.total_entries}` verified) |",
        f"| **Chain Head Hash (SHA-256)** | `{chain_result.head_hash}` |",
        f"| **Merkle Root (SHA-256)** | `{merkle_root}` |",
        "",
        "## 2. Authorized Scope Policy",
        "",
        f"- **Allowed CIDRs:** {', '.join(f'`{c}`' for c in scope_info['allowed_cidrs'])}",
        f"- **Allowed Domains:** {', '.join(f'`{d}`' for d in scope_info['allowed_domains'])}",
        f"- **Allowed Ports:** {', '.join(f'`{p}`' for p in scope_info['allowed_ports'])}",
        f"- **Allowed Commands:** {', '.join(f'`{c}`' for c in scope_info['allowed_commands'])}",
        f"- **Forbidden Flags / Patterns:** {', '.join(f'`{f}`' for f in scope_info['forbidden_flags'])}",
        "",
        "## 3. Chronological Session Audit Trail",
        "",
    ]

    if entries:
        lines.extend(
            [
                "| Seq | Timestamp (UTC) | Target | Port | Command | MITRE ATT&CK | Risk | DLP | Status | Duration (ms) | Entry Hash (prefix) | Output Summary |",
                "|---:|---|---|---:|---|---|---|---|---|---:|---|---|",
            ]
        )
        for e in entries:
            status = str(e.get("status", ""))
            safe_cmd, _ = redactor.redact_text(str(e.get("command", "")))
            safe_out, _ = redactor.redact_text(str(e.get("output_summary", "")))
            mitre = e.get("mitre")
            if not isinstance(mitre, dict) or not mitre.get("technique_id"):
                mitre = mapper.map_step(safe_cmd, status=status).to_dict()
            mitre_lbl = f"{mitre.get('technique_id', 'T1595')} - {mitre.get('technique_name', 'Active Scanning')}"
            risk_lbl = mitre.get("risk_level", e.get("risk_level", "LOW"))
            red_cnt = int(e.get("redacted_count") or 0)
            lines.append(
                "| {seq} | `{ts}` | `{target}` | {port} | `{cmd}` | `{mitre}` | `{risk}` | {dlp} | **{status}** | {dur} | `{ehash}` | {out} |".format(
                    seq=e.get("seq", "?"),
                    ts=_md_escape(e.get("timestamp", "")),
                    target=_md_escape(e.get("target", "")),
                    port=_md_escape(e.get("port") if e.get("port") is not None else "-"),
                    cmd=_md_escape(safe_cmd),
                    mitre=_md_escape(mitre_lbl),
                    risk=_md_escape(risk_lbl),
                    dlp=red_cnt,
                    status=_md_escape(status),
                    dur=_md_escape(e.get("duration_ms", 0.0)),
                    ehash=_md_escape(str(e.get("entry_hash", ""))[:12]),
                    out=_md_escape(safe_out),
                )
            )
    else:
        lines.append("_No audit entries recorded in this session._")

    lines.extend(["", "## 4. Blocked Out-of-Scope & Policy Violations", ""])
    if refused_entries:
        lines.extend(
            [
                "| Seq | Target | Command | AI Agent | Refusal Reason |",
                "|---:|---|---|---|---|",
            ]
        )
        for e in refused_entries:
            ai = e.get("ai_disclosure") or {}
            safe_cmd, _ = redactor.redact_text(str(e.get("command", "")))
            safe_reason, _ = redactor.redact_text(str(e.get("output_summary", "")))
            lines.append(
                "| {seq} | `{target}` | `{cmd}` | `{agent}` | {reason} |".format(
                    seq=e.get("seq", "?"),
                    target=_md_escape(e.get("target", "")),
                    cmd=_md_escape(safe_cmd),
                    agent=_md_escape(ai.get("agent_id", "unknown")),
                    reason=_md_escape(safe_reason),
                )
            )
    else:
        lines.append("_No out-of-scope attempts were recorded._")

    lines.extend(
        [
            "",
            "## 5. Hash-Chain & Merkle-Tree Verification Summary",
            "",
            f"- **Genesis Hash:** `{GENESIS_HASH}`",
            f"- **Verification Outcome:** `{chain_result.status}` (`valid={chain_result.valid}`)",
            f"- **Binary Merkle Root (SHA-256):** `{merkle_root}` (`{merkle_info['leaf_count']}` leaves, depth `{merkle_info['tree_depth']}`)",
            f"- **Details:** {chain_result.reason}",
            "",
            "## 6. AI-Use Disclosure Appendix",
            "",
            "Every step executed or blocked by the Pentest Subagent records mandatory AI provenance metadata:",
            "",
        ]
    )

    if entries:
        lines.extend(
            [
                "| Seq | Agent ID | Model | Tool Name | Human Approved | Prompt Hash (SHA-256) | Reasoning |",
                "|---:|---|---|---|---|---|---|",
            ]
        )
        for e in entries:
            ai = e.get("ai_disclosure") or {}
            lines.append(
                "| {seq} | `{agent}` | `{model}` | `{tool}` | `{approved}` | `{phash}` | {reason} |".format(
                    seq=e.get("seq", "?"),
                    agent=_md_escape(ai.get("agent_id", "-")),
                    model=_md_escape(ai.get("model", "-")),
                    tool=_md_escape(ai.get("tool_name", "-")),
                    approved=_md_escape(ai.get("human_approved", False)),
                    phash=_md_escape(ai.get("prompt_hash", "-")),
                    reason=_md_escape(ai.get("reasoning", "-")),
                )
            )
    else:
        lines.append("_No AI subagent actions recorded._")

    lines.append("")
    rpath.parent.mkdir(parents=True, exist_ok=True)
    rpath.write_text("\n".join(lines), encoding="utf-8")

    sig_payload = sign_report(
        rpath,
        sig_path=resolved_sig_path,
        secret_key=signing_key,
        key_path=key_path,
    )

    sarif_summary = forensic.export_sarif(
        entries=entries,
        scope_info=scope_info,
        sarif_path=resolved_sarif_path,
        log_filename=lpath.name,
    )

    upstream_artifacts = [
        p
        for p in (spath, lpath, rpath, resolved_sig_path, resolved_sarif_path)
        if p.exists()
    ]
    pre_manifest = forensic.export_evidence_manifest(
        session_id=str(scope_info.get("session_id", "session")),
        entries=entries,
        artifact_paths=upstream_artifacts,
        manifest_path=resolved_manifest_path,
        extra_metadata={
            "compliance_score": compliance.get("score"),
            "audit_chain_status": chain_result.status,
            "sarif_findings": sarif_summary.get("total_findings", 0),
        },
    )

    generate_html_dashboard(
        entries=entries,
        scope_info=scope_info,
        chain_result=chain_result,
        compliance=compliance,
        signature=sig_payload,
        generated_at=generated_at,
        html_path=resolved_html_path,
        merkle_info=merkle_info,
        sarif_summary=sarif_summary,
        manifest_data=pre_manifest,
        circuit_breaker_info=cb_info,
    )

    all_artifacts = [*upstream_artifacts, resolved_html_path]
    manifest_data = forensic.export_evidence_manifest(
        session_id=str(scope_info.get("session_id", "session")),
        entries=entries,
        artifact_paths=all_artifacts,
        manifest_path=resolved_manifest_path,
        extra_metadata={
            "compliance_score": compliance.get("score"),
            "audit_chain_status": chain_result.status,
            "sarif_findings": sarif_summary.get("total_findings", 0),
            "circuit_breaker_state": cb_info.get("state"),
        },
    )

    return {
        "report_path": str(rpath),
        "sig_path": str(resolved_sig_path),
        "html_path": str(resolved_html_path),
        "sarif_path": str(resolved_sarif_path),
        "manifest_path": str(resolved_manifest_path),
        "chain_status": chain_result.status,
        "merkle_root": merkle_root,
        "merkle_tree": {
            "merkle_root": merkle_root,
            "leaf_count": merkle_info["leaf_count"],
            "tree_depth": merkle_info["tree_depth"],
        },
        "total_entries": len(entries),
        "executed_count": len(executed_entries),
        "refused_count": len(refused_entries),
        "prompt_injection_blocks": len(prompt_injection_entries),
        "redacted_secrets": compliance["redacted_secrets"],
        "compliance": compliance,
        "signature": sig_payload,
        "sarif_summary": {
            "sarif_path": sarif_summary["sarif_path"],
            "total_findings": sarif_summary["total_findings"],
            "rule_counts": sarif_summary["rule_counts"],
        },
        "manifest": manifest_data,
        "circuit_breaker": cb_info,
    }
