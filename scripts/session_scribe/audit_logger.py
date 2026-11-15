#!/usr/bin/env python3
"""Tamper-evident SHA-256 hash-chained audit logger for PENT-20 Session Scribe.

Stores every pentest subagent decision and execution step as newline-delimited
JSON (JSONL) where each entry embeds ``prev_hash`` and ``entry_hash`` computed
over canonical JSON using SHA-256. Any deletion, insertion, reordering, or
single-character modification breaks the chain and triggers ``TAMPER_DETECTED``.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .mitre_mapper import MitreMapper
from .redactor import SecretRedactor

GENESIS_HASH = "0" * 64
VALID_STATUSES = (
    "ALLOWED",
    "REFUSED_OUT_OF_SCOPE",
    "REFUSED_PROMPT_INJECTION",
    "EXECUTED",
    "CIRCUIT_RESET",
    "KILL_SWITCH_TRIPPED",
)


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format with Z suffix."""
    return _dt.datetime.now(_dt.timezone.utc).isoformat().replace("+00:00", "Z")


def compute_entry_hash(entry_without_hash: dict[str, Any]) -> str:
    """Compute canonical SHA-256 hex digest over a log entry dict (excluding entry_hash)."""
    payload = {k: v for k, v in entry_without_hash.items() if k != "entry_hash"}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ChainVerificationResult:
    """Result of verifying a hash-chained JSONL audit log."""

    valid: bool
    status: str
    total_entries: int
    verified_entries: int
    failed_seq: int | None = None
    reason: str = ""
    head_hash: str = GENESIS_HASH

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "status": self.status,
            "total_entries": self.total_entries,
            "verified_entries": self.verified_entries,
            "failed_seq": self.failed_seq,
            "reason": self.reason,
            "head_hash": self.head_hash,
        }


def verify_log_chain(log_path: str | Path) -> ChainVerificationResult:
    """Verify sequence continuity, prev_hash linkage, and SHA-256 digests in a JSONL log."""
    path = Path(log_path)
    if not path.exists() or not path.is_file():
        return ChainVerificationResult(
            valid=False,
            status="TAMPER_DETECTED",
            total_entries=0,
            verified_entries=0,
            failed_seq=None,
            reason=f"Audit log file does not exist: {path}",
            head_hash=GENESIS_HASH,
        )

    try:
        raw_text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return ChainVerificationResult(
            valid=False,
            status="TAMPER_DETECTED",
            total_entries=0,
            verified_entries=0,
            failed_seq=None,
            reason=f"Failed to read audit log: {exc}",
            head_hash=GENESIS_HASH,
        )

    lines = raw_text.splitlines()
    if not lines:
        return ChainVerificationResult(
            valid=True,
            status="EMPTY",
            total_entries=0,
            verified_entries=0,
            failed_seq=None,
            reason="Audit log is empty (0 entries).",
            head_hash=GENESIS_HASH,
        )

    expected_prev = GENESIS_HASH
    verified = 0
    total = len(lines)

    for idx, line in enumerate(lines, start=1):
        if not line.strip():
            return ChainVerificationResult(
                valid=False,
                status="TAMPER_DETECTED",
                total_entries=total,
                verified_entries=verified,
                failed_seq=idx,
                reason=f"Blank or truncated line detected at line {idx} (possible deletion/tampering).",
                head_hash=expected_prev,
            )

        try:
            entry = json.loads(line)
        except json.JSONDecodeError as exc:
            return ChainVerificationResult(
                valid=False,
                status="TAMPER_DETECTED",
                total_entries=total,
                verified_entries=verified,
                failed_seq=idx,
                reason=f"Corrupted JSON at line {idx}: {exc}",
                head_hash=expected_prev,
            )

        if not isinstance(entry, dict):
            return ChainVerificationResult(
                valid=False,
                status="TAMPER_DETECTED",
                total_entries=total,
                verified_entries=verified,
                failed_seq=idx,
                reason=f"Line {idx} is not a JSON object.",
                head_hash=expected_prev,
            )

        seq = entry.get("seq")
        if not isinstance(seq, int) or isinstance(seq, bool) or seq != idx:
            return ChainVerificationResult(
                valid=False,
                status="TAMPER_DETECTED",
                total_entries=total,
                verified_entries=verified,
                failed_seq=idx,
                reason=(
                    f"Sequence continuity broken at line {idx}: expected seq={idx}, got seq={seq!r} "
                    "(possible entry deletion, insertion, or reordering)."
                ),
                head_hash=expected_prev,
            )

        prev_hash = entry.get("prev_hash")
        if not isinstance(prev_hash, str) or not hmac.compare_digest(prev_hash, expected_prev):
            return ChainVerificationResult(
                valid=False,
                status="TAMPER_DETECTED",
                total_entries=total,
                verified_entries=verified,
                failed_seq=seq,
                reason=(
                    f"Hash chain link broken at seq={seq}: expected prev_hash={expected_prev}, "
                    f"got prev_hash={prev_hash!r}."
                ),
                head_hash=expected_prev,
            )

        stored_hash = entry.get("entry_hash")
        if not isinstance(stored_hash, str) or len(stored_hash) != 64:
            return ChainVerificationResult(
                valid=False,
                status="TAMPER_DETECTED",
                total_entries=total,
                verified_entries=verified,
                failed_seq=seq,
                reason=f"Missing or malformed entry_hash at seq={seq}.",
                head_hash=expected_prev,
            )

        recomputed = compute_entry_hash(entry)
        if not hmac.compare_digest(stored_hash, recomputed):
            return ChainVerificationResult(
                valid=False,
                status="TAMPER_DETECTED",
                total_entries=total,
                verified_entries=verified,
                failed_seq=seq,
                reason=(
                    f"Payload digest mismatch at seq={seq}: stored entry_hash={stored_hash[:16]}... "
                    f"!= recomputed={recomputed[:16]}... (entry was modified)."
                ),
                head_hash=expected_prev,
            )

        expected_prev = stored_hash
        verified += 1

    return ChainVerificationResult(
        valid=True,
        status="VALID",
        total_entries=total,
        verified_entries=verified,
        failed_seq=None,
        reason=f"All {verified} audit entries verified with unbroken SHA-256 hash chain.",
        head_hash=expected_prev,
    )


class AuditLogger:
    """Append-only SHA-256 hash-chained JSONL logger for pentest sessions."""

    def __init__(self, log_path: str | Path, session_id: str = "pent20-lab-session") -> None:
        self.log_path = Path(log_path)
        self.session_id = session_id
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._seq = 0
        self._last_hash = GENESIS_HASH
        self._redactor = SecretRedactor()
        self._mitre_mapper = MitreMapper()
        self._sync_tail_state()

    def _sync_tail_state(self) -> None:
        if not self.log_path.exists():
            self.log_path.touch()
            return
        lines = [ln for ln in self.log_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        if not lines:
            self._seq = 0
            self._last_hash = GENESIS_HASH
            return
        last = json.loads(lines[-1])
        self._seq = int(last["seq"])
        self._last_hash = str(last["entry_hash"])

    def log_step(
        self,
        *,
        target: str,
        command: str,
        status: str,
        duration_ms: float = 0.0,
        output_summary: str = "",
        ai_disclosure: dict[str, Any] | None = None,
        port: int | None = None,
        matched_rule: str | None = None,
        timestamp: str | None = None,
        redacted_count: int = 0,
        mitre: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Append a single DLP-redacted, hash-chained audit record and return the persisted dict."""
        if status not in VALID_STATUSES:
            raise ValueError(f"Invalid audit status '{status}'. Expected one of: {', '.join(VALID_STATUSES)}")

        cmd_redaction = self._redactor.redact(command)
        out_redaction = self._redactor.redact(output_summary)
        total_redacted = int(redacted_count) + cmd_redaction.redacted_count + out_redaction.redacted_count

        mitre_dict = (
            dict(mitre)
            if mitre is not None
            else self._mitre_mapper.map_step(cmd_redaction.redacted_text, status=status).to_dict()
        )
        risk_level = str(mitre_dict.get("risk_level", "LOW"))

        next_seq = self._seq + 1
        entry: dict[str, Any] = {
            "seq": next_seq,
            "timestamp": timestamp or utc_now_iso(),
            "session_id": self.session_id,
            "target": target,
            "port": port,
            "command": cmd_redaction.redacted_text,
            "status": status,
            "duration_ms": round(float(duration_ms), 3),
            "output_summary": out_redaction.redacted_text,
            "redacted_count": total_redacted,
            "matched_rule": matched_rule,
            "mitre": mitre_dict,
            "risk_level": risk_level,
            "ai_disclosure": ai_disclosure if ai_disclosure is not None else {},
            "prev_hash": self._last_hash,
        }
        entry["entry_hash"] = compute_entry_hash(entry)

        serialized = json.dumps(entry, sort_keys=True, ensure_ascii=False)
        with self.log_path.open("a", encoding="utf-8", newline="\n") as fh:
            fh.write(serialized + "\n")
            fh.flush()
            try:
                os.fsync(fh.fileno())
            except OSError:
                pass

        self._seq = next_seq
        self._last_hash = entry["entry_hash"]
        return entry

    def read_entries(self) -> list[dict[str, Any]]:
        """Read all JSONL entries from disk in order."""
        if not self.log_path.exists():
            return []
        entries: list[dict[str, Any]] = []
        for line in self.log_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                entries.append(json.loads(line))
        return entries

    def verify(self) -> ChainVerificationResult:
        """Verify the integrity of the log file managed by this logger."""
        return verify_log_chain(self.log_path)
