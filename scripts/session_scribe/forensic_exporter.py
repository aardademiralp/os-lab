#!/usr/bin/env python3
"""Forensic Merkle-Tree, SARIF v2.1.0 & Evidence Manifest exporter for PENT-20.

Computes a binary SHA-256 Merkle root over all audit entry hashes, exports
security findings (scope violations, prompt injection blocks, DLP redactions,
and circuit-breaker events) in OASIS SARIF v2.1.0 format, and seals all
generated session artifacts inside ``EVIDENCE_MANIFEST.json``.
Uses only Python standard library modules.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

from .audit_logger import GENESIS_HASH, utc_now_iso

SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def build_merkle_tree(entry_hashes: list[str]) -> dict[str, Any]:
    """Build a binary SHA-256 Merkle tree from an ordered list of entry hashes."""
    leaves = [str(h).strip().lower() for h in entry_hashes if isinstance(h, str) and h.strip()]
    if not leaves:
        return {
            "merkle_root": GENESIS_HASH,
            "leaf_count": 0,
            "tree_depth": 1,
            "levels": [[GENESIS_HASH]],
        }

    levels: list[list[str]] = [leaves]
    current = leaves
    while len(current) > 1:
        working = list(current)
        if len(working) % 2 == 1:
            working.append(working[-1])
        next_level: list[str] = []
        for idx in range(0, len(working), 2):
            pair = f"{working[idx]}:{working[idx + 1]}"
            next_level.append(hashlib.sha256(pair.encode("utf-8")).hexdigest())
        levels.append(next_level)
        current = next_level

    return {
        "merkle_root": current[0],
        "leaf_count": len(leaves),
        "tree_depth": len(levels),
        "levels": levels,
    }


def compute_merkle_root(entry_hashes: list[str]) -> str:
    """Compute only the binary SHA-256 Merkle root hex digest."""
    return str(build_merkle_tree(entry_hashes)["merkle_root"])


_SARIF_RULES: list[dict[str, Any]] = [
    {
        "id": "PENT20-SCOPE-001",
        "name": "OutOfScopeTargetOrPolicyViolation",
        "shortDescription": {"text": "Unauthorized target, port, or command blocked by ScopeGuard."},
        "fullDescription": {
            "text": "The subagent attempted an action outside authorized CIDRs/domains/ports/commands or used forbidden flags/shell metacharacters and was refused prior to execution."
        },
        "defaultConfiguration": {"level": "error"},
        "properties": {"tags": ["security", "scope-guard", "PENT-20"]},
    },
    {
        "id": "PENT20-PROMPT-002",
        "name": "PromptInjectionOrJailbreakDetected",
        "shortDescription": {"text": "AI prompt injection, jailbreak, or exfiltration payload blocked."},
        "fullDescription": {
            "text": "PromptInjectionGuard detected direct or indirect prompt override instructions, obfuscated encodings, or secret/environment exfiltration attempts."
        },
        "defaultConfiguration": {"level": "error"},
        "properties": {"tags": ["security", "ai-safety", "prompt-injection", "PENT-20"]},
    },
    {
        "id": "PENT20-DLP-003",
        "name": "SensitiveSecretRedactedByDLP",
        "shortDescription": {"text": "Credential or secret detected and masked prior to persistence."},
        "fullDescription": {
            "text": "SecretRedactor intercepted sensitive secrets (Bearer token, JWT, API key, AWS credential, password, or private key) and replaced them with [REDACTED:<TYPE>]."
        },
        "defaultConfiguration": {"level": "warning"},
        "properties": {"tags": ["security", "dlp", "secret-redaction", "PENT-20"]},
    },
    {
        "id": "PENT20-CIRCUIT-004",
        "name": "AutonomousCircuitBreakerEvent",
        "shortDescription": {"text": "Subagent kill-switch trip or human-operator unlock event recorded."},
        "fullDescription": {
            "text": "Tracks emergency kill-switch engagement after consecutive policy violations and subsequent audited human-in-the-loop override resets."
        },
        "defaultConfiguration": {"level": "note"},
        "properties": {"tags": ["governance", "kill-switch", "hitl", "PENT-20"]},
    },
]


class ForensicExporter:
    """Exports Merkle proofs, OASIS SARIF v2.1.0 findings, and SHA-256 evidence manifests."""

    def compute_merkle_root(self, entry_hashes: list[str]) -> str:
        return compute_merkle_root(entry_hashes)

    def build_merkle_tree(self, entry_hashes: list[str]) -> dict[str, Any]:
        return build_merkle_tree(entry_hashes)

    def build_sarif_payload(
        self,
        *,
        entries: list[dict[str, Any]],
        scope_info: dict[str, Any],
        log_filename: str = "session_audit.jsonl",
    ) -> tuple[dict[str, Any], dict[str, int]]:
        """Build an in-memory SARIF v2.1.0 dictionary and per-rule finding counts."""
        results: list[dict[str, Any]] = []
        rule_counts: dict[str, int] = {r["id"]: 0 for r in _SARIF_RULES}

        for entry in entries:
            seq = int(entry.get("seq") or 0)
            status = str(entry.get("status", ""))
            target = str(entry.get("target", ""))
            cmd = str(entry.get("command", ""))
            out = str(entry.get("output_summary", ""))
            red_cnt = int(entry.get("redacted_count") or 0)
            mitre = entry.get("mitre") or {}
            ai = entry.get("ai_disclosure") or {}

            base_location = [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": log_filename},
                        "region": {"startLine": max(1, seq)},
                    }
                }
            ]
            common_props = {
                "seq": seq,
                "target": target,
                "status": status,
                "entry_hash": entry.get("entry_hash"),
                "mitre_technique": mitre.get("technique_id"),
                "risk_level": entry.get("risk_level"),
                "agent_id": ai.get("agent_id"),
            }

            if status == "REFUSED_OUT_OF_SCOPE":
                rule_id = "PENT20-SCOPE-001"
                rule_counts[rule_id] += 1
                results.append(
                    {
                        "ruleId": rule_id,
                        "level": "error",
                        "message": {"text": f"[seq={seq}] ScopeGuard blocked '{target}' (`{cmd}`): {out}"},
                        "locations": base_location,
                        "properties": common_props,
                    }
                )
            elif status == "REFUSED_PROMPT_INJECTION":
                rule_id = "PENT20-PROMPT-002"
                rule_counts[rule_id] += 1
                results.append(
                    {
                        "ruleId": rule_id,
                        "level": "error",
                        "message": {"text": f"[seq={seq}] PromptInjectionGuard blocked step on '{target}': {out}"},
                        "locations": base_location,
                        "properties": common_props,
                    }
                )
            elif status in ("KILL_SWITCH_TRIPPED", "CIRCUIT_RESET"):
                rule_id = "PENT20-CIRCUIT-004"
                rule_counts[rule_id] += 1
                results.append(
                    {
                        "ruleId": rule_id,
                        "level": "note",
                        "message": {"text": f"[seq={seq}] {status} event: {out}"},
                        "locations": base_location,
                        "properties": common_props,
                    }
                )

            if red_cnt > 0:
                rule_id = "PENT20-DLP-003"
                rule_counts[rule_id] += 1
                results.append(
                    {
                        "ruleId": rule_id,
                        "level": "warning",
                        "message": {
                            "text": f"[seq={seq}] SecretRedactor masked {red_cnt} secret(s) before persisting output for '{target}'."
                        },
                        "locations": base_location,
                        "properties": {**common_props, "redacted_count": red_cnt},
                    }
                )

        sarif_doc: dict[str, Any] = {
            "$schema": SARIF_SCHEMA_URI,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "PENT-20 Pentest Session Scribe",
                            "semanticVersion": "2.0.0",
                            "informationUri": "https://github.com/keyvanarasteh/os-lab",
                            "rules": _SARIF_RULES,
                        }
                    },
                    "automationDetails": {"id": f"pent20/{scope_info.get('session_id', 'session')}"},
                    "results": results,
                }
            ],
        }
        return sarif_doc, rule_counts

    def export_sarif(
        self,
        *,
        entries: list[dict[str, Any]],
        scope_info: dict[str, Any],
        sarif_path: str | Path,
        log_filename: str = "session_audit.jsonl",
    ) -> dict[str, Any]:
        """Write ``SESSION_FINDINGS.sarif.json`` and return export summary metadata."""
        dest = Path(sarif_path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        sarif_doc, rule_counts = self.build_sarif_payload(
            entries=entries,
            scope_info=scope_info,
            log_filename=log_filename,
        )
        dest.write_text(json.dumps(sarif_doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return {
            "sarif_path": str(dest),
            "total_findings": sum(rule_counts.values()),
            "rule_counts": rule_counts,
            "sarif": sarif_doc,
        }

    def export_evidence_manifest(
        self,
        *,
        session_id: str,
        entries: list[dict[str, Any]],
        artifact_paths: list[str | Path],
        manifest_path: str | Path,
        extra_metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Compute SHA-256 digests of all session artifacts and Merkle root into ``EVIDENCE_MANIFEST.json``."""
        dest = Path(manifest_path)
        dest.parent.mkdir(parents=True, exist_ok=True)

        entry_hashes = [str(e.get("entry_hash", "")) for e in entries if e.get("entry_hash")]
        merkle_info = self.build_merkle_tree(entry_hashes)

        artifacts: list[dict[str, Any]] = []
        seen: set[str] = set()
        for raw_p in artifact_paths:
            p = Path(raw_p)
            key = str(p.resolve())
            if key in seen or not p.exists() or not p.is_file():
                continue
            seen.add(key)
            artifacts.append(
                {
                    "filename": p.name,
                    "path": str(p),
                    "bytes": p.stat().st_size,
                    "sha256": _sha256_file(p),
                }
            )

        manifest: dict[str, Any] = {
            "manifest_version": "1.0",
            "generated_at_utc": utc_now_iso(),
            "session_id": session_id,
            "hash_algorithm": "SHA-256",
            "merkle_root": merkle_info["merkle_root"],
            "merkle_leaf_count": merkle_info["leaf_count"],
            "merkle_tree_depth": merkle_info["tree_depth"],
            "artifact_count": len(artifacts),
            "artifacts": artifacts,
        }
        if extra_metadata:
            manifest["metadata"] = extra_metadata

        dest.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return manifest

    def verify_evidence_manifest(self, manifest_path: str | Path) -> dict[str, Any]:
        """Verify SHA-256 checksums of all artifacts listed in ``EVIDENCE_MANIFEST.json``."""
        mpath = Path(manifest_path)
        manifest = json.loads(mpath.read_text(encoding="utf-8"))
        artifacts = manifest.get("artifacts", [])
        verified = 0
        mismatches: list[dict[str, Any]] = []

        for item in artifacts:
            fname = str(item.get("filename", ""))
            expected_sha = str(item.get("sha256", ""))
            candidate = mpath.parent / fname if fname else Path(str(item.get("path", "")))
            if not candidate.exists():
                candidate = Path(str(item.get("path", "")))
            if not candidate.exists() or not candidate.is_file():
                mismatches.append({"filename": fname, "reason": "missing"})
                continue
            actual_sha = _sha256_file(candidate)
            if not hmac.compare_digest(actual_sha, expected_sha):
                mismatches.append(
                    {"filename": fname, "reason": "sha256_mismatch", "expected": expected_sha, "actual": actual_sha}
                )
            else:
                verified += 1

        return {
            "valid": len(mismatches) == 0 and verified == len(artifacts),
            "verified_files": verified,
            "total_files": len(artifacts),
            "mismatches": mismatches,
            "merkle_root": manifest.get("merkle_root"),
        }
