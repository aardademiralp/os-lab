#!/usr/bin/env python3
"""Self-contained 4-Tab interactive dark-mode Command Center HTML dashboard for PENT-20.

Generates ``SESSION_DASHBOARD.html`` alongside ``SESSION_REPORT.md`` using only
inline CSS and vanilla JS (zero external CDN, font, or script dependencies).
Features 4 interactive tabs:
  1. Executive Overview & Telemetry (KPIs, Compliance Score, Merkle Root, Circuit Breaker)
  2. MITRE ATT&CK & Live Timeline
  3. AI Governance & Prompt Shield (AI-Use Disclosure, Prompt Injection blocks, Kill-Switch)
  4. Cryptographic & Forensic Verification (Hash Chain, Merkle Tree, SARIF, Evidence Manifest, HMAC Sig)
"""
from __future__ import annotations

import html
from pathlib import Path
from typing import Any

from .audit_logger import GENESIS_HASH, ChainVerificationResult
from .forensic_exporter import ForensicExporter
from .mitre_mapper import MitreMapper


def _esc(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _status_badge(status: str) -> str:
    cls_map = {
        "EXECUTED": "badge-green",
        "ALLOWED": "badge-cyan",
        "REFUSED_OUT_OF_SCOPE": "badge-red",
        "REFUSED_PROMPT_INJECTION": "badge-red",
        "KILL_SWITCH_TRIPPED": "badge-amber",
        "CIRCUIT_RESET": "badge-purple",
    }
    cls = cls_map.get(status, "badge-slate")
    return f'<span class="badge {cls}">{_esc(status)}</span>'


def _risk_badge(risk: str) -> str:
    cls_map = {
        "LOW": "risk-low",
        "MEDIUM": "risk-medium",
        "HIGH": "risk-high",
        "CRITICAL_BLOCKED": "risk-critical",
    }
    cls = cls_map.get(risk, "risk-low")
    return f'<span class="badge {cls}">{_esc(risk)}</span>'


_DARK_THEME_CSS = """
:root {
  --bg-root: #070b14;
  --bg-panel: #0f172a;
  --bg-card: #131f38;
  --bg-row-alt: #0d1527;
  --border: #1e293b;
  --border-glow: #0ea5e9;
  --text-main: #e2e8f0;
  --text-muted: #94a3b8;
  --cyan: #38bdf8;
  --green: #10b981;
  --red: #f43f5e;
  --amber: #f59e0b;
  --purple: #a78bfa;
  --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  --sans: system-ui, -apple-system, "Segoe UI", Roboto, Ubuntu, sans-serif;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  padding: 28px 20px 48px;
  background: radial-gradient(circle at top right, #0c1930 0%, var(--bg-root) 55%);
  color: var(--text-main);
  font-family: var(--sans);
  line-height: 1.5;
}
.container { max-width: 1360px; margin: 0 auto; }
.header {
  display: flex;
  flex-wrap: wrap;
  justify-content: space-between;
  align-items: center;
  gap: 16px;
  padding: 22px 26px;
  background: linear-gradient(135deg, #0f172a 0%, #16223b 100%);
  border: 1px solid var(--border);
  border-left: 4px solid var(--cyan);
  border-radius: 12px;
  margin-bottom: 18px;
}
.header h1 {
  margin: 0 0 6px;
  font-size: 1.42rem;
  letter-spacing: 0.02em;
  color: #f8fafc;
}
.header-meta { font-size: 0.88rem; color: var(--text-muted); }
.header-meta code {
  font-family: var(--mono);
  color: var(--cyan);
  background: rgba(56, 189, 248, 0.1);
  padding: 2px 6px;
  border-radius: 4px;
}
.pill-group { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }
.pill-status {
  padding: 8px 16px;
  border-radius: 999px;
  font-weight: 700;
  font-size: 0.82rem;
  letter-spacing: 0.04em;
  border: 1px solid transparent;
}
.pill-valid { background: rgba(16, 185, 129, 0.15); color: #34d399; border-color: rgba(16, 185, 129, 0.45); }
.pill-bad { background: rgba(244, 63, 94, 0.15); color: #fb7185; border-color: rgba(244, 63, 94, 0.45); }
.pill-cyan { background: rgba(56, 189, 248, 0.14); color: #38bdf8; border-color: rgba(56, 189, 248, 0.4); }

.tab-bar {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  background: var(--bg-panel);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 8px;
  margin-bottom: 22px;
}
.tab-btn {
  flex: 1 1 200px;
  background: transparent;
  color: var(--text-muted);
  border: 1px solid transparent;
  border-radius: 8px;
  padding: 11px 16px;
  font-size: 0.88rem;
  font-weight: 700;
  cursor: pointer;
  transition: all 0.15s ease;
  text-align: center;
}
.tab-btn:hover { color: #f8fafc; background: rgba(56, 189, 248, 0.08); }
.tab-btn.active {
  background: linear-gradient(135deg, rgba(14, 165, 233, 0.2), rgba(16, 185, 129, 0.12));
  color: #f8fafc;
  border-color: rgba(56, 189, 248, 0.55);
  box-shadow: 0 0 14px rgba(14, 165, 233, 0.16);
}
.tab-panel { display: none; }
.tab-panel.active { display: block; animation: fadeIn 0.18s ease-in; }
@keyframes fadeIn { from { opacity: 0; transform: translateY(3px); } to { opacity: 1; transform: translateY(0); } }

.kpi-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 16px;
  margin-bottom: 22px;
}
.kpi-card {
  background: var(--bg-panel);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 18px 20px;
  position: relative;
  overflow: hidden;
}
.kpi-card::before {
  content: "";
  position: absolute;
  top: 0; left: 0; right: 0; height: 3px;
  background: var(--accent, var(--cyan));
}
.kpi-card.kpi-green { --accent: var(--green); }
.kpi-card.kpi-red { --accent: var(--red); border-color: rgba(244, 63, 94, 0.35); }
.kpi-card.kpi-amber { --accent: var(--amber); }
.kpi-card.kpi-purple { --accent: var(--purple); }
.kpi-label { font-size: 0.76rem; text-transform: uppercase; letter-spacing: 0.06em; color: var(--text-muted); }
.kpi-value { font-size: 1.85rem; font-weight: 800; margin: 6px 0 4px; color: #f8fafc; }
.kpi-red .kpi-value { color: #fb7185; }
.kpi-green .kpi-value { color: #34d399; }
.kpi-amber .kpi-value { color: #fbbf24; }
.kpi-purple .kpi-value { color: #c4b5fd; }
.kpi-sub { font-size: 0.8rem; color: var(--text-muted); }
.panel {
  background: var(--bg-panel);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 20px 22px;
  margin-bottom: 22px;
}
.panel h2 {
  margin: 0 0 14px;
  font-size: 1.05rem;
  color: #f1f5f9;
  border-bottom: 1px solid var(--border);
  padding-bottom: 10px;
  display: flex;
  flex-wrap: wrap;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
}
.ai-banner, .sig-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 12px;
  margin-bottom: 14px;
}
.ai-chip, .sig-item {
  background: var(--bg-card);
  border: 1px solid #26344d;
  border-radius: 8px;
  padding: 12px 14px;
}
.ai-chip .label, .sig-item .k { font-size: 0.74rem; text-transform: uppercase; color: var(--purple); font-weight: 700; }
.ai-chip .val { font-family: var(--mono); font-size: 0.84rem; color: #f8fafc; margin-top: 4px; word-break: break-all; }
.sig-item .k { color: var(--text-muted); }
.sig-item .v { font-family: var(--mono); font-size: 0.82rem; color: #34d399; margin-top: 4px; word-break: break-all; }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: 0.84rem; }
th {
  text-align: left;
  padding: 10px 10px;
  color: var(--cyan);
  background: var(--bg-card);
  border-bottom: 1px solid var(--border);
  font-size: 0.75rem;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  white-space: nowrap;
}
td { padding: 10px 10px; border-bottom: 1px solid var(--border); vertical-align: top; }
tr:nth-child(even) td { background: var(--bg-row-alt); }
code.mono {
  font-family: var(--mono);
  font-size: 0.79rem;
  color: #cbd5e1;
  background: #090e1a;
  padding: 2px 5px;
  border-radius: 4px;
  word-break: break-all;
}
.badge {
  display: inline-block;
  padding: 3px 8px;
  border-radius: 6px;
  font-size: 0.72rem;
  font-weight: 700;
  font-family: var(--mono);
  white-space: nowrap;
}
.badge-green { background: rgba(16, 185, 129, 0.16); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.4); }
.badge-cyan { background: rgba(56, 189, 248, 0.15); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.4); }
.badge-red { background: rgba(244, 63, 94, 0.18); color: #fb7185; border: 1px solid rgba(244, 63, 94, 0.45); }
.badge-purple { background: rgba(167, 139, 250, 0.16); color: #c4b5fd; border: 1px solid rgba(167, 139, 250, 0.4); }
.badge-amber { background: rgba(245, 158, 11, 0.16); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.4); }
.badge-slate { background: rgba(148, 163, 184, 0.15); color: #cbd5e1; border: 1px solid rgba(148, 163, 184, 0.35); }
.risk-low { background: rgba(16, 185, 129, 0.12); color: #6ee7b7; border: 1px solid rgba(16, 185, 129, 0.35); }
.risk-medium { background: rgba(245, 158, 11, 0.15); color: #fcd34d; border: 1px solid rgba(245, 158, 11, 0.4); }
.risk-high { background: rgba(249, 115, 22, 0.18); color: #fdba74; border: 1px solid rgba(249, 115, 22, 0.45); }
.risk-critical { background: rgba(244, 63, 94, 0.22); color: #fda4af; border: 1px solid rgba(244, 63, 94, 0.55); }
.chain-flow { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; padding: 12px 4px 4px; }
.chain-node {
  background: var(--bg-card);
  border: 1px solid #283855;
  border-radius: 8px;
  padding: 10px 12px;
  min-width: 170px;
  font-family: var(--mono);
  font-size: 0.75rem;
}
.chain-node.genesis { border-color: var(--cyan); }
.chain-node.valid-end { border-color: var(--green); background: rgba(16, 185, 129, 0.12); }
.chain-node.bad-end { border-color: var(--red); background: rgba(244, 63, 94, 0.14); }
.chain-node .title { font-weight: 700; color: #f8fafc; margin-bottom: 4px; }
.chain-node .hash { color: var(--cyan); }
.chain-arrow { color: var(--green); font-weight: 900; font-size: 1.1rem; }
.chain-arrow.bad { color: var(--red); }
.footer-note { text-align: center; font-size: 0.78rem; color: var(--text-muted); margin-top: 18px; }
"""

_TAB_JS = """
function switchTab(tabId, btn) {
  var panels = document.querySelectorAll('.tab-panel');
  for (var i = 0; i < panels.length; i++) {
    panels[i].classList.remove('active');
  }
  var buttons = document.querySelectorAll('.tab-btn');
  for (var j = 0; j < buttons.length; j++) {
    buttons[j].classList.remove('active');
    buttons[j].setAttribute('aria-selected', 'false');
  }
  var target = document.getElementById('tab-' + tabId);
  if (target) {
    target.classList.add('active');
  }
  if (btn) {
    btn.classList.add('active');
    btn.setAttribute('aria-selected', 'true');
  }
}
"""


class HTMLDashboard:
    """Renders a self-contained 4-Tab interactive dark-mode audit command center."""

    def __init__(self) -> None:
        self._mapper = MitreMapper()
        self._forensic = ForensicExporter()

    def render(
        self,
        *,
        entries: list[dict[str, Any]],
        scope_info: dict[str, Any],
        chain_result: ChainVerificationResult,
        compliance: dict[str, Any],
        signature: dict[str, Any],
        generated_at: str,
        merkle_info: dict[str, Any] | None = None,
        sarif_summary: dict[str, Any] | None = None,
        manifest_data: dict[str, Any] | None = None,
        circuit_breaker_info: dict[str, Any] | None = None,
    ) -> str:
        """Render complete 4-Tab HTML string for ``SESSION_DASHBOARD.html``."""
        total_steps = int(compliance.get("total_steps", len(entries)))
        in_scope_steps = int(compliance.get("in_scope_steps", 0))
        blocked_steps = int(compliance.get("blocked_steps", 0))
        prompt_blocks = int(compliance.get("prompt_injection_blocks", 0))
        redacted_secrets = int(compliance.get("redacted_secrets", 0))
        score = int(compliance.get("score", 100))
        grade = str(compliance.get("grade", "A+ (EXCELLENT)"))

        if merkle_info is None:
            hashes = [str(e.get("entry_hash", "")) for e in entries if e.get("entry_hash")]
            merkle_info = self._forensic.build_merkle_tree(hashes)
        merkle_root = str(merkle_info.get("merkle_root", GENESIS_HASH))

        if sarif_summary is None:
            _, rule_counts = self._forensic.build_sarif_payload(entries=entries, scope_info=scope_info)
            sarif_summary = {"total_findings": sum(rule_counts.values()), "rule_counts": rule_counts}

        chain_ok = chain_result.valid
        chain_pill_cls = "pill-valid" if chain_ok else "pill-bad"
        chain_pill_label = (
            f"AUDIT CHAIN: {chain_result.status} ({chain_result.verified_entries}/{chain_result.total_entries})"
        )

        # Infer circuit breaker state from entries if not explicitly supplied
        cb_trips = sum(1 for e in entries if e.get("status") == "KILL_SWITCH_TRIPPED")
        cb_resets = sum(1 for e in entries if e.get("status") == "CIRCUIT_RESET")
        cb_state = str((circuit_breaker_info or {}).get("state", ""))
        if not cb_state:
            cb_state = "OPEN (LOCKED)" if cb_trips > cb_resets else "CLOSED (ARMED)"
        cb_locked = "OPEN" in cb_state

        agents = sorted(
            {
                str((e.get("ai_disclosure") or {}).get("agent_id", "")).strip()
                for e in entries
                if str((e.get("ai_disclosure") or {}).get("agent_id", "")).strip()
            }
        ) or ["pentest-scribe-subagent"]
        models = sorted(
            {
                str((e.get("ai_disclosure") or {}).get("model", "")).strip()
                for e in entries
                if str((e.get("ai_disclosure") or {}).get("model", "")).strip()
            }
        ) or ["os-lab-auditor"]

        step_rows: list[str] = []
        ai_rows: list[str] = []
        shield_rows: list[str] = []

        for e in entries:
            seq = e.get("seq", "?")
            status = str(e.get("status", "UNKNOWN"))
            cmd = str(e.get("command", ""))
            mitre = e.get("mitre")
            if not isinstance(mitre, dict) or not mitre.get("technique_id"):
                mitre = self._mapper.map_step(cmd, status=status).to_dict()
            tech_id = mitre.get("technique_id", "T1595")
            tech_name = mitre.get("technique_name", "Active Scanning")
            tactic_name = mitre.get("tactic_name", "Reconnaissance")
            risk = str(mitre.get("risk_level", e.get("risk_level", "LOW")))
            red_cnt = int(e.get("redacted_count") or 0)
            dlp_badge = (
                f'<span class="badge badge-amber">{red_cnt} masked</span>'
                if red_cnt > 0
                else '<span class="badge badge-slate">0</span>'
            )

            step_rows.append(
                "<tr>"
                f"<td><strong>#{_esc(seq)}</strong></td>"
                f"<td><code class=\"mono\">{_esc(e.get('timestamp', ''))}</code></td>"
                f"<td><code class=\"mono\">{_esc(e.get('target', ''))}</code></td>"
                f"<td><code class=\"mono\">{_esc(cmd)}</code></td>"
                f"<td><span class=\"badge badge-purple\">{_esc(tech_id)}</span> {_esc(tech_name)}</td>"
                f"<td>{_esc(tactic_name)}</td>"
                f"<td>{_risk_badge(risk)}</td>"
                f"<td>{dlp_badge}</td>"
                f"<td>{_status_badge(status)}</td>"
                f"<td>{_esc(e.get('output_summary', ''))}</td>"
                "</tr>"
            )

            ai = e.get("ai_disclosure") or {}
            approved_val = bool(ai.get("human_approved", False))
            approved_badge = (
                '<span class="badge badge-green">TRUE</span>'
                if approved_val
                else '<span class="badge badge-red">FALSE</span>'
            )
            ai_rows.append(
                "<tr>"
                f"<td><strong>#{_esc(seq)}</strong></td>"
                f"<td><code class=\"mono\">{_esc(ai.get('agent_id', '-'))}</code></td>"
                f"<td><code class=\"mono\">{_esc(ai.get('model', '-'))}</code></td>"
                f"<td><code class=\"mono\">{_esc(ai.get('tool_name', '-'))}</code></td>"
                f"<td>{approved_badge}</td>"
                f"<td><code class=\"mono\">{_esc(str(ai.get('prompt_hash', '-'))[:24])}...</code></td>"
                f"<td>{_esc(ai.get('reasoning', '-'))}</td>"
                "</tr>"
            )

            if status in ("REFUSED_PROMPT_INJECTION", "KILL_SWITCH_TRIPPED", "CIRCUIT_RESET"):
                shield_rows.append(
                    "<tr>"
                    f"<td><strong>#{_esc(seq)}</strong></td>"
                    f"<td>{_status_badge(status)}</td>"
                    f"<td><code class=\"mono\">{_esc(e.get('target', '-'))}</code></td>"
                    f"<td><code class=\"mono\">{_esc(cmd)}</code></td>"
                    f"<td><code class=\"mono\">{_esc(ai.get('agent_id', '-'))}</code></td>"
                    f"<td>{_esc(e.get('output_summary', ''))}</td>"
                    "</tr>"
                )

        if not step_rows:
            step_rows.append('<tr><td colspan="10"><em>No audit steps recorded.</em></td></tr>')
        if not ai_rows:
            ai_rows.append('<tr><td colspan="7"><em>No AI subagent disclosures recorded.</em></td></tr>')
        if not shield_rows:
            shield_rows.append(
                '<tr><td colspan="6"><em>No Prompt Injection blocks or Circuit Breaker events in this session.</em></td></tr>'
            )

        # Visual SHA-256 Hash-Chain
        arrow_cls = "chain-arrow" if chain_ok else "chain-arrow bad"
        chain_nodes: list[str] = [
            '<div class="chain-node genesis">'
            '<div class="title">GENESIS</div>'
            f'<div class="hash">{_esc(GENESIS_HASH[:16])}...</div>'
            '</div>'
        ]
        for e in entries:
            seq = e.get("seq", "?")
            prev_h = str(e.get("prev_hash", ""))[:12]
            curr_h = str(e.get("entry_hash", ""))[:12]
            status = str(e.get("status", ""))
            chain_nodes.append(f'<span class="{arrow_cls}">&rarr;</span>')
            chain_nodes.append(
                '<div class="chain-node">'
                f'<div class="title">Entry #{_esc(seq)} ({_esc(status)})</div>'
                f'<div>prev: <span class="hash">{_esc(prev_h)}...</span></div>'
                f'<div>hash: <span class="hash">{_esc(curr_h)}...</span></div>'
                '</div>'
            )
        end_cls = "valid-end" if chain_ok else "bad-end"
        end_title = "CHAIN VALID" if chain_ok else f"TAMPER_DETECTED (seq={chain_result.failed_seq})"
        chain_nodes.append(f'<span class="{arrow_cls}">&rarr;</span>')
        chain_nodes.append(
            f'<div class="chain-node {end_cls}">'
            f'<div class="title">{_esc(end_title)}</div>'
            f'<div>head: <span class="hash">{_esc(chain_result.head_hash[:16])}...</span></div>'
            '</div>'
        )

        # Evidence Manifest table rows (Tab 4)
        manifest_rows: list[str] = []
        artifacts = (manifest_data or {}).get("artifacts", [])
        for art in artifacts:
            manifest_rows.append(
                "<tr>"
                f"<td><code class=\"mono\">{_esc(art.get('filename', '-'))}</code></td>"
                f"<td>{_esc(art.get('bytes', 0))} bytes</td>"
                f"<td><code class=\"mono\">{_esc(art.get('sha256', '-'))}</code></td>"
                "</tr>"
            )
        if not manifest_rows:
            manifest_rows.append('<tr><td colspan="3"><em>Manifest metadata generated upon full bundle export.</em></td></tr>')

        # SARIF Rule summary chips (Tab 4)
        sarif_counts = sarif_summary.get("rule_counts", {})

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PENT-20 Command Center — {_esc(scope_info.get('session_id', 'session'))}</title>
  <style>{_DARK_THEME_CSS}</style>
</head>
<body>
  <div class="container">
    <header class="header">
      <div>
        <h1>PENT-20 Pentest Session Scribe — Security &amp; AI Governance Command Center</h1>
        <div class="header-meta">
          Session: <code>{_esc(scope_info.get('session_id', '-'))}</code> &bull;
          Scope: <strong>{_esc(scope_info.get('name', '-'))}</strong> &bull;
          Generated (UTC): <code>{_esc(generated_at)}</code>
        </div>
      </div>
      <div class="pill-group">
        <div class="pill-status pill-cyan">COMPLIANCE: {score}/100</div>
        <div class="pill-status {chain_pill_cls}">{_esc(chain_pill_label)}</div>
      </div>
    </header>

    <nav class="tab-bar" role="tablist" aria-label="Dashboard Sections">
      <button type="button" class="tab-btn active" role="tab" aria-selected="true" onclick="switchTab('overview', this)">1. Executive Overview &amp; Telemetry</button>
      <button type="button" class="tab-btn" role="tab" aria-selected="false" onclick="switchTab('mitre', this)">2. MITRE ATT&amp;CK &amp; Live Timeline</button>
      <button type="button" class="tab-btn" role="tab" aria-selected="false" onclick="switchTab('governance', this)">3. AI Governance &amp; Prompt Shield</button>
      <button type="button" class="tab-btn" role="tab" aria-selected="false" onclick="switchTab('forensic', this)">4. Cryptographic &amp; Forensic Verification</button>
    </nav>

    <!-- TAB 1: EXECUTIVE OVERVIEW & TELEMETRY -->
    <div id="tab-overview" class="tab-panel active">
      <section class="kpi-grid" aria-label="Session KPIs">
        <div class="kpi-card">
          <div class="kpi-label">Total Logged Steps</div>
          <div class="kpi-value">{total_steps}</div>
          <div class="kpi-sub">All audited &amp; chained events</div>
        </div>
        <div class="kpi-card kpi-green">
          <div class="kpi-label">In-Scope Approved</div>
          <div class="kpi-value">{in_scope_steps}</div>
          <div class="kpi-sub">Authorized lab targets only</div>
        </div>
        <div class="kpi-card kpi-red">
          <div class="kpi-label">Threats Blocked</div>
          <div class="kpi-value">{blocked_steps}</div>
          <div class="kpi-sub">Scope + {prompt_blocks} Prompt Shield</div>
        </div>
        <div class="kpi-card kpi-amber">
          <div class="kpi-label">Masked Secrets (DLP)</div>
          <div class="kpi-value">{redacted_secrets}</div>
          <div class="kpi-sub">Redacted before log persistence</div>
        </div>
        <div class="kpi-card kpi-purple">
          <div class="kpi-label">Compliance &amp; Safety</div>
          <div class="kpi-value">{score}/100</div>
          <div class="kpi-sub">{_esc(grade)}</div>
        </div>
        <div class="kpi-card {'kpi-red' if cb_locked else 'kpi-green'}">
          <div class="kpi-label">Circuit Breaker</div>
          <div class="kpi-value" style="font-size:1.25rem;">{_esc(cb_state)}</div>
          <div class="kpi-sub">Trips: {cb_trips} &bull; HITL Resets: {cb_resets}</div>
        </div>
      </section>

      <section class="panel">
        <h2>
          <span>Authorized Scope Policy &amp; Cryptographic Anchors</span>
          <span class="badge badge-cyan">FAIL-CLOSED SCOPE ENGINE</span>
        </h2>
        <div class="ai-banner">
          <div class="ai-chip">
            <div class="label">Allowed CIDRs</div>
            <div class="val">{_esc(', '.join(scope_info.get('allowed_cidrs', ())))}</div>
          </div>
          <div class="ai-chip">
            <div class="label">Allowed Domains</div>
            <div class="val">{_esc(', '.join(scope_info.get('allowed_domains', ())))}</div>
          </div>
          <div class="ai-chip">
            <div class="label">Allowed Commands</div>
            <div class="val">{_esc(', '.join(scope_info.get('allowed_commands', ())))}</div>
          </div>
          <div class="ai-chip">
            <div class="label">Binary Merkle Root (SHA-256)</div>
            <div class="val">{_esc(merkle_root)}</div>
          </div>
        </div>
      </section>
    </div>

    <!-- TAB 2: MITRE ATT&CK & LIVE TIMELINE -->
    <div id="tab-mitre" class="tab-panel">
      <section class="panel">
        <h2>
          <span>MITRE ATT&amp;CK&reg; Execution &amp; Scope Enforcement Ledger</span>
          <span class="badge badge-cyan">DLP + SCOPE GUARD ACTIVE</span>
        </h2>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Seq</th>
                <th>Timestamp (UTC)</th>
                <th>Target</th>
                <th>Command (Sanitized)</th>
                <th>MITRE ATT&amp;CK Technique</th>
                <th>Tactic</th>
                <th>Risk Level</th>
                <th>DLP</th>
                <th>Status</th>
                <th>Output Summary</th>
              </tr>
            </thead>
            <tbody>
              {''.join(step_rows)}
            </tbody>
          </table>
        </div>
      </section>
    </div>

    <!-- TAB 3: AI GOVERNANCE & PROMPT SHIELD -->
    <div id="tab-governance" class="tab-panel">
      <section class="panel">
        <h2>
          <span>AI-Use Disclosure &amp; Autonomous Agent Safety Controls</span>
          <span class="badge badge-purple">PROMPT SHIELD + KILL-SWITCH</span>
        </h2>
        <div class="ai-banner">
          <div class="ai-chip">
            <div class="label">Agent Identity</div>
            <div class="val">{_esc(', '.join(agents))}</div>
          </div>
          <div class="ai-chip">
            <div class="label">AI Model(s)</div>
            <div class="val">{_esc(', '.join(models))}</div>
          </div>
          <div class="ai-chip">
            <div class="label">Prompt Injection Blocks</div>
            <div class="val">{prompt_blocks} Blocked (Direct + Indirect)</div>
          </div>
          <div class="ai-chip">
            <div class="label">Circuit Breaker Status</div>
            <div class="val">{_esc(cb_state)} (Trips: {cb_trips}, Unlocks: {cb_resets})</div>
          </div>
        </div>

        <h3 style="font-size:0.95rem;color:#fb7185;margin:14px 0 8px;">Prompt Injection Shield &amp; Circuit Breaker Events</h3>
        <div class="table-wrap" style="margin-bottom:18px;">
          <table>
            <thead>
              <tr>
                <th>Seq</th>
                <th>Event Status</th>
                <th>Target</th>
                <th>Command / Payload</th>
                <th>Actor / Agent</th>
                <th>Shield / Kill-Switch Details</th>
              </tr>
            </thead>
            <tbody>
              {''.join(shield_rows)}
            </tbody>
          </table>
        </div>

        <h3 style="font-size:0.95rem;color:#c4b5fd;margin:14px 0 8px;">Complete AI-Use Disclosure Provenance Ledger</h3>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Seq</th>
                <th>Agent ID</th>
                <th>Model</th>
                <th>Tool</th>
                <th>Human Approved</th>
                <th>Prompt Hash (SHA-256)</th>
                <th>Reasoning</th>
              </tr>
            </thead>
            <tbody>
              {''.join(ai_rows)}
            </tbody>
          </table>
        </div>
      </section>
    </div>

    <!-- TAB 4: CRYPTOGRAPHIC & FORENSIC VERIFICATION -->
    <div id="tab-forensic" class="tab-panel">
      <section class="panel">
        <h2>
          <span>SHA-256 Hash-Chain Visual Verification</span>
          <span class="badge {'badge-green' if chain_ok else 'badge-red'}">{_esc(chain_result.status)}</span>
        </h2>
        <div class="chain-flow">
          {''.join(chain_nodes)}
        </div>
      </section>

      <section class="panel">
        <h2>
          <span>Forensic Merkle-Tree &amp; SARIF v2.1.0 Summary</span>
          <span class="badge badge-cyan">{int(sarif_summary.get('total_findings', 0))} SARIF FINDINGS</span>
        </h2>
        <div class="sig-grid" style="margin-bottom:16px;">
          <div class="sig-item">
            <div class="k">Merkle Tree Root (SHA-256)</div>
            <div class="v">{_esc(merkle_root)}</div>
          </div>
          <div class="sig-item">
            <div class="k">Merkle Leaves / Tree Depth</div>
            <div class="v">{int(merkle_info.get('leaf_count', 0))} leaves / depth {int(merkle_info.get('tree_depth', 1))}</div>
          </div>
          <div class="sig-item">
            <div class="k">SARIF Findings by Rule</div>
            <div class="v">SCOPE={int(sarif_counts.get('PENT20-SCOPE-001', 0))} &bull; PROMPT={int(sarif_counts.get('PENT20-PROMPT-002', 0))} &bull; DLP={int(sarif_counts.get('PENT20-DLP-003', 0))} &bull; CIRCUIT={int(sarif_counts.get('PENT20-CIRCUIT-004', 0))}</div>
          </div>
        </div>
        <h3 style="font-size:0.95rem;color:#38bdf8;margin:10px 0 8px;">Evidence Manifest (EVIDENCE_MANIFEST.json SHA-256 Checksums)</h3>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Artifact File</th>
                <th>Size</th>
                <th>SHA-256 Checksum</th>
              </tr>
            </thead>
            <tbody>
              {''.join(manifest_rows)}
            </tbody>
          </table>
        </div>
      </section>

      <section class="panel">
        <h2>
          <span>Cryptographic Report Signature Proof (SHA-256 + HMAC-SHA256)</span>
          <span class="badge badge-green">SIGNED</span>
        </h2>
        <div class="sig-grid">
          <div class="sig-item">
            <div class="k">Signed Markdown Report</div>
            <div class="v">{_esc(signature.get('report_file', 'SESSION_REPORT.md'))} ({_esc(signature.get('report_bytes', 0))} bytes)</div>
          </div>
          <div class="sig-item">
            <div class="k">Signature Algorithm</div>
            <div class="v">{_esc(signature.get('algorithm', 'HMAC-SHA256'))} / {_esc(signature.get('hash_algorithm', 'SHA-256'))}</div>
          </div>
          <div class="sig-item">
            <div class="k">Content SHA-256 Digest</div>
            <div class="v">{_esc(signature.get('content_sha256', '-'))}</div>
          </div>
          <div class="sig-item">
            <div class="k">HMAC-SHA256 Signature</div>
            <div class="v">{_esc(signature.get('hmac_sha256', '-'))}</div>
          </div>
          <div class="sig-item">
            <div class="k">Key Fingerprint</div>
            <div class="v">{_esc(signature.get('key_fingerprint', '-'))}</div>
          </div>
          <div class="sig-item">
            <div class="k">Signed At (UTC)</div>
            <div class="v">{_esc(signature.get('signed_at', generated_at))}</div>
          </div>
        </div>
      </section>
    </div>

    <div class="footer-note">
      PENT-20: Pentest Session Scribe &bull; Authorization: {_esc(scope_info.get('authorization', '-'))} &bull; Self-Contained Offline 4-Tab Forensic Command Center
    </div>
  </div>
  <script>{_TAB_JS}</script>
</body>
</html>
"""

    def write(
        self,
        *,
        entries: list[dict[str, Any]],
        scope_info: dict[str, Any],
        chain_result: ChainVerificationResult,
        compliance: dict[str, Any],
        signature: dict[str, Any],
        generated_at: str,
        html_path: str | Path,
        merkle_info: dict[str, Any] | None = None,
        sarif_summary: dict[str, Any] | None = None,
        manifest_data: dict[str, Any] | None = None,
        circuit_breaker_info: dict[str, Any] | None = None,
    ) -> Path:
        """Render and write ``SESSION_DASHBOARD.html`` to disk."""
        dest = Path(html_path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        content = self.render(
            entries=entries,
            scope_info=scope_info,
            chain_result=chain_result,
            compliance=compliance,
            signature=signature,
            generated_at=generated_at,
            merkle_info=merkle_info,
            sarif_summary=sarif_summary,
            manifest_data=manifest_data,
            circuit_breaker_info=circuit_breaker_info,
        )
        dest.write_text(content, encoding="utf-8")
        return dest


def generate_html_dashboard(
    *,
    entries: list[dict[str, Any]],
    scope_info: dict[str, Any],
    chain_result: ChainVerificationResult,
    compliance: dict[str, Any],
    signature: dict[str, Any],
    generated_at: str,
    html_path: str | Path,
    merkle_info: dict[str, Any] | None = None,
    sarif_summary: dict[str, Any] | None = None,
    manifest_data: dict[str, Any] | None = None,
    circuit_breaker_info: dict[str, Any] | None = None,
) -> Path:
    """Convenience function to write a self-contained 4-Tab ``SESSION_DASHBOARD.html``."""
    return HTMLDashboard().write(
        entries=entries,
        scope_info=scope_info,
        chain_result=chain_result,
        compliance=compliance,
        signature=signature,
        generated_at=generated_at,
        html_path=html_path,
        merkle_info=merkle_info,
        sarif_summary=sarif_summary,
        manifest_data=manifest_data,
        circuit_breaker_info=circuit_breaker_info,
    )
