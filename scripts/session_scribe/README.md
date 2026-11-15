# PENT-20: Pentest Session Scribe — Scoped, Logged, AI-Disclosed (Subagent)

- **Öğrenci / Geliştirici:** Aydın Arda Demiralp (`@aardademiralp`)
- **Ders / Görev:** MYO062 · **PENT-20**
- **Dal (Branch):** `feat/pent-20-session-scribe`
- **Kanıt Videosu:** [PENT-20 Kanıt Videosu — YouTube](https://youtu.be/VFLu1myMy_o) (`https://youtu.be/VFLu1myMy_o`)
- **Teslim Raporları:** [`REPORT.md`](REPORT.md) · [`docs/tasks/PENT-20/REPORT.md`](../../docs/tasks/PENT-20/REPORT.md)
- **Çalışma Ortamı:** Yalnızca Python 3.11+ Standart Kütüphanesi (harici `pip` bağımlılığı gerektirmez)

---

## Modül Mimarisi

| Modül | Görev |
|---|---|
| [`scope_guard.py`](scope_guard.py) & [`scope.json`](scope.json) | CIDR (`10.0.0.0/24`, `192.168.56.0/24`, `127.0.0.0/8`, `::1/128`), `*.lab.local` / `localhost`, izinli portlar ve komut allowlist denetimi (`ScopeGuard`, `ScopeViolationError`) |
| [`prompt_guard.py`](prompt_guard.py) | Doğrudan/dolaylı Prompt Injection, Jailbreak, Base64/Hex/ROT13 gizli yük ve `$AWS_SECRET` / `/etc/shadow` / `printenv` sızdırma engeli (`PromptInjectionGuard`, `REFUSED_PROMPT_INJECTION`) |
| [`circuit_breaker.py`](circuit_breaker.py) | Ardışık 3 ihlalde ajanı `OPEN (LOCKED)` kilidine alan otonom Kill-Switch (`SubagentCircuitBreaker`, `EmergencyKillSwitchError`) ve insan operatör onayıyla `reset_with_human_token()` kilidi açma (`CIRCUIT_RESET`) |
| [`redactor.py`](redactor.py) | Bearer token, JWT, API key, AWS sırrı, parola ve SSH/PEM özel anahtarlarını diske yazmadan `[REDACTED:<TYPE>]` olarak maskeleyen DLP modülü (`SecretRedactor`) |
| [`mitre_mapper.py`](mitre_mapper.py) | Her komutu MITRE ATT&CK taktik/teknik kimliği ve risk seviyesiyle etiketleyip 100 üzerinden Scope Compliance puanı hesaplayan motor (`MitreMapper`) |
| [`audit_logger.py`](audit_logger.py) | UTC zaman damgası, `seq`, `prev_hash` + `entry_hash` SHA-256 zincirli `session_audit.jsonl` kaydı ve `verify_log_chain()` (`TAMPER_DETECTED`) |
| [`subagent.py`](subagent.py) | Zorunlu `AIDisclosure` (`agent_id`, `model`, `reasoning`, `human_approved`, `tool_name`, `prompt_hash`), güvenli `subprocess.run(..., shell=False)` ve `--simulate` yürütme orkestratörü (`PentestSubagent`) |
| [`forensic_exporter.py`](forensic_exporter.py) | İkili SHA-256 Merkle Kökü (`build_merkle_tree`), OASIS SARIF v2.1.0 (`SESSION_FINDINGS.sarif.json`) ve tüm artefaktları mühürleyen `EVIDENCE_MANIFEST.json` (`ForensicExporter`) |
| [`html_dashboard.py`](html_dashboard.py) | Harici ağ/CDN isteği olmadan inline CSS + vanilla JS ile çalışan **4 Sekmeli** koyu temalı HTML Komuta Merkezi (`SESSION_DASHBOARD.html`) |
| [`report_signer.py`](report_signer.py) | `SESSION_REPORT.md` + SHA-256 / HMAC-SHA256 `.sig` üretimi ve doğrulaması (`generate_session_report`, `verify_report`) |
| [`cli.py`](cli.py) & [`__main__.py`](__main__.py) | Komut satırı arayüzü, `demo` modu ve varsayılan `--pause 2.2` sn (~88 sn) 10 aşamalı `showcase` sunumu |

---

## Hızlı Başlangıç ve CLI Komutları

### 10 Aşamalı Video Gösterim Modu
```bash
# Tüm 7 artefaktı belirli klasörde üret (~88 sn tam akış, varsayılan --pause 2.2)
python scripts/session_scribe/cli.py showcase --out-dir /tmp/pent20-showcase

# Duraklatmasız hızlı doğrulama
python scripts/session_scribe/cli.py showcase --pause 0 --no-color
```

### Adım Adım Oturum Yönetimi
```bash
# 1. Oturum çalışma alanını başlat
python scripts/session_scribe/cli.py init --dir /tmp/pent20-session

# 2. Kapsam denetimi (kapsam içi: exit 0, kapsam dışı: exit 1)
python scripts/session_scribe/cli.py check-scope 10.0.0.15 --command "nmap -sV -p 22,80 10.0.0.15"
python scripts/session_scribe/cli.py check-scope google.com

# 3. AI-Disclosed Subagent komutu çalıştır
python scripts/session_scribe/cli.py exec \
  --target 10.0.0.15 \
  --command "nmap -sV -p 22,80,8080 10.0.0.15" \
  --agent-id pentest-scribe-subagent-01 \
  --model os-lab-auditor-v1 \
  --reasoning "Yetkili lab VM port taraması" \
  --tool-name nmap \
  --prompt "10.0.0.15 hedefinde izinli portları tara" \
  --human-approved \
  --simulate \
  --scope /tmp/pent20-session/scope.json \
  --log /tmp/pent20-session/session_audit.jsonl

# 4. Hash zincirini doğrula
python scripts/session_scribe/cli.py verify-logs --log /tmp/pent20-session/session_audit.jsonl

# 5. İmzalı Markdown raporu, 4 sekmeli HTML Dashboard, SARIF v2.1.0 ve Evidence Manifest üret
python scripts/session_scribe/cli.py export-report \
  --log /tmp/pent20-session/session_audit.jsonl \
  --scope /tmp/pent20-session/scope.json \
  --out /tmp/pent20-session/SESSION_REPORT.md

# 6. Rapor imzasını doğrula
python scripts/session_scribe/cli.py verify-report /tmp/pent20-session/SESSION_REPORT.md
```

---

## Testleri Çalıştırma

```bash
# Python standart kütüphane testleri (42 test)
python -m unittest discover -s scripts/session_scribe/tests -v

# Pytest ile modül testleri
pytest scripts/session_scribe/tests/test_session_scribe.py -v
pytest android-lab/lab/tests/test_pent20_session_scribe.py -v
```
