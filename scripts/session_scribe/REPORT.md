# PENT-20 — Pentest Session Scribe: Scoped, Logged, AI-Disclosed (Subagent)

| Alan | Değer |
|---|---|
| **Öğrenci** | Aydın Arda Demiralp (`aardademiralp`) |
| **Ders** | MYO062 — Vize Projesi |
| **Görev** | [PENT-20](../../CONTRIBUTING.md) · Pentest Session Scribe: Scoped, Logged, AI-Disclosed (Subagent) |
| **Dal (Branch)** | `feat/pent-20-session-scribe` |
| **Rezervasyon** | [`reservations/PENT-20.json`](../../reservations/PENT-20.json) |
| **Çalışma Ortamı** | Yalnızca Python Standart Kütüphanesi (Python 3.11+, harici `pip` paketi gerektirmez) |

> **Kanıt Videosu (2-4 dk):** [PENT-20 Kanıt Videosu — YouTube](https://youtu.be/VFLu1myMy_o) (`https://youtu.be/VFLu1myMy_o`)

---

## 1. Proje Amacı ve PENT-20 Gereksinim Karşılama Tablosu

**PENT-20 (Pentest Session Scribe)**, `os-lab` ekosistemindeki *"yalnızca yetkili ve izole lab hedefleri"* ilkesini ve `AGENTS.md` alt-ajan (subagent) yönetişim modelini kod seviyesinde zorunlu kılan; kapsam denetimi, DLP maskeleme, MITRE ATT&CK telemetrisi, AI Prompt Injection kalkanı, otonom devre kesici (Kill-Switch) ve adli bilişim (Merkle Tree, SARIF v2.1.0, Evidence Manifest) çıktıları üreten tam kapsamlı bir sızma testi oturum kayıt ve denetim platformudur.

Aracın temel yetenekleri:
1. Sızma testi sırasında yalnızca `scope.json` içinde tanımlı CIDR alt ağlarına, lab domainlerine, izinli portlara ve güvenli komutlara izin vermek; tüm kapsam dışı hedefleri (`google.com`, `8.8.8.8`, `1.1.1.1` vb.) ve tehlikeli bayrakları/kabuk enjeksiyonlarını çalıştırmadan reddetmek (`ScopeViolationError`).
2. Alt-ajan istemlerinde, teknik gerekçelerde, komutlarda veya hedef çıktılarında gizlenmiş doğrudan/dolaylı **Prompt Injection**, **Jailbreak**, kodlanmış yük (**Base64 / Hex / ROT13**) ve sır sızdırma (`cat /etc/shadow`, `$AWS_SECRET`, `printenv`) girişimlerini `REFUSED_PROMPT_INJECTION` olarak engellemek (`PromptInjectionGuard`).
3. Üst üste 3 güvenlik ihlali yaşandığında otonom alt-ajanı `OPEN (LOCKED)` durumuna geçirip `EmergencyKillSwitchError` ile dondurmak ve yalnızca insan operatör onaylı token (`reset_with_human_token`) ile kilidi açmak (`SubagentCircuitBreaker`).
4. Komutlarda ve çıktılarda yer alabilecek hassas verileri (`Bearer <token>`, JWT, API anahtarları, AWS sırları, parolalar, SSH/PEM özel anahtarları) diske yazılmadan önce `[REDACTED:<TYPE>]` biçiminde maskelemek (`SecretRedactor`).
5. Her komutu otomatik olarak **MITRE ATT&CK** taktik/teknik kimliği ve risk seviyesiyle (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL_BLOCKED`) etiketleyip 100 üzerinden **Scope Compliance & Safety Score** hesaplamak (`MitreMapper`).
6. Her adımı **AI-Use Disclosure** verileriyle (`agent_id`, `model`, `reasoning`, `human_approved`, `tool_name`, `prompt_hash`) birlikte kurcalamaya karşı korumalı **SHA-256 hash zincirli JSONL** (`session_audit.jsonl`) olarak kaydetmek ve ikili **Merkle Ağacı Kök Özeti (`merkle_root`)**, **OASIS SARIF v2.1.0 (`SESSION_FINDINGS.sarif.json`)** ve **`EVIDENCE_MANIFEST.json`** üretmek (`ForensicExporter`).
7. Oturum sonunda **SHA-256 + HMAC-SHA256** imzalı `SESSION_REPORT.md` + `SESSION_REPORT.md.sig` ile birlikte internet bağlantısı gerektirmeyen **4 sekmeli etkileşimli koyu temalı HTML Komuta Merkezi** (`SESSION_DASHBOARD.html`) oluşturmak.

### Gereksinim Karşılama Tablosu

| Gereksinim | Modül / Bileşen | Uygulanan Davranış | Durum |
|---|---|---|---|
| **Kapsam & Yetki Denetimi** | [`scope_guard.py`](scope_guard.py), [`scope.json`](scope.json) | `ipaddress` ile CIDR (`10.0.0.0/24`, `192.168.56.0/24`, `127.0.0.0/8`, `::1/128`), `*.lab.local`/`localhost` domain, port ve komut allowlist denetimi; kapsam dışı hedeflerde `ScopeViolationError` | Tamamlandı |
| **AI Prompt Injection & Jailbreak Kalkanı** | [`prompt_guard.py`](prompt_guard.py) | `PromptInjectionGuard` ile kural atlatma (`ignore previous instructions`, `override scope.json`), Base64/Hex/ROT13 gizli yük ve doğrudan/dolaylı enjeksiyon engeli (`REFUSED_PROMPT_INJECTION`) | Tamamlandı |
| **Otonom Devre Kesici & Kill-Switch** | [`circuit_breaker.py`](circuit_breaker.py) | `SubagentCircuitBreaker(max_violations=3)` ile 3 ardışık ihlalde `OPEN (LOCKED)` + `EmergencyKillSwitchError` kilidi; insan operatör onayıyla `CIRCUIT_RESET` | Tamamlandı |
| **DLP Hassas Veri & Sır Maskeleme** | [`redactor.py`](redactor.py) | `SecretRedactor` ile API anahtarları, `Bearer` token, JWT, `password=`, AWS sırları ve SSH Private Key bloklarını `[REDACTED:<TYPE>]` olarak maskeleme; `redacted_count` kaydı | Tamamlandı |
| **MITRE ATT&CK & Uyumluluk Puanı** | [`mitre_mapper.py`](mitre_mapper.py) | `MitreMapper` ile teknik/taktik eşleştirme (`T1046`, `T1595.002`, `T1018`, `T1590.002`, `T1057`, `T1082`, `T1059`, `T1499`, `T1078`), risk sınıfı ve 100 üzerinden Score | Tamamlandı |
| **Kurcalamaya Korumalı Hash-Chained Log** | [`audit_logger.py`](audit_logger.py) | UTC ISO-8601, `seq`, `redacted_count`, `mitre`, `risk_level`, `status`, `prev_hash` + `entry_hash` (SHA-256); `verify_log_chain()` ile `TAMPER_DETECTED` | Tamamlandı |
| **AI-Disclosed Subagent Katmanı** | [`subagent.py`](subagent.py) | Zorunlu `AIDisclosure`; yürütme öncesi `PromptInjectionGuard` + `ScopeGuard` + `SubagentCircuitBreaker`, yürütme sonrası çıktı üzerinde dolaylı enjeksiyon denetimi | Tamamlandı |
| **Merkle Tree, SARIF v2.1.0 & Evidence Manifest** | [`forensic_exporter.py`](forensic_exporter.py) | `ForensicExporter` ile ikili SHA-256 Merkle kökü (`merkle_root`), `SESSION_FINDINGS.sarif.json` (SARIF v2.1.0) ve 6 artefaktın SHA-256'sını mühürleyen `EVIDENCE_MANIFEST.json` | Tamamlandı |
| **İmzalı Rapor & 4 Sekmeli HTML Komuta Merkezi** | [`report_signer.py`](report_signer.py), [`html_dashboard.py`](html_dashboard.py) | `SESSION_REPORT.md` + `SESSION_REPORT.md.sig` (SHA-256 + HMAC-SHA256) ve inline CSS/JS ile 4 sekmeli çevrimdışı `SESSION_DASHBOARD.html` | Tamamlandı |
| **CLI, Demo & 10 Aşamalı Video Sunumu** | [`cli.py`](cli.py), [`__main__.py`](__main__.py) | `init`, `check-scope`, `exec`, `verify-logs`, `export-report`, `verify-report`, `demo` ve `--pause 2.2` (~88 sn) varsayılanlı 10 aşamalı `showcase` komutu | Tamamlandı |
| **Testler & Repo Entegrasyonu** | [`tests/test_session_scribe.py`](tests/test_session_scribe.py), [`scripts/run-tests.sh`](../../scripts/run-tests.sh) | 42 birim/entegrasyon testi (`unittest` & `pytest`), `android-lab` pytest sarmalayıcısı, `run-tests.sh` entegrasyonu ve [`lat.md/tooling.md`](../../lat.md/tooling.md) düğümü | Tamamlandı |

---

## 2. Mimari ve Modül Açıklamaları

```text
scripts/session_scribe/
├── __init__.py           # Paket dışa aktarımları
├── __main__.py           # `python -m scripts.session_scribe` giriş noktası
├── scope.json            # Varsayılan yetkili lab kapsam bildirimi
├── scope_guard.py        # Kapsam ve yetki motoru (ScopeGuard, ScopeViolationError)
├── prompt_guard.py       # AI Prompt Injection & Jailbreak kalkanı (PromptInjectionGuard)
├── circuit_breaker.py    # Otonom Kill-Switch & HITL sıfırlama (SubagentCircuitBreaker)
├── redactor.py           # DLP hassas veri ve sır maskeleyici (SecretRedactor)
├── mitre_mapper.py       # MITRE ATT&CK eşleştirici ve Compliance Score motoru (MitreMapper)
├── audit_logger.py       # SHA-256 hash zincirli JSONL denetim günlüğü ve doğrulayıcı
├── subagent.py           # AI-Disclosed Subagent yürütücü ve güvenlik orkestratörü
├── forensic_exporter.py  # Binary Merkle Tree, SARIF v2.1.0 & Evidence Manifest ihracatçısı
├── html_dashboard.py     # Çevrimdışı 4 sekmeli dark-mode SESSION_DASHBOARD.html üreticisi
├── report_signer.py      # Rapor üretici ve SHA-256/HMAC-SHA256 imza doğrulayıcı
├── cli.py                # Komut satırı arayüzü, `demo` ve 10 aşamalı `showcase` sunumu
├── REPORT.md             # Görev teslim raporu
└── tests/
    ├── __init__.py
    └── test_session_scribe.py  # 42 birim ve entegrasyon testi
```

### Modül Detayları

1. **`scope_guard.py` (Kapsam ve Yetki Motoru):**
   - `scope.json` dosyasını fail-closed prensibiyle yükler; DNS çözümlemesi veya ağ bağlantısı yapmaz.
   - `ipaddress` modülü ile IPv4/IPv6 CIDR alt ağlarını (`10.0.0.0/24`, `192.168.56.0/24`, `127.0.0.0/8`, `::1/128`) ve `*.lab.local`/`localhost` kurallarını denetler; URL userinfo gizleme (`http://localhost@evil.com/`), belirsiz IP yazımları (`2130706433`, `127.1`), yetkisiz portlar, yasaklı bayraklar (`--script=exploit`) ve kabuk enjeksiyonlarını (`;`, `&&`, `||`, `|`, `` ` ``, `$(`) `ScopeViolationError` ile reddeder.

2. **`prompt_guard.py` (AI Prompt Injection & Jailbreak Kalkanı):**
   - Alt-ajan `prompt`, `reasoning` ve `command` girdilerini yürütme öncesinde; hedef çıktılarını da yürütme sonrasında (dolaylı enjeksiyon) tarar (`PromptInjectionGuard`, `PromptThreatResult`, `PromptInjectionError`).
   - Kapsam atlatma ifadeleri (`ignore previous instructions`, `override scope.json`, `bypass guard`, `system prompt`), gizlenmiş **Base64 / Hex / ROT13** yükleri ve sır sızdırma komutlarını (`$AWS_SECRET`, `cat /etc/shadow`, `printenv`) tespit ettiğinde `REFUSED_PROMPT_INJECTION` olarak engeller ve zincire işler.

3. **`circuit_breaker.py` (Otonom Devre Kesici & Kill-Switch):**
   - `SubagentCircuitBreaker(max_violations=3)` ardışık `REFUSED_OUT_OF_SCOPE` veya `REFUSED_PROMPT_INJECTION` olaylarını sayar. Eşik değerine ulaşıldığında devreyi `OPEN (LOCKED)` konumuna geçirir, `KILL_SWITCH_TRIPPED` kaydını yazar ve `EmergencyKillSwitchError` fırlatarak ajanı tamamen dondurur.
   - Yetkili kapsam içi bir işlemin başarıyla çalışması ardışık sayacı sıfırlar; kilitli ajan yalnızca insan operatör adı ve gerekçesi verilen `reset_with_human_token(operator, reason)` çağrısıyla (`CIRCUIT_RESET`) yeniden açılır.

4. **`redactor.py` (DLP Hassas Veri ve Sır Maskeleyici):**
   - Sıralı regex kurallarıyla PEM/SSH özel anahtar bloklarını (`[REDACTED:PRIVATE_KEY]`), JWT tokenları (`[REDACTED:JWT]`), HTTP `Bearer` tokenlarını (`[REDACTED:BEARER_TOKEN]`), AWS Access/Secret anahtarlarını (`[REDACTED:AWS_SECRET]`), API anahtarlarını (`[REDACTED:API_KEY]`) ve parolaları (`[REDACTED:PASSWORD]`) tespit edip maskeler.

5. **`mitre_mapper.py` (MITRE ATT&CK Eşleştirici & Uyumluluk Puanlayıcı):**
   - Komutları ve engelleme olaylarını `T1046`, `T1595.002`, `T1018`, `T1590.002`, `T1057`, `T1082`, `T1059`, `T1499`, `T1078` kimlikleriyle etiketler ve 100 üzerinden `Scope Compliance & Safety Score` hesaplar.

6. **`audit_logger.py` & `forensic_exporter.py` (Hash Zinciri, Merkle Ağacı, SARIF v2.1.0 & Evidence Manifest):**
   - `AuditLogger` tüm olayları (`ALLOWED`, `EXECUTED`, `REFUSED_OUT_OF_SCOPE`, `REFUSED_PROMPT_INJECTION`, `KILL_SWITCH_TRIPPED`, `CIRCUIT_RESET`) `prev_hash` + `entry_hash` SHA-256 zinciriyle kaydeder.
   - `ForensicExporter`, `entry_hash` yapraklarından ikili **SHA-256 Merkle Kökü (`merkle_root`)** üretir, bulguları (`PENT20-SCOPE-001`, `PENT20-PROMPT-002`, `PENT20-DLP-003`, `PENT20-CIRCUIT-004`) **OASIS SARIF v2.1.0 (`SESSION_FINDINGS.sarif.json`)** olarak dışa aktarır ve tüm oturum dosyalarının SHA-256 özetlerini **`EVIDENCE_MANIFEST.json`** içinde mühürleyip `verify_evidence_manifest()` ile doğrular.

7. **`report_signer.py` & `html_dashboard.py` (İmzalı Raporlar & 4 Sekmeli HTML Komuta Merkezi):**
   - Dış CDN/URL kullanmadan (inline CSS + vanilla JS `switchTab`) 4 etkileşimli sekmeli koyu tema paneli üretir:
     1. *Executive Overview & Telemetry* (KPI kartları, 100/100 A+ Puan, Merkle Root, Devre Kesici & DLP özeti)
     2. *MITRE ATT&CK & Live Timeline* (MITRE taktik/teknik etiketleri, risk rozetleri, maskelenmiş çıktılar)
     3. *AI Governance & Prompt Shield* (AI-Use Disclosure kimlik bilgileri, engellenen prompt injection olayları ve Kill-Switch denetimi)
     4. *Cryptographic & Forensic Verification* (`GENESIS` -> `CHAIN VALID` akışı, Merkle Ağacı, SARIF v2.1.0 bulguları, `EVIDENCE_MANIFEST.json` SHA-256 tablosu ve HMAC-SHA256 imza bloğu)

8. **`cli.py` (Komut Satırı Arayüzü, Demo ve 10 Aşamalı Video Sunumu):**
   - `showcase` alt komutu varsayılan `--pause 2.2` ve ara adım duraklatmalarıyla (~87-90 sn akış) 10 aşamalı canlı kanıt gösterimi sunar; `--out-dir` ile tüm 7 çıktı dosyasını tek dizinde toplar.

---

## 3. Kurulum, Kullanım ve Doğrulama Komutları

Harici bağımlılık gerekmez; yalnızca Python 3.11+ standart kütüphanesi kullanılır.

### Canlı Kanıt Videosu İçin Önerilen Komutlar
```bash
# 10 aşamalı görsel terminal sunumu (~88 sn akış, varsayılan --pause 2.2 sn)
python scripts/session_scribe/cli.py showcase

# Tüm artefaktları (MD, .sig, 4-Tab HTML, SARIF v2.1.0, Evidence Manifest) belirli klasörde sakla
python scripts/session_scribe/cli.py showcase --out-dir /tmp/pent20-showcase

# Hızlı doğrulama için sıfır bekleme modu
python scripts/session_scribe/cli.py showcase --pause 0 --no-color
```
*Komut tamamlandığında Stage 10/10'da basılan `SESSION_DASHBOARD.html` dosyasını tarayıcıda açarak 4 sekmeli koyu tema Komuta Merkezi'ni inceleyebilirsiniz.*

### Adım Adım Oturum Kullanımı
```bash
# 1. Oturum çalışma alanını başlat
python scripts/session_scribe/cli.py init --dir /tmp/pent20-session

# 2. Kapsam denetimi (kapsam içi = exit 0, kapsam dışı = exit 1)
python scripts/session_scribe/cli.py check-scope 10.0.0.15 --command "nmap -sV -p 22,80 10.0.0.15"
python scripts/session_scribe/cli.py check-scope google.com

# 3. AI-Disclosed Subagent adımı yürütme
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

# 4. Log hash zinciri doğrulaması
python scripts/session_scribe/cli.py verify-logs --log /tmp/pent20-session/session_audit.jsonl

# 5. İmzalı Markdown raporu + 4 Sekmeli HTML Dashboard + SARIF v2.1.0 + Evidence Manifest üretimi
python scripts/session_scribe/cli.py export-report \
  --log /tmp/pent20-session/session_audit.jsonl \
  --scope /tmp/pent20-session/scope.json \
  --out /tmp/pent20-session/SESSION_REPORT.md \
  --html /tmp/pent20-session/SESSION_DASHBOARD.html \
  --sarif /tmp/pent20-session/SESSION_FINDINGS.sarif.json \
  --manifest /tmp/pent20-session/EVIDENCE_MANIFEST.json

python scripts/session_scribe/cli.py verify-report /tmp/pent20-session/SESSION_REPORT.md
```

### Doğrulama ve Test Çıktıları

1. **Standart Kütüphane Birim Testleri (`unittest`):**
```text
$ python -m unittest discover -s scripts/session_scribe/tests -v
...
Ran 42 tests in 1.739s

OK
```

2. **`pytest` ile Birim Testleri:**
```text
$ .venv-test\Scripts\python.exe -m pytest scripts/session_scribe/tests/test_session_scribe.py -v
42 passed in 2.06s

$ .venv-test\Scripts\python.exe -m pytest android-lab/lab/tests/test_pent20_session_scribe.py -v
42 passed in 1.99s
```

3. **Repository-Wide Test Çalıştırıcısı (`./scripts/run-tests.sh --quick`):**
Windows Git Bash ortamında çalıştırılarak Stage 1 test paketlerinin tamamının hatasız geçtiği doğrulanmıştır.

---

## 4. AI-Use Disclosure (Yapay Zeka Kullanım Beyanı)

### A. Çalışma Zamanı (Runtime) AI Beyanı Mekanizması
PENT-20 alt-ajanı (`scripts/session_scribe/subagent.py`), çalıştırılan veya engellenen **her** komut öncesinde aşağıdaki alanları zorunlu olarak denetler, Prompt Injection ve DLP filtrelerinden geçirir, MITRE ATT&CK etiketiyle birlikte `session_audit.jsonl` dosyasına yazar ve imzalı oturum raporuyla 4 sekmeli HTML panele yansıtır:
- `agent_id`: İşlemi öneren/yürüten alt-ajan kimliği
- `model`: Kullanılan yapay zeka model adı
- `reasoning`: Adımın teknik gerekçesi
- `human_approved`: İnsan operatör onay durumu (`true` / `false`)
- `tool_name`: Çağrılan güvenlik aracı (`nmap`, `curl`, `python`, vb.)
- `prompt_hash`: Operatör/ajan isteminin SHA-256 özeti (64-hex)

### B. Geliştirme Süreci AI Beyanı
- Bu görevdeki tüm çekirdek ve ileri seviye modüller (`scope_guard.py`, `prompt_guard.py`, `circuit_breaker.py`, `redactor.py`, `mitre_mapper.py`, `audit_logger.py`, `subagent.py`, `forensic_exporter.py`, `html_dashboard.py`, `report_signer.py`, `cli.py`), 42 birim testi ve dokümantasyon; Google Antigravity IDE yapay zeka asistanı desteğiyle tasarlanıp geliştirilmiştir.
- Tüm mimari kararlar, Prompt Injection/Kill-Switch eşikleri, DLP/MITRE kuralları, kapsam sınırları (`scope.json`), adli bilişim doğrulamaları ve test sonuçları geliştirici (**Aydın Arda Demiralp**) tarafından incelenmiş ve yerel ortamda çalıştırılarak doğrulanmıştır.
