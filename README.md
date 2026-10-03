# 🔐 FortifyOne Audit Framework v5.4

[![Version](https://img.shields.io/badge/version-5.4.0-blue)](https://github.com/trintechdigitaldefense/fortifyone)

**Professional Cybersecurity Audit Framework**  
[TrinTech Digital Defense](https://trintechdigitaldefense.github.io)

---

## ⚠ AUTHORIZED USE ONLY

Authorized assessments only. Unauthorized scanning is illegal under the Trinidad & Tobago Cybercrime Act and equivalent laws.

---

## v5.4 highlights

| Feature | Description |
|---------|-------------|
| **TLS / HTTP posture** | Certificate validity, protocol support (TLS 1.0–1.3), security headers (HSTS, CSP, etc.) |
| **Richer safe templates** | 35 curated non-exploitative indicators (databases, containers, management UIs, weak ciphers…) |
| **Interactive HTML dashboard** | Self-contained offline dashboard with severity filters and control evidence |
| **Redacted report mode** | `--redacted` scrubs internal IPs for client-shareable outputs |
| **Multi-host credentialed** | SSH inventory file + improved WinRM (readiness + optional pywinrm auth) |
| **Stronger compliance mapping** | NIST CSF, CIS v8, HIPAA, ISO 27001, PCI-DSS indicators + evidence-to-control linkage |
| **Watch / continuous mode** | Lightweight external + TLS + web delta for retainers (`fortifyone watch`) |
| **Plugin system** | Drop Python plugins into `modules/plugins/` |
| **Better secret handling** | Key file, optional OS keyring, restrictive secret file helpers |

---

## Install

```bash
git pull
pip3 install -r requirements.txt
# nmap, dig, ssh client recommended
# optional: pip install pywinrm keyring
python3 main.py info
```

---

## Quick start

```bash
python3 main.py new -c "ClientName" -d example.com -i 203.0.113.10 --authorized-by "You"
python3 main.py run -m all -f <audit.json>
python3 main.py report -f <updated.json>
python3 main.py report -f <updated.json> --redacted   # client-shareable
python3 main.py pack -f <updated.json>
python3 main.py watch -f <audit.json>                 # continuous delta
```

---

## Credentialed (SSH multi-host + WinRM)

```bash
# Single host
export FORTIFYONE_SSH_HOST=10.0.0.10
export FORTIFYONE_SSH_USER=auditor
export FORTIFYONE_SSH_KEY=~/.ssh/id_ed25519

# Multi-host inventory (one line per host)
# host user [key] [port]
# winrm:host user
export FORTIFYONE_SSH_INVENTORY=./inventory.txt

# WinRM (optional full checks need: pip install pywinrm)
export FORTIFYONE_WINRM_HOST=10.0.0.20
export FORTIFYONE_WINRM_USER=auditor
# export FORTIFYONE_WINRM_PASS=...   # never stored in audit JSON

python3 main.py run -m credentialed -f <audit.json>
```

---

## TLS posture & templates

```bash
python3 main.py run -m tls -f <audit.json>
# Vuln templates: config/vuln_templates.json (35 safe indicators)
```

---

## Plugins

```bash
python3 main.py plugins --list
# Drop modules/plugins/mycheck.py with:
#   PLUGIN_NAME = "mycheck"
#   def run(audit_data): ...
python3 main.py run -m plugins -f <audit.json>
```

---

## Secrets

```bash
export FORTIFYONE_PASSPHRASE='long-random-secret'
# or
export FORTIFYONE_KEY_FILE=~/.fortifyone/key
# optional: pip install keyring  (OS keyring support)
```

---

## Modules

ReconVision · VulnProbe (+ templates) · WebProbe · **TLSPosture** · InternalScan · LocalHardening · **Credentialed (SSH multi-host + WinRM)** · PolicyEngine (evidence linkage) · BreachVault · SaaS-Sentinel · ReportGenius · **Dashboard** · EvidencePack · **WatchMode** · **PluginLoader** · CryptoUtils

---

https://github.com/trintechdigitaldefense/fortifyone
