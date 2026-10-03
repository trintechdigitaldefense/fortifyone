# 🔐 FortifyOne Audit Framework v5.3

[![Version](https://img.shields.io/badge/version-5.3.0-blue)](https://github.com/trintechdigitaldefense/fortifyone)

**Professional Cybersecurity Audit Framework**  
[TrinTech Digital Defense](https://trintechdigitaldefense.github.io)

---

## ⚠ AUTHORIZED USE ONLY

Authorized assessments only. Unauthorized scanning is illegal under the Trinidad & Tobago Cybercrime Act and equivalent laws.

---

## v5.3 highlights

| Feature | Description |
|---------|-------------|
| **Credentialed SSH (strengthened)** | Deeper key-based checks: sshd hardening, listeners, patch/reboot signals, sudo/NOPASSWD, multiple UID 0, firewall status. WinRM readiness probe (no secrets). |
| **Stronger branded multi-page PDF** | Cover with risk snapshot, scope/ROE, methodology, executive metrics, prioritized findings (severity-coloured), priority recommendations |
| **Professional engagement letter** | Authorization, ROE, in/out of scope, deliverables, signature blocks |
| **Expanded curated vuln templates** | 20 safe indicators (Heartbleed, EternalBlue, exposed DBs/Redis/Mongo/K8s/Docker, etc.) in `config/vuln_templates.json` |
| **Evidence pack** | ZIP with reports, signatures, findings index, policy evidence, credentialed summary, pack README, MANIFEST |
| **Encrypted audits + signed reports** | From v5.1 (`FORTIFYONE_PASSPHRASE`) |

---

## Install

```bash
git pull
pip3 install -r requirements.txt
# nmap, dig, ssh client recommended
python3 main.py info
```

---

## Credentialed SSH

```bash
export FORTIFYONE_SSH_HOST=10.0.0.10
export FORTIFYONE_SSH_USER=auditor
export FORTIFYONE_SSH_KEY=~/.ssh/id_ed25519
# optional
export FORTIFYONE_SSH_PORT=22
export FORTIFYONE_WINRM_HOST=10.0.0.20   # readiness only
export FORTIFYONE_WINRM_USER=auditor

python3 main.py run -m credentialed -f <audit.json>
# or include in full run:
python3 main.py run -m all -f <audit.json>
```

---

## Reports & evidence pack

```bash
python3 main.py report -f <updated.json>
# → Executive PDF/HTML, Engagement Letter, CSV, optional .sig files

python3 main.py pack -f <updated.json>
# → *_Evidence_Pack_*.zip (reports + index + policy evidence + README)
```

---

## Encryption / signing

```bash
export FORTIFYONE_PASSPHRASE='long-random-secret'
python3 main.py verify -f output/Client/Client_Executive_Report.pdf
```

---

## Modules

ReconVision · VulnProbe (+ templates) · WebProbe · InternalScan · LocalHardening · **Credentialed (SSH + WinRM readiness)** · PolicyEngine · BreachVault · SaaS-Sentinel · **ReportGenius v5.3** · **EvidencePack** · CryptoUtils

---

https://github.com/trintechdigitaldefense/fortifyone
