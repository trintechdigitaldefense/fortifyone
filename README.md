# 🔐 FortifyOne Audit Framework v5.2

[![Version](https://img.shields.io/badge/version-5.2.0-blue)](https://github.com/trintechdigitaldefense/fortifyone)

**Professional Cybersecurity Audit Framework**  
[TrinTech Digital Defense](https://trintechdigitaldefense.github.io)

---

## ⚠ AUTHORIZED USE ONLY

Authorized assessments only. Unauthorized scanning is illegal.

---

## v5.2 highlights

| Feature | Description |
|---------|-------------|
| **Credentialed SSH (MVP)** | Key-based remote checks (sshd hardening, listeners, patch hints). No passwords stored in audits. |
| **Branded multi-page PDF** | Cover + scope/ROE + methodology + prioritized findings |
| **Engagement letter** | Auto-generated ROE / authorization PDF |
| **Curated vuln templates** | `config/vuln_templates.json` drives safe indicators |
| **Evidence pack** | `pack` builds a client ZIP (reports, sigs, findings index, policy evidence) |
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
# → *_Evidence_Pack_*.zip
```

---

## Encryption / signing

```bash
export FORTIFYONE_PASSPHRASE='long-random-secret'
python3 main.py verify -f output/Client/Client_Executive_Report.pdf
```

---

## Modules

ReconVision · VulnProbe (+ templates) · WebProbe · InternalScan · LocalHardening · **Credentialed** · PolicyEngine · BreachVault · SaaS-Sentinel · ReportGenius · **EvidencePack** · CryptoUtils

---

https://github.com/trintechdigitaldefense/fortifyone
