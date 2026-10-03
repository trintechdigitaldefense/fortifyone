# 🔐 FortifyOne Audit Framework v5.1

[![Version](https://img.shields.io/badge/version-5.1.0-blue)](https://github.com/trintechdigitaldefense/fortifyone)

**Hardened Cybersecurity Audit Framework**  
[TrinTech Digital Defense](https://trintechdigitaldefense.github.io) – *Securing Your Digital World*

---

## ⚠ AUTHORIZED USE ONLY

Authorized assessments only. Unauthorized scanning is illegal.

---

## What’s new in v5.1 (Hardened)

| Feature | What it does |
|---------|----------------|
| **Encrypted audits at rest** | Audit JSON encrypted with Fernet (PBKDF2) when a passphrase is set |
| **HMAC-SHA256 signed reports** | PDF / HTML / CSV get `.sig` files so tampering is detectable |
| **`verify` command** | Check signature validity or confirm an audit decrypts |
| **Backward compatible** | Without a passphrase, behaviour is unchanged (plaintext) |

---

## Install

```bash
git clone git@github.com:trintechdigitaldefense/fortifyone.git
cd fortifyone
pip3 install -r requirements.txt
# requires: nmap, dig
python3 main.py info
```

---

## Enable encryption & signing

```bash
# Recommended: environment variable
export FORTIFYONE_PASSPHRASE='your-long-random-secret'

# Or a key file
export FORTIFYONE_KEY_FILE=/secure/path/fortifyone.key

# Or per-command
python3 main.py new -c "Acme" -t "acme.com" --passphrase 'your-secret'
```

When a passphrase is configured:
- New/updated audits are **encrypted** on disk (mode 0600)
- `report` writes **`.sig`** alongside each deliverable

---

## Typical flow

```bash
export FORTIFYONE_PASSPHRASE='...'

python3 main.py new -c "Acme Corp" -t "203.0.113.1,acme.com" --industry Healthcare --authorized-by "Jane Doe"
python3 main.py run -m all -f <audit.json>
python3 main.py report -f <updated.json>

# Verify a deliverable was not tampered with
python3 main.py verify -f output/Acme_Corp/Acme_Corp_Executive_Report.pdf
```

---

## Modules

| Module | Role |
|--------|------|
| ReconVision | Multi-target / CIDR external scan |
| VulnProbe | Safe NSE + heuristics |
| WebProbe | CMS / admin path / exposure checks |
| InternalScan | On-site host discovery |
| LocalHardening | Local firewall / SSH / patch signals |
| PolicyEngine | Industry baseline (NIST / CIS / HIPAA) |
| BreachVault | Credential exposure patterns |
| SaaS-Sentinel | SPF / DKIM / DMARC + headers |
| ReportGenius | PDF + HTML + CSV |
| **CryptoUtils** | Encryption + signing |

---

## Security notes

- Passphrase never written to audit JSON
- Encrypted files start with magic `F1ENC1`
- Signatures: `HMAC-SHA256 fortifyone-v1 <hexdigest>` in `*.sig`
- Same passphrase must be used to decrypt and to verify

---

## Next upgrade candidates

1. Credentialed internal checks (WinRM / SSH MVP)  
2. Stronger branded multi-page PDF + engagement letter  
3. Curated safe vuln templates  
4. Evidence pack generation  

---

https://trintechdigitaldefense.github.io  
https://github.com/trintechdigitaldefense/fortifyone
