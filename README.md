# 🔐 FortifyOne Audit Framework

[![Version](https://img.shields.io/badge/version-4.1.0-blue)](https://github.com/trintechdigitaldefense/fortifyone)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8%2B-yellow)](https://python.org)
[![Hardened](https://img.shields.io/badge/security-hardened-brightgreen)](https://github.com/trintechdigitaldefense/fortifyone)

**Complete Cybersecurity Audit Framework for Local Businesses**

Built by [TrinTech Digital Defense](https://trintechdigitaldefense.github.io)

> *"Securing Your Digital World"*

---

## ⚠ AUTHORIZED USE ONLY

This tool is intended **exclusively for authorized security assessments**.  
Unauthorized scanning of systems you do not own or lack written permission to test is **illegal** under the Trinidad & Tobago Cybercrime Act and equivalent laws worldwide.  
TrinTech Digital Defense accepts **no liability** for misuse.

---

## ⚡ One-Command Audit

```bash
fortifyone quick --domain "example.com" --industry "Healthcare"
```

**In under 60 seconds, you get:**
- 🔍 External vulnerability scan (Nmap + optional Shodan)
- 📋 Compliance baseline (HIPAA, NIST CSF, CIS v8)
- 🔐 Credential exposure check (100% free, k-anonymity)
- ☁️ SaaS security posture (SPF/DKIM/DMARC/headers)
- 📊 Executive HTML report with D3.js attack simulation

---

## 🎯 Sample Output

```
═══════════════════════════════════════
  FORTIFYONE AUDIT FRAMEWORK
  TrinTech Digital Defense
  "Securing Your Digital World"
═══════════════════════════════════════

═══ Quick Audit Complete ═══
┌──────────────────────┬─────────────────────────┐
│ Metric               │ Result                  │
├──────────────────────┼─────────────────────────┤
│ Open Ports           │ 2 (RDP 3389, SMB 445)   │
│ External Risk        │ 85/100                  │
│ Credential Exposures │ 33                      │
│ Breach Risk          │ CRITICAL                │
│ Policy Compliance    │ 20%                     │
│ SaaS Grade           │ F (15/100)              │
└──────────────────────┴─────────────────────────┘
```

---

## 📦 Installation

```bash
# Clone the repository
git clone git@github.com:trintechdigitaldefense/fortifyone.git
cd fortifyone

# Install dependencies
pip3 install -r requirements.txt

# Verify installation
python3 main.py info
```

### Requirements
- Python 3.8+
- Nmap (`apt install nmap` / `pkg install nmap` on Termux)
- 4GB RAM recommended (runs on Android/Termux, Linux, macOS)

---

## 🚀 Quick Start

```bash
# 1. Create a new audit engagement
fortifyone new --client "Acme Corp" --domain acme.com --ip 203.0.113.1 --industry Healthcare

# 2. Run all security modules
fortifyone run --module all --file Acme_Corp_20250101_120000.json

# 3. Generate executive report
fortifyone report --file Acme_Corp_updated_20250101_120030.json

# 4. View all audits
fortifyone list
```

---

## 🏗 Architecture

```
┌─────────────────────────────────────────────┐
│                 main.py                      │
│         (Branded Orchestrator v4.1)          │
└──────┬──────┬──────┬──────┬──────┬──────────┘
       │      │      │      │      │
       ▼      ▼      ▼      ▼      ▼
  ┌─────────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────────┐
  │ReconVision│ │Policy│ │Breach│ │SaaS- │ │Report    │
  │+ Shodan  │ │Engine│ │Vault │ │Sentinel│ │Genius   │
  └────┬─────┘ └──┬───┘ └──┬───┘ └──┬───┘ └────┬─────┘
       │         │       │       │         │
       ▼         ▼       ▼       ▼         ▼
   schema.json ←──────────────→ audit_summary.json
                                       │
                                       ▼
                              ┌────────────────┐
                              │  DELIVERABLES   │
                              │  HTML / CSV /   │
                              │  JSON           │
                              └────────────────┘
```

---

## 🔧 Modules

### 🔍 ReconVision — External Scanning (Hardened)
- Strict IP + domain validation before any scan
- Stealth SYN port scan (Nmap) with safer flags
- Service version fingerprinting
- Optional Shodan enrichment (CVE + historical data)
- Refuses localhost / zero addresses
- **Output:** Open ports, risk score (0-100), vulnerability flags

### 📋 PolicyEngine — Compliance Baseline
- Instant automated assessment
- Maps to HIPAA, CIS Controls v8, NIST CSF
- 5 critical controls checked in < 1 second
- Non-blocking batch mode
- **Output:** Compliance percentage, framework gap analysis

### 🔐 BreachVault — Credential Exposure
- 100% FREE — no API keys required
- k-anonymity password checking (HIBP)
- Organization-specific pattern analysis
- **Privacy:** Only first 5 SHA-1 characters sent externally
- **Output:** Compromised credentials count, risk level, top breached passwords

### ☁️ SaaS-Sentinel — Cloud Security
- SPF record verification
- DKIM signing detection
- DMARC policy strength grading
- Email provider identification (M365, Google Workspace)
- HTTP security headers check
- **Output:** Letter grade (A–F), security score (0-100)

### 📊 ReportGenius — Deliverables
- Interactive HTML with D3.js attack path simulation
- Estimated financial impact and downtime
- Prioritized CSV remediation plan
- Complete JSON audit data
- Branded TrinTech headers
- **Output:** 4 deliverable files ready for client presentation

---

## 📋 CLI Commands

| Command | Description |
|---------|-------------|
| `fortifyone new` | Create a new audit engagement |
| `fortifyone list` | View all saved audits |
| `fortifyone run` | Execute security modules |
| `fortifyone report` | Generate client deliverables |
| `fortifyone quick` | Rapid automated audit |
| `fortifyone info` | System dashboard |
| `fortifyone about` | Company information |

### Examples

```bash
# Create with industry context
fortifyone new -c "Riverside Dental" -d riversidedental.com -i 203.0.113.1 --industry Healthcare

# Run specific module only
fortifyone run -m breach -f client_20250101_120000.json

# Quick audit on any domain
fortifyone quick -d example.com --industry Finance
```

---

## 📊 Generated Reports

All reports saved to `output/CLIENT_NAME/`:

| File | Format | Description |
|------|--------|-------------|
| `*_Executive_Report.html` | HTML | Interactive with attack simulation |
| `*_Remediation_Plan.csv` | CSV | Prioritized fix items |
| `audit_summary.json` | JSON | Complete raw audit data |
| `*_Complete_Audit.json` | JSON | Branded full report |

---

## 🔑 Optional API Integrations

All core features work with **zero paid APIs**. These enhance scanning:

| Service | Variable | Free Tier | Unlocks |
|---------|----------|-----------|---------|
| Shodan | `SHODAN_API_KEY` | Yes | Internet-wide scan data, CVEs |
| Censys | `CENSYS_API_ID` + `CENSYS_API_SECRET` | Yes | Passive recon, historical data |
| HIBP | `HIBP_API_KEY` | Yes | Email breach searches |

```bash
# Add to ~/.bashrc or ~/.zshrc
export SHODAN_API_KEY="your-key"
export CENSYS_API_ID="your-id"
export CENSYS_API_SECRET="your-secret"
export HIBP_API_KEY="your-key"
```

---

## 🛡️ Privacy, Security & Hardening (v4.1)

**What was hardened:**
- Strict IP and domain validation before any network activity
- Client names sanitized (no path traversal)
- Audit files written with `0o600` permissions
- Subprocess calls use list form only (no shell injection)
- Shodan module never leaks API keys in errors
- Localhost / zero addresses refused
- Authorized-use notice displayed on every major command
- `.gitignore` added for `data/`, `output/`, secrets, `__pycache__`
- Dependency versions pinned

**Privacy guarantees:**
- Passwords: SHA-1 hashed locally. Only first 5 hex chars sent to HIBP (k-anonymity)
- All audit data stays local. Nothing is uploaded to TrinTech or third parties by default
- Network scans target only the specified IP
- APIs are read-only

---

## 📁 Project Structure

```
fortifyone/
├── main.py              # Branded orchestrator (v4.1 Hardened)
├── requirements.txt     # Pinned dependencies
├── .gitignore           # Protects data/, output/, secrets
├── LICENSE              # MIT License
├── README.md            # This file
├── config/
│   └── schema.json      # Universal data contract
├── modules/
│   ├── external_scan.py # ReconVision (hardened)
│   ├── shodan_scan.py   # Shodan enrichment
│   ├── policy_engine.py # PolicyEngine
│   ├── breach_vault.py  # BreachVault
│   ├── saas_sentinel.py # SaaS-Sentinel
│   └── report_builder.py# ReportGenius
├── data/                # Audit files (gitignored)
└── output/              # Generated reports (gitignored)
```

---

## 🎯 Use Cases

| Industry | Key Checks |
|----------|------------|
| **Healthcare** | HIPAA compliance, patient data exposure, RDP security |
| **Legal** | Client confidentiality, email spoofing, credential leaks |
| **Finance** | External attack surface, MFA enforcement, breach history |
| **Retail** | POS system exposure, weak passwords, phishing readiness |
| **Non-Profit** | Donor data protection, volunteer access, budget-appropriate controls |

---

## 💻 Development

```bash
# Run tests
python3 modules/breach_vault.py    # Test BreachVault standalone
python3 modules/external_scan.py   # Test ReconVision standalone
python3 modules/shodan_scan.py     # Test Shodan (needs API key)

# Verify
python3 main.py info
```

---

## 🌐 Links

| Channel | URL |
|---------|-----|
| Website | [trintechdigitaldefense.github.io](https://trintechdigitaldefense.github.io) |
| GitHub | [github.com/trintechdigitaldefense](https://github.com/trintechdigitaldefense) |
| Facebook | [TrinTech Digital Defense](https://www.facebook.com/share/1ZCKz7dfpY/) |
| Email | contact@trintechdefense.com |

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgments

- [Have I Been Pwned](https://haveibeenpwned.com) — k-anonymity password API
- [Nmap](https://nmap.org) — Network discovery
- [Shodan](https://shodan.io) — Internet-wide scanning
- [Rich](https://github.com/Textualize/rich) — Terminal formatting
- [D3.js](https://d3js.org) — Attack path visualization

---

*Built with purpose. Deployed with confidence. Hardened for production use.*

**TrinTech Digital Defense — "Securing Your Digital World"**
