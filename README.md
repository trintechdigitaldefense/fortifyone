# 🔐 FortifyOne Audit Framework

[![Version](https://img.shields.io/badge/version-4.0.0-blue)](https://github.com/trintechdigitaldefense/fortifyone)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8%2B-yellow)](https://python.org)

**Complete Cybersecurity Audit Framework for Local Businesses**

Built by [TrinTech Digital Defense](https://trintechdigitaldefense.github.io)

> *"Securing Your Digital World"*

---

## ⚡ One-Command Audit

```bash
fortifyone quick --domain "example.com" --industry "Healthcare"
```

**In under 60 seconds, you get:**
- 🔍 External vulnerability scan (Nmap + Shodan)
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
- Nmap (`apt install nmap`)
- 4GB RAM (runs on Android/Termux, Linux, macOS)

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
│         (Branded Orchestrator)               │
└──────┬──────┬──────┬──────┬──────┬──────────┘
       │      │      │      │      │
       ▼      ▼      ▼      ▼      ▼
  ┌─────────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────────┐
  │ReconVision│ │Policy│ │Breach│ │SaaS- │ │Report    │
  │External  │ │Engine│ │Vault │ │Sentinel│ │Genius   │
  │Scan      │ │      │ │      │ │      │ │          │
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

### 🔍 ReconVision — External Scanning
- Stealth SYN port scan (Nmap)
- Service version fingerprinting
- DNS and email security checks
- Shodan/Censys passive reconnaissance (optional)
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
- Local breach database support
- **Privacy:** Only first 5 SHA-1 characters sent externally
- **Output:** Compromised credentials count, risk level, top breached passwords

### ☁️ SaaS-Sentinel — Cloud Security
- SPF record verification
- DKIM signing detection
- DMARC policy strength grading
- Email provider identification (M365, Google Workspace)
- HTTP security headers check
- **Output:** Letter grade (A+ to F), security score (0-100)

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
# Add to ~/.bashrc
export SHODAN_API_KEY="your-key"
export CENSYS_API_ID="your-id"
export CENSYS_API_SECRET="your-secret"
export HIBP_API_KEY="your-key"
```

---

## 🛡️ Privacy & Security

- **Passwords:** SHA-1 hashed locally. Only 5 hex chars sent to HIBP (k-anonymity model)
- **Data:** All audit data stored locally. Nothing sent to cloud.
- **Network:** Scans target IP only. No data exfiltration.
- **APIs:** All integrations are read-only.

---

## 📁 Project Structure

```
fortifyone/
├── main.py              # Branded orchestrator
├── requirements.txt     # Python dependencies
├── LICENSE              # MIT License
├── README.md            # This file
├── config/
│   └── schema.json      # Universal data contract
├── modules/
│   ├── external_scan.py # ReconVision
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

# Add new module
cp modules/_template.py modules/your_module.py
# Then register in main.py
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

*Built with purpose. Deployed with confidence.*

**TrinTech Digital Defense — "Securing Your Digital World"**
```
