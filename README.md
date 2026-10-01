# 🔐 FortifyOne Audit Framework

[![Version](https://img.shields.io/badge/version-4.4.0-blue)](https://github.com/trintechdigitaldefense/fortifyone)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8%2B-yellow)](https://python.org)

**Professional Cybersecurity Audit Framework for Local Businesses**  
Built by [TrinTech Digital Defense](https://trintechdigitaldefense.github.io)

> *"Securing Your Digital World"*

---

## ⚠ AUTHORIZED USE ONLY

Authorized security assessments only. Unauthorized scanning is illegal.

---

## v4.4 Highlights

- **Professional PDF reports** (in addition to HTML + CSV)
- **Stronger, actionable remediation language** mapped to common high-risk ports and controls
- Multi-target + CIDR external scanning
- Internal discovery
- Industry-aware PolicyEngine
- Scope / ROE recording

---

## Install

```bash
git clone git@github.com:trintechdigitaldefense/fortifyone.git
cd fortifyone
pip3 install -r requirements.txt
# requires nmap
python3 main.py info
```

---

## Usage

```bash
# Multi-target engagement
python3 main.py new -c "Acme Corp" \
  -t "203.0.113.1,acme.com,203.0.113.0/29" \
  --industry Healthcare --authorized-by "Jane Doe"

# Run all modules
python3 main.py run -m all -f <audit_file.json>

# Generate HTML + PDF + CSV
python3 main.py report -f <updated_file.json>
```

---

## Deliverables

| File | Description |
|------|-------------|
| `*_Executive_Report.pdf` | Professional PDF for clients |
| `*_Executive_Report.html` | Interactive HTML version |
| `*_Remediation_Plan.csv` | Prioritized fix list with effort estimates |
| `audit_summary.json` | Full raw data |

---

## Current Readiness

| Capability | Status |
|------------|--------|
| Multi-target / CIDR external scan | ✅ |
| Internal host discovery | ✅ Basic |
| Professional PDF + HTML reports | ✅ |
| Strong remediation language | ✅ |
| Industry policy baseline | ✅ |
| Scope / ROE | ✅ |
| Credentialed / authenticated scanning | ❌ Not yet |
| Deep vulnerability scanning (Nuclei-style) | ❌ Not yet |
| Web application scanning | ❌ Not yet |
| Continuous / scheduled re-scans | ❌ Not yet |

**Best for:** External posture assessments, sales demos, light on-site discovery, and professional client deliverables.  
**Not a full replacement for:** Credentialed internal audits or penetration tests.

---

**TrinTech Digital Defense**  
https://trintechdigitaldefense.github.io
