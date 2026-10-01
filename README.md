# 🔐 FortifyOne Audit Framework

[![Version](https://img.shields.io/badge/version-4.2.0-blue)](https://github.com/trintechdigitaldefense/fortifyone)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8%2B-yellow)](https://python.org)
[![Hardened](https://img.shields.io/badge/security-hardened-brightgreen)](https://github.com/trintechdigitaldefense/fortifyone)

**Complete Cybersecurity Audit Framework for Local Businesses**

Built by [TrinTech Digital Defense](https://trintechdigitaldefense.github.io)

> *"Securing Your Digital World"*

---

## ⚠ AUTHORIZED USE ONLY

This tool is intended **exclusively for authorized security assessments**.  
Unauthorized scanning of systems you do not own or lack written permission to test is **illegal**.  
TrinTech Digital Defense accepts **no liability** for misuse.

---

## What's New in 4.2

- **PolicyEngine v2** — Industry-aware control set (Healthcare, Finance, Legal, Retail) with critical-gap tracking and remediation language
- **InternalScan module** — Basic host discovery + top-port enumeration when run from inside the client network
- **Expanded schema** — Scope / ROE section, internal_scan results, richer policy_compliance
- **Improved ReportGenius** — ROE block, policy gaps, internal findings, better severity labels and CSV remediation plan
- Hardened input validation, file permissions, and authorized-use notices (from 4.1)

---

## Current Readiness for Client Networks

| Capability | Status |
|------------|--------|
| External recon (Nmap + Shodan) | ✅ Ready |
| Email / SaaS posture | ✅ Ready |
| Credential exposure (HIBP) | ✅ Ready |
| Industry-aware policy baseline | ✅ Ready (v2) |
| Internal discovery (on-site) | ✅ Basic |
| Scope / ROE recording | ✅ Schema ready |
| Multi-target / CIDR ranges | ⚠️ Partial (schema supports, CLI still single-primary) |
| Credentialed / deep internal | ❌ Not yet |
| Professional PDF | ❌ HTML + CSV only |

**Recommendation:** Suitable for external posture assessments, sales demos, and light on-site discovery. For full paid internal network audits, pair with manual testing and expand multi-target support.

---

## Quick Start

```bash
git clone git@github.com:trintechdigitaldefense/fortifyone.git
cd fortifyone
pip3 install -r requirements.txt
python3 main.py info

# Create engagement
python3 main.py new -c "Acme Corp" -d acme.com -i 203.0.113.1 --industry Healthcare

# Run modules
python3 main.py run -m all -f <audit_file.json>

# Generate reports
python3 main.py report -f <updated_audit_file.json>
```

---

## Modules

| Module | Description |
|--------|-------------|
| **ReconVision** | External SYN scan + Shodan enrichment |
| **InternalScan** | On-site host discovery + limited port scan |
| **PolicyEngine v2** | Industry-aware compliance controls + critical gaps |
| **BreachVault** | Free HIBP k-anonymity password pattern checks |
| **SaaS-Sentinel** | SPF / DKIM / DMARC + security headers |
| **ReportGenius** | HTML executive report + prioritized CSV remediation |

---

## Project Structure

```
fortifyone/
├── main.py
├── requirements.txt
├── .gitignore
├── config/
│   └── schema.json          # Includes scope/ROE + internal_scan
├── modules/
│   ├── external_scan.py
│   ├── internal_scan.py     # NEW
│   ├── policy_engine.py     # v2
│   ├── breach_vault.py
│   ├── saas_sentinel.py
│   ├── shodan_scan.py
│   └── report_builder.py    # Improved
├── data/                    # gitignored
└── output/                  # gitignored
```

---

## Legal

Authorized testing only. See the authorized-use notice printed by every major command.

MIT License — see LICENSE.

---

**TrinTech Digital Defense** — Securing Your Digital World  
https://trintechdigitaldefense.github.io
