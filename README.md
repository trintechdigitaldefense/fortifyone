# 🔐 FortifyOne Audit Framework

[![Version](https://img.shields.io/badge/version-4.3.0-blue)](https://github.com/trintechdigitaldefense/fortifyone)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8%2B-yellow)](https://python.org)

**Complete Cybersecurity Audit Framework for Local Businesses**  
Built by [TrinTech Digital Defense](https://trintechdigitaldefense.github.io)

> *"Securing Your Digital World"*

---

## ⚠ AUTHORIZED USE ONLY

Authorized security assessments only. Unauthorized scanning is illegal.  
TrinTech Digital Defense accepts no liability for misuse.

---

## What's New in 4.3 — Full Multi-Target / CIDR Support

- **Multi-target scanning**: pass multiple IPs, domains, and CIDR ranges in one engagement
- **CLI flags**: `--targets` / `-t` and `--targets-file`
- **Safety limits**: external scans reject ranges larger than /23 (512 hosts); internal allows up to /22
- **Per-target results** stored in the audit JSON
- InternalScan prefers an explicit CIDR from scope when present

---

## Quick Start

```bash
git clone git@github.com:trintechdigitaldefense/fortifyone.git
cd fortifyone
pip3 install -r requirements.txt
python3 main.py info
```

### Create engagement (single or multi-target)

```bash
# Classic single target
python3 main.py new -c "Acme Corp" -d acme.com -i 203.0.113.1 --industry Healthcare

# Multiple targets (IPs + domain + small CIDR)
python3 main.py new -c "Acme Corp" \
  -t "203.0.113.1,203.0.113.5,acme.com,203.0.113.0/29" \
  --industry Finance --authorized-by "Jane Doe"

# From a targets file (one per line, # comments allowed)
python3 main.py new -c "Acme Corp" --targets-file scope.txt --authorized-by "Jane Doe"
```

### Run & Report

```bash
python3 main.py run -m all -f <audit_file.json>
python3 main.py report -f <updated_file.json>
```

### Quick multi-target scan

```bash
python3 main.py quick -t "example.com,93.184.216.34,203.0.113.0/29" --industry Retail
```

---

## Modules

| Module | Multi-target aware |
|--------|--------------------|
| **ReconVision** | ✅ Full (IPs, domains, CIDRs ≤ /23) |
| **InternalScan** | ✅ Uses CIDR from scope or auto-detects |
| **PolicyEngine** | Industry-aware baseline |
| **BreachVault** | Domain-based |
| **SaaS-Sentinel** | Domain-based |
| **ReportGenius** | Aggregates multi-target findings |

---

## Scope / ROE

Every engagement stores:

```json
"scope": {
  "in_scope_targets": ["203.0.113.1", "acme.com", "10.0.0.0/24"],
  "out_of_scope": [],
  "roe_text": "...",
  "authorized_by": "Jane Doe",
  "authorization_date": "2026-09-30"
}
```

---

## Safety Limits

- External scans: max 30 targets, CIDR ≤ /23 (512 hosts)
- Internal scans: max ~20 hosts for port enumeration, CIDR ≤ /22
- Localhost / zero addresses are refused
- All subprocess calls use list form (no shell injection)

---

## Project Structure

```
fortifyone/
├── main.py                 # v4.3 Multi-Target orchestrator
├── modules/
│   ├── external_scan.py    # Multi-target + CIDR
│   ├── internal_scan.py    # Scope-aware
│   ├── policy_engine.py
│   ├── breach_vault.py
│   ├── saas_sentinel.py
│   ├── shodan_scan.py
│   └── report_builder.py
├── config/schema.json
└── ...
```

---

**TrinTech Digital Defense** — Securing Your Digital World  
https://trintechdigitaldefense.github.io
