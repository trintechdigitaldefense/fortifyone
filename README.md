# 🔐 FortifyOne Audit Framework v5.0

[![Version](https://img.shields.io/badge/version-5.0.0-blue)](https://github.com/trintechdigitaldefense/fortifyone)

**Client-Ready Cybersecurity Audit Framework**  
[TrinTech Digital Defense](https://trintechdigitaldefense.github.io) – *Securing Your Digital World*

---

## ⚠ AUTHORIZED USE ONLY

Authorized assessments only. Unauthorized scanning is illegal under the Trinidad & Tobago Cybercrime Act and equivalent laws.

---

## What’s in v5.0

| Module | Capability |
|--------|------------|
| **ReconVision** | Multi-target / CIDR external port & service scan |
| **VulnProbe** | Safe NSE scripts + high-risk service heuristics |
| **WebProbe** | CMS detection, admin paths, `.env`/`.git`/backup exposure |
| **InternalScan** | On-site host discovery + limited port scan |
| **LocalHardening** | Firewall, SSH, patch signals on the auditor machine |
| **PolicyEngine** | Industry-aware NIST/CIS/HIPAA baseline + evidence notes |
| **BreachVault** | Credential exposure patterns |
| **SaaS-Sentinel** | SPF/DKIM/DMARC + web security headers |
| **ReportGenius** | Professional **PDF** + HTML + prioritized CSV |
| **compare** | Delta between two audit runs |

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

## Typical engagement flow

```bash
# 1. Create engagement (multi-target OK)
python3 main.py new -c "Acme Corp" \
  -t "203.0.113.1,acme.com,203.0.113.0/29" \
  --industry Healthcare --authorized-by "Jane Doe"

# 2. Run everything
python3 main.py run -m all -f <audit.json>

# Or selective
python3 main.py run -m external -f <audit.json>
python3 main.py run -m web -f <audit.json>
python3 main.py run -m local -f <audit.json>   # on-site machine

# 3. Deliverables
python3 main.py report -f <updated.json>
# → PDF + HTML + CSV remediation plan

# 4. Re-assessment delta
python3 main.py compare -b old.json -c new.json
```

---

## Readiness matrix

| Use case | Ready? |
|----------|--------|
| External posture assessment | ✅ |
| Light vulnerability indicators | ✅ |
| Web exposure / CMS checks | ✅ |
| Professional client PDF | ✅ |
| On-site discovery + local hardening | ✅ |
| Policy baseline (HIPAA/Finance/etc.) | ✅ |
| Re-scan comparison | ✅ |
| Full domain-joined credentialed audit | ⚠ Partial (local host only) |
| Deep web app / authenticated testing | ❌ Out of scope |
| Continuous scheduled scanning | ❌ Use cron + `run` |

**v5.0 is ready for paid external assessments and light on-site work** with professional deliverables. It is **not** a full internal penetration-testing suite.

---

## Safety

- List-form subprocess only (no shell injection)
- CIDR limited (external ≤ /23)
- Localhost refused
- Authorized-use notices on every command
- Scope / ROE stored in every engagement

---

https://trintechdigitaldefense.github.io
