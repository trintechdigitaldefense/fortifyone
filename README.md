# 🔐 FortifyOne Audit Engine v6.0

[![Version](https://img.shields.io/badge/version-6.0.0-blue)](https://github.com/trintechdigitaldefense/fortifyone)

**Primary professional network audit platform — TrinTech Digital Defense**

One coherent workflow for chargeable, defensible assessments:

```text
fortifyone init  →  fortifyone run  →  fortifyone report  →  fortifyone pack
```

Sentinel, Mirage, and trintech-guardian remain **post-audit** continuous protection tools.  
FortifyOne is the **only** primary audit engine.

---

## ⚠ AUTHORIZED USE ONLY

Authorized assessments only. Unauthorized scanning is illegal under the Trinidad & Tobago Cybercrime Act and equivalent laws. Always record ROE / authorization reference.

---

## Operator workflow (locked)

```bash
# 1. Create engagement with ROE
python3 main.py init -c "Client Name" -d example.com -i 203.0.113.10 \
  --roe "ROE-2026-042 / Jane Doe" --service smallbiz --industry Technology

# 2. Run modules (full or selective)
python3 main.py run -m all -f <engagement.json>
# or: -m external,osint,web,tls,vuln,credentialed,policy

# 3. Professional deliverables
python3 main.py report -f <updated.json>
python3 main.py report -f <updated.json> --redacted   # client-shareable

# 4. Evidence pack (mandatory for delivery)
python3 main.py pack -f <updated.json>
```

Engagement IDs look like `ENG-261006-A1B2C3`.

---

## What v6 absorbs / strengthens

| Capability | Status |
|------------|--------|
| Discovery & inventory | External multi-target + internal + OSINT subdomain/DNS/WHOIS hints |
| Vulnerability identification | 35+ safe templates + NSE-oriented VulnProbe |
| Configuration / hardening | Multi-host SSH credentialed + WinRM path |
| Web application coverage | Expanded paths, CMS, headers, TLS posture |
| OSINT | DNS, WHOIS summary, SPF/DMARC, common subdomain resolution |
| Professional reporting | Branded PDF, letter, interactive dashboard, redacted mode |
| Scoring & roadmap | 100−penalty score, Grade A–F, Immediate/This Week/This Month/Ongoing |
| Evidence chain | Signed reports + EvidencePack ZIP |
| Secrets | Passphrase, key file, optional OS keyring |

---

## Install

```bash
git clone https://github.com/trintechdigitaldefense/fortifyone.git
cd fortifyone
pip3 install -r requirements.txt
# Recommended: nmap, dig, whois, ssh client
# Optional: pywinrm, keyring
python3 main.py about
```

---

## Modules

ReconVision · OSINT · VulnProbe · WebProbe · TLSPosture · InternalScan · LocalHardening · Credentialed (SSH multi-host + WinRM) · PolicyEngine · BreachVault · SaaS-Sentinel · Scoring · ReportGenius · Dashboard · EvidencePack · WatchMode · PluginLoader · CryptoUtils

---

## Keep separate (do not merge)

- **Sentinel** — continuous monitoring, FIM, reverse-shell
- **Mirage** — pure deception layer
- **trintech-guardian** — active containment / IPS

---

## License & contact

Authorized defensive use only.  
TrinTech Digital Defense · Trinidad & Tobago  
https://trintechdigitaldefense.github.io
