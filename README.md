# FortifyOne — Professional Network Audit Engine

**TrinTech Digital Defense** · Trinidad & Tobago 🇹🇹

Primary platform for chargeable, defensible network security assessments.

```text
fortifyone init  →  fortifyone run  →  fortifyone report  →  fortifyone pack
```

Sentinel and Mirage are the **post-audit** continuous protection layer.  
FortifyOne is the **only** primary audit engine.

---

## Authorized Use Only

Authorized assessments only. Unauthorized scanning is illegal under the Trinidad & Tobago Cybercrime Act and equivalent laws. Always record the ROE / authorization reference.

---

## Operator Workflow

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

## Core Capabilities

| Capability | Status |
|------------|--------|
| Discovery & inventory | External multi-target + internal + OSINT |
| Vulnerability identification | 35+ safe templates + NSE-oriented VulnProbe |
| Configuration / hardening | Multi-host SSH credentialed + WinRM path |
| Web application coverage | Paths, CMS, headers, TLS posture |
| OSINT | DNS, WHOIS, SPF/DMARC, common subdomains |
| Professional reporting | Branded PDF, letter, dashboard, redacted mode |
| Scoring & roadmap | Score 0–100, Grade A–F, prioritized remediation |
| Evidence chain | Signed reports + EvidencePack ZIP |

---

## Install

```bash
git clone https://github.com/trintechdigitaldefense/fortifyone.git
cd fortifyone
pip3 install -r requirements.txt
# Recommended: nmap, dig, whois, ssh client
python3 main.py about
```

---

## Continuous Protection Package

| Component | Role |
|-----------|------|
| **FortifyOne** | Professional point-in-time network audit (this tool) |
| **Sentinel** | Continuous monitoring, FIM, reverse-shell detection |
| **Mirage** | Active deception layer |

---

## Contact

**TrinTech Digital Defense**  
Email: trintechdigitaldefense@gmail.com  
WhatsApp: +1 (868) 362-0679  
Web: https://trintechdigitaldefense.github.io

---

Authorized defensive use only.  
Unauthorized access is illegal under the Trinidad & Tobago Cybercrime Act and applicable law.

*Defend. Detect. Dominate.*
