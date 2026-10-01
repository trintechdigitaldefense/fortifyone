# 🔐 FortifyOne Audit Framework

[![Version](https://img.shields.io/badge/version-4.5.0-blue)](https://github.com/trintechdigitaldefense/fortifyone)

**Professional Cybersecurity Audit Framework**  
TrinTech Digital Defense – *Securing Your Digital World*

---

## ⚠ AUTHORIZED USE ONLY

Authorized assessments only. Unauthorized scanning is illegal.

---

## v4.5 – VulnAware

- **VulnProbe** – Safe nmap NSE scripts + version heuristics (Heartbleed, EternalBlue indicators, anonymous FTP, SSHv1, exposed RDP/SMB, etc.)
- Stronger SaaS/Web checks (server disclosure, robots.txt, light directory listing probe)
- Professional PDF + HTML + CSV reports with unified findings
- Multi-target / CIDR support
- Industry-aware PolicyEngine

---

## Install

```bash
git clone git@github.com:trintechdigitaldefense/fortifyone.git
cd fortifyone
pip3 install -r requirements.txt
# nmap required
python3 main.py info
```

---

## Quick Use

```bash
python3 main.py new -c "Acme" -t "203.0.113.1,acme.com,203.0.113.0/29" --industry Healthcare
python3 main.py run -m all -f <file.json>
python3 main.py report -f <updated.json>
```

---

## Modules

| Module | Purpose |
|--------|---------|
| ReconVision | Multi-target external port/service scan |
| **VulnProbe** | Safe NSE + heuristic vulnerability indicators |
| InternalScan | On-site host discovery |
| PolicyEngine | Industry-aware compliance baseline |
| BreachVault | Credential exposure (HIBP-style) |
| SaaS-Sentinel | SPF/DKIM/DMARC + web security posture |
| ReportGenius | HTML + PDF + prioritized CSV |

---

## Still Missing (Honest)

| Gap | Status |
|-----|--------|
| Credentialed internal scanning | Not yet |
| Full web app scanner | Basic only |
| Continuous / scheduled scans | Not yet |
| Sentinel integration | Not yet |

**Best for:** External posture assessments, light vuln indicators, professional client PDFs.  
**Not a replacement for:** Full internal penetration tests or authenticated audits.

---

https://trintechdigitaldefense.github.io
