#!/usr/bin/env python3
"""
OSINTRecon - Lightweight public intelligence (safe, non-intrusive)
Absorbed patterns from trin-tech-audit / Apex-Recon style recon.
DNS, WHOIS summary, email auth signals, basic subdomain hints.
"""

from __future__ import annotations

import datetime
import re
import socket
import subprocess
from typing import Any, Dict, List, Optional


def _run(cmd: List[str], timeout: int = 12) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return ((r.stdout or "") + (r.stderr or "")).strip()
    except Exception as e:
        return f"error: {type(e).__name__}"


def _dns_records(domain: str) -> Dict[str, List[str]]:
    records: Dict[str, List[str]] = {}
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"):
        out = _run(["dig", "+short", domain, rtype])
        if out and not out.startswith("error"):
            lines = [l.strip() for l in out.splitlines() if l.strip()]
            if lines:
                records[rtype] = lines[:15]
    return records


def _whois_summary(domain: str) -> Dict[str, str]:
    out = _run(["whois", domain], timeout=15)
    summary = {"raw_snippet": out[:800] if out else ""}
    for key, pattern in [
        ("registrar", r"Registrar:\s*(.+)"),
        ("creation_date", r"Creation Date:\s*(.+)"),
        ("expiry_date", r"Expir(?:y|ation) Date:\s*(.+)"),
        ("name_servers", r"Name Server:\s*(.+)"),
    ]:
        m = re.search(pattern, out or "", re.I)
        if m:
            summary[key] = m.group(1).strip()[:120]
    return summary


def _subdomain_hints(domain: str) -> List[str]:
    """Very light common-prefix resolution (safe, low volume)."""
    prefixes = ["www", "mail", "webmail", "remote", "vpn", "portal", "api", "dev", "staging", "admin"]
    found = []
    for p in prefixes:
        host = f"{p}.{domain}"
        try:
            socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            found.append(host)
        except socket.gaierror:
            pass
        except Exception:
            pass
    return found


def run_scan(audit_data: dict) -> dict:
    meta = audit_data.get("audit_metadata", {})
    domain = (meta.get("domain") or "").strip().lower()
    result: Dict[str, Any] = {
        "domain": domain or None,
        "dns": {},
        "whois": {},
        "subdomains": [],
        "findings": [],
        "risk_score": 0,
        "scan_timestamp": datetime.datetime.now().isoformat(),
        "note": "",
    }
    if not domain:
        result["note"] = "No domain for OSINT"
        audit_data["osint_recon"] = result
        print("[OSINT] Skipped — no domain")
        return audit_data

    print(f"\n[OSINT] Public intelligence for {domain}...")
    findings: List[Dict[str, Any]] = []

    dns = _dns_records(domain)
    result["dns"] = dns
    if not dns.get("A") and not dns.get("AAAA"):
        findings.append({
            "title": "No A/AAAA records resolved",
            "detail": f"dig returned no address records for {domain}",
            "severity": "medium",
            "category": "DNS",
            "remediation": "Verify domain DNS configuration.",
            "controls": ["PR.DS-2"],
        })
    txt = " ".join(dns.get("TXT") or []).lower()
    if "v=spf1" not in txt:
        findings.append({
            "title": "SPF record not detected in TXT",
            "detail": "No v=spf1 in TXT records",
            "severity": "high",
            "category": "Email",
            "remediation": "Publish an SPF record; prefer -all or ~all with monitoring.",
            "controls": ["PR.DS-2", "CIS-9.1"],
        })
    if "v=dmarc1" not in txt:
        findings.append({
            "title": "DMARC record not detected",
            "detail": "No v=DMARC1 in TXT (check _dmarc subdomain separately if needed)",
            "severity": "high",
            "category": "Email",
            "remediation": "Publish DMARC at _dmarc.<domain> with p=quarantine or p=reject.",
            "controls": ["PR.DS-2", "CIS-9.1"],
        })

    # DMARC dedicated check
    dmarc = _run(["dig", "+short", f"_dmarc.{domain}", "TXT"])
    if dmarc and "v=dmarc1" in dmarc.lower():
        result["dmarc"] = dmarc[:200]
        if "p=none" in dmarc.lower():
            findings.append({
                "title": "DMARC policy is p=none (monitor only)",
                "detail": dmarc[:180],
                "severity": "medium",
                "category": "Email",
                "remediation": "Move DMARC to p=quarantine then p=reject after monitoring.",
                "controls": ["PR.DS-2"],
            })
    else:
        result["dmarc"] = None

    result["whois"] = _whois_summary(domain)
    subs = _subdomain_hints(domain)
    result["subdomains"] = subs
    if len(subs) >= 5:
        findings.append({
            "title": f"{len(subs)} common subdomains resolve",
            "detail": ", ".join(subs[:8]),
            "severity": "info",
            "category": "Discovery",
            "remediation": "Review public-facing subdomains; remove unused ones.",
            "controls": ["ID.AM-1"],
        })

    crit = sum(1 for f in findings if f.get("severity") == "critical")
    high = sum(1 for f in findings if f.get("severity") == "high")
    med = sum(1 for f in findings if f.get("severity") == "medium")
    result["findings"] = findings
    result["risk_score"] = min(crit * 25 + high * 12 + med * 5, 100)
    audit_data["osint_recon"] = result
    print(f"[OSINT] Complete: {len(findings)} findings | {len(subs)} subdomain hints | Risk {result['risk_score']}/100")
    return audit_data
