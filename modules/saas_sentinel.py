#!/usr/bin/env python3
"""
SaaS-Sentinel - Cloud & Web Posture Scanner (v2)
Email auth (SPF/DKIM/DMARC) + web security headers + basic exposure checks.
TrinTech Digital Defense
"""

import json
import datetime
import subprocess
import urllib.request
import ssl
import socket
from typing import Dict, List, Any


def run_scan(audit_data: dict) -> dict:
    domain = audit_data.get("audit_metadata", {}).get("domain", "")
    if not domain:
        audit_data["saas_posture"] = {
            "score_grade": "N/A", "score": 0, "findings": [],
            "scan_timestamp": datetime.datetime.now().isoformat(),
            "note": "No domain provided",
        }
        return audit_data

    print(f"\n[SAAS-SENTINEL] Auditing cloud/web security for {domain}...")

    findings: List[Dict] = []
    score = 100
    checks: Dict[str, Any] = {}

    # ── Email Security ──
    print("[SAAS-SENTINEL] Checking email authentication...")

    spf = check_dns_record(domain, "TXT", "v=spf1")
    checks["spf"] = {"passed": bool(spf), "record": spf[:120] if spf else ""}
    if spf:
        findings.append({"severity": "good", "title": "SPF Configured", "detail": spf[:100]})
    else:
        findings.append({"severity": "critical", "title": "Missing SPF Record",
                         "detail": "Email spoofing is trivial without SPF. Configure immediately."})
        score -= 25

    dkim = check_dns_record(domain, "TXT", "v=DKIM1")
    # Also try common selectors
    if not dkim:
        for sel in ("default", "google", "selector1", "k1"):
            dkim = check_dns_record(f"{sel}._domainkey.{domain}", "TXT", "v=DKIM1")
            if dkim:
                break
    checks["dkim"] = {"passed": bool(dkim)}
    if dkim:
        findings.append({"severity": "good", "title": "DKIM Configured", "detail": "Email signing appears enabled"})
    else:
        findings.append({"severity": "high", "title": "DKIM not detected",
                         "detail": "Emails may be altered in transit or fail authentication at receivers."})
        score -= 18

    dmarc = check_dns_record(f"_dmarc.{domain}", "TXT", "v=DMARC1")
    checks["dmarc"] = {"passed": bool(dmarc), "record": dmarc[:120] if dmarc else ""}
    if dmarc:
        low = dmarc.lower()
        if "p=reject" in low:
            findings.append({"severity": "good", "title": "Strong DMARC (p=reject)", "detail": dmarc[:100]})
        elif "p=quarantine" in low:
            findings.append({"severity": "medium", "title": "DMARC p=quarantine",
                             "detail": "Good progress – plan upgrade to p=reject after monitoring."})
            score -= 5
        else:
            findings.append({"severity": "high", "title": "Weak DMARC (p=none)",
                             "detail": "Policy is monitoring-only. Move to quarantine/reject."})
            score -= 15
    else:
        findings.append({"severity": "critical", "title": "Missing DMARC",
                         "detail": "No email authentication policy. Spoofing and phishing risk is high."})
        score -= 25

    mx_records = check_mx_records(domain)
    checks["mx"] = mx_records
    if mx_records:
        provider = identify_email_provider(mx_records)
        findings.append({"severity": "info", "title": f"Email Provider: {provider}",
                         "detail": ", ".join(mx_records[:3])})
    else:
        findings.append({"severity": "medium", "title": "No MX records found",
                         "detail": "Domain may not be used for email."})
        score -= 5

    # ── Web Security Headers & Exposure ──
    print("[SAAS-SENTINEL] Checking web security posture...")
    web = check_web_security(domain)
    checks["web"] = web

    for header in ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
                   "X-Content-Type-Options", "Referrer-Policy"]:
        if web.get("headers", {}).get(header):
            findings.append({"severity": "good", "title": f"{header} present",
                             "detail": web["headers"][header][:90]})
        else:
            findings.append({"severity": "medium", "title": f"Missing {header}",
                             "detail": "Recommended browser security control not set."})
            score -= 4

    if web.get("server_header"):
        findings.append({"severity": "low", "title": "Server header discloses software",
                         "detail": f"Server: {web['server_header']}. Consider suppressing version banners."})
        score -= 3

    if web.get("directory_listing"):
        findings.append({"severity": "high", "title": "Possible directory listing",
                         "detail": "A common path returned a listing-style response. Verify and disable if unintended."})
        score -= 12

    if web.get("robots_sensitive"):
        findings.append({"severity": "medium", "title": "robots.txt references sensitive paths",
                         "detail": "Review robots.txt – it can reveal admin or backup locations to attackers."})
        score -= 6

    if web.get("https_error"):
        findings.append({"severity": "high", "title": "HTTPS connection issue",
                         "detail": web["https_error"][:120]})
        score -= 15

    score = max(0, min(100, score))
    if score >= 80:
        grade = "A"
    elif score >= 65:
        grade = "B"
    elif score >= 50:
        grade = "C"
    elif score >= 35:
        grade = "D"
    else:
        grade = "F"

    audit_data["saas_posture"] = {
        "score_grade": grade,
        "score": score,
        "checks": checks,
        "findings": findings,
        "scan_timestamp": datetime.datetime.now().isoformat(),
    }
    print(f"[SAAS-SENTINEL] Score: {score}/100 – Grade: {grade}\n")
    return audit_data


def check_dns_record(name: str, rtype: str, contains: str) -> str:
    try:
        res = subprocess.run(["dig", "+short", rtype, name], capture_output=True, text=True, timeout=8)
        for line in res.stdout.splitlines():
            if contains.lower() in line.lower():
                return line.strip().strip('"')
    except Exception:
        pass
    return ""


def check_mx_records(domain: str) -> list:
    try:
        res = subprocess.run(["dig", "+short", "MX", domain], capture_output=True, text=True, timeout=8)
        records = []
        for line in res.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                records.append(parts[-1].rstrip("."))
        return records
    except Exception:
        return []


def identify_email_provider(mx: list) -> str:
    s = " ".join(mx).lower()
    if "google" in s or "googlemail" in s:
        return "Google Workspace"
    if "outlook" in s or "protection.outlook" in s:
        return "Microsoft 365"
    if "amazonses" in s:
        return "AWS SES"
    if "zoho" in s:
        return "Zoho"
    return "Other / Self-hosted"


def check_web_security(domain: str) -> dict:
    result = {"headers": {}, "server_header": "", "directory_listing": False,
              "robots_sensitive": False, "https_error": ""}
    ctx = ssl.create_default_context()

    # Headers
    try:
        req = urllib.request.Request(f"https://{domain}/", headers={"User-Agent": "FortifyOne-Audit/4.5"})
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            for h in ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
                      "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"]:
                val = resp.headers.get(h)
                if val:
                    result["headers"][h] = val
            result["server_header"] = resp.headers.get("Server", "")
    except Exception as e:
        result["https_error"] = str(e)[:150]

    # robots.txt quick look
    try:
        req = urllib.request.Request(f"https://{domain}/robots.txt", headers={"User-Agent": "FortifyOne-Audit/4.5"})
        with urllib.request.urlopen(req, timeout=6, context=ctx) as resp:
            body = resp.read(4000).decode("utf-8", errors="ignore").lower()
            sensitive = ["admin", "backup", "wp-admin", "phpmyadmin", "config", "sql", "private"]
            if any(s in body for s in sensitive):
                result["robots_sensitive"] = True
    except Exception:
        pass

    # Very light directory listing probe (common path)
    try:
        req = urllib.request.Request(f"https://{domain}/images/", headers={"User-Agent": "FortifyOne-Audit/4.5"})
        with urllib.request.urlopen(req, timeout=6, context=ctx) as resp:
            body = resp.read(2000).decode("utf-8", errors="ignore").lower()
            if "index of" in body or "directory listing" in body:
                result["directory_listing"] = True
    except Exception:
        pass

    return result


if __name__ == "__main__":
    test = {"audit_metadata": {"domain": "example.com"}, "saas_posture": {}}
    print(json.dumps(run_scan(test)["saas_posture"], indent=2))
