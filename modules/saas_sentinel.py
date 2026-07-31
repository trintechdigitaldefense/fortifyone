#!/usr/bin/env python3
"""
SaaS-Sentinel - Cloud Posture Scanner
Audits Microsoft 365 and Google Workspace security configurations
TrinTech Digital Defense
"""

import json
import datetime
import os
import subprocess

def run_scan(audit_data: dict) -> dict:
    """
    Audit cloud/SaaS security posture.
    Checks SPF, DKIM, DMARC, and basic cloud security headers.
    """
    domain = audit_data["audit_metadata"]["domain"]
    
    print(f"\n[SAAS-SENTINEL] Auditing cloud security for {domain}...")
    
    findings = []
    score = 100
    checks = {}
    
    # ── Email Security Checks ──
    print("[SAAS-SENTINEL] Checking email security...")
    
    # SPF Check
    spf = check_dns_record(domain, 'TXT', 'v=spf1')
    checks["spf"] = {"passed": bool(spf), "record": spf}
    if spf:
        findings.append({"severity": "good", "title": "SPF Configured", "detail": f"SPF record found: {spf[:80]}..."})
    else:
        findings.append({"severity": "critical", "title": "Missing SPF Record", "detail": "Email spoofing possible. Configure SPF immediately."})
        score -= 25
    
    # DKIM Check
    dkim = check_dns_record(domain, 'TXT', 'v=DKIM1')
    checks["dkim"] = {"passed": bool(dkim), "record": dkim}
    if dkim:
        findings.append({"severity": "good", "title": "DKIM Configured", "detail": "Email signing enabled"})
    else:
        findings.append({"severity": "high", "title": "Missing DKIM", "detail": "Emails may be modified in transit"})
        score -= 20
    
    # DMARC Check
    dmarc = check_dns_record(f'_dmarc.{domain}', 'TXT', 'v=DMARC1')
    checks["dmarc"] = {"passed": bool(dmarc), "record": dmarc}
    if dmarc:
        # Check DMARC policy strength
        if 'p=reject' in dmarc.lower():
            findings.append({"severity": "good", "title": "Strong DMARC Policy", "detail": "p=reject configured"})
        elif 'p=quarantine' in dmarc.lower():
            findings.append({"severity": "medium", "title": "Moderate DMARC Policy", "detail": "p=quarantine - consider upgrading to reject"})
            score -= 5
        else:
            findings.append({"severity": "high", "title": "Weak DMARC Policy", "detail": "p=none - not actively protecting"})
            score -= 15
    else:
        findings.append({"severity": "critical", "title": "Missing DMARC", "detail": "No email authentication policy"})
        score -= 25
    
    # MX Record Check
    mx_records = check_mx_records(domain)
    checks["mx"] = mx_records
    if mx_records:
        provider = identify_email_provider(mx_records)
        findings.append({
            "severity": "info", 
            "title": f"Email Provider: {provider}", 
            "detail": f"MX records: {', '.join(mx_records[:3])}"
        })
    else:
        findings.append({"severity": "high", "title": "No MX Records", "detail": "Email may not be configured"})
        score -= 10
    
    # ── Web Security Headers ──
    print("[SAAS-SENTINEL] Checking web security headers...")
    
    web_headers = check_web_security_headers(domain)
    checks["web_headers"] = web_headers
    
    security_headers = ['Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options']
    for header in security_headers:
        if web_headers.get(header):
            findings.append({"severity": "good", "title": f"{header} Present", "detail": web_headers[header][:100]})
        else:
            findings.append({"severity": "medium", "title": f"Missing {header}", "detail": "Recommended security header not set"})
            score -= 5
    
    # ── Calculate Final Score ──
    score = max(0, min(100, score))
    
    if score >= 80:
        grade = 'A'
    elif score >= 65:
        grade = 'B'
    elif score >= 50:
        grade = 'C'
    elif score >= 35:
        grade = 'D'
    else:
        grade = 'F'
    
    # Update audit data
    audit_data["saas_posture"] = {
        "score_grade": grade,
        "score": score,
        "checks": checks,
        "findings": findings,
        "scan_timestamp": datetime.datetime.now().isoformat()
    }
    
    print(f"\n[SAAS-SENTINEL] Score: {score}/100 - Grade: {grade}")
    
    return audit_data


def check_dns_record(domain: str, record_type: str, contains: str) -> str:
    """Check for specific DNS record."""
    try:
        result = subprocess.run(
            ['dig', '+short', record_type, domain],
            capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.split('\n'):
            if contains.lower() in line.lower():
                return line.strip().strip('"')
        return ""
    except Exception:
        return ""


def check_mx_records(domain: str) -> list:
    """Get MX records for domain."""
    try:
        result = subprocess.run(
            ['dig', '+short', 'MX', domain],
            capture_output=True, text=True, timeout=10
        )
        records = []
        for line in result.stdout.split('\n'):
            if line.strip():
                parts = line.split()
                if len(parts) >= 2:
                    records.append(parts[-1].rstrip('.'))
        return records
    except:
        return []


def identify_email_provider(mx_records: list) -> str:
    """Identify email provider from MX records."""
    mx_str = ' '.join(mx_records).lower()
    if 'google' in mx_str or 'googlemail' in mx_str:
        return 'Google Workspace'
    elif 'outlook' in mx_str or 'protection.outlook' in mx_str:
        return 'Microsoft 365'
    elif 'amazonses' in mx_str:
        return 'AWS SES'
    elif 'mailgun' in mx_str:
        return 'Mailgun'
    elif 'zoho' in mx_str:
        return 'Zoho'
    else:
        return 'Unknown/Other'


def check_web_security_headers(domain: str) -> dict:
    """Check HTTP security headers."""
    headers = {}
    try:
        import urllib.request
        req = urllib.request.Request(f'https://{domain}', headers={'User-Agent': 'FortifyOne'})
        with urllib.request.urlopen(req, timeout=10) as resp:
            for header in ['Strict-Transport-Security', 'Content-Security-Policy', 
                          'X-Frame-Options', 'X-Content-Type-Options', 
                          'Referrer-Policy', 'Permissions-Policy']:
                value = resp.headers.get(header)
                if value:
                    headers[header] = value
    except Exception as e:
        headers['_error'] = str(e)
    return headers


if __name__ == "__main__":
    print("SaaS-Sentinel - Standalone Test")
    print("-" * 40)
    
    test_data = {
        "audit_metadata": {
            "client_name": "Test",
            "domain": "example.com",
            "public_ip": "93.184.216.34"
        },
        "saas_posture": {}
    }
    
    result = run_scan(test_data)
    print("\n" + json.dumps(result["saas_posture"], indent=2))
