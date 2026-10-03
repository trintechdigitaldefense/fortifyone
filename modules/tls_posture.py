#!/usr/bin/env python3
"""
TLSPosture - Lightweight TLS / HTTP Security Posture Checks
TrinTech Digital Defense

Safe, non-destructive checks for certificate validity, protocol support,
security headers, and common misconfigurations. Pure Python + stdlib where possible.
"""

from __future__ import annotations

import datetime
import socket
import ssl
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse


SECURITY_HEADERS = [
    ("Strict-Transport-Security", "HSTS", "high"),
    ("Content-Security-Policy", "CSP", "medium"),
    ("X-Content-Type-Options", "X-Content-Type-Options", "medium"),
    ("X-Frame-Options", "X-Frame-Options", "medium"),
    ("Referrer-Policy", "Referrer-Policy", "low"),
    ("Permissions-Policy", "Permissions-Policy", "low"),
]


def _fetch_https(host: str, timeout: int = 10) -> Tuple[Optional[int], str, Dict[str, str], Optional[ssl.SSLObject]]:
    """Return status, body snippet, headers, ssl_obj."""
    url = f"https://{host}/"
    ctx = ssl.create_default_context()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "FortifyOne-TLSPosture/5.4"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(6000).decode("utf-8", errors="ignore")
            headers = {k.lower(): v for k, v in resp.headers.items()}
            # Try to get SSL object if available
            ssl_obj = getattr(resp, "fp", None)
            if ssl_obj and hasattr(ssl_obj, "raw"):
                ssl_obj = getattr(ssl_obj.raw, "_sslobj", None)
            return resp.status, body, headers, ssl_obj
    except urllib.error.HTTPError as e:
        try:
            body = e.read(2000).decode("utf-8", errors="ignore")
        except Exception:
            body = ""
        return e.code, body, {k.lower(): v for k, v in (e.headers.items() if e.headers else [])}, None
    except Exception:
        return None, "", {}, None


def _cert_info(host: str, port: int = 443, timeout: int = 8) -> Dict[str, Any]:
    """Fetch certificate details via raw SSL connection."""
    info: Dict[str, Any] = {
        "host": host,
        "port": port,
        "valid": False,
        "issuer": "",
        "subject": "",
        "not_before": "",
        "not_after": "",
        "days_remaining": None,
        "san": [],
        "version": None,
        "error": None,
    }
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    info["error"] = "No certificate returned"
                    return info
                info["valid"] = True
                info["subject"] = dict(x[0] for x in cert.get("subject", ()))
                info["issuer"] = dict(x[0] for x in cert.get("issuer", ()))
                info["not_before"] = cert.get("notBefore", "")
                info["not_after"] = cert.get("notAfter", "")
                # Days remaining
                try:
                    from datetime import datetime
                    exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                    info["days_remaining"] = (exp - datetime.utcnow()).days
                except Exception:
                    pass
                # SANs
                sans = []
                for typ, val in cert.get("subjectAltName", ()):
                    if typ == "DNS":
                        sans.append(val)
                info["san"] = sans
                info["version"] = ssock.version()
    except ssl.SSLError as e:
        info["error"] = f"SSL error: {e}"
    except socket.timeout:
        info["error"] = "Connection timeout"
    except Exception as e:
        info["error"] = f"{type(e).__name__}: {e}"
    return info


def _protocol_probe(host: str, port: int = 443) -> Dict[str, bool]:
    """Probe supported TLS versions (safe)."""
    results = {}
    for label, proto in [
        ("TLSv1.0", ssl.TLSVersion.TLSv1),
        ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
        ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
        ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
    ]:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.minimum_version = proto
            ctx.maximum_version = proto
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    results[label] = True
        except Exception:
            results[label] = False
    return results


def run_scan(audit_data: dict) -> dict:
    """Run TLS/HTTP posture checks against the primary domain or first HTTPS target."""
    meta = audit_data.get("audit_metadata", {})
    domain = (meta.get("domain") or "").strip().lower()
    targets = audit_data.get("scope", {}).get("in_scope_targets", []) or []

    # Prefer domain; fall back to first target that looks like a hostname
    host = domain
    if not host:
        for t in targets:
            t = str(t).strip()
            if t and not t.replace(".", "").isdigit() and "/" not in t:
                host = t
                break

    result: Dict[str, Any] = {
        "host": host or None,
        "findings": [],
        "certificate": {},
        "protocols": {},
        "headers": {},
        "risk_score": 0,
        "scan_timestamp": datetime.datetime.now().isoformat(),
        "note": "",
    }

    if not host:
        result["note"] = "No domain or hostname available for TLS checks"
        audit_data["tls_posture"] = result
        print("[TLSPOSTURE] Skipped — no domain/hostname")
        return audit_data

    print(f"\n[TLSPOSTURE] Checking TLS/HTTP posture for {host}...")

    findings: List[Dict[str, Any]] = []

    # Certificate
    cert = _cert_info(host)
    result["certificate"] = cert
    if cert.get("error"):
        findings.append({
            "title": f"TLS connection / certificate error on {host}",
            "detail": cert["error"],
            "severity": "high",
            "category": "TLS",
            "remediation": "Ensure a valid certificate is installed and port 443 is reachable.",
            "controls": ["PR.DS-2", "CIS-3.1"],
        })
    else:
        days = cert.get("days_remaining")
        if days is not None and days < 0:
            findings.append({
                "title": "TLS certificate has expired",
                "detail": f"Expired on {cert.get('not_after')}",
                "severity": "critical",
                "category": "TLS",
                "remediation": "Renew the certificate immediately and automate renewal (e.g. ACME).",
                "controls": ["PR.DS-2", "CIS-3.1"],
            })
        elif days is not None and days < 30:
            findings.append({
                "title": f"TLS certificate expires in {days} days",
                "detail": f"Expires {cert.get('not_after')}",
                "severity": "high",
                "category": "TLS",
                "remediation": "Renew before expiry; prefer automated renewal.",
                "controls": ["PR.DS-2"],
            })
        elif days is not None and days < 90:
            findings.append({
                "title": f"TLS certificate expires in {days} days",
                "detail": f"Expires {cert.get('not_after')}",
                "severity": "medium",
                "category": "TLS",
                "remediation": "Plan renewal; automate if possible.",
                "controls": ["PR.DS-2"],
            })

    # Protocol support
    protos = _protocol_probe(host)
    result["protocols"] = protos
    if protos.get("TLSv1.0") or protos.get("TLSv1.1"):
        findings.append({
            "title": "Legacy TLS protocols (1.0/1.1) still enabled",
            "detail": str(protos),
            "severity": "high",
            "category": "TLS",
            "remediation": "Disable TLS 1.0 and 1.1. Prefer TLS 1.2+ only.",
            "controls": ["PR.DS-2", "CIS-3.1"],
        })
    if not protos.get("TLSv1.2") and not protos.get("TLSv1.3"):
        findings.append({
            "title": "Modern TLS (1.2/1.3) not detected",
            "detail": str(protos),
            "severity": "critical",
            "category": "TLS",
            "remediation": "Enable TLS 1.2 and preferably TLS 1.3.",
            "controls": ["PR.DS-2"],
        })

    # HTTP security headers (via HTTPS fetch)
    status, body, headers, _ = _fetch_https(host)
    result["headers"] = {k: headers.get(k.lower()) for k, _, _ in SECURITY_HEADERS}
    result["http_status"] = status

    if status is None:
        findings.append({
            "title": f"HTTPS fetch failed for {host}",
            "detail": "Could not retrieve homepage over HTTPS",
            "severity": "medium",
            "category": "HTTP",
            "remediation": "Ensure the site is reachable over HTTPS.",
            "controls": ["PR.DS-2"],
        })
    else:
        for header_name, label, sev in SECURITY_HEADERS:
            if header_name.lower() not in headers:
                findings.append({
                    "title": f"Missing security header: {label}",
                    "detail": f"{header_name} not present",
                    "severity": sev,
                    "category": "HTTP Headers",
                    "remediation": f"Add the {header_name} header with a secure value.",
                    "controls": ["PR.DS-5", "CIS-9.1"],
                })

        # HSTS specific
        hsts = headers.get("strict-transport-security", "")
        if hsts and "max-age=0" in hsts.lower():
            findings.append({
                "title": "HSTS max-age is 0 (effectively disabled)",
                "detail": hsts,
                "severity": "high",
                "category": "HTTP Headers",
                "remediation": "Set a long max-age (e.g. 31536000) and includeSubDomains where appropriate.",
                "controls": ["PR.DS-2"],
            })

    # Risk score
    crit = sum(1 for f in findings if f.get("severity") == "critical")
    high = sum(1 for f in findings if f.get("severity") == "high")
    med = sum(1 for f in findings if f.get("severity") == "medium")
    risk = min(crit * 25 + high * 12 + med * 5, 100)

    result["findings"] = findings
    result["risk_score"] = risk
    audit_data["tls_posture"] = result

    print(f"[TLSPOSTURE] Complete: {len(findings)} findings | Risk {risk}/100")
    return audit_data
