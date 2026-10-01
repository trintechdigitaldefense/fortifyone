#!/usr/bin/env python3
"""
WebProbe - Lightweight Web Application Exposure Checks
TrinTech Digital Defense

Detects common CMS, exposed admin panels, backup files, and basic misconfigs.
Non-destructive. No exploitation.
"""

import datetime
import ssl
import urllib.request
import urllib.error
from typing import Dict, List, Any
from urllib.parse import urljoin

COMMON_PATHS = [
    ("/wp-admin/", "WordPress admin"),
    ("/wp-login.php", "WordPress login"),
    ("/administrator/", "Joomla / generic admin"),
    ("/admin/", "Generic admin path"),
    ("/phpmyadmin/", "phpMyAdmin"),
    ("/pma/", "phpMyAdmin (alt)"),
    ("/.env", "Exposed environment file"),
    ("/.git/HEAD", "Exposed Git repository"),
    ("/backup.zip", "Backup archive"),
    ("/backup.sql", "SQL backup"),
    ("/server-status", "Apache server-status"),
    ("/server-info", "Apache server-info"),
    ("/robots.txt", "robots.txt"),
    ("/sitemap.xml", "Sitemap"),
]

CMS_SIGNATURES = [
    ("wp-content", "WordPress"),
    ("wp-includes", "WordPress"),
    ("Drupal.settings", "Drupal"),
    ("Joomla!", "Joomla"),
    ("Shopify", "Shopify"),
    ("cdn.shopify.com", "Shopify"),
    ("Squarespace", "Squarespace"),
    ("Wix.com", "Wix"),
]


def _fetch(url: str, timeout: int = 8) -> tuple:
    """Return (status_code, body_snippet, headers_dict) or (None, '', {})."""
    ctx = ssl.create_default_context()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "FortifyOne-WebProbe/5.0"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(8000).decode("utf-8", errors="ignore")
            headers = {k: v for k, v in resp.headers.items()}
            return resp.status, body, headers
    except urllib.error.HTTPError as e:
        try:
            body = e.read(2000).decode("utf-8", errors="ignore")
        except Exception:
            body = ""
        return e.code, body, dict(e.headers) if e.headers else {}
    except Exception:
        return None, "", {}


def run_scan(audit_data: dict) -> dict:
    domain = audit_data.get("audit_metadata", {}).get("domain", "").strip()
    if not domain:
        audit_data["web_probe"] = {
            "findings": [], "cms": None, "risk_score": 0,
            "note": "No domain provided", "scan_timestamp": datetime.datetime.now().isoformat(),
        }
        return audit_data

    print(f"\n[WEBPROBE] Scanning web presence for {domain}...")
    base = f"https://{domain}"
    findings: List[Dict[str, Any]] = []
    cms_detected = None

    # Homepage
    status, body, headers = _fetch(base + "/")
    if status is None:
        # Try http fallback info only
        findings.append({
            "title": "HTTPS not reachable",
            "detail": f"Could not connect to https://{domain}",
            "severity": "high",
            "category": "Web Availability",
        })
    else:
        # CMS detection
        low = body.lower()
        for sig, name in CMS_SIGNATURES:
            if sig.lower() in low:
                cms_detected = name
                findings.append({
                    "title": f"CMS detected: {name}",
                    "detail": "Identify and keep the platform patched. Remove unused plugins/themes.",
                    "severity": "info",
                    "category": "CMS",
                })
                break

        server = headers.get("Server") or headers.get("server")
        if server:
            findings.append({
                "title": f"Server banner: {server}",
                "detail": "Consider suppressing version information in the Server header.",
                "severity": "low",
                "category": "Information Disclosure",
            })

        powered = headers.get("X-Powered-By") or headers.get("x-powered-by")
        if powered:
            findings.append({
                "title": f"X-Powered-By discloses: {powered}",
                "detail": "Remove or suppress the X-Powered-By header.",
                "severity": "low",
                "category": "Information Disclosure",
            })

    # Path probes
    for path, label in COMMON_PATHS:
        code, pbody, _ = _fetch(urljoin(base + "/", path.lstrip("/")))
        if code is None:
            continue
        if path in ("/robots.txt", "/sitemap.xml"):
            if code == 200:
                findings.append({
                    "title": f"{label} present",
                    "detail": f"{path} returned HTTP {code}",
                    "severity": "info",
                    "category": "Web Exposure",
                })
            continue

        # Interesting if 200 or 403 (exists but forbidden) or 401
        if code in (200, 401, 403):
            sev = "critical" if path in ("/.env", "/.git/HEAD", "/backup.sql", "/backup.zip") else \
                  "high" if path in ("/phpmyadmin/", "/pma/", "/server-status") else "medium"
            findings.append({
                "title": f"Exposed path: {path} ({label})",
                "detail": f"HTTP {code}. Verify this is intentional and properly protected.",
                "severity": sev,
                "category": "Web Exposure",
            })

    # Risk score
    critical = sum(1 for f in findings if f["severity"] == "critical")
    high = sum(1 for f in findings if f["severity"] == "high")
    medium = sum(1 for f in findings if f["severity"] == "medium")
    risk_score = min(critical * 35 + high * 18 + medium * 8, 100)

    audit_data["web_probe"] = {
        "cms": cms_detected,
        "findings": findings,
        "paths_checked": len(COMMON_PATHS),
        "risk_score": risk_score,
        "scan_timestamp": datetime.datetime.now().isoformat(),
        "note": "Passive path and signature checks only. Manual verification required for confirmed exposures.",
    }
    print(f"[WEBPROBE] Complete: CMS={cms_detected or 'none'} | {len(findings)} findings | Risk {risk_score}/100\n")
    return audit_data


if __name__ == "__main__":
    test = {"audit_metadata": {"domain": "example.com"}, "web_probe": {}}
    print(run_scan(test)["web_probe"])
