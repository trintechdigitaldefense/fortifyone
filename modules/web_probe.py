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
    ("/admin/login", "Admin login"),
    ("/user/login", "User login"),
    ("/phpmyadmin/", "phpMyAdmin"),
    ("/pma/", "phpMyAdmin (alt)"),
    ("/.env", "Exposed environment file"),
    ("/.git/HEAD", "Exposed Git repository"),
    ("/.svn/entries", "Exposed SVN"),
    ("/backup.zip", "Backup archive"),
    ("/backup.sql", "SQL backup"),
    ("/dump.sql", "SQL dump"),
    ("/db.sql", "Database dump"),
    ("/server-status", "Apache server-status"),
    ("/server-info", "Apache server-info"),
    ("/robots.txt", "robots.txt"),
    ("/sitemap.xml", "Sitemap"),
    ("/actuator/health", "Spring Actuator health"),
    ("/actuator/env", "Spring Actuator env"),
    ("/api/", "API root"),
    ("/graphql", "GraphQL endpoint"),
    ("/swagger-ui.html", "Swagger UI"),
    ("/swagger/index.html", "Swagger"),
    ("/elmah.axd", "ELMAH error log"),
    ("/debug/", "Debug path"),
    ("/config.php", "Config file"),
    ("/web.config", "IIS web.config"),
    ("/crossdomain.xml", "Flash crossdomain"),
    ("/security.txt", "security.txt"),
    ("/.well-known/security.txt", "security.txt (well-known)"),
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
        req = urllib.request.Request(url, headers={"User-Agent": "FortifyOne-WebProbe/6.1"})
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
                "remediation": "Remove X-Powered-By from web server/app config.",
                "controls": ["PR.DS-5"],
            })

        # Cookie security flags
        set_cookies = []
        for k, v in headers.items():
            if k.lower() == "set-cookie":
                set_cookies.append(v)
        # also try get_all style via response not available; single header may be combined
        for ck in set_cookies:
            low_ck = ck.lower()
            if "secure" not in low_ck:
                findings.append({
                    "title": "Cookie without Secure flag",
                    "detail": ck[:160],
                    "severity": "medium",
                    "category": "Session",
                    "remediation": "Set Secure on all session cookies.",
                    "controls": ["PR.DS-2"],
                })
            if "httponly" not in low_ck:
                findings.append({
                    "title": "Cookie without HttpOnly flag",
                    "detail": ck[:160],
                    "severity": "medium",
                    "category": "Session",
                    "remediation": "Set HttpOnly on session cookies to reduce XSS impact.",
                    "controls": ["PR.DS-5"],
                })
            if "samesite" not in low_ck:
                findings.append({
                    "title": "Cookie without SameSite attribute",
                    "detail": ck[:160],
                    "severity": "low",
                    "category": "Session",
                    "remediation": "Set SameSite=Lax or Strict on cookies.",
                    "controls": ["PR.DS-5"],
                })

        # Security headers (complement TLS posture)
        hdr_l = {k.lower(): v for k, v in headers.items()}
        for hname, label, sev in [
            ("strict-transport-security", "HSTS", "high"),
            ("content-security-policy", "CSP", "medium"),
            ("x-frame-options", "X-Frame-Options", "medium"),
            ("x-content-type-options", "X-Content-Type-Options", "low"),
        ]:
            if hname not in hdr_l:
                findings.append({
                    "title": f"Missing security header: {label}",
                    "detail": f"{hname} not present on homepage",
                    "severity": sev,
                    "category": "HTTP Headers",
                    "remediation": f"Add {label} with a secure value.",
                    "controls": ["PR.DS-5", "CIS-9.1"],
                })

        # Tech fingerprint extras
        tech = []
        if "wp-content" in low or "wordpress" in low:
            tech.append("WordPress")
        if "react" in low or "__next" in low:
            tech.append("React/Next")
        if "drupal" in low:
            tech.append("Drupal")
        if tech:
            findings.append({
                "title": f"Technology signals: {', '.join(tech)}",
                "detail": "Keep frameworks and CMS plugins patched; remove unused components.",
                "severity": "info",
                "category": "Tech Stack",
                "controls": ["PR.IP-1"],
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
            sev = "critical" if path in ("/.env", "/.git/HEAD", "/.svn/entries", "/backup.sql", "/backup.zip", "/dump.sql", "/db.sql", "/config.php", "/actuator/env") else \
                  "high" if path in ("/phpmyadmin/", "/pma/", "/server-status", "/admin/", "/wp-login.php", "/swagger-ui.html", "/graphql") else "medium"
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
