#!/usr/bin/env python3
"""
WebProbe - Web Application Exposure Checks (v6.2)
TrinTech Digital Defense

Multi-target web discovery: homepage analysis, security headers, cookie flags,
CMS/tech fingerprinting, and sensitive path exposure checks.
Non-destructive. No exploitation. Authorized use only.
"""

from __future__ import annotations

import datetime
import re
import ssl
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin

COMMON_PATHS = [
    ("/wp-admin/", "WordPress admin", "high"),
    ("/wp-login.php", "WordPress login", "high"),
    ("/administrator/", "Joomla / generic admin", "high"),
    ("/admin/", "Generic admin path", "high"),
    ("/admin/login", "Admin login", "high"),
    ("/user/login", "User login", "medium"),
    ("/phpmyadmin/", "phpMyAdmin", "critical"),
    ("/pma/", "phpMyAdmin (alt)", "critical"),
    ("/.env", "Exposed environment file", "critical"),
    ("/.git/HEAD", "Exposed Git repository", "critical"),
    ("/.svn/entries", "Exposed SVN", "critical"),
    ("/backup.zip", "Backup archive", "critical"),
    ("/backup.sql", "SQL backup", "critical"),
    ("/dump.sql", "SQL dump", "critical"),
    ("/db.sql", "Database dump", "critical"),
    ("/server-status", "Apache server-status", "high"),
    ("/server-info", "Apache server-info", "high"),
    ("/robots.txt", "robots.txt", "info"),
    ("/sitemap.xml", "Sitemap", "info"),
    ("/actuator/health", "Spring Actuator health", "medium"),
    ("/actuator/env", "Spring Actuator env", "critical"),
    ("/api/", "API root", "medium"),
    ("/api/v1/", "API v1", "medium"),
    ("/graphql", "GraphQL endpoint", "high"),
    ("/swagger-ui.html", "Swagger UI", "high"),
    ("/swagger/index.html", "Swagger", "high"),
    ("/api-docs", "API docs", "high"),
    ("/elmah.axd", "ELMAH error log", "high"),
    ("/debug/", "Debug path", "high"),
    ("/config.php", "Config file", "critical"),
    ("/web.config", "IIS web.config", "high"),
    ("/crossdomain.xml", "Flash crossdomain", "low"),
    ("/security.txt", "security.txt", "info"),
    ("/.well-known/security.txt", "security.txt (well-known)", "info"),
    ("/login", "Login page", "medium"),
    ("/wp-json/", "WordPress REST API", "medium"),
    ("/xmlrpc.php", "WordPress XML-RPC", "medium"),
    ("/trace.axd", "ASP.NET trace", "high"),
    ("/cgi-bin/", "CGI bin", "medium"),
    ("/uploads/", "Uploads directory", "medium"),
    ("/files/", "Files directory", "medium"),
    ("/.DS_Store", "macOS DS_Store", "low"),
    ("/package.json", "Node package.json", "medium"),
    ("/composer.json", "PHP composer.json", "medium"),
]

CMS_SIGNATURES = [
    ("wp-content", "WordPress"),
    ("wp-includes", "WordPress"),
    ("wordpress", "WordPress"),
    ("Drupal.settings", "Drupal"),
    ("drupal.js", "Drupal"),
    ("Joomla!", "Joomla"),
    ("/media/jui/", "Joomla"),
    ("Shopify", "Shopify"),
    ("cdn.shopify.com", "Shopify"),
    ("Squarespace", "Squarespace"),
    ("static.squarespace.com", "Squarespace"),
    ("Wix.com", "Wix"),
    ("static.wixstatic.com", "Wix"),
    ("cdn.webflow.com", "Webflow"),
    ("ghost.org", "Ghost"),
    ("/skin/frontend/", "Magento"),
    ("Magento", "Magento"),
    ("laravel", "Laravel"),
    ("csrf-token", "Laravel/modern framework"),
    ("__next", "Next.js"),
    ("_next/static", "Next.js"),
    ("nuxt", "Nuxt.js"),
    ("react", "React"),
    ("vue.js", "Vue"),
    ("angular", "Angular"),
]

TECH_HEADER_HINTS = [
    ("x-powered-by", None),
    ("server", None),
    ("x-aspnet-version", "ASP.NET"),
    ("x-aspnetmvc-version", "ASP.NET MVC"),
    ("x-drupal-cache", "Drupal"),
    ("x-generator", None),
    ("x-shopify-stage", "Shopify"),
]


def _fetch(url: str, timeout: int = 8) -> Tuple[Optional[int], str, Dict[str, str]]:
    """Return (status_code, body_snippet, headers_dict)."""
    ctx = ssl.create_default_context()
    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "FortifyOne-WebProbe/6.2 (+https://trintechdigitaldefense.github.io)",
                "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
            },
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(12000).decode("utf-8", errors="ignore")
            headers = {k: v for k, v in resp.headers.items()}
            return resp.status, body, headers
    except urllib.error.HTTPError as e:
        try:
            body = e.read(3000).decode("utf-8", errors="ignore")
        except Exception:
            body = ""
        return e.code, body, dict(e.headers) if e.headers else {}
    except Exception:
        return None, "", {}


def _collect_web_targets(audit_data: dict) -> List[str]:
    """Build list of web targets: primary domain + hosts with web ports."""
    targets: List[str] = []
    seen: Set[str] = set()

    def add(host: str):
        host = (host or "").strip().lower()
        if not host or host in seen:
            return
        # Skip pure IPs for path probing if no domain context? Still useful.
        if host in ("localhost", "127.0.0.1", "0.0.0.0"):
            return
        seen.add(host)
        targets.append(host)

    meta = audit_data.get("audit_metadata") or {}
    if meta.get("domain"):
        add(str(meta["domain"]))

    # From external open ports
    for p in (audit_data.get("external_scan") or {}).get("open_ports") or []:
        if not isinstance(p, dict):
            continue
        port = str(p.get("port") or "")
        svc = (p.get("service") or "").lower()
        if port in ("80", "443", "8080", "8443", "8000", "8888") or "http" in svc:
            add(str(p.get("host") or p.get("ip") or ""))

    # From inventory
    for a in (audit_data.get("inventory") or {}).get("assets") or []:
        if not isinstance(a, dict):
            continue
        role = (a.get("role") or "").lower()
        ports = [str(x) for x in (a.get("ports") or [])]
        if role == "web" or any(p in ports for p in ("80", "443", "8080", "8443")):
            add(str(a.get("host") or ""))

    # Scope domains
    for t in (audit_data.get("scope") or {}).get("in_scope_targets") or []:
        t = str(t).strip()
        if re.match(r"^[a-z0-9].*\.[a-z]{2,}$", t, re.I):
            add(t)

    return targets[:8]  # safety cap


def _analyze_homepage(base_url: str, host: str) -> Tuple[List[Dict], Optional[str], Dict]:
    """Analyze homepage: CMS, headers, cookies, tech."""
    findings: List[Dict[str, Any]] = []
    cms_detected = None
    meta: Dict[str, Any] = {"url": base_url, "status": None, "server": None}

    status, body, headers = _fetch(base_url + "/")
    meta["status"] = status

    if status is None:
        findings.append({
            "target": host,
            "title": f"Web not reachable over {base_url.split(':')[0].upper()}",
            "detail": f"Could not connect to {base_url}",
            "severity": "medium" if base_url.startswith("https") else "low",
            "category": "Web Availability",
            "remediation": "Confirm DNS, firewall, and TLS configuration if the site should be public.",
            "controls": ["PR.IP-1"],
        })
        return findings, None, meta

    low = body.lower()
    hdr_l = {k.lower(): v for k, v in headers.items()}

    # CMS / tech from body
    for sig, name in CMS_SIGNATURES:
        if sig.lower() in low:
            cms_detected = name
            findings.append({
                "target": host,
                "title": f"Platform detected: {name}",
                "detail": f"Signature '{sig}' found on homepage. Keep platform and plugins patched.",
                "severity": "info",
                "category": "CMS / Tech",
                "remediation": f"Maintain {name} on a supported version; remove unused plugins/themes/modules.",
                "controls": ["PR.IP-1", "CIS-7.1"],
            })
            break

    # Header disclosures
    server = hdr_l.get("server")
    if server:
        meta["server"] = server
        findings.append({
            "target": host,
            "title": f"Server banner: {server}",
            "detail": "Server header discloses software/version information.",
            "severity": "low",
            "category": "Information Disclosure",
            "remediation": "Suppress or genericize the Server header where possible.",
            "controls": ["PR.DS-5"],
        })

    powered = hdr_l.get("x-powered-by")
    if powered:
        findings.append({
            "target": host,
            "title": f"X-Powered-By discloses: {powered}",
            "detail": powered[:200],
            "severity": "low",
            "category": "Information Disclosure",
            "remediation": "Remove the X-Powered-By header from the application/web server.",
            "controls": ["PR.DS-5"],
        })

    for hname, label in TECH_HEADER_HINTS:
        if hname in hdr_l and hname not in ("server", "x-powered-by"):
            val = hdr_l[hname]
            title = f"Tech header {hname}: {val}" if not label else f"{label} indicated via {hname}"
            findings.append({
                "target": host,
                "title": title[:120],
                "detail": f"{hname}: {val[:160]}",
                "severity": "info",
                "category": "Tech Stack",
                "controls": ["ID.AM-1"],
            })

    # Cookie flags
    cookies = []
    for k, v in headers.items():
        if k.lower() == "set-cookie":
            cookies.append(v)
    # Some stacks combine multiple Set-Cookie into one string
    expanded = []
    for ck in cookies:
        expanded.extend(re.split(r",(?=[^;]+?=)", ck) if "," in ck else [ck])

    for ck in expanded:
        low_ck = ck.lower()
        if "secure" not in low_ck and base_url.startswith("https"):
            findings.append({
                "target": host,
                "title": "Cookie without Secure flag",
                "detail": ck[:160],
                "severity": "medium",
                "category": "Session",
                "remediation": "Set the Secure flag on all session cookies.",
                "controls": ["PR.DS-2", "CIS-9.1"],
            })
        if "httponly" not in low_ck:
            findings.append({
                "target": host,
                "title": "Cookie without HttpOnly flag",
                "detail": ck[:160],
                "severity": "medium",
                "category": "Session",
                "remediation": "Set HttpOnly on session cookies to reduce XSS impact.",
                "controls": ["PR.DS-5"],
            })
        if "samesite" not in low_ck:
            findings.append({
                "target": host,
                "title": "Cookie without SameSite attribute",
                "detail": ck[:160],
                "severity": "low",
                "category": "Session",
                "remediation": "Set SameSite=Lax or Strict on cookies.",
                "controls": ["PR.DS-5"],
            })

    # Security headers
    for hname, label, sev in [
        ("strict-transport-security", "HSTS", "high"),
        ("content-security-policy", "Content-Security-Policy", "medium"),
        ("x-frame-options", "X-Frame-Options", "medium"),
        ("x-content-type-options", "X-Content-Type-Options", "low"),
        ("referrer-policy", "Referrer-Policy", "low"),
        ("permissions-policy", "Permissions-Policy", "low"),
    ]:
        if hname not in hdr_l:
            findings.append({
                "target": host,
                "title": f"Missing security header: {label}",
                "detail": f"{hname} not present on homepage response",
                "severity": sev,
                "category": "HTTP Headers",
                "remediation": f"Add a secure {label} header.",
                "controls": ["PR.DS-5", "CIS-9.1"],
            })

    # Mixed content / forms over HTTP (basic)
    if base_url.startswith("http://") and status == 200:
        findings.append({
            "target": host,
            "title": "Site served over cleartext HTTP",
            "detail": base_url,
            "severity": "high",
            "category": "Transport",
            "remediation": "Redirect all traffic to HTTPS and enable HSTS.",
            "controls": ["PR.DS-2"],
        })

    return findings, cms_detected, meta


def _probe_paths(base_url: str, host: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for path, label, default_sev in COMMON_PATHS:
        url = urljoin(base_url + "/", path.lstrip("/"))
        code, pbody, _ = _fetch(url)
        if code is None:
            continue

        if path in ("/robots.txt", "/sitemap.xml", "/security.txt", "/.well-known/security.txt"):
            if code == 200:
                findings.append({
                    "target": host,
                    "title": f"{label} present",
                    "detail": f"{path} returned HTTP {code}",
                    "severity": "info",
                    "category": "Web Exposure",
                    "controls": ["ID.AM-1"],
                })
            continue

        if code in (200, 401, 403):
            sev = default_sev
            # Escalate if body looks like real content for sensitive files
            if path in ("/.env", "/backup.sql", "/dump.sql", "/db.sql", "/config.php") and code == 200:
                if any(x in (pbody or "").lower() for x in ("password", "secret", "api_key", "db_", "mysql", "app_key")):
                    sev = "critical"
            findings.append({
                "target": host,
                "title": f"Exposed path: {path} ({label})",
                "detail": f"HTTP {code} on {url}. Verify this is intentional and properly protected.",
                "severity": sev,
                "category": "Web Exposure",
                "remediation": (
                    "Restrict access, remove the resource from the web root, or place it behind authentication."
                ),
                "controls": ["PR.AC-3", "PR.DS-5"],
            })
    return findings


def run_scan(audit_data: dict) -> dict:
    targets = _collect_web_targets(audit_data)

    if not targets:
        audit_data["web_probe"] = {
            "findings": [],
            "cms": None,
            "targets": [],
            "paths_checked": len(COMMON_PATHS),
            "risk_score": 0,
            "note": "No web targets found (no domain and no hosts with web ports)",
            "scan_timestamp": datetime.datetime.now().isoformat(),
        }
        print("[WEBPROBE] No web targets — skipped")
        return audit_data

    print(f"\n[WEBPROBE] Scanning {len(targets)} web target(s)...")

    all_findings: List[Dict[str, Any]] = []
    cms_detected = None
    per_target: List[Dict[str, Any]] = []

    for host in targets:
        # Prefer HTTPS, fall back to HTTP
        for scheme in ("https", "http"):
            base = f"{scheme}://{host}"
            findings, cms, meta = _analyze_homepage(base, host)
            if meta.get("status") is not None:
                all_findings.extend(findings)
                if cms and not cms_detected:
                    cms_detected = cms
                path_findings = _probe_paths(base, host)
                all_findings.extend(path_findings)
                per_target.append({
                    "host": host,
                    "scheme": scheme,
                    "status": meta.get("status"),
                    "server": meta.get("server"),
                    "cms": cms,
                    "findings_count": len(findings) + len(path_findings),
                })
                break  # do not double-probe HTTP if HTTPS worked
        else:
            per_target.append({
                "host": host,
                "scheme": None,
                "status": None,
                "server": None,
                "cms": None,
                "findings_count": 0,
                "error": "unreachable",
            })

    # Dedup by target+title
    deduped = []
    seen = set()
    for f in all_findings:
        k = (f.get("target"), f.get("title"))
        if k not in seen:
            seen.add(k)
            deduped.append(f)

    critical = sum(1 for f in deduped if f.get("severity") == "critical")
    high = sum(1 for f in deduped if f.get("severity") == "high")
    medium = sum(1 for f in deduped if f.get("severity") == "medium")
    risk_score = min(critical * 35 + high * 16 + medium * 7, 100)

    audit_data["web_probe"] = {
        "cms": cms_detected,
        "findings": deduped,
        "targets": per_target,
        "targets_count": len(targets),
        "paths_checked": len(COMMON_PATHS),
        "risk_score": risk_score,
        "scan_timestamp": datetime.datetime.now().isoformat(),
        "note": (
            "Multi-target passive web checks: homepage, headers, cookies, CMS/tech signatures, "
            "and sensitive path probes. Manual verification required for confirmed exposures."
        ),
    }
    print(
        f"[WEBPROBE] Complete: targets={len(targets)} CMS={cms_detected or 'none'} "
        f"| {len(deduped)} findings | Risk {risk_score}/100\n"
    )
    return audit_data


if __name__ == "__main__":
    test = {"audit_metadata": {"domain": "example.com"}, "web_probe": {}}
    print(run_scan(test)["web_probe"])
