#!/usr/bin/env python3
"""
Scoring - Unified security score + plain-English remediation roadmap
TrinTech Digital Defense

Language tuned for Trinidad & Tobago / Caribbean SMB owners and managers
who are not security specialists.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple


def grade_from_score(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def collect_all_findings(audit: dict) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    sections = (
        "external_scan", "vuln_probe", "web_probe", "tls_posture",
        "osint_recon", "local_hardening", "credentialed_scan",
        "saas_posture", "breach_exposure", "internal_scan",
    )
    for section in sections:
        data = audit.get(section) or {}
        items = data.get("findings") or data.get("vulnerabilities") or []
        if not isinstance(items, list):
            continue
        for it in items:
            if isinstance(it, dict):
                sev = (it.get("severity") or "info").lower()
                out.append({
                    "source": section,
                    "title": it.get("title") or str(it.get("detail", ""))[:80],
                    "severity": sev,
                    "detail": it.get("detail") or "",
                    "remediation": it.get("remediation") or "",
                    "host": it.get("host") or it.get("target") or "",
                    "controls": it.get("controls") or [],
                    "category": it.get("category") or section,
                })
            elif isinstance(it, str) and it.strip():
                # Skip pure status lines that are not actionable findings
                if it.startswith("[ACTIVE]") or it.startswith("[INTERNAL]"):
                    continue
                if it.startswith("[ERROR]") or it.startswith("[INFO]"):
                    continue
                out.append({
                    "source": section,
                    "title": it[:100],
                    "severity": "medium",
                    "detail": it,
                    "remediation": "",
                    "host": "",
                    "controls": [],
                    "category": section,
                })
    return out


def compute_score(findings: List[Dict[str, Any]]) -> Tuple[int, Dict[str, int]]:
    """100 - (crit*25 + high*12 + med*5 + low*2), floored at 0."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        s = f.get("severity", "info")
        if s in counts:
            counts[s] += 1
    penalty = (
        counts["critical"] * 25
        + counts["high"] * 12
        + counts["medium"] * 5
        + counts["low"] * 2
    )
    score = max(0, min(100, 100 - penalty))
    return score, counts


def urgency_bucket(severity: str) -> str:
    s = (severity or "").lower()
    if s == "critical":
        return "Immediate"
    if s == "high":
        return "This Week"
    if s == "medium":
        return "This Month"
    return "Ongoing"


# Plain-English explanations for common finding patterns (T&T SMB audience)
PLAIN_MEANING = [
    ("rdp", "Remote Desktop is reachable in a way that attackers on the internet commonly target."),
    ("3389", "Remote Desktop (port 3389) is exposed. Criminals scan for this daily."),
    ("smb", "File sharing (SMB) is visible where it should not be for an internet-facing system."),
    ("445", "Windows file sharing port is exposed. This has been used in major ransomware outbreaks."),
    ("telnet", "Telnet sends passwords in clear text and should not be used."),
    ("ftp", "FTP is outdated for sensitive transfers; prefer SFTP or a secure portal."),
    ("redis", "A database cache service appears exposed without proper protection."),
    ("mongodb", "A database service appears exposed. Databases should not face the public internet."),
    ("mysql", "A database service appears exposed. Restrict it to internal networks only."),
    ("postgres", "A database service appears exposed. Restrict it to internal networks only."),
    ("passwordauthentication yes", "SSH still allows password logins, which are easier to brute-force than keys."),
    ("permitrootlogin yes", "Direct root login over SSH is allowed. That gives attackers a high-value target."),
    ("missing security header", "The website is missing a protective browser header that reduces common attacks."),
    ("hsts", "The site does not tell browsers to always use HTTPS, which can allow downgrade attacks."),
    ("cookie without", "Session cookies are missing a security flag, which can make account theft easier."),
    ("exposed path", "A sensitive web path responded as present. If real, it may leak data or admin access."),
    (".env", "An environment file may be downloadable. These files often contain passwords and API keys."),
    (".git", "A Git repository appears exposed on the web server, which can leak source code and secrets."),
    ("outdated", "Software version indicators suggest the system is behind on security updates."),
    ("reboot required", "Security updates are installed but the system still needs a restart to fully apply them."),
    ("nopasswd", "Some accounts can run admin commands without a password. That increases insider and malware risk."),
    ("firewall", "The host firewall does not appear active, so the server relies only on network-edge controls."),
]


def _plain_meaning(title: str, detail: str) -> str:
    blob = f"{title} {detail}".lower()
    for key, text in PLAIN_MEANING:
        if key in blob:
            return text
    if detail and len(detail) > 20:
        return detail[:220]
    return (
        f"{title}. This was flagged during the authorized assessment and should be reviewed "
        "against your normal business need for the service."
    )


def _plain_action(title: str, remediation: str, severity: str) -> str:
    if remediation and len(remediation) > 15:
        return remediation
    sev = (severity or "").lower()
    title_l = (title or "").lower()
    if "rdp" in title_l or "3389" in title_l:
        return "Block Remote Desktop from the internet. Allow access only via VPN, with MFA if possible."
    if "smb" in title_l or "445" in title_l:
        return "Block SMB from the internet immediately. File sharing should stay on the internal network or VPN."
    if "ssh" in title_l and "password" in title_l:
        return "Switch SSH to key-based login only and disable password authentication."
    if "header" in title_l:
        return "Ask your web developer or host to add the missing security header on the live site."
    if "cookie" in title_l:
        return "Ask your web developer to set Secure, HttpOnly, and SameSite on session cookies."
    if sev == "critical":
        return "Treat as urgent: restrict access, patch, or take the service offline until fixed."
    if sev == "high":
        return "Schedule a fix this week: restrict network access, apply updates, or harden the service."
    return "Review whether this is required for business. If not, disable it; if yes, harden and monitor it."


def build_remediation_roadmap(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    roadmap = []
    order = {"Immediate": 0, "This Week": 1, "This Month": 2, "Ongoing": 3}
    for f in findings:
        if f.get("severity") in ("info",):
            continue
        title = f.get("title") or "Finding"
        detail = f.get("detail") or ""
        remediation = f.get("remediation") or ""
        roadmap.append({
            "urgency": urgency_bucket(f.get("severity", "low")),
            "title": title,
            "severity": f.get("severity"),
            "host": f.get("host") or "",
            "what_it_means": _plain_meaning(title, detail),
            "what_to_do": _plain_action(title, remediation, f.get("severity", "")),
            "source": f.get("source"),
            "controls": f.get("controls") or [],
        })
    roadmap.sort(key=lambda x: order.get(x["urgency"], 9))
    return roadmap


def _executive_summary(
    client: str,
    score: int,
    grade: str,
    counts: Dict[str, int],
    asset_count: int,
) -> str:
    crit = counts.get("critical", 0)
    high = counts.get("high", 0)
    med = counts.get("medium", 0)

    if score >= 85:
        posture = (
            f"{client} shows a relatively strong security posture for a small or medium organisation. "
            "Remaining items are mostly hardening and hygiene rather than open emergency risk."
        )
    elif score >= 70:
        posture = (
            f"{client} has a workable baseline, but several issues should be fixed soon to reduce "
            "the chance of a successful attack or ransomware incident."
        )
    elif score >= 50:
        posture = (
            f"{client} has meaningful gaps. Attackers scanning the internet or an internal network "
            "could find and abuse weak points. Prioritise the Immediate and This Week items below."
        )
    else:
        posture = (
            f"{client} currently has serious exposure. Critical or high-severity issues should be "
            "treated as urgent. Do not wait for a convenient maintenance window if systems are "
            "reachable from the internet."
        )

    counts_line = (
        f"This assessment scored **{score}/100 (Grade {grade})** with "
        f"{crit} critical, {high} high, and {med} medium findings"
    )
    if asset_count:
        counts_line += f" across {asset_count} asset(s) in scope."
    else:
        counts_line += "."

    next_steps = (
        "Focus first on anything labelled Immediate (usually internet-exposed admin services, "
        "weak remote access, or leaked files). Then schedule This Week items such as missing "
        "patches, weak SSH settings, and important web security headers. TrinTech can support "
        "remediation and ongoing monitoring through Sentinel and Mirage after this audit."
    )

    return f"{counts_line} {posture} {next_steps}"


def apply_scoring(audit_data: dict) -> dict:
    findings = collect_all_findings(audit_data)
    score, counts = compute_score(findings)
    grade = grade_from_score(score)
    roadmap = build_remediation_roadmap(findings)

    client = (audit_data.get("audit_metadata") or {}).get("client_name") or "The organisation"
    asset_count = (audit_data.get("inventory") or {}).get("asset_count") or 0
    summary = _executive_summary(client, score, grade, counts, asset_count)

    audit_data["final_report"] = {
        "executive_summary": summary,
        "risk_score": score,
        "grade": grade,
        "severity_counts": counts,
        "estimated_financial_impact": "",
        "remediation_plan": roadmap[:50],
        "findings_total": len(findings),
        "audience_note": (
            "Written for business owners and managers in Trinidad & Tobago and the Caribbean. "
            "Technical detail is available in module outputs and the evidence pack."
        ),
    }
    audit_data["scoring"] = {
        "score": score,
        "grade": grade,
        "severity_counts": counts,
        "roadmap_items": len(roadmap),
    }
    print(
        f"[SCORING] Score {score}/100 Grade {grade} | "
        f"{len(findings)} findings | {len(roadmap)} roadmap items"
    )
    return audit_data
