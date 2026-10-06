#!/usr/bin/env python3
"""
Scoring - Unified security score + remediation urgency
Absorbed language from trin-tech-audit style client scoring.
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
                    "host": it.get("host") or "",
                    "controls": it.get("controls") or [],
                })
            elif isinstance(it, str) and it.strip():
                out.append({
                    "source": section,
                    "title": it[:100],
                    "severity": "medium",
                    "detail": it,
                    "remediation": "",
                    "host": "",
                    "controls": [],
                })
    return out


def compute_score(findings: List[Dict[str, Any]]) -> Tuple[int, Dict[str, int]]:
    """trin-tech-audit style: 100 - (crit*25 + high*12 + med*5 + low*2)."""
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


def build_remediation_roadmap(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    roadmap = []
    order = {"Immediate": 0, "This Week": 1, "This Month": 2, "Ongoing": 3}
    for f in findings:
        if f.get("severity") in ("info",):
            continue
        roadmap.append({
            "urgency": urgency_bucket(f.get("severity", "low")),
            "title": f.get("title"),
            "severity": f.get("severity"),
            "what_it_means": f.get("detail") or f.get("title"),
            "what_to_do": f.get("remediation") or "Review and remediate according to policy.",
            "source": f.get("source"),
            "controls": f.get("controls") or [],
        })
    roadmap.sort(key=lambda x: order.get(x["urgency"], 9))
    return roadmap


def apply_scoring(audit_data: dict) -> dict:
    findings = collect_all_findings(audit_data)
    score, counts = compute_score(findings)
    grade = grade_from_score(score)
    roadmap = build_remediation_roadmap(findings)

    audit_data["final_report"] = {
        "executive_summary": (
            f"Overall security score {score}/100 (Grade {grade}). "
            f"Findings: {counts['critical']} critical, {counts['high']} high, "
            f"{counts['medium']} medium, {counts['low']} low."
        ),
        "risk_score": score,
        "grade": grade,
        "severity_counts": counts,
        "estimated_financial_impact": "",
        "remediation_plan": roadmap[:40],
        "findings_total": len(findings),
    }
    # Also store under scoring for clarity
    audit_data["scoring"] = {
        "score": score,
        "grade": grade,
        "severity_counts": counts,
        "roadmap_items": len(roadmap),
    }
    print(f"[SCORING] Score {score}/100 Grade {grade} | {len(findings)} findings | {len(roadmap)} roadmap items")
    return audit_data
