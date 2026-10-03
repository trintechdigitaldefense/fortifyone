#!/usr/bin/env python3
"""
PolicyEngine - Compliance Evaluator (v3)
TrinTech Digital Defense

Industry-aware compliance baseline with evidence-to-control linkage.
Maps findings and questionnaire answers to NIST CSF, CIS Controls v8,
HIPAA, and high-level ISO 27001 / PCI-DSS indicators.
"""

from __future__ import annotations

import datetime
from typing import Any, Dict, List, Optional

# Core questions applicable to all industries
CORE_QUESTIONS = [
    {
        "id": "POL-001",
        "question": "Acceptable Use Policy (AUP) exists and is signed by all staff?",
        "critical": True,
        "frameworks": ["CIS", "NIST", "ISO27001"],
        "controls": ["PR.AT-1", "CIS-14.1", "A.8.1.3"],
        "default": False,
        "remediation": "Draft and enforce a written Acceptable Use Policy. Require annual acknowledgment.",
    },
    {
        "id": "POL-002",
        "question": "Multi-Factor Authentication (MFA) enforced for all remote access and privileged accounts?",
        "critical": True,
        "frameworks": ["CIS", "NIST", "HIPAA", "PCI"],
        "controls": ["PR.AC-7", "CIS-6.3", "A.9.4.2"],
        "default": False,
        "remediation": "Enable MFA on all VPN, RDP, email, and admin accounts. Prefer authenticator apps or hardware keys.",
    },
    {
        "id": "POL-003",
        "question": "Incident Response Plan exists, is documented, and has been tested in the last 12 months?",
        "critical": True,
        "frameworks": ["CIS", "NIST", "HIPAA", "ISO27001"],
        "controls": ["RS.RP-1", "CIS-17.1", "A.16.1.1"],
        "default": False,
        "remediation": "Create a written IR plan covering detection, containment, eradication, recovery, and lessons learned. Run a tabletop exercise annually.",
    },
    {
        "id": "POL-004",
        "question": "Automated patch management is active for operating systems and critical applications?",
        "critical": True,
        "frameworks": ["CIS", "NIST", "PCI"],
        "controls": ["PR.IP-1", "CIS-7.1", "A.12.6.1"],
        "default": False,
        "remediation": "Deploy centralized patch management (WSUS, Intune, or equivalent). Critical patches within 14 days.",
    },
    {
        "id": "POL-005",
        "question": "Regular offsite / cloud backups are performed and restore tests are conducted?",
        "critical": True,
        "frameworks": ["CIS", "NIST", "HIPAA", "ISO27001"],
        "controls": ["PR.IP-4", "CIS-11.1", "A.12.3.1"],
        "default": False,
        "remediation": "Implement 3-2-1 backup rule. Test restores quarterly. Encrypt backups.",
    },
    {
        "id": "POL-006",
        "question": "Endpoint protection (AV/EDR) is installed and up to date on all workstations and servers?",
        "critical": True,
        "frameworks": ["CIS", "NIST", "PCI"],
        "controls": ["PR.PT-1", "CIS-10.1", "A.12.2.1"],
        "default": False,
        "remediation": "Deploy modern EDR/antivirus with central management and automatic updates.",
    },
    {
        "id": "POL-007",
        "question": "User accounts are reviewed and disabled promptly when staff leave?",
        "critical": False,
        "frameworks": ["CIS", "NIST", "HIPAA", "ISO27001"],
        "controls": ["PR.AC-1", "CIS-5.3", "A.9.2.6"],
        "default": False,
        "remediation": "Implement a formal offboarding checklist. Disable accounts within 24 hours of termination.",
    },
    {
        "id": "POL-008",
        "question": "Privileged accounts are limited and use unique credentials (no shared admin passwords)?",
        "critical": True,
        "frameworks": ["CIS", "NIST", "PCI", "ISO27001"],
        "controls": ["PR.AC-4", "CIS-5.4", "A.9.2.3"],
        "default": False,
        "remediation": "Eliminate shared admin accounts. Use individual privileged accounts + MFA + just-in-time elevation where possible.",
    },
    {
        "id": "POL-009",
        "question": "Email authentication (SPF, DKIM, DMARC) is correctly configured?",
        "critical": True,
        "frameworks": ["CIS", "NIST"],
        "controls": ["PR.DS-2", "CIS-9.1"],
        "default": False,
        "remediation": "Publish SPF, enable DKIM signing, and set DMARC policy to quarantine/reject.",
    },
    {
        "id": "POL-010",
        "question": "Security awareness training is delivered at least annually?",
        "critical": False,
        "frameworks": ["CIS", "NIST", "HIPAA", "ISO27001"],
        "controls": ["PR.AT-1", "CIS-14.2", "A.7.2.2"],
        "default": False,
        "remediation": "Deliver annual (or more frequent) security awareness training covering phishing, passwords, and data handling.",
    },
]

INDUSTRY_EXTRA = {
    "Healthcare": [
        {
            "id": "HIP-001",
            "question": "Business Associate Agreements (BAAs) are in place with all vendors handling ePHI?",
            "critical": True,
            "frameworks": ["HIPAA"],
            "controls": ["HIPAA-164.308"],
            "default": False,
            "remediation": "Execute BAAs with every vendor that creates, receives, maintains, or transmits ePHI.",
        },
        {
            "id": "HIP-002",
            "question": "Access to ePHI is logged and access logs are reviewed periodically?",
            "critical": True,
            "frameworks": ["HIPAA", "NIST"],
            "controls": ["HIPAA-164.312", "PR.PT-1"],
            "default": False,
            "remediation": "Enable audit logging for systems containing ePHI and review logs at defined intervals.",
        },
    ],
    "Finance": [
        {
            "id": "FIN-001",
            "question": "Cardholder data environment (CDE) is segmented and access is strictly controlled?",
            "critical": True,
            "frameworks": ["PCI", "NIST"],
            "controls": ["PCI-1.1", "PR.AC-3"],
            "default": False,
            "remediation": "Segment the CDE; restrict access on a need-to-know basis; monitor all CDE access.",
        },
    ],
    "Technology": [],
    "General": [],
}


def _collect_evidence_links(audit_data: dict) -> List[Dict[str, Any]]:
    """Map technical findings from other modules to control IDs."""
    links: List[Dict[str, Any]] = []

    def add(finding: dict, source: str):
        controls = finding.get("controls") or []
        if not controls and finding.get("category"):
            # Heuristic mapping
            cat = (finding.get("category") or "").lower()
            if "ssh" in cat or "credential" in cat or "privilege" in cat:
                controls = ["PR.AC-3", "PR.AC-4", "CIS-5.1"]
            elif "tls" in cat or "ssl" in cat or "http" in cat:
                controls = ["PR.DS-2", "CIS-3.1"]
            elif "patch" in cat:
                controls = ["PR.IP-1", "CIS-7.1"]
            elif "network" in cat or "firewall" in cat:
                controls = ["PR.AC-3", "CIS-5.1"]
            elif "email" in cat or "saas" in cat:
                controls = ["PR.DS-2", "CIS-9.1"]
        if controls:
            links.append({
                "source": source,
                "title": finding.get("title") or finding.get("detail", "")[:80],
                "severity": finding.get("severity", "info"),
                "controls": controls,
                "host": finding.get("host"),
            })

    for section, key in [
        ("external_scan", "vulnerabilities"),
        ("vuln_probe", "findings"),
        ("web_probe", "findings"),
        ("tls_posture", "findings"),
        ("local_hardening", "findings"),
        ("credentialed_scan", "findings"),
        ("saas_posture", "findings"),
        ("breach_exposure", "findings"),
    ]:
        data = audit_data.get(section, {})
        items = data.get(key) or data.get("findings") or []
        if isinstance(items, list):
            for it in items:
                if isinstance(it, dict):
                    add(it, section)
                elif isinstance(it, str) and it.startswith("["):
                    # Simple string findings
                    links.append({
                        "source": section,
                        "title": it[:100],
                        "severity": "medium",
                        "controls": ["PR.IP-1"],
                    })

    return links


def run_questionnaire(audit_data: dict, answers: Optional[Dict[str, bool]] = None) -> dict:
    """
    Evaluate compliance baseline.
    If answers is None, use defaults (all False) for a conservative gap analysis
    or pull from existing policy_compliance.responses if present.
    Also builds evidence-to-control linkage from technical modules.
    """
    industry = (audit_data.get("audit_metadata", {}).get("industry") or "General").strip()
    questions = list(CORE_QUESTIONS)
    questions.extend(INDUSTRY_EXTRA.get(industry, []))

    # Existing answers
    existing = {}
    prev = audit_data.get("policy_compliance", {}).get("responses") or []
    for r in prev:
        if isinstance(r, dict) and "id" in r:
            existing[r["id"]] = bool(r.get("compliant") or r.get("answer"))

    if answers:
        existing.update(answers)

    responses = []
    critical_gaps = []
    framework_gaps: Dict[str, List[str]] = {}
    control_coverage: Dict[str, List[str]] = {}  # control_id -> list of evidence titles

    for q in questions:
        qid = q["id"]
        compliant = existing.get(qid, q.get("default", False))
        responses.append({
            "id": qid,
            "question": q["question"],
            "compliant": compliant,
            "critical": q.get("critical", False),
            "frameworks": q.get("frameworks", []),
            "controls": q.get("controls", []),
            "remediation": q.get("remediation", ""),
        })
        if not compliant:
            if q.get("critical"):
                critical_gaps.append(qid)
            for fw in q.get("frameworks", []):
                framework_gaps.setdefault(fw, []).append(qid)
            for c in q.get("controls", []):
                control_coverage.setdefault(c, []).append(f"GAP:{qid}")

    # Evidence linkage from technical findings
    evidence_links = _collect_evidence_links(audit_data)
    for link in evidence_links:
        for c in link.get("controls", []):
            control_coverage.setdefault(c, []).append(
                f"{link.get('source')}:{link.get('title', '')[:60]}"
            )

    total = len(responses)
    compliant_count = sum(1 for r in responses if r["compliant"])
    pct = (compliant_count / total * 100) if total else 0

    audit_data["policy_compliance"] = {
        "responses": responses,
        "overall_compliance_percentage": round(pct, 1),
        "total_controls": total,
        "compliant_controls": compliant_count,
        "critical_gaps": critical_gaps,
        "framework_gaps": framework_gaps,
        "control_evidence": control_coverage,
        "evidence_links": evidence_links,
        "industry": industry,
        "timestamp": datetime.datetime.now().isoformat(),
        "notes": "Evidence-to-control linkage auto-generated from technical modules + questionnaire.",
    }

    print(f"[POLICYENGINE] Evaluating {total} controls for industry: {industry}")
    print(f"[POLICYENGINE] Complete: {pct:.0f}% compliance | {len(critical_gaps)} critical gaps | {len(evidence_links)} evidence links")
    return audit_data


if __name__ == "__main__":
    print(run_questionnaire({"audit_metadata": {"industry": "Technology"}}).get("policy_compliance", {}).get("overall_compliance_percentage"))
