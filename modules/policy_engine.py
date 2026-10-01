#!/usr/bin/env python3
"""
PolicyEngine - Compliance Evaluator (v2)
TrinTech Digital Defense

Industry-aware compliance baseline with evidence support.
Maps to NIST CSF, CIS Controls v8, and HIPAA where relevant.
"""

import datetime
from typing import Dict, List, Any

# Core questions applicable to all industries
CORE_QUESTIONS = [
    {
        "id": "POL-001",
        "question": "Acceptable Use Policy (AUP) exists and is signed by all staff?",
        "critical": True,
        "frameworks": ["CIS", "NIST"],
        "default": False,
        "remediation": "Draft and enforce a written Acceptable Use Policy. Require annual acknowledgment."
    },
    {
        "id": "POL-002",
        "question": "Multi-Factor Authentication (MFA) enforced for all remote access and privileged accounts?",
        "critical": True,
        "frameworks": ["CIS", "NIST", "HIPAA"],
        "default": False,
        "remediation": "Enable MFA on all VPN, RDP, email, and admin accounts. Prefer authenticator apps or hardware keys."
    },
    {
        "id": "POL-003",
        "question": "Incident Response Plan exists, is documented, and has been tested in the last 12 months?",
        "critical": True,
        "frameworks": ["CIS", "NIST", "HIPAA"],
        "default": False,
        "remediation": "Create a written IR plan covering detection, containment, eradication, recovery, and lessons learned. Run a tabletop exercise annually."
    },
    {
        "id": "POL-004",
        "question": "Automated patch management is active for operating systems and critical applications?",
        "critical": True,
        "frameworks": ["CIS", "NIST"],
        "default": False,
        "remediation": "Deploy centralized patch management (WSUS, Intune, or equivalent). Critical patches within 14 days."
    },
    {
        "id": "POL-005",
        "question": "Regular offsite / cloud backups are performed and restore tests are conducted?",
        "critical": True,
        "frameworks": ["CIS", "NIST", "HIPAA"],
        "default": False,
        "remediation": "Implement 3-2-1 backup rule. Test restores quarterly. Encrypt backups."
    },
    {
        "id": "POL-006",
        "question": "Endpoint protection (AV/EDR) is installed and up to date on all workstations and servers?",
        "critical": True,
        "frameworks": ["CIS", "NIST"],
        "default": False,
        "remediation": "Deploy modern EDR/antivirus with central management and automatic updates."
    },
    {
        "id": "POL-007",
        "question": "User accounts are reviewed and disabled promptly when staff leave?",
        "critical": False,
        "frameworks": ["CIS", "NIST", "HIPAA"],
        "default": False,
        "remediation": "Implement a formal offboarding checklist. Disable accounts within 24 hours of termination."
    },
    {
        "id": "POL-008",
        "question": "Privileged accounts are limited and use unique credentials (no shared admin passwords)?",
        "critical": True,
        "frameworks": ["CIS", "NIST"],
        "default": False,
        "remediation": "Eliminate shared admin accounts. Use individual privileged accounts + MFA + just-in-time elevation where possible."
    },
]

# Industry-specific additional questions
INDUSTRY_QUESTIONS = {
    "Healthcare": [
        {
            "id": "HIPAA-001",
            "question": "Business Associate Agreements (BAAs) are in place with all vendors that handle PHI?",
            "critical": True,
            "frameworks": ["HIPAA"],
            "default": False,
            "remediation": "Inventory all vendors touching ePHI and execute current BAAs."
        },
        {
            "id": "HIPAA-002",
            "question": "Risk analysis under HIPAA Security Rule has been completed and documented?",
            "critical": True,
            "frameworks": ["HIPAA"],
            "default": False,
            "remediation": "Conduct and document a formal risk analysis covering all ePHI systems."
        },
        {
            "id": "HIPAA-003",
            "question": "Access to ePHI is logged and audited periodically?",
            "critical": False,
            "frameworks": ["HIPAA"],
            "default": False,
            "remediation": "Enable audit logging on EHR and file shares containing PHI. Review logs monthly."
        },
    ],
    "Finance": [
        {
            "id": "FIN-001",
            "question": "Encryption is enforced for data at rest and in transit for sensitive financial data?",
            "critical": True,
            "frameworks": ["CIS", "NIST"],
            "default": False,
            "remediation": "Enable full-disk encryption and TLS 1.2+ for all financial systems and file transfers."
        },
        {
            "id": "FIN-002",
            "question": "Segregation of duties is enforced for financial transactions and system administration?",
            "critical": True,
            "frameworks": ["CIS", "NIST"],
            "default": False,
            "remediation": "Ensure no single person can both initiate and approve high-value transactions or changes."
        },
    ],
    "Legal": [
        {
            "id": "LEG-001",
            "question": "Client confidentiality and data handling procedures are documented and trained?",
            "critical": True,
            "frameworks": ["CIS", "NIST"],
            "default": False,
            "remediation": "Create written client data handling policy and train all staff annually."
        },
    ],
    "Retail": [
        {
            "id": "RET-001",
            "question": "Payment systems / POS are segmented from the rest of the network?",
            "critical": True,
            "frameworks": ["CIS", "NIST"],
            "default": False,
            "remediation": "Isolate POS systems on a separate VLAN with restricted outbound access."
        },
    ],
}


def get_questions_for_industry(industry: str) -> List[Dict[str, Any]]:
    """Return core + industry-specific questions."""
    questions = list(CORE_QUESTIONS)
    industry_key = industry.strip().title() if industry else "General"
    # Fuzzy match common names
    if industry_key in ("Health", "Medical", "Healthcare"):
        industry_key = "Healthcare"
    elif industry_key in ("Banking", "Finance", "Financial"):
        industry_key = "Finance"
    elif industry_key in ("Law", "Legal"):
        industry_key = "Legal"
    elif industry_key in ("Retail", "Ecommerce", "Shop"):
        industry_key = "Retail"

    extra = INDUSTRY_QUESTIONS.get(industry_key, [])
    questions.extend(extra)
    return questions


def run_questionnaire(audit_data: dict, interactive: bool = False) -> dict:
    """
    Run compliance questionnaire.

    interactive=False (default): uses conservative defaults (mostly non-compliant)
    interactive=True: would prompt (currently still non-interactive for automation safety)
    """
    industry = audit_data.get("audit_metadata", {}).get("industry", "General")
    client = audit_data.get("audit_metadata", {}).get("client_name", "Client")

    questions = get_questions_for_industry(industry)
    responses = []
    yes_count = 0
    critical_gaps = []
    framework_gaps = {"CIS": 0, "NIST": 0, "HIPAA": 0}

    print(f"[POLICYENGINE] Evaluating {len(questions)} controls for industry: {industry}")

    for q in questions:
        # Conservative default: assume non-compliant unless explicitly set
        compliant = q.get("default", False)

        # In a future interactive mode we could prompt here.
        # For now we stay non-interactive and honest about the baseline.

        response = {
            "question_id": q["id"],
            "question": q["question"],
            "compliant": compliant,
            "critical": q.get("critical", False),
            "frameworks": q.get("frameworks", []),
            "evidence": "Automated baseline assessment – manual verification required",
            "remediation": q.get("remediation", "Review and remediate this control."),
        }
        responses.append(response)

        if compliant:
            yes_count += 1
        else:
            if q.get("critical"):
                critical_gaps.append(q["id"])
            for fw in q.get("frameworks", []):
                if fw in framework_gaps:
                    framework_gaps[fw] += 1

    total = len(questions)
    percentage = (yes_count / total * 100) if total > 0 else 0

    # Risk adjustment: heavy penalty for critical gaps
    if critical_gaps:
        percentage = max(0, percentage - (len(critical_gaps) * 8))

    audit_data["policy_compliance"] = {
        "responses": responses,
        "overall_compliance_percentage": round(percentage, 1),
        "total_controls": total,
        "compliant_controls": yes_count,
        "critical_gaps": critical_gaps,
        "framework_gaps": framework_gaps,
        "industry": industry,
        "timestamp": datetime.datetime.now().isoformat(),
        "notes": "Baseline assessment only. All critical controls require manual verification and evidence collection during the engagement."
    }

    print(f"[POLICYENGINE] Complete: {percentage:.0f}% compliance | {len(critical_gaps)} critical gaps\n")
    return audit_data


if __name__ == "__main__":
    test = {
        "audit_metadata": {"client_name": "Test Clinic", "industry": "Healthcare"},
        "policy_compliance": {}
    }
    result = run_questionnaire(test)
    print(f"Score: {result['policy_compliance']['overall_compliance_percentage']}%")
    print(f"Critical gaps: {result['policy_compliance']['critical_gaps']}")
