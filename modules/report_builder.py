#!/usr/bin/env python3
"""
ReportGenius - Professional Client Deliverable Engine (v3)
Generates HTML + PDF executive reports and prioritized CSV remediation plans.
TrinTech Digital Defense
"""

import json
import os
import datetime
from pathlib import Path
from typing import List, Dict, Any
from jinja2 import Template

try:
    from fpdf import FPDF
    HAS_FPDF = True
except ImportError:
    HAS_FPDF = False


# ─────────────────────────────────────────────────────────────
# Stronger remediation templates
# ─────────────────────────────────────────────────────────────

PORT_REMEDIATION = {
    "3389": "Disable public RDP. Place behind VPN or zero-trust access. Enable NLA and account lockout. Prefer Azure AD / RD Gateway if remote access is required.",
    "445": "Never expose SMB (445) to the internet. Block at the perimeter firewall. Use VPN for any legitimate file-share access.",
    "135": "Block RPC endpoint mapper (135) from the internet. This is a common lateral-movement and exploit path.",
    "139": "Block NetBIOS (139) at the perimeter. Legacy protocol with no place on the public internet.",
    "22": "Restrict SSH to known administrative IP ranges or require VPN + key-based auth only. Disable password authentication.",
    "23": "Telnet is cleartext and obsolete. Disable the service completely and replace with SSH.",
    "21": "FTP is cleartext. Replace with SFTP/FTPS and restrict access.",
    "3306": "Do not expose MySQL/MariaDB to the internet. Bind to localhost or private network only; use SSH tunnel or VPN.",
    "5432": "Do not expose PostgreSQL to the internet. Restrict to private network / VPN.",
    "1433": "Do not expose MS SQL to the internet. Use private connectivity or VPN.",
    "5900": "VNC should never be internet-facing. Require VPN and strong authentication.",
}

DEFAULT_PORT_REMEDIATION = (
    "Restrict this port to authorized IP addresses only or place the service behind a VPN / reverse proxy with authentication. "
    "Document business justification for any remaining public exposure."
)


def _port_remediation(port: str, service: str) -> str:
    return PORT_REMEDIATION.get(str(port), DEFAULT_PORT_REMEDIATION)


def _build_findings(audit_data: dict) -> List[Dict[str, Any]]:
    """Normalize all findings into a consistent structure with strong remediation."""
    findings = []
    external = audit_data.get("external_scan", {})
    internal = audit_data.get("internal_scan", {})
    policy = audit_data.get("policy_compliance", {})
    breach = audit_data.get("breach_exposure", {})
    saas = audit_data.get("saas_posture", {})

    # External ports
    for p in external.get("open_ports", []):
        risk = p.get("risk_level", "medium")
        sev = "critical" if risk == "critical" else "high" if risk == "high" else "medium"
        host = p.get("host") or p.get("ip") or "external"
        port = str(p.get("port", "?"))
        service = p.get("service", "unknown")
        findings.append({
            "title": f"Publicly exposed service: {host}:{port} ({service})",
            "description": (
                f"The service on port {port} ({service}) is reachable from the internet. "
                f"Attackers routinely scan for and exploit exposed management and database ports."
            ),
            "remediation": _port_remediation(port, service),
            "severity": sev,
            "category": "Network Exposure",
            "effort": "2–8 hours",
        })

    # Internal high-risk ports (sample)
    for p in internal.get("open_ports", [])[:12]:
        risk = p.get("risk_level", "medium")
        if risk not in ("critical", "high"):
            continue
        sev = "critical" if risk == "critical" else "high"
        findings.append({
            "title": f"Internal high-risk service: {p.get('ip')}:{p.get('port')} ({p.get('service')})",
            "description": "High-risk service detected on the internal network. Segment or harden to limit lateral movement.",
            "remediation": "Place on a restricted VLAN, apply host firewall rules, and ensure the service is patched and authenticated.",
            "severity": sev,
            "category": "Internal Network",
            "effort": "2–6 hours",
        })

    # Policy critical gaps
    for r in policy.get("responses", []):
        if not r.get("compliant") and r.get("critical"):
            findings.append({
                "title": f"{r.get('question_id')}: {r.get('question')}",
                "description": "Critical control is not in place or could not be verified during the baseline assessment.",
                "remediation": r.get("remediation", "Implement and document this control. Retain evidence of enforcement."),
                "severity": "high",
                "category": "Policy / Compliance",
                "effort": "4–16 hours",
                "evidence": r.get("evidence", ""),
            })

    # Breach exposure
    if breach.get("compromised_credentials", 0) > 0:
        findings.append({
            "title": f"Organization-related passwords found in breach data ({breach.get('compromised_credentials')} patterns)",
            "description": "Common or organization-themed passwords appear in public breach corpora. This increases credential-stuffing and password-spraying risk.",
            "remediation": "Enforce a strong password policy, block known-breached passwords (e.g. via HIBP or similar), require MFA everywhere, and force resets for any reused credentials.",
            "severity": "high" if breach.get("compromised_credentials", 0) > 5 else "medium",
            "category": "Identity",
            "effort": "4–12 hours",
        })

    # SaaS critical issues
    for f in saas.get("findings", []):
        if f.get("severity") in ("critical", "high"):
            findings.append({
                "title": f.get("title", "SaaS / Email configuration issue"),
                "description": f.get("detail", f.get("description", "")),
                "remediation": "Correct the email authentication record (SPF/DKIM/DMARC) or missing security header according to current best practice. Aim for DMARC p=reject after monitoring.",
                "severity": f.get("severity", "medium"),
                "category": "Email / SaaS",
                "effort": "1–4 hours",
            })

    # Sort critical → high → medium
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda x: order.get(x.get("severity", "medium"), 9))
    return findings


def _overall_risk(audit_data: dict) -> int:
    external = audit_data.get("external_scan", {})
    internal = audit_data.get("internal_scan", {})
    policy = audit_data.get("policy_compliance", {})
    ext = external.get("risk_score", 0)
    inte = internal.get("risk_score", 0)
    pol = policy.get("overall_compliance_percentage", 100)
    return min(100, int(ext * 0.45 + inte * 0.25 + (100 - pol) * 0.30))


# ─────────────────────────────────────────────────────────────
# HTML Report
# ─────────────────────────────────────────────────────────────

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>FortifyOne Audit Report – {{ client_name }}</title>
<style>
body{font-family:Segoe UI,system-ui,sans-serif;margin:0;padding:24px;background:#0a0e27;color:#e0e6ed;line-height:1.55}
.container{max-width:980px;margin:0 auto}
.header{text-align:center;padding:28px;background:linear-gradient(135deg,#1a1f3a,#0d1126);border-radius:12px;margin-bottom:22px;border:1px solid #2d3561}
.header h1{color:#00d4ff;margin:0 0 6px;font-size:1.75em}
.tagline{color:#8892b0;font-size:.92em}
.roe{background:#1a1f3a;border-left:4px solid #ffa502;padding:14px 18px;border-radius:8px;margin-bottom:22px;font-size:.9em}
.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:26px}
.metric{background:#1a1f3a;padding:16px;border-radius:10px;text-align:center;border-left:4px solid #00d4ff}
.metric.crit{border-left-color:#ff4757}.metric.warn{border-left-color:#ffa502}
.metric .val{font-size:1.9em;font-weight:700;color:#00d4ff}
.metric .lbl{color:#8892b0;font-size:.78em;text-transform:uppercase;margin-top:3px}
h2{color:#00d4ff;margin-top:30px;border-bottom:1px solid #2d3561;padding-bottom:7px;font-size:1.2em}
.finding{background:#1a1f3a;padding:15px;border-radius:8px;margin-bottom:11px;border-left:4px solid #ff4757}
.finding.high{border-left-color:#ff6b6b}.finding.medium{border-left-color:#ffa502}.finding.low{border-left-color:#2ed573}
.finding h3{margin:0 0 6px;color:#fff;font-size:1.02em}
.finding p{margin:3px 0;color:#8892b0;font-size:.9em}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.72em;font-weight:600;text-transform:uppercase}
.badge.critical{background:#ff4757;color:#fff}.badge.high{background:#ff6b6b;color:#fff}
.badge.medium{background:#ffa502;color:#1a1f3a}.badge.low{background:#2ed573;color:#0a0e27}
.footer{text-align:center;color:#8892b0;margin-top:42px;font-size:.78em;border-top:1px solid #2d3561;padding-top:14px}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>🛡️ FortifyOne Security Assessment</h1>
    <p class="tagline">{{ client_name }} &nbsp;|&nbsp; {{ date }} &nbsp;|&nbsp; TrinTech Digital Defense</p>
    <p class="tagline">Framework v{{ version }}</p>
  </div>

  {% if roe_text %}
  <div class="roe">
    <strong>Rules of Engagement / Scope</strong><br>{{ roe_text }}
    {% if authorized_by %}<br><em>Authorized by: {{ authorized_by }}</em>{% endif %}
  </div>
  {% endif %}

  <div class="metrics">
    <div class="metric {% if overall_risk > 70 %}crit{% elif overall_risk > 40 %}warn{% endif %}">
      <div class="val">{{ overall_risk }}</div><div class="lbl">Overall Risk</div>
    </div>
    <div class="metric"><div class="val">{{ external_ports }}</div><div class="lbl">External Ports</div></div>
    <div class="metric"><div class="val">{{ compliance }}%</div><div class="lbl">Policy Compliance</div></div>
    <div class="metric"><div class="val">{{ breach_count }}</div><div class="lbl">Credential Hits</div></div>
    <div class="metric"><div class="val">{{ internal_hosts }}</div><div class="lbl">Internal Hosts</div></div>
    <div class="metric"><div class="val">{{ saas_grade }}</div><div class="lbl">SaaS Grade</div></div>
  </div>

  <h2>Prioritized Findings</h2>
  {% if findings %}
    {% for f in findings %}
    <div class="finding {{ f.severity }}">
      <h3><span class="badge {{ f.severity }}">{{ f.severity }}</span> &nbsp; {{ f.title }}</h3>
      <p>{{ f.description }}</p>
      <p><strong>Remediation:</strong> {{ f.remediation }}</p>
      <p><strong>Category:</strong> {{ f.category }} &nbsp;|&nbsp; <strong>Est. Effort:</strong> {{ f.effort }}</p>
    </div>
    {% endfor %}
  {% else %}
    <p style="color:#8892b0">No high-priority findings recorded in this assessment.</p>
  {% endif %}

  <div class="footer">
    Generated by FortifyOne | TrinTech Digital Defense | {{ generation_date }}<br>
    Confidential – intended solely for the named client. Authorized use only.
  </div>
</div>
</body>
</html>
"""


def generate_executive_report(audit_data: dict, output_dir: str) -> str:
    """Generate professional HTML executive report."""
    meta = audit_data.get("audit_metadata", {})
    client_name = meta.get("client_name", "Client")
    scope = audit_data.get("scope", {})
    findings = _build_findings(audit_data)
    overall = _overall_risk(audit_data)

    external = audit_data.get("external_scan", {})
    internal = audit_data.get("internal_scan", {})
    policy = audit_data.get("policy_compliance", {})
    breach = audit_data.get("breach_exposure", {})
    saas = audit_data.get("saas_posture", {})

    html = Template(HTML_TEMPLATE).render(
        client_name=client_name,
        date=str(meta.get("date", ""))[:10],
        version=meta.get("framework_version", "4.4"),
        overall_risk=overall,
        external_ports=len(external.get("open_ports", [])),
        compliance=round(policy.get("overall_compliance_percentage", 0)),
        breach_count=breach.get("compromised_credentials", 0),
        internal_hosts=internal.get("hosts_discovered", 0),
        saas_grade=saas.get("score_grade", "N/A"),
        findings=findings[:20],
        roe_text=scope.get("roe_text", ""),
        authorized_by=scope.get("authorized_by", ""),
        generation_date=datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
    )

    safe = client_name.replace(" ", "_")
    path = os.path.join(output_dir, f"{safe}_Executive_Report.html")
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    return path


# ─────────────────────────────────────────────────────────────
# PDF Report (fpdf2)
# ─────────────────────────────────────────────────────────────

class AuditPDF(FPDF):
    def header(self):
        self.set_font("Helvetica", "B", 11)
        self.set_text_color(0, 100, 140)
        self.cell(0, 8, "FortifyOne Security Assessment – TrinTech Digital Defense", ln=True)
        self.set_draw_color(0, 150, 200)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(4)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(120, 120, 120)
        self.cell(0, 8, f"Confidential | Page {self.page_no()}/{{nb}} | Authorized use only", align="C")


def generate_pdf_report(audit_data: dict, output_dir: str) -> str:
    """Generate a clean professional PDF. Returns path or empty string if fpdf2 missing."""
    if not HAS_FPDF:
        print("[REPORT] fpdf2 not installed – skipping PDF generation")
        return ""

    meta = audit_data.get("audit_metadata", {})
    client_name = meta.get("client_name", "Client")
    scope = audit_data.get("scope", {})
    findings = _build_findings(audit_data)
    overall = _overall_risk(audit_data)
    external = audit_data.get("external_scan", {})
    policy = audit_data.get("policy_compliance", {})
    breach = audit_data.get("breach_exposure", {})
    internal = audit_data.get("internal_scan", {})
    saas = audit_data.get("saas_posture", {})

    pdf = AuditPDF()
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_page()

    # Title
    pdf.set_font("Helvetica", "B", 18)
    pdf.set_text_color(0, 80, 120)
    pdf.cell(0, 10, "Security Assessment Report", ln=True)
    pdf.set_font("Helvetica", "", 12)
    pdf.set_text_color(40, 40, 40)
    pdf.cell(0, 7, f"Client: {client_name}", ln=True)
    pdf.cell(0, 7, f"Date: {str(meta.get('date', ''))[:10]}   |   Framework: v{meta.get('framework_version', '4.4')}", ln=True)
    pdf.ln(3)

    # ROE
    if scope.get("roe_text"):
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(0, 6, "Rules of Engagement / Scope", ln=True)
        pdf.set_font("Helvetica", "", 9)
        pdf.multi_cell(0, 5, scope.get("roe_text", ""))
        if scope.get("authorized_by"):
            pdf.cell(0, 5, f"Authorized by: {scope.get('authorized_by')}", ln=True)
        pdf.ln(3)

    # Metrics
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(0, 6, "Executive Summary Metrics", ln=True)
    pdf.set_font("Helvetica", "", 9)
    pdf.cell(0, 5, f"Overall Risk Score: {overall}/100", ln=True)
    pdf.cell(0, 5, f"External open ports: {len(external.get('open_ports', []))}   |   Internal hosts discovered: {internal.get('hosts_discovered', 0)}", ln=True)
    pdf.cell(0, 5, f"Policy compliance: {policy.get('overall_compliance_percentage', 0):.0f}%   |   Credential exposure hits: {breach.get('compromised_credentials', 0)}", ln=True)
    pdf.cell(0, 5, f"SaaS / Email grade: {saas.get('score_grade', 'N/A')}", ln=True)
    pdf.ln(4)

    # Findings
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 7, "Prioritized Findings & Remediation", ln=True)
    pdf.ln(1)

    if not findings:
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(0, 5, "No high-priority findings recorded in this assessment.", ln=True)
    else:
        for i, f in enumerate(findings[:18], 1):
            sev = f.get("severity", "medium").upper()
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_text_color(180, 40, 40) if sev == "CRITICAL" else pdf.set_text_color(40, 40, 40)
            pdf.multi_cell(0, 5, f"{i}. [{sev}] {f.get('title', '')}")
            pdf.set_text_color(40, 40, 40)
            pdf.set_font("Helvetica", "", 8)
            pdf.multi_cell(0, 4, f.get("description", ""))
            pdf.set_font("Helvetica", "I", 8)
            pdf.multi_cell(0, 4, f"Remediation: {f.get('remediation', '')}")
            pdf.set_font("Helvetica", "", 8)
            pdf.cell(0, 4, f"Category: {f.get('category', '')}  |  Est. Effort: {f.get('effort', 'TBD')}", ln=True)
            pdf.ln(2)

    # Closing
    pdf.ln(4)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(100, 100, 100)
    pdf.multi_cell(0, 4, "This report is confidential and intended solely for the named client. "
                   "Assessments were performed under agreed Rules of Engagement. "
                   "TrinTech Digital Defense – Securing Your Digital World.")

    safe = client_name.replace(" ", "_")
    path = os.path.join(output_dir, f"{safe}_Executive_Report.pdf")
    pdf.output(path)
    return path


def generate_remediation_plan(audit_data: dict, output_dir: str) -> str:
    """Prioritized CSV remediation plan with strong language."""
    meta = audit_data.get("audit_metadata", {})
    client_name = meta.get("client_name", "Client")
    findings = _build_findings(audit_data)

    safe = client_name.replace(" ", "_")
    path = os.path.join(output_dir, f"{safe}_Remediation_Plan.csv")

    with open(path, "w", encoding="utf-8") as f:
        f.write("Priority,Severity,Finding,Category,Estimated Effort,Status,Remediation\n")
        for i, item in enumerate(findings, 1):
            title = item.get("title", "").replace('"', "'")
            rem = item.get("remediation", "").replace('"', "'")
            f.write(
                f'{i},{item.get("severity", "medium").capitalize()},"{title}",'
                f'{item.get("category", "")},{item.get("effort", "TBD")},Not Started,"{rem}"\n'
            )
    return path


if __name__ == "__main__":
    print("ReportGenius v3 ready – HTML + PDF + CSV")
