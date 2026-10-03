#!/usr/bin/env python3
"""
ReportGenius v5.3 – Stronger branded multi-page PDF, engagement letter, HTML, CSV
TrinTech Digital Defense
"""
import os
import datetime
from typing import List, Dict, Any
from jinja2 import Template

try:
    from fpdf import FPDF
    HAS_FPDF = True
except ImportError:
    HAS_FPDF = False

PORT_REMEDIATION = {
    "3389": "Disable public RDP. Use VPN/zero-trust. Enable NLA and lockout.",
    "445": "Never expose SMB to the internet. Block at perimeter.",
    "135": "Block RPC (135) from the internet.",
    "139": "Block NetBIOS (139) at the perimeter.",
    "22": "Restrict SSH to admin IPs or VPN + keys only. Disable passwords.",
    "23": "Disable Telnet. Use SSH.",
    "21": "Replace FTP with SFTP/FTPS.",
    "3306": "Do not expose MySQL publicly.",
    "5432": "Do not expose PostgreSQL publicly.",
    "1433": "Do not expose MS SQL publicly.",
    "5900": "Do not expose VNC publicly.",
    "6379": "Do not expose Redis publicly. Require AUTH.",
    "27017": "Do not expose MongoDB publicly. Enable auth.",
    "9200": "Do not expose Elasticsearch publicly.",
}

def _port_remediation(port: str, service: str) -> str:
    return PORT_REMEDIATION.get(str(port), "Restrict to authorized IPs or place behind VPN/authenticated proxy.")

def _build_findings(audit_data: dict) -> List[Dict[str, Any]]:
    findings = []
    external = audit_data.get("external_scan", {})
    internal = audit_data.get("internal_scan", {})
    policy = audit_data.get("policy_compliance", {})
    breach = audit_data.get("breach_exposure", {})
    saas = audit_data.get("saas_posture", {})
    vuln = audit_data.get("vuln_probe", {})
    web = audit_data.get("web_probe", {})
    local = audit_data.get("local_hardening", {})
    cred = audit_data.get("credentialed_scan", {})

    for p in external.get("open_ports", []):
        risk = p.get("risk_level", "medium")
        sev = "critical" if risk == "critical" else "high" if risk == "high" else "medium"
        host = p.get("host") or p.get("ip") or "external"
        port, service = str(p.get("port", "?")), p.get("service", "unknown")
        findings.append({
            "title": f"Publicly exposed: {host}:{port} ({service})",
            "description": f"Port {port} reachable from the internet.",
            "remediation": _port_remediation(port, service),
            "severity": sev, "category": "Network Exposure", "effort": "2–8 hours",
        })

    for p in internal.get("open_ports", [])[:10]:
        if p.get("risk_level") not in ("critical", "high"):
            continue
        findings.append({
            "title": f"Internal: {p.get('ip')}:{p.get('port')} ({p.get('service')})",
            "description": "High-risk internal service.",
            "remediation": "Segment, firewall, patch, authenticate.",
            "severity": p.get("risk_level"), "category": "Internal Network", "effort": "2–6 hours",
        })

    for r in policy.get("responses", []):
        if not r.get("compliant") and r.get("critical"):
            findings.append({
                "title": f"{r.get('question_id')}: {r.get('question')}",
                "description": r.get("evidence", "Critical control not verified."),
                "remediation": r.get("remediation", "Implement and document."),
                "severity": "high", "category": "Policy", "effort": "4–16 hours",
                "evidence": r.get("evidence", ""),
            })

    if breach.get("compromised_credentials", 0) > 0:
        findings.append({
            "title": f"Breach password patterns ({breach.get('compromised_credentials')})",
            "description": "Organization-related passwords seen in breach data.",
            "remediation": "Strong policy, block breached passwords, MFA, forced resets.",
            "severity": "high", "category": "Identity", "effort": "4–12 hours",
        })

    for f in saas.get("findings", []):
        if f.get("severity") in ("critical", "high"):
            findings.append({
                "title": f.get("title", "Email/SaaS issue"),
                "description": f.get("detail", ""),
                "remediation": "Fix SPF/DKIM/DMARC; target p=reject.",
                "severity": f.get("severity"), "category": "Email / SaaS", "effort": "1–4 hours",
            })

    for f in vuln.get("findings", []):
        if f.get("severity") in ("info", "low"):
            continue
        findings.append({
            "title": f.get("title", "Vuln indicator"),
            "description": f.get("detail", ""),
            "remediation": f.get("remediation") or "Validate, patch, restrict access.",
            "severity": f.get("severity", "medium"), "category": "Vulnerability", "effort": "2–12 hours",
        })

    for f in web.get("findings", []):
        if f.get("severity") in ("info", "low", "good"):
            continue
        findings.append({
            "title": f.get("title", "Web exposure"),
            "description": f.get("detail", ""),
            "remediation": "Protect or remove exposed paths; keep CMS patched.",
            "severity": f.get("severity", "medium"), "category": "Web Application", "effort": "1–8 hours",
        })

    for f in local.get("findings", []):
        if f.get("severity") in ("info", "good", "low"):
            continue
        findings.append({
            "title": f.get("title", "Local hardening"),
            "description": f.get("detail", ""),
            "remediation": f.get("remediation", "Harden host configuration."),
            "severity": f.get("severity", "medium"), "category": "Local Host", "effort": "1–4 hours",
        })

    for f in cred.get("findings", []):
        if f.get("severity") in ("info", "good", "low"):
            continue
        findings.append({
            "title": f.get("title", "Credentialed finding"),
            "description": f.get("detail", ""),
            "remediation": f.get("remediation", "Remediate on the authenticated host."),
            "severity": f.get("severity", "medium"), "category": f.get("category", "Credentialed"), "effort": "1–8 hours",
        })

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda x: order.get(x.get("severity", "medium"), 9))
    return findings

def _overall_risk(audit_data: dict) -> int:
    ext = audit_data.get("external_scan", {}).get("risk_score", 0)
    inte = audit_data.get("internal_scan", {}).get("risk_score", 0)
    pol = audit_data.get("policy_compliance", {}).get("overall_compliance_percentage", 100)
    v = audit_data.get("vuln_probe", {}).get("risk_score", 0)
    w = audit_data.get("web_probe", {}).get("risk_score", 0)
    loc = audit_data.get("local_hardening", {}).get("risk_score", 0)
    cred = audit_data.get("credentialed_scan", {}).get("risk_score", 0)
    return min(100, int(ext * 0.25 + inte * 0.12 + v * 0.15 + w * 0.10 + loc * 0.08 + cred * 0.10 + (100 - pol) * 0.20))

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>FortifyOne – {{ client_name }}</title>
<style>
body{font-family:Segoe UI,system-ui,sans-serif;margin:0;padding:24px;background:#0a0e27;color:#e0e6ed;line-height:1.55}
.container{max-width:980px;margin:0 auto}
.header{text-align:center;padding:28px;background:linear-gradient(135deg,#1a1f3a,#0d1126);border-radius:12px;margin-bottom:22px;border:1px solid #2d3561}
.header h1{color:#00d4ff;margin:0 0 6px;font-size:1.75em}.tagline{color:#8892b0;font-size:.92em}
.roe{background:#1a1f3a;border-left:4px solid #ffa502;padding:14px 18px;border-radius:8px;margin-bottom:22px;font-size:.9em}
.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:26px}
.metric{background:#1a1f3a;padding:14px;border-radius:10px;text-align:center;border-left:4px solid #00d4ff}
.metric.crit{border-left-color:#ff4757}.metric.warn{border-left-color:#ffa502}
.metric .val{font-size:1.8em;font-weight:700;color:#00d4ff}.metric .lbl{color:#8892b0;font-size:.75em;text-transform:uppercase;margin-top:3px}
h2{color:#00d4ff;margin-top:28px;border-bottom:1px solid #2d3561;padding-bottom:7px}
.finding{background:#1a1f3a;padding:14px;border-radius:8px;margin-bottom:10px;border-left:4px solid #ff4757}
.finding.high{border-left-color:#ff6b6b}.finding.medium{border-left-color:#ffa502}
.finding h3{margin:0 0 5px;color:#fff;font-size:1em}.finding p{margin:3px 0;color:#8892b0;font-size:.88em}
.badge{display:inline-block;padding:2px 7px;border-radius:4px;font-size:.7em;font-weight:600;text-transform:uppercase}
.badge.critical{background:#ff4757;color:#fff}.badge.high{background:#ff6b6b;color:#fff}.badge.medium{background:#ffa502;color:#1a1f3a}
.footer{text-align:center;color:#8892b0;margin-top:40px;font-size:.78em;border-top:1px solid #2d3561;padding-top:14px}
</style></head><body><div class="container">
<div class="header"><h1>FortifyOne Security Assessment</h1>
<p class="tagline">{{ client_name }} | {{ date }} | TrinTech Digital Defense</p>
<p class="tagline">Framework v{{ version }}</p></div>
{% if roe_text %}<div class="roe"><strong>Rules of Engagement / Scope</strong><br>{{ roe_text }}
{% if authorized_by %}<br><em>Authorized by: {{ authorized_by }}</em>{% endif %}</div>{% endif %}
<div class="metrics">
<div class="metric {% if overall_risk > 70 %}crit{% elif overall_risk > 40 %}warn{% endif %}"><div class="val">{{ overall_risk }}</div><div class="lbl">Overall Risk</div></div>
<div class="metric"><div class="val">{{ external_ports }}</div><div class="lbl">External Ports</div></div>
<div class="metric"><div class="val">{{ compliance }}%</div><div class="lbl">Policy</div></div>
<div class="metric"><div class="val">{{ breach_count }}</div><div class="lbl">Credential Hits</div></div>
<div class="metric"><div class="val">{{ internal_hosts }}</div><div class="lbl">Internal Hosts</div></div>
<div class="metric"><div class="val">{{ saas_grade }}</div><div class="lbl">SaaS Grade</div></div>
</div>
<h2>Prioritized Findings</h2>
{% if findings %}{% for f in findings %}
<div class="finding {{ f.severity }}"><h3><span class="badge {{ f.severity }}">{{ f.severity }}</span> {{ f.title }}</h3>
<p>{{ f.description }}</p><p><strong>Remediation:</strong> {{ f.remediation }}</p>
<p><strong>Category:</strong> {{ f.category }} | <strong>Effort:</strong> {{ f.effort }}</p></div>
{% endfor %}{% else %}<p style="color:#8892b0">No high-priority findings.</p>{% endif %}
<div class="footer">FortifyOne | TrinTech Digital Defense | {{ generation_date }} | Confidential</div>
</div></body></html>"""

def generate_executive_report(audit_data: dict, output_dir: str) -> str:
    meta = audit_data.get("audit_metadata", {})
    client_name = meta.get("client_name", "Client")
    scope = audit_data.get("scope", {})
    findings = _build_findings(audit_data)
    overall = _overall_risk(audit_data)
    html = Template(HTML_TEMPLATE).render(
        client_name=client_name, date=str(meta.get("date", ""))[:10],
        version=meta.get("framework_version", "5.3"), overall_risk=overall,
        external_ports=len(audit_data.get("external_scan", {}).get("open_ports", [])),
        compliance=round(audit_data.get("policy_compliance", {}).get("overall_compliance_percentage", 0)),
        breach_count=audit_data.get("breach_exposure", {}).get("compromised_credentials", 0),
        internal_hosts=audit_data.get("internal_scan", {}).get("hosts_discovered", 0),
        saas_grade=audit_data.get("saas_posture", {}).get("score_grade", "N/A"),
        findings=findings[:22], roe_text=scope.get("roe_text", ""),
        authorized_by=scope.get("authorized_by", ""),
        generation_date=datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
    )
    path = os.path.join(output_dir, f"{client_name.replace(' ', '_')}_Executive_Report.html")
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    return path

class BrandPDF(FPDF):
    def header(self):
        if self.page_no() == 1:
            return
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(0, 100, 140)
        self.cell(0, 7, "FortifyOne  |  TrinTech Digital Defense", ln=True)
        self.set_draw_color(0, 150, 200)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(3)

    def footer(self):
        self.set_y(-14)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(120, 120, 120)
        self.cell(0, 8, f"Confidential  |  Page {self.page_no()}/{{nb}}  |  Authorized use only", align="C")

def generate_pdf_report(audit_data: dict, output_dir: str) -> str:
    if not HAS_FPDF:
        return ""
    meta = audit_data.get("audit_metadata", {})
    client_name = meta.get("client_name", "Client")
    scope = audit_data.get("scope", {})
    findings = _build_findings(audit_data)
    overall = _overall_risk(audit_data)

    crit = sum(1 for f in findings if f.get("severity") == "critical")
    high = sum(1 for f in findings if f.get("severity") == "high")
    med = sum(1 for f in findings if f.get("severity") == "medium")

    pdf = BrandPDF()
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=18)

    # ===== COVER =====
    pdf.add_page()
    pdf.set_fill_color(10, 14, 39)
    pdf.rect(0, 0, 210, 297, "F")
    pdf.set_text_color(0, 212, 255)
    pdf.set_font("Helvetica", "B", 28)
    pdf.ln(50)
    pdf.cell(0, 14, "SECURITY ASSESSMENT", ln=True, align="C")
    pdf.set_font("Helvetica", "", 15)
    pdf.set_text_color(200, 210, 220)
    pdf.cell(0, 10, "Executive Report", ln=True, align="C")
    pdf.ln(18)
    pdf.set_draw_color(0, 180, 220)
    pdf.set_line_width(0.6)
    pdf.line(60, pdf.get_y(), 150, pdf.get_y())
    pdf.ln(14)
    pdf.set_font("Helvetica", "B", 18)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(0, 10, client_name, ln=True, align="C")
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(180, 190, 200)
    pdf.cell(0, 8, f"Date: {str(meta.get('date', ''))[:10]}", ln=True, align="C")
    pdf.cell(0, 8, f"Framework: FortifyOne v{meta.get('framework_version', '5.3')}", ln=True, align="C")
    pdf.cell(0, 8, f"Overall Risk Score: {overall}/100", ln=True, align="C")
    pdf.ln(8)
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 6, f"Critical: {crit}   |   High: {high}   |   Medium: {med}", ln=True, align="C")
    pdf.ln(28)
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(0, 212, 255)
    pdf.cell(0, 6, "TrinTech Digital Defense", ln=True, align="C")
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(160, 170, 180)
    pdf.cell(0, 5, "Securing Your Digital World", ln=True, align="C")
    pdf.cell(0, 5, "https://trintechdigitaldefense.github.io", ln=True, align="C")
    pdf.ln(10)
    pdf.set_font("Helvetica", "I", 8)
    pdf.cell(0, 5, "CONFIDENTIAL — Authorized recipients only", ln=True, align="C")

    # ===== SCOPE & ROE =====
    pdf.add_page()
    pdf.set_text_color(40, 40, 40)
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 8, "1. Scope & Rules of Engagement", ln=True)
    pdf.set_draw_color(0, 150, 200)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(4)
    pdf.set_font("Helvetica", "", 9)
    pdf.multi_cell(0, 5, scope.get("roe_text", "Authorized security assessment only."))
    if scope.get("authorized_by"):
        pdf.ln(2)
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(0, 5, f"Authorized by: {scope.get('authorized_by')}  |  Date: {scope.get('authorization_date', 'N/A')}", ln=True)
    targets = scope.get("in_scope_targets") or []
    if targets:
        pdf.ln(2)
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(0, 5, "In-scope targets:", ln=True)
        pdf.set_font("Helvetica", "", 8)
        pdf.multi_cell(0, 4, ", ".join(str(t) for t in targets[:40]))

    pdf.ln(6)
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 8, "2. Methodology", ln=True)
    pdf.set_draw_color(0, 150, 200)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(3)
    pdf.set_font("Helvetica", "", 9)
    pdf.multi_cell(0, 5,
        "This assessment used FortifyOne modules: external multi-target scanning (ReconVision), "
        "safe vulnerability indicators (VulnProbe + curated templates), web exposure checks (WebProbe), "
        "optional internal discovery, local hardening signals, optional SSH credentialed checks "
        "(with WinRM readiness), email/SaaS posture, credential exposure patterns, and an "
        "industry-aware policy baseline (NIST/CIS/HIPAA). No denial-of-service or exploitation was performed."
    )

    # ===== EXECUTIVE SUMMARY =====
    pdf.ln(6)
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 8, "3. Executive Summary Metrics", ln=True)
    pdf.set_draw_color(0, 150, 200)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(3)
    pdf.set_font("Helvetica", "", 9)
    pdf.cell(0, 5, f"Overall Risk Score: {overall}/100", ln=True)
    pdf.cell(0, 5, f"Findings by severity — Critical: {crit}  |  High: {high}  |  Medium: {med}", ln=True)
    pdf.cell(0, 5, f"External open ports: {len(audit_data.get('external_scan', {}).get('open_ports', []))}", ln=True)
    pdf.cell(0, 5, f"Internal hosts discovered: {audit_data.get('internal_scan', {}).get('hosts_discovered', 0)}", ln=True)
    pdf.cell(0, 5, f"Policy compliance: {audit_data.get('policy_compliance', {}).get('overall_compliance_percentage', 0):.0f}%", ln=True)
    pdf.cell(0, 5, f"SaaS / Email grade: {audit_data.get('saas_posture', {}).get('score_grade', 'N/A')}", ln=True)
    cred = audit_data.get("credentialed_scan", {})
    if cred.get("enabled"):
        pdf.cell(0, 5, f"Credentialed checks: {cred.get('checks_run', 0)} run | Risk {cred.get('risk_score', 0)}/100", ln=True)

    # ===== FINDINGS =====
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(40, 40, 40)
    pdf.cell(0, 8, "4. Prioritized Findings & Remediation", ln=True)
    pdf.set_draw_color(0, 150, 200)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(4)
    if not findings:
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(0, 5, "No high-priority findings recorded.", ln=True)
    else:
        for i, f in enumerate(findings[:25], 1):
            sev = f.get("severity", "medium").upper()
            if sev == "CRITICAL":
                pdf.set_text_color(180, 30, 30)
            elif sev == "HIGH":
                pdf.set_text_color(200, 80, 40)
            else:
                pdf.set_text_color(40, 40, 40)
            pdf.set_font("Helvetica", "B", 9)
            pdf.multi_cell(0, 5, f"{i}. [{sev}] {f.get('title', '')}")
            pdf.set_text_color(40, 40, 40)
            pdf.set_font("Helvetica", "", 8)
            pdf.multi_cell(0, 4, f.get("description", ""))
            pdf.set_font("Helvetica", "I", 8)
            pdf.multi_cell(0, 4, f"Remediation: {f.get('remediation', '')}")
            pdf.set_font("Helvetica", "", 8)
            pdf.cell(0, 4, f"Category: {f.get('category', '')}  |  Effort: {f.get('effort', 'TBD')}", ln=True)
            pdf.ln(2)

    # ===== RECOMMENDATIONS =====
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(40, 40, 40)
    pdf.cell(0, 8, "5. Priority Recommendations", ln=True)
    pdf.set_draw_color(0, 150, 200)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(4)
    pdf.set_font("Helvetica", "", 9)
    recs = [
        "Address all Critical findings within 7–14 days.",
        "Close High findings within 30 days and track in a remediation register.",
        "Enforce MFA on all remote access and privileged accounts.",
        "Remove or tightly restrict public exposure of management and database ports.",
        "Maintain current patch levels and enable automatic security updates where possible.",
        "Review and strengthen email authentication (SPF / DKIM / DMARC toward p=reject).",
        "Document and test incident response and backup restore procedures.",
    ]
    for r in recs:
        pdf.multi_cell(0, 5, f"•  {r}")
        pdf.ln(1)

    pdf.ln(8)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(100, 100, 100)
    pdf.multi_cell(0, 4,
        "This report is confidential and intended solely for the named client. "
        "Findings are indicators and require validation in context. "
        "TrinTech Digital Defense – Securing Your Digital World."
    )

    path = os.path.join(output_dir, f"{client_name.replace(' ', '_')}_Executive_Report.pdf")
    pdf.output(path)
    return path

def generate_engagement_letter(audit_data: dict, output_dir: str) -> str:
    """Generate a professional engagement / ROE letter PDF."""
    if not HAS_FPDF:
        return ""
    meta = audit_data.get("audit_metadata", {})
    scope = audit_data.get("scope", {})
    client = meta.get("client_name", "Client")

    pdf = FPDF()
    pdf.add_page()

    # Header bar
    pdf.set_fill_color(10, 14, 39)
    pdf.rect(0, 0, 210, 28, "F")
    pdf.set_text_color(0, 212, 255)
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_xy(10, 8)
    pdf.cell(0, 8, "TrinTech Digital Defense", ln=True)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(180, 190, 200)
    pdf.set_x(10)
    pdf.cell(0, 5, "Engagement Letter & Rules of Engagement", ln=True)

    pdf.set_y(38)
    pdf.set_text_color(40, 40, 40)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Engagement Confirmation", ln=True)
    pdf.set_font("Helvetica", "", 10)
    pdf.ln(2)
    pdf.cell(0, 6, f"Client: {client}", ln=True)
    pdf.cell(0, 6, f"Date: {str(meta.get('date', ''))[:10]}", ln=True)
    pdf.cell(0, 6, f"Auditor: {meta.get('auditor', 'TrinTech Digital Defense')}", ln=True)
    pdf.cell(0, 6, f"Industry: {meta.get('industry', 'General')}", ln=True)
    pdf.cell(0, 6, f"Framework: FortifyOne v{meta.get('framework_version', '5.3')}", ln=True)

    pdf.ln(6)
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 7, "Authorization", ln=True)
    pdf.set_font("Helvetica", "", 9)
    pdf.multi_cell(0, 5,
        f"This letter confirms that a security assessment has been authorized for the named client. "
        f"Authorized by: {scope.get('authorized_by', 'Client representative')}. "
        f"Authorization date: {scope.get('authorization_date', 'N/A')}."
    )

    pdf.ln(4)
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 7, "Rules of Engagement", ln=True)
    pdf.set_font("Helvetica", "", 9)
    pdf.multi_cell(0, 5, scope.get("roe_text", "Authorized assessment only."))

    pdf.ln(4)
    targets = scope.get("in_scope_targets") or []
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 7, "In-Scope Targets", ln=True)
    pdf.set_font("Helvetica", "", 9)
    if targets:
        pdf.multi_cell(0, 5, ", ".join(str(t) for t in targets))
    else:
        pdf.cell(0, 5, "As defined in the engagement record.", ln=True)

    pdf.ln(4)
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 7, "Out of Scope / Prohibited", ln=True)
    pdf.set_font("Helvetica", "", 9)
    pdf.multi_cell(0, 5,
        "Denial-of-service testing; social engineering of staff without separate written approval; "
        "data exfiltration; testing of systems not listed in scope; any activity outside the authorization window."
    )

    pdf.ln(4)
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 7, "Deliverables", ln=True)
    pdf.set_font("Helvetica", "", 9)
    pdf.multi_cell(0, 5,
        "Executive PDF report, HTML summary, prioritized remediation CSV, engagement letter, "
        "and optional evidence pack (ZIP) containing findings index and policy evidence."
    )

    pdf.ln(10)
    pdf.set_font("Helvetica", "", 9)
    pdf.cell(0, 5, "Authorized representative signature: _______________________________", ln=True)
    pdf.ln(3)
    pdf.cell(0, 5, "Date: ____________________", ln=True)
    pdf.ln(6)
    pdf.cell(0, 5, "Auditor signature: _______________________________________________", ln=True)
    pdf.ln(3)
    pdf.cell(0, 5, "Date: ____________________", ln=True)

    pdf.ln(12)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(100, 100, 100)
    pdf.multi_cell(0, 4, "TrinTech Digital Defense  |  https://trintechdigitaldefense.github.io  |  Confidential")

    path = os.path.join(output_dir, f"{client.replace(' ', '_')}_Engagement_Letter.pdf")
    pdf.output(path)
    return path

def generate_remediation_plan(audit_data: dict, output_dir: str) -> str:
    client_name = audit_data.get("audit_metadata", {}).get("client_name", "Client")
    findings = _build_findings(audit_data)
    path = os.path.join(output_dir, f"{client_name.replace(' ', '_')}_Remediation_Plan.csv")
    with open(path, "w", encoding="utf-8") as f:
        f.write("Priority,Severity,Finding,Category,Estimated Effort,Status,Remediation\n")
        for i, item in enumerate(findings, 1):
            title = item.get("title", "").replace('"', "'")
            rem = item.get("remediation", "").replace('"', "'")
            f.write(f'{i},{item.get("severity","medium").capitalize()},"{title}",{item.get("category","")},{item.get("effort","TBD")},Not Started,"{rem}"\n')
    return path

if __name__ == "__main__":
    print("ReportGenius v5.3 ready")
