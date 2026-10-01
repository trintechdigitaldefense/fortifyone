#!/usr/bin/env python3
"""
ReportGenius v4 – HTML + PDF + CSV
Includes external, vuln, web, local hardening, policy, breach, SaaS findings.
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
                "remediation": "Fix SPF/DKIM/DMARC; target p=reject. Add missing security headers.",
                "severity": f.get("severity"), "category": "Email / SaaS", "effort": "1–4 hours",
            })

    for f in vuln.get("findings", []):
        if f.get("severity") in ("info", "low"):
            continue
        findings.append({
            "title": f.get("title", "Vuln indicator"),
            "description": f.get("detail", ""),
            "remediation": "Validate, patch, disable obsolete protocols, restrict access.",
            "severity": f.get("severity", "medium"), "category": "Vulnerability", "effort": "2–12 hours",
        })

    for f in web.get("findings", []):
        if f.get("severity") in ("info", "low", "good"):
            continue
        findings.append({
            "title": f.get("title", "Web exposure"),
            "description": f.get("detail", ""),
            "remediation": "Remove or protect exposed paths; restrict admin interfaces; keep CMS patched.",
            "severity": f.get("severity", "medium"), "category": "Web Application", "effort": "1–8 hours",
        })

    for f in local.get("findings", []):
        if f.get("severity") in ("info", "good", "low"):
            continue
        findings.append({
            "title": f.get("title", "Local hardening"),
            "description": f.get("detail", ""),
            "remediation": f.get("remediation", "Harden the local host configuration."),
            "severity": f.get("severity", "medium"), "category": "Local Host", "effort": "1–4 hours",
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
    return min(100, int(ext * 0.28 + inte * 0.15 + v * 0.17 + w * 0.12 + loc * 0.08 + (100 - pol) * 0.20))

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
<div class="header"><h1>🛡️ FortifyOne Security Assessment</h1>
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
<div class="footer">FortifyOne | TrinTech Digital Defense | {{ generation_date }} | Confidential – authorized use only</div>
</div></body></html>"""

def generate_executive_report(audit_data: dict, output_dir: str) -> str:
    meta = audit_data.get("audit_metadata", {})
    client_name = meta.get("client_name", "Client")
    scope = audit_data.get("scope", {})
    findings = _build_findings(audit_data)
    overall = _overall_risk(audit_data)
    html = Template(HTML_TEMPLATE).render(
        client_name=client_name, date=str(meta.get("date", ""))[:10],
        version=meta.get("framework_version", "5.0"), overall_risk=overall,
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

class AuditPDF(FPDF):
    def header(self):
        self.set_font("Helvetica", "B", 11)
        self.set_text_color(0, 100, 140)
        self.cell(0, 8, "FortifyOne – TrinTech Digital Defense", ln=True)
        self.set_draw_color(0, 150, 200)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(4)
    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(120, 120, 120)
        self.cell(0, 8, f"Confidential | Page {self.page_no()}/{{nb}}", align="C")

def generate_pdf_report(audit_data: dict, output_dir: str) -> str:
    if not HAS_FPDF:
        return ""
    meta = audit_data.get("audit_metadata", {})
    client_name = meta.get("client_name", "Client")
    scope = audit_data.get("scope", {})
    findings = _build_findings(audit_data)
    overall = _overall_risk(audit_data)
    pdf = AuditPDF()
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 18)
    pdf.set_text_color(0, 80, 120)
    pdf.cell(0, 10, "Security Assessment Report", ln=True)
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(40, 40, 40)
    pdf.cell(0, 7, f"Client: {client_name}", ln=True)
    pdf.cell(0, 7, f"Date: {str(meta.get('date', ''))[:10]} | v{meta.get('framework_version', '5.0')}", ln=True)
    pdf.ln(2)
    if scope.get("roe_text"):
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(0, 6, "Rules of Engagement", ln=True)
        pdf.set_font("Helvetica", "", 9)
        pdf.multi_cell(0, 5, scope.get("roe_text", ""))
        if scope.get("authorized_by"):
            pdf.cell(0, 5, f"Authorized by: {scope.get('authorized_by')}", ln=True)
        pdf.ln(2)
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(0, 6, f"Overall Risk: {overall}/100", ln=True)
    pdf.set_font("Helvetica", "", 9)
    pdf.ln(3)
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 7, "Prioritized Findings", ln=True)
    for i, f in enumerate(findings[:16], 1):
        sev = f.get("severity", "medium").upper()
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(180, 40, 40) if sev == "CRITICAL" else pdf.set_text_color(40, 40, 40)
        pdf.multi_cell(0, 5, f"{i}. [{sev}] {f.get('title', '')}")
        pdf.set_text_color(40, 40, 40)
        pdf.set_font("Helvetica", "", 8)
        pdf.multi_cell(0, 4, f.get("description", ""))
        pdf.set_font("Helvetica", "I", 8)
        pdf.multi_cell(0, 4, f"Fix: {f.get('remediation', '')}")
        pdf.ln(1)
    pdf.ln(3)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(100, 100, 100)
    pdf.multi_cell(0, 4, "Confidential. Authorized use only. TrinTech Digital Defense.")
    path = os.path.join(output_dir, f"{client_name.replace(' ', '_')}_Executive_Report.pdf")
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
    print("ReportGenius v4 ready")
