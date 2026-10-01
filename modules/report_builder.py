#!/usr/bin/env python3
"""
ReportGenius - Client Deliverable Engine (v2)
Generates professional HTML + CSV reports from audit data.
TrinTech Digital Defense
"""

import json
import os
import datetime
from pathlib import Path
from jinja2 import Template

EXECUTIVE_REPORT_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FortifyOne Audit Report - {{ client_name }}</title>
    <style>
        body { font-family: 'Segoe UI', system-ui, sans-serif; margin: 0; padding: 20px; background: #0a0e27; color: #e0e6ed; line-height: 1.5; }
        .container { max-width: 960px; margin: 0 auto; }
        .header { text-align: center; padding: 28px; background: linear-gradient(135deg, #1a1f3a, #0d1126); border-radius: 12px; margin-bottom: 24px; border: 1px solid #2d3561; }
        .header h1 { color: #00d4ff; margin: 0 0 8px 0; font-size: 1.8em; }
        .header .tagline { color: #8892b0; font-size: 0.95em; }
        .roe { background: #1a1f3a; border-left: 4px solid #ffa502; padding: 14px 18px; border-radius: 8px; margin-bottom: 24px; font-size: 0.9em; }
        .metric-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 14px; margin-bottom: 28px; }
        .metric-card { background: #1a1f3a; padding: 18px; border-radius: 10px; text-align: center; border-left: 4px solid #00d4ff; }
        .metric-card.critical { border-left-color: #ff4757; }
        .metric-card.warning { border-left-color: #ffa502; }
        .metric-value { font-size: 2.2em; font-weight: 700; color: #00d4ff; }
        .metric-label { color: #8892b0; font-size: 0.82em; margin-top: 4px; text-transform: uppercase; letter-spacing: 0.5px; }
        h2 { color: #00d4ff; margin-top: 32px; border-bottom: 1px solid #2d3561; padding-bottom: 8px; }
        .finding { background: #1a1f3a; padding: 16px; border-radius: 8px; margin-bottom: 12px; border-left: 4px solid #ff4757; }
        .finding.high { border-left-color: #ff6b6b; }
        .finding.medium { border-left-color: #ffa502; }
        .finding.low { border-left-color: #2ed573; }
        .finding h3 { margin: 0 0 6px 0; color: #fff; font-size: 1.05em; }
        .finding p { margin: 4px 0; color: #8892b0; font-size: 0.9em; }
        .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75em; font-weight: 600; text-transform: uppercase; }
        .badge.critical { background: #ff4757; color: #fff; }
        .badge.high { background: #ff6b6b; color: #fff; }
        .badge.medium { background: #ffa502; color: #1a1f3a; }
        .footer { text-align: center; color: #8892b0; margin-top: 48px; font-size: 0.8em; border-top: 1px solid #2d3561; padding-top: 16px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ FortifyOne Security Audit Report</h1>
            <p class="tagline">{{ client_name }} &nbsp;|&nbsp; {{ date }} &nbsp;|&nbsp; TrinTech Digital Defense</p>
            <p class="tagline">Framework v{{ version }}</p>
        </div>

        {% if roe_text %}
        <div class="roe">
            <strong>Rules of Engagement / Scope</strong><br>
            {{ roe_text }}
            {% if authorized_by %}<br><em>Authorized by: {{ authorized_by }}</em>{% endif %}
        </div>
        {% endif %}

        <div class="metric-grid">
            <div class="metric-card {% if overall_risk > 70 %}critical{% elif overall_risk > 40 %}warning{% endif %}">
                <div class="metric-value">{{ overall_risk }}</div>
                <div class="metric-label">Overall Risk</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{{ external_ports }}</div>
                <div class="metric-label">External Ports</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{{ compliance }}%</div>
                <div class="metric-label">Policy Compliance</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{{ breach_count }}</div>
                <div class="metric-label">Credential Hits</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{{ internal_hosts }}</div>
                <div class="metric-label">Internal Hosts</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{{ saas_grade }}</div>
                <div class="metric-label">SaaS Grade</div>
            </div>
        </div>

        <h2>Critical & High Findings</h2>
        {% if findings %}
            {% for finding in findings %}
            <div class="finding {{ finding.severity }}">
                <h3><span class="badge {{ finding.severity }}">{{ finding.severity }}</span> &nbsp; {{ finding.title }}</h3>
                <p>{{ finding.description }}</p>
                <p><strong>Remediation:</strong> {{ finding.remediation }}</p>
            </div>
            {% endfor %}
        {% else %}
            <p style="color:#8892b0;">No critical external findings recorded in this assessment.</p>
        {% endif %}

        {% if policy_gaps %}
        <h2>Policy & Compliance Gaps</h2>
        {% for gap in policy_gaps %}
        <div class="finding high">
            <h3>{{ gap.question_id }} — {{ gap.question }}</h3>
            <p><strong>Remediation:</strong> {{ gap.remediation }}</p>
        </div>
        {% endfor %}
        {% endif %}

        <div class="footer">
            Generated by FortifyOne | TrinTech Digital Defense | {{ generation_date }}<br>
            This report is confidential and intended solely for the named client. Unauthorized distribution is prohibited.<br>
            Authorized use only. Assessments performed under agreed Rules of Engagement.
        </div>
    </div>
</body>
</html>
"""


def generate_executive_report(audit_data: dict, output_dir: str) -> str:
    """Generate the professional HTML executive report."""
    meta = audit_data.get("audit_metadata", {})
    client_name = meta.get("client_name", "Client")
    external = audit_data.get("external_scan", {})
    internal = audit_data.get("internal_scan", {})
    policy = audit_data.get("policy_compliance", {})
    breach = audit_data.get("breach_exposure", {})
    saas = audit_data.get("saas_posture", {})
    scope = audit_data.get("scope", {})

    # Composite risk (simple weighted)
    ext_risk = external.get("risk_score", 0)
    int_risk = internal.get("risk_score", 0)
    pol_score = policy.get("overall_compliance_percentage", 100)
    overall_risk = min(100, int(ext_risk * 0.45 + int_risk * 0.25 + (100 - pol_score) * 0.3))

    findings = []
    for port_info in external.get("open_ports", []):
        risk = port_info.get("risk_level", "medium")
        sev = "critical" if risk == "critical" else "high" if risk == "high" else "medium"
        findings.append({
            "title": f"Port {port_info.get('port')} ({port_info.get('service', 'unknown')}) exposed",
            "description": f"Service visible from the internet. Risk level: {risk}.",
            "remediation": f"Restrict or close port {port_info.get('port')}. Prefer VPN or IP allow-listing over public exposure.",
            "severity": sev
        })

    # Policy critical gaps
    policy_gaps = []
    for r in policy.get("responses", []):
        if not r.get("compliant") and r.get("critical"):
            policy_gaps.append(r)

    template = Template(EXECUTIVE_REPORT_TEMPLATE)
    html_content = template.render(
        client_name=client_name,
        date=meta.get("date", "")[:10],
        version=meta.get("framework_version", "4.2"),
        overall_risk=overall_risk,
        external_ports=len(external.get("open_ports", [])),
        compliance=round(policy.get("overall_compliance_percentage", 0)),
        breach_count=breach.get("compromised_credentials", 0),
        internal_hosts=internal.get("hosts_discovered", 0),
        saas_grade=saas.get("score_grade", "N/A"),
        findings=findings[:15],
        policy_gaps=policy_gaps[:10],
        roe_text=scope.get("roe_text", ""),
        authorized_by=scope.get("authorized_by", ""),
        generation_date=datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
    )

    safe_name = client_name.replace(" ", "_")
    filename = f"{safe_name}_Executive_Report.html"
    filepath = os.path.join(output_dir, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html_content)
    return filepath


def generate_remediation_plan(audit_data: dict, output_dir: str) -> str:
    """Generate prioritized CSV remediation plan."""
    meta = audit_data.get("audit_metadata", {})
    client_name = meta.get("client_name", "Client")
    external = audit_data.get("external_scan", {})
    policy = audit_data.get("policy_compliance", {})
    internal = audit_data.get("internal_scan", {})

    safe_name = client_name.replace(" ", "_")
    filename = f"{safe_name}_Remediation_Plan.csv"
    filepath = os.path.join(output_dir, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write("Priority,Finding,Category,Severity,Estimated Effort,Status,Remediation\n")
        priority = 1

        for port in external.get("open_ports", []):
            sev = port.get("risk_level", "medium").capitalize()
            f.write(f'{priority},"Close or restrict port {port.get("port")} ({port.get("service")})",Network,{sev},2-4 hours,Not Started,"Firewall rule or service hardening"\n')
            priority += 1

        for port in internal.get("open_ports", [])[:10]:
            sev = port.get("risk_level", "medium").capitalize()
            f.write(f'{priority},"Internal host {port.get("ip")}:{port.get("port")} ({port.get("service")})",Internal Network,{sev},1-3 hours,Not Started,"Segment or harden internal service"\n')
            priority += 1

        for r in policy.get("responses", []):
            if not r.get("compliant") and r.get("critical"):
                f.write(f'{priority},"{r.get("question_id")}: {r.get("question")[:80]}",Policy,Critical,4-16 hours,Not Started,"{r.get("remediation", "Implement control")}"\n')
                priority += 1

    return filepath


if __name__ == "__main__":
    print("ReportGenius ready")
