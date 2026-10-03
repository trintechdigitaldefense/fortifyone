#!/usr/bin/env python3
"""
Dashboard - Interactive single-file HTML dashboard + redacted report support
TrinTech Digital Defense
"""

from __future__ import annotations

import html
import json
import re
from pathlib import Path
from typing import Any, Dict, Optional


def _esc(s: Any) -> str:
    return html.escape(str(s) if s is not None else "")


def _risk_color(score: int) -> str:
    if score >= 70:
        return "#c0392b"
    if score >= 40:
        return "#e67e22"
    if score >= 20:
        return "#f1c40f"
    return "#27ae60"


def _collect_findings(audit: dict) -> list:
    out = []
    for section in (
        "external_scan", "vuln_probe", "web_probe", "tls_posture",
        "local_hardening", "credentialed_scan", "saas_posture", "breach_exposure",
    ):
        data = audit.get(section) or {}
        items = data.get("findings") or data.get("vulnerabilities") or []
        if isinstance(items, list):
            for it in items:
                if isinstance(it, dict):
                    out.append({
                        "source": section,
                        "title": it.get("title") or it.get("detail", "")[:80],
                        "severity": (it.get("severity") or "info").lower(),
                        "detail": it.get("detail") or "",
                        "remediation": it.get("remediation") or "",
                        "host": it.get("host") or "",
                        "controls": it.get("controls") or [],
                    })
                elif isinstance(it, str):
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


def redact_audit(audit: dict) -> dict:
    """Produce a client-shareable redacted copy (no internal IPs, hostnames minimized)."""
    import copy
    data = copy.deepcopy(audit)

    # Redact common internal patterns
    def scrub(obj):
        if isinstance(obj, dict):
            return {k: scrub(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [scrub(x) for x in obj]
        if isinstance(obj, str):
            # Simple internal IP redaction
            s = re.sub(r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "[INTERNAL_IP]", obj)
            s = re.sub(r"\b192\.168\.\d{1,3}\.\d{1,3}\b", "[INTERNAL_IP]", s)
            s = re.sub(r"\b172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}\b", "[INTERNAL_IP]", s)
            return s
        return obj

    data = scrub(data)
    data.setdefault("audit_metadata", {})["redacted"] = True
    data["audit_metadata"]["notes"] = (data["audit_metadata"].get("notes") or "") + " [REDACTED VERSION]"
    return data


def generate_interactive_dashboard(audit: dict, output_dir: str, redacted: bool = False) -> str:
    """Generate a self-contained interactive HTML dashboard. Returns path."""
    if redacted:
        audit = redact_audit(audit)

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    meta = audit.get("audit_metadata", {})
    client = meta.get("client_name") or "Client"
    safe = re.sub(r"[^a-zA-Z0-9_\-]", "_", client)
    suffix = "_Redacted" if redacted else ""
    path = out / f"{safe}_Dashboard{suffix}.html"

    findings = _collect_findings(audit)
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        s = f.get("severity", "info")
        if s in sev_counts:
            sev_counts[s] += 1

    policy = audit.get("policy_compliance", {})
    tls = audit.get("tls_posture", {})
    external = audit.get("external_scan", {})
    overall_risk = max(
        external.get("risk_score") or 0,
        tls.get("risk_score") or 0,
        audit.get("final_report", {}).get("risk_score") or 0,
        0,
    )
    # Prefer computed from findings if available
    if findings:
        crit = sev_counts["critical"]
        high = sev_counts["high"]
        med = sev_counts["medium"]
        overall_risk = max(overall_risk, min(crit * 25 + high * 12 + med * 5, 100))

    findings_json = json.dumps(findings[:200], ensure_ascii=False)
    sev_json = json.dumps(sev_counts)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>FortifyOne Dashboard — {_esc(client)}</title>
<style>
:root {{
  --bg: #0f1419; --card: #1a2332; --text: #e7ecf3; --muted: #8b9bb4;
  --accent: #3b82f6; --crit: #ef4444; --high: #f97316; --med: #eab308; --low: #22c55e;
}}
* {{ box-sizing: border-box; }}
body {{ margin:0; font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
  background: var(--bg); color: var(--text); line-height: 1.5; }}
header {{ background: linear-gradient(135deg, #1e3a5f, #0f172a); padding: 1.5rem 2rem;
  border-bottom: 1px solid #334155; }}
header h1 {{ margin:0 0 .25rem; font-size: 1.5rem; }}
header .sub {{ color: var(--muted); font-size: .9rem; }}
.container {{ max-width: 1100px; margin: 0 auto; padding: 1.5rem; }}
.grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin-bottom: 1.5rem; }}
.card {{ background: var(--card); border-radius: 10px; padding: 1.1rem 1.25rem;
  border: 1px solid #2d3a4f; }}
.card h3 {{ margin:0 0 .5rem; font-size: .8rem; text-transform: uppercase; letter-spacing: .05em; color: var(--muted); }}
.card .val {{ font-size: 1.75rem; font-weight: 700; }}
.risk {{ color: {_risk_color(overall_risk)}; }}
table {{ width:100%; border-collapse: collapse; font-size: .9rem; }}
th, td {{ text-align: left; padding: .55rem .7rem; border-bottom: 1px solid #2d3a4f; }}
th {{ color: var(--muted); font-weight: 600; font-size: .75rem; text-transform: uppercase; }}
.badge {{ display:inline-block; padding: .15rem .5rem; border-radius: 999px; font-size: .7rem; font-weight: 600; }}
.badge.critical {{ background:#7f1d1d; color:#fecaca; }}
.badge.high {{ background:#7c2d12; color:#fed7aa; }}
.badge.medium {{ background:#713f12; color:#fef08a; }}
.badge.low {{ background:#14532d; color:#bbf7d0; }}
.badge.info {{ background:#1e3a5f; color:#bfdbfe; }}
.filters {{ margin-bottom: 1rem; display:flex; gap:.5rem; flex-wrap:wrap; }}
.filters button {{ background:#1e293b; border:1px solid #334155; color:var(--text);
  padding:.4rem .8rem; border-radius:6px; cursor:pointer; font-size:.85rem; }}
.filters button.active {{ background: var(--accent); border-color: var(--accent); }}
footer {{ text-align:center; padding: 2rem; color: var(--muted); font-size: .8rem; }}
.note {{ background:#1e293b; border-left: 3px solid var(--accent); padding: .75rem 1rem; margin-bottom: 1.25rem; border-radius: 0 6px 6px 0; font-size: .9rem; }}
</style>
</head>
<body>
<header>
  <h1>FortifyOne Security Dashboard</h1>
  <div class="sub">{_esc(client)} · { _esc(meta.get("date","")[:10]) } · Framework v{ _esc(meta.get("framework_version","5.4")) }
  {" · <strong>REDACTED</strong>" if redacted else ""}</div>
</header>
<div class="container">
  <div class="note">Interactive summary generated by TrinTech Digital Defense. Click severity filters to focus findings. This file is self-contained and works offline.</div>
  <div class="grid">
    <div class="card"><h3>Overall Risk</h3><div class="val risk">{overall_risk}/100</div></div>
    <div class="card"><h3>Critical</h3><div class="val" style="color:var(--crit)">{sev_counts['critical']}</div></div>
    <div class="card"><h3>High</h3><div class="val" style="color:var(--high)">{sev_counts['high']}</div></div>
    <div class="card"><h3>Medium</h3><div class="val" style="color:var(--med)">{sev_counts['medium']}</div></div>
    <div class="card"><h3>Compliance</h3><div class="val">{policy.get("overall_compliance_percentage", 0):.0f}%</div></div>
    <div class="card"><h3>TLS Risk</h3><div class="val">{tls.get("risk_score", 0)}</div></div>
  </div>

  <div class="card" style="margin-bottom:1.5rem">
    <h3 style="margin-bottom:1rem">Prioritized Findings</h3>
    <div class="filters" id="filters">
      <button class="active" data-sev="all">All</button>
      <button data-sev="critical">Critical</button>
      <button data-sev="high">High</button>
      <button data-sev="medium">Medium</button>
      <button data-sev="low">Low</button>
    </div>
    <table>
      <thead><tr><th>Severity</th><th>Title</th><th>Source</th><th>Host</th></tr></thead>
      <tbody id="findings-body"></tbody>
    </table>
  </div>

  <div class="card">
    <h3>Control Evidence Snapshot</h3>
    <p style="color:var(--muted);font-size:.9rem">Top linked controls from technical findings + policy gaps.</p>
    <ul style="font-size:.9rem">
"""
    control_ev = policy.get("control_evidence") or {}
    for i, (ctrl, items) in enumerate(list(control_ev.items())[:12]):
        html_content += f"      <li><strong>{_esc(ctrl)}</strong> — {_esc(str(items[0])[:80] if items else '')}</li>\n"
    if not control_ev:
        html_content += "      <li>No control evidence linked yet. Run policy + technical modules.</li>\n"

    html_content += f"""
    </ul>
  </div>
</div>
<footer>
  TrinTech Digital Defense · FortifyOne · Authorized use only<br>
  Generated for {_esc(client)}
</footer>
<script>
const FINDINGS = {findings_json};
const SEV = {sev_json};
function render(filter) {{
  const body = document.getElementById('findings-body');
  body.innerHTML = '';
  const list = filter === 'all' ? FINDINGS : FINDINGS.filter(f => f.severity === filter);
  if (!list.length) {{
    body.innerHTML = '<tr><td colspan="4" style="color:#8b9bb4">No findings for this filter.</td></tr>';
    return;
  }}
  list.forEach(f => {{
    const tr = document.createElement('tr');
    tr.innerHTML = `<td><span class="badge ${{f.severity}}">${{f.severity}}</span></td>
      <td>${{escapeHtml(f.title)}}</td>
      <td>${{escapeHtml(f.source)}}</td>
      <td>${{escapeHtml(f.host || '—')}}</td>`;
    body.appendChild(tr);
  }});
}}
function escapeHtml(s) {{
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}}
document.getElementById('filters').addEventListener('click', e => {{
  if (e.target.tagName !== 'BUTTON') return;
  document.querySelectorAll('#filters button').forEach(b => b.classList.remove('active'));
  e.target.classList.add('active');
  render(e.target.dataset.sev);
}});
render('all');
</script>
</body>
</html>
"""
    path.write_text(html_content, encoding="utf-8")
    return str(path)
