#!/usr/bin/env python3
"""
Evidence Pack generator v5.3
Creates a client-ready ZIP: reports, signatures, findings index, policy evidence, README.
"""

from __future__ import annotations

import csv
import datetime
import json
import os
import zipfile
from pathlib import Path
from typing import List, Optional


def _safe_name(name: str) -> str:
    return "".join(c if c.isalnum() or c in "-_" else "_" for c in (name or "Client"))[:80]


def build_evidence_pack(
    audit_data: dict,
    output_dir: str,
    extra_files: Optional[List[str]] = None,
) -> str:
    """
    Build ZIP under output_dir.
    Returns path to the zip file.
    """
    meta = audit_data.get("audit_metadata", {})
    client = _safe_name(meta.get("client_name", "Client"))
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    # Findings index CSV
    try:
        from report_builder import _build_findings
        findings = _build_findings(audit_data)
    except Exception:
        findings = []

    index_path = out / f"{client}_Findings_Index.csv"
    with open(index_path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["#", "Severity", "Category", "Title", "Remediation", "Effort", "Evidence"])
        for i, item in enumerate(findings, 1):
            w.writerow([
                i,
                item.get("severity", ""),
                item.get("category", ""),
                item.get("title", ""),
                item.get("remediation", ""),
                item.get("effort", ""),
                item.get("evidence", item.get("description", ""))[:500],
            ])

    # Policy evidence notes
    policy_path = out / f"{client}_Policy_Evidence.json"
    policy = audit_data.get("policy_compliance", {})
    evidence_rows = []
    for r in policy.get("responses", []):
        evidence_rows.append({
            "id": r.get("question_id"),
            "question": r.get("question"),
            "compliant": r.get("compliant"),
            "critical": r.get("critical"),
            "evidence": r.get("evidence", ""),
            "remediation": r.get("remediation", ""),
        })
    policy_path.write_text(json.dumps({
        "client": meta.get("client_name"),
        "industry": policy.get("industry") or meta.get("industry"),
        "overall_compliance_percentage": policy.get("overall_compliance_percentage"),
        "critical_gaps": policy.get("critical_gaps", []),
        "responses": evidence_rows,
        "generated": datetime.datetime.now().isoformat(),
    }, indent=2), encoding="utf-8")

    # Credentialed summary (no secrets)
    cred_path = out / f"{client}_Credentialed_Summary.json"
    cred = audit_data.get("credentialed_scan", {})
    if cred:
        cred_path.write_text(json.dumps({
            "enabled": cred.get("enabled"),
            "host": cred.get("host"),
            "checks_run": cred.get("checks_run"),
            "risk_score": cred.get("risk_score"),
            "findings_count": len(cred.get("findings", [])),
            "winrm": cred.get("winrm", {}),
            "note": cred.get("note"),
            "scan_timestamp": cred.get("scan_timestamp"),
        }, indent=2), encoding="utf-8")

    # Pack README
    readme_path = out / "README_EVIDENCE_PACK.txt"
    readme_path.write_text(
        f"FortifyOne Evidence Pack\n"
        f"=======================\n"
        f"Client: {meta.get('client_name')}\n"
        f"Generated: {datetime.datetime.now().isoformat()}\n"
        f"Framework: {meta.get('framework_version')}\n"
        f"\nContents:\n"
        f"- Executive Report (PDF/HTML)\n"
        f"- Engagement Letter (PDF)\n"
        f"- Remediation Plan (CSV)\n"
        f"- Findings Index (CSV)\n"
        f"- Policy Evidence (JSON)\n"
        f"- Credentialed Summary (JSON, if run)\n"
        f"- audit_summary.json\n"
        f"- Optional .sig signature files\n"
        f"- MANIFEST.json\n"
        f"\nThis pack is confidential and intended solely for the named client.\n"
        f"TrinTech Digital Defense – Securing Your Digital World\n",
        encoding="utf-8",
    )

    # Manifest
    manifest = {
        "client": meta.get("client_name"),
        "generated": datetime.datetime.now().isoformat(),
        "framework_version": meta.get("framework_version"),
        "scope": audit_data.get("scope", {}),
        "overall_risk_hint": None,
        "contents": [],
    }

    zip_path = out / f"{client}_Evidence_Pack_{ts}.zip"
    patterns = [
        f"{client}_Executive_Report.pdf",
        f"{client}_Executive_Report.html",
        f"{client}_Remediation_Plan.csv",
        f"{client}_Engagement_Letter.pdf",
        "audit_summary.json",
    ]
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name in patterns:
            p = out / name
            if p.is_file():
                zf.write(p, arcname=p.name)
                manifest["contents"].append(p.name)
                sig = Path(str(p) + ".sig")
                if not sig.exists():
                    sig = p.with_suffix(p.suffix + ".sig")
                if sig.is_file():
                    zf.write(sig, arcname=sig.name)
                    manifest["contents"].append(sig.name)

        for p in (index_path, policy_path, readme_path):
            if p.is_file():
                zf.write(p, arcname=p.name)
                manifest["contents"].append(p.name)

        if cred_path.is_file():
            zf.write(cred_path, arcname=cred_path.name)
            manifest["contents"].append(cred_path.name)

        if extra_files:
            for fp in extra_files:
                p = Path(fp)
                if p.is_file():
                    zf.write(p, arcname=p.name)
                    manifest["contents"].append(p.name)

        zf.writestr("MANIFEST.json", json.dumps(manifest, indent=2))

    return str(zip_path)


if __name__ == "__main__":
    print("Evidence pack module ready (v5.3)")
