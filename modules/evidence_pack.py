#!/usr/bin/env python3
"""
Evidence Pack generator v6.1
Client-ready ZIP: reports, signatures, findings index, inventory, scoring roadmap,
policy evidence, credentialed summary, chain-of-custody MANIFEST.
"""

from __future__ import annotations

import csv
import datetime
import hashlib
import json
import zipfile
from pathlib import Path
from typing import List, Optional


def _safe_name(name: str) -> str:
    return "".join(c if c.isalnum() or c in "-_" else "_" for c in (name or "Client"))[:80]


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


def build_evidence_pack(
    audit_data: dict,
    output_dir: str,
    extra_files: Optional[List[str]] = None,
) -> str:
    """Build ZIP under output_dir. Returns path to the zip file."""
    meta = audit_data.get("audit_metadata", {})
    client = _safe_name(meta.get("client_name", "Client"))
    eng_id = meta.get("engagement_id") or "N/A"
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    # Findings index
    try:
        from report_builder import _build_findings
        findings = _build_findings(audit_data)
    except Exception:
        findings = []
        # Fallback: collect from modules
        try:
            from scoring import collect_all_findings
            findings = collect_all_findings(audit_data)
        except Exception:
            pass

    index_path = out / f"{client}_Findings_Index.csv"
    with open(index_path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["#", "Severity", "Category", "Title", "Remediation", "Source", "Host"])
        for i, item in enumerate(findings, 1):
            w.writerow([
                i,
                item.get("severity", ""),
                item.get("category", item.get("source", "")),
                item.get("title", ""),
                item.get("remediation", ""),
                item.get("source", item.get("category", "")),
                item.get("host", item.get("target", "")),
            ])

    # Remediation roadmap from scoring
    roadmap_path = out / f"{client}_Remediation_Roadmap.json"
    final = audit_data.get("final_report") or {}
    scoring = audit_data.get("scoring") or {}
    roadmap_path.write_text(json.dumps({
        "engagement_id": eng_id,
        "client": meta.get("client_name"),
        "score": scoring.get("score", final.get("risk_score")),
        "grade": scoring.get("grade", final.get("grade")),
        "severity_counts": scoring.get("severity_counts") or final.get("severity_counts"),
        "roadmap": final.get("remediation_plan") or [],
        "generated": datetime.datetime.now().isoformat(),
    }, indent=2), encoding="utf-8")

    # Inventory
    inv_path = out / f"{client}_Asset_Inventory.json"
    inv = audit_data.get("inventory") or {}
    inv_path.write_text(json.dumps({
        "engagement_id": eng_id,
        "client": meta.get("client_name"),
        "asset_count": inv.get("asset_count", 0),
        "assets": inv.get("assets") or [],
        "topology_notes": inv.get("topology_notes") or [],
        "generated": datetime.datetime.now().isoformat(),
    }, indent=2), encoding="utf-8")

    # Policy evidence
    policy_path = out / f"{client}_Policy_Evidence.json"
    policy = audit_data.get("policy_compliance", {})
    evidence_rows = []
    for r in policy.get("responses", []):
        evidence_rows.append({
            "id": r.get("id") or r.get("question_id"),
            "question": r.get("question"),
            "compliant": r.get("compliant"),
            "critical": r.get("critical"),
            "controls": r.get("controls"),
            "remediation": r.get("remediation", ""),
        })
    policy_path.write_text(json.dumps({
        "client": meta.get("client_name"),
        "industry": policy.get("industry") or meta.get("industry"),
        "overall_compliance_percentage": policy.get("overall_compliance_percentage"),
        "critical_gaps": policy.get("critical_gaps", []),
        "control_evidence": policy.get("control_evidence", {}),
        "responses": evidence_rows,
        "generated": datetime.datetime.now().isoformat(),
    }, indent=2), encoding="utf-8")

    # Credentialed summary (no secrets)
    cred_path = out / f"{client}_Credentialed_Summary.json"
    cred = audit_data.get("credentialed_scan", {})
    cred_path.write_text(json.dumps({
        "enabled": cred.get("enabled"),
        "hosts_scanned": cred.get("hosts_scanned") or cred.get("host"),
        "hosts_count": cred.get("hosts_count"),
        "checks_run": cred.get("checks_run"),
        "risk_score": cred.get("risk_score"),
        "findings_count": len(cred.get("findings", [])),
        "winrm": {k: v for k, v in (cred.get("winrm") or {}).items() if k != "password"},
        "note": cred.get("note"),
        "scan_timestamp": cred.get("scan_timestamp"),
    }, indent=2), encoding="utf-8")

    # Scope / ROE snapshot
    scope_path = out / f"{client}_Scope_ROE.json"
    scope = audit_data.get("scope") or {}
    scope_path.write_text(json.dumps({
        "engagement_id": eng_id,
        "client": meta.get("client_name"),
        "authorized_by": scope.get("authorized_by"),
        "authorization_date": scope.get("authorization_date"),
        "roe_text": scope.get("roe_text"),
        "in_scope_targets": scope.get("in_scope_targets"),
        "out_of_scope": scope.get("out_of_scope"),
        "service_tier": meta.get("service_tier"),
        "framework_version": meta.get("framework_version"),
    }, indent=2), encoding="utf-8")

    # Pack README
    readme_path = out / "README_EVIDENCE_PACK.txt"
    readme_path.write_text(
        f"FortifyOne Evidence Pack v6.1\n"
        f"=============================\n"
        f"Client: {meta.get('client_name')}\n"
        f"Engagement ID: {eng_id}\n"
        f"Generated: {datetime.datetime.now().isoformat()}\n"
        f"Framework: FortifyOne {meta.get('framework_version', '6.1')}\n"
        f"Score: {scoring.get('score', 'N/A')} Grade: {scoring.get('grade', 'N/A')}\n"
        f"\n"
        f"Contents:\n"
        f"  - Executive report (PDF/HTML) and engagement letter (if present)\n"
        f"  - Findings index CSV\n"
        f"  - Remediation roadmap JSON\n"
        f"  - Asset inventory JSON\n"
        f"  - Scope & ROE snapshot\n"
        f"  - Policy evidence + credentialed summary\n"
        f"  - MANIFEST.json (SHA-256 of each file)\n"
        f"\n"
        f"AUTHORIZED USE ONLY. Chain of custody: retain this pack with signed ROE.\n",
        encoding="utf-8",
    )

    # Collect files for ZIP
    candidates = list(out.glob(f"{client}_*")) + [
        out / "audit_summary.json",
        readme_path,
    ]
    # Include signatures
    candidates += list(out.glob("*.sig"))
    if extra_files:
        for ef in extra_files:
            ep = Path(ef)
            if ep.is_file():
                candidates.append(ep)

    files: List[Path] = []
    seen = set()
    for c in candidates:
        if c.is_file() and c.name not in seen and c.suffix != ".zip":
            files.append(c)
            seen.add(c.name)

    # MANIFEST with hashes
    manifest = {
        "engagement_id": eng_id,
        "client": meta.get("client_name"),
        "generated": datetime.datetime.now().isoformat(),
        "framework_version": meta.get("framework_version"),
        "score": scoring.get("score"),
        "grade": scoring.get("grade"),
        "files": [],
    }
    for fp in files:
        manifest["files"].append({
            "name": fp.name,
            "sha256": _sha256(fp),
            "size": fp.stat().st_size,
        })
    manifest_path = out / "MANIFEST.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    files.append(manifest_path)

    zip_path = out / f"{client}_Evidence_Pack_{ts}.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for fp in files:
            zf.write(fp, arcname=fp.name)
        zf.writestr("README_EVIDENCE_PACK.txt", readme_path.read_text(encoding="utf-8"))

    return str(zip_path)
