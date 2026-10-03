#!/usr/bin/env python3
"""
VulnProbe - Lightweight Vulnerability Probing + curated templates
TrinTech Digital Defense
Safe, non-destructive nmap NSE + template-driven heuristics.
"""

import datetime
import json
import subprocess
from pathlib import Path
from typing import Dict, List, Any

SAFE_SCRIPTS = [
    "ssl-heartbleed",
    "ssl-poodle",
    "ssl-ccs-injection",
    "smb-vuln-ms17-010",
    "smb-vuln-ms08-067",
    "http-slowloris-check",
    "ftp-anon",
    "sshv1",
]

HIGH_INTEREST_PORTS = {"21", "22", "23", "25", "80", "443", "445", "3389", "5900", "8080", "8443"}


def _load_templates() -> List[dict]:
    candidates = [
        Path(__file__).resolve().parent.parent / "config" / "vuln_templates.json",
        Path("config/vuln_templates.json"),
    ]
    for p in candidates:
        if p.is_file():
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                return data.get("templates", [])
            except Exception:
                pass
    return []


def _apply_templates(findings: List[dict], open_ports: List[dict], nse_text: str) -> List[dict]:
    templates = _load_templates()
    nse_low = nse_text.lower()
    seen = {(f.get("target"), f.get("title")) for f in findings}

    for t in templates:
        tid = t.get("id", "")
        title = t.get("title", tid)
        sev = t.get("severity", "medium")
        rem = t.get("remediation", "Validate and remediate.")

        # NSE line matches
        match_nse = [m.lower() for m in t.get("match_nse", [])]
        if match_nse and all(m in nse_low for m in match_nse[:1]) and any(m in nse_low for m in match_nse):
            # Prefer multi-token: if first token present, check others loosely
            if any(m in nse_low for m in match_nse):
                key = ("nse", title)
                if key not in seen:
                    findings.append({
                        "target": "nse",
                        "title": title,
                        "detail": f"Template {tid} matched NSE output",
                        "severity": sev,
                        "source": f"template:{tid}",
                        "remediation": rem,
                    })
                    seen.add(key)

        # Port / service matches from open_ports
        ports = set(str(x) for x in t.get("match_port", []))
        services = [s.lower() for s in t.get("match_service", [])]
        for p in open_ports:
            port = str(p.get("port", ""))
            service = (p.get("service") or "").lower()
            host = p.get("host") or p.get("ip") or "unknown"
            hit = False
            if ports and port in ports:
                hit = True
            if services and any(s in service for s in services):
                hit = True
            if hit:
                key = (host, title)
                if key not in seen:
                    findings.append({
                        "target": host,
                        "port": port,
                        "title": title,
                        "detail": f"Service {service or 'unknown'} on port {port} matched template {tid}",
                        "severity": sev,
                        "source": f"template:{tid}",
                        "remediation": rem,
                    })
                    seen.add(key)
    return findings


def run_scan(audit_data: dict) -> dict:
    print("\n[VULNPROBE] Starting vulnerability probes (templates + NSE)...")

    external = audit_data.get("external_scan", {})
    open_ports = external.get("open_ports", [])
    targets = set()

    for p in open_ports:
        host = p.get("host") or p.get("ip") or audit_data.get("audit_metadata", {}).get("public_ip")
        if host:
            targets.add(str(host))

    primary = audit_data.get("audit_metadata", {}).get("public_ip")
    if primary and primary not in ("0.0.0.0", "127.0.0.1"):
        targets.add(primary)

    if not targets:
        audit_data["vuln_probe"] = {
            "findings": [],
            "risk_score": 0,
            "note": "No targets available for probing",
            "scan_timestamp": datetime.datetime.now().isoformat(),
        }
        print("[VULNPROBE] No targets – skipped")
        return audit_data

    findings: List[Dict[str, Any]] = []
    script_hits = 0
    nse_blob = []
    target_list = list(targets)[:8]
    print(f"[VULNPROBE] Probing {len(target_list)} target(s)...")

    for target in target_list:
        try:
            cmd = [
                "nmap", "-sV", "-T4",
                "--script", ",".join(SAFE_SCRIPTS),
                "--script-args", "unsafe=0",
                "--top-ports", "50", "--open",
                "--max-retries", "1", "--host-timeout", "90s",
                target,
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=150)
            nse_blob.append(res.stdout)
            current_port = None
            for line in res.stdout.splitlines():
                line = line.strip()
                if "/tcp" in line and "open" in line:
                    parts = line.split()
                    current_port = parts[0].split("/")[0]
                elif "VULNERABLE" in line.upper() or "LIKELY VULNERABLE" in line.upper():
                    script_hits += 1
                    findings.append({
                        "target": target,
                        "port": current_port or "unknown",
                        "title": f"Potential vulnerability indicated on {target}",
                        "detail": line[:200],
                        "severity": "critical" if "VULNERABLE" in line.upper() else "high",
                        "source": "nmap-nse",
                    })
                elif "anonymous" in line.lower() and "ftp" in line.lower():
                    findings.append({
                        "target": target, "port": "21",
                        "title": "Anonymous FTP access possible",
                        "detail": line[:200], "severity": "high", "source": "nmap-nse",
                    })
                elif "SSHv1" in line or "sshv1" in line.lower():
                    findings.append({
                        "target": target, "port": "22",
                        "title": "Obsolete SSHv1 protocol supported",
                        "detail": "SSHv1 is insecure and should be disabled",
                        "severity": "high", "source": "nmap-nse",
                    })
        except subprocess.TimeoutExpired:
            findings.append({"target": target, "title": "Probe timed out",
                             "detail": f"Scan of {target} exceeded time limit",
                             "severity": "info", "source": "vuln_probe"})
        except FileNotFoundError:
            findings.append({"target": target, "title": "nmap not found",
                             "detail": "Install nmap to enable vulnerability probing",
                             "severity": "info", "source": "vuln_probe"})
            break
        except Exception as e:
            findings.append({"target": target, "title": f"Probe error: {type(e).__name__}",
                             "detail": str(e)[:150], "severity": "info", "source": "vuln_probe"})

    # Legacy heuristics
    for p in open_ports:
        service = (p.get("service") or "").lower()
        port = str(p.get("port", ""))
        host = p.get("host") or p.get("ip") or "unknown"
        if port in HIGH_INTEREST_PORTS:
            if "microsoft-ds" in service or port == "445":
                findings.append({"target": host, "port": port, "title": "SMB service exposed",
                                 "detail": "SMB on the public internet is high risk.",
                                 "severity": "critical", "source": "heuristic"})
            elif "ms-wbt-server" in service or port == "3389":
                findings.append({"target": host, "port": port, "title": "RDP exposed to the internet",
                                 "detail": "Public RDP is a top ransomware entry vector.",
                                 "severity": "critical", "source": "heuristic"})
            elif "telnet" in service or port == "23":
                findings.append({"target": host, "port": port, "title": "Telnet service detected",
                                 "detail": "Cleartext protocol. Replace with SSH.",
                                 "severity": "critical", "source": "heuristic"})

    # Curated templates
    findings = _apply_templates(findings, open_ports, "\n".join(nse_blob))

    seen = set()
    unique = []
    for f in findings:
        key = (f.get("target"), f.get("title"))
        if key not in seen:
            seen.add(key)
            unique.append(f)

    critical = sum(1 for f in unique if f.get("severity") == "critical")
    high = sum(1 for f in unique if f.get("severity") == "high")
    risk_score = min(critical * 30 + high * 15 + script_hits * 10, 100)

    audit_data["vuln_probe"] = {
        "findings": unique,
        "script_hits": script_hits,
        "targets_probed": len(target_list),
        "templates_loaded": len(_load_templates()),
        "risk_score": risk_score,
        "scan_timestamp": datetime.datetime.now().isoformat(),
        "note": "Safe probes + curated templates only. Positive findings require manual verification.",
    }
    print(f"[VULNPROBE] Complete: {len(unique)} findings | templates={len(_load_templates())} | Risk {risk_score}/100\n")
    return audit_data


if __name__ == "__main__":
    print("VulnProbe ready")
