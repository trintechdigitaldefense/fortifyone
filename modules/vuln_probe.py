#!/usr/bin/env python3
"""
VulnProbe - Lightweight Vulnerability Probing
TrinTech Digital Defense

Uses safe, non-destructive nmap NSE scripts and version heuristics.
Does NOT perform exploitation or aggressive testing.
"""

import datetime
import subprocess
from typing import Dict, List, Any

# Safe, informative NSE scripts only
SAFE_SCRIPTS = [
    "ssl-heartbleed",
    "ssl-poodle",
    "ssl-ccs-injection",
    "smb-vuln-ms17-010",   # EternalBlue check (safe)
    "smb-vuln-ms08-067",
    "http-slowloris-check",
    "ftp-anon",
    "sshv1",
]

# Ports that commonly warrant extra attention
HIGH_INTEREST_PORTS = {"21", "22", "23", "25", "80", "443", "445", "3389", "5900", "8080", "8443"}


def run_scan(audit_data: dict) -> dict:
    """
    Run lightweight vulnerability probes against open ports
    discovered in external_scan (and internal if present).
    """
    print("\n[VULNPROBE] Starting lightweight vulnerability probes...")

    external = audit_data.get("external_scan", {})
    open_ports = external.get("open_ports", [])
    targets = set()

    for p in open_ports:
        host = p.get("host") or p.get("ip") or audit_data.get("audit_metadata", {}).get("public_ip")
        if host:
            targets.add(str(host))

    # Also include primary IP
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

    # Limit to first 8 targets for safety/performance
    target_list = list(targets)[:8]
    print(f"[VULNPROBE] Probing {len(target_list)} target(s) with safe NSE scripts...")

    for target in target_list:
        try:
            # Run a focused, safe script scan on top ports only
            cmd = [
                "nmap",
                "-sV",
                "-T4",
                "--script",
                ",".join(SAFE_SCRIPTS),
                "--script-args",
                "unsafe=0",
                "--top-ports", "50",
                "--open",
                "--max-retries", "1",
                "--host-timeout", "90s",
                target,
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=150)

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
                        "target": target,
                        "port": "21",
                        "title": "Anonymous FTP access possible",
                        "detail": line[:200],
                        "severity": "high",
                        "source": "nmap-nse",
                    })
                elif "SSHv1" in line or "sshv1" in line.lower():
                    findings.append({
                        "target": target,
                        "port": "22",
                        "title": "Obsolete SSHv1 protocol supported",
                        "detail": "SSHv1 is insecure and should be disabled",
                        "severity": "high",
                        "source": "nmap-nse",
                    })

        except subprocess.TimeoutExpired:
            findings.append({
                "target": target,
                "title": "Probe timed out",
                "detail": f"Scan of {target} exceeded time limit",
                "severity": "info",
                "source": "vuln_probe",
            })
        except FileNotFoundError:
            findings.append({
                "target": target,
                "title": "nmap not found",
                "detail": "Install nmap to enable vulnerability probing",
                "severity": "info",
                "source": "vuln_probe",
            })
            break
        except Exception as e:
            findings.append({
                "target": target,
                "title": f"Probe error: {type(e).__name__}",
                "detail": str(e)[:150],
                "severity": "info",
                "source": "vuln_probe",
            })

    # Version-based heuristics from existing open_ports data
    for p in open_ports:
        service = (p.get("service") or "").lower()
        port = str(p.get("port", ""))
        host = p.get("host") or p.get("ip") or "unknown"

        if port in HIGH_INTEREST_PORTS:
            if "microsoft-ds" in service or port == "445":
                findings.append({
                    "target": host,
                    "port": port,
                    "title": "SMB service exposed",
                    "detail": "SMB on the public internet is high risk. Confirm it is intentional and hardened.",
                    "severity": "critical",
                    "source": "heuristic",
                })
            elif "ms-wbt-server" in service or port == "3389":
                findings.append({
                    "target": host,
                    "port": port,
                    "title": "RDP exposed to the internet",
                    "detail": "Remote Desktop exposed publicly is a top ransomware entry vector.",
                    "severity": "critical",
                    "source": "heuristic",
                })
            elif "telnet" in service or port == "23":
                findings.append({
                    "target": host,
                    "port": port,
                    "title": "Telnet service detected",
                    "detail": "Cleartext protocol. Replace with SSH immediately.",
                    "severity": "critical",
                    "source": "heuristic",
                })

    # Deduplicate roughly by title+target
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
        "risk_score": risk_score,
        "scan_timestamp": datetime.datetime.now().isoformat(),
        "note": "Safe, non-exploitative probes only. Positive findings require manual verification.",
    }

    print(f"[VULNPROBE] Complete: {len(unique)} findings | Risk contribution: {risk_score}/100\n")
    return audit_data


if __name__ == "__main__":
    print("VulnProbe standalone test")
