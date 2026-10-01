#!/usr/bin/env python3
"""
LocalHardening - Safe Local Host Checks
TrinTech Digital Defense

Run FROM an authorized workstation/server inside the client environment.
Performs non-destructive local checks only (no remote exploitation).
"""

import datetime
import os
import platform
import subprocess
from typing import Dict, List, Any


def _run(cmd: list, timeout: int = 15) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (r.stdout or "") + (r.stderr or "")
    except Exception:
        return ""


def run_scan(audit_data: dict) -> dict:
    print("\n[LOCALHARDENING] Running local host hardening checks...")
    findings: List[Dict[str, Any]] = []
    system = platform.system().lower()
    info = {
        "os": platform.platform(),
        "hostname": platform.node(),
        "user": os.environ.get("USER") or os.environ.get("USERNAME") or "unknown",
    }

    # ── Linux / Termux / Unix ──
    if system in ("linux", "darwin"):
        # Firewall
        ufw = _run(["ufw", "status"])
        if "Status: active" in ufw:
            findings.append({"title": "UFW firewall active", "severity": "good",
                             "detail": "Host firewall appears enabled.", "category": "Firewall"})
        elif ufw:
            findings.append({"title": "UFW firewall not active", "severity": "high",
                             "detail": "Enable and configure a host firewall.", "category": "Firewall",
                             "remediation": "sudo ufw enable && sudo ufw default deny incoming"})

        # SSH config hardening (if readable)
        sshd = ""
        for p in ("/etc/ssh/sshd_config",):
            if os.path.isfile(p) and os.access(p, os.R_OK):
                try:
                    with open(p) as f:
                        sshd = f.read()
                except Exception:
                    pass
        if sshd:
            if "PasswordAuthentication yes" in sshd and "#PasswordAuthentication" not in sshd:
                findings.append({"title": "SSH password authentication may be enabled",
                                 "severity": "high", "category": "SSH",
                                 "detail": "Prefer key-based authentication only.",
                                 "remediation": "Set PasswordAuthentication no in sshd_config and restart sshd."})
            if "PermitRootLogin yes" in sshd:
                findings.append({"title": "SSH PermitRootLogin is yes",
                                 "severity": "critical", "category": "SSH",
                                 "detail": "Root SSH login should be disabled.",
                                 "remediation": "Set PermitRootLogin no (or prohibit-password)."})

        # World-writable sensitive dirs (sample)
        for path in ("/tmp",):
            try:
                st = os.stat(path)
                if st.st_mode & 0o002:
                    findings.append({"title": f"{path} is world-writable",
                                     "severity": "info", "category": "Filesystem",
                                     "detail": "Expected for /tmp; ensure sticky bit is set."})
            except Exception:
                pass

        # Pending updates (best effort)
        apt = _run(["apt-get", "-s", "upgrade"], timeout=20)
        if "Inst " in apt or "The following packages will be upgraded" in apt:
            findings.append({"title": "Package updates appear available",
                             "severity": "medium", "category": "Patching",
                             "detail": "Unattended simulation suggests pending upgrades.",
                             "remediation": "Apply security updates and enable automatic security patches."})

    # ── Windows (best effort via commands) ──
    elif system == "windows":
        # Firewall profiles
        fw = _run(["netsh", "advfirewall", "show", "allprofiles"])
        if "State" in fw and "OFF" in fw.upper():
            findings.append({"title": "Windows Firewall profile appears OFF",
                             "severity": "critical", "category": "Firewall",
                             "detail": fw[:200],
                             "remediation": "Enable Windows Firewall for all profiles."})
        elif "State" in fw:
            findings.append({"title": "Windows Firewall status retrieved",
                             "severity": "info", "category": "Firewall", "detail": "Review profiles manually."})

        # Local admins (sample)
        admins = _run(["net", "localgroup", "administrators"])
        if admins:
            findings.append({"title": "Local Administrators group membership",
                             "severity": "info", "category": "Accounts",
                             "detail": "Review membership for least privilege.",
                             "remediation": "Remove unnecessary local admin accounts."})

    else:
        findings.append({"title": f"Unsupported platform for deep local checks: {system}",
                         "severity": "info", "category": "System", "detail": info["os"]})

    # Shared risk scoring
    critical = sum(1 for f in findings if f.get("severity") == "critical")
    high = sum(1 for f in findings if f.get("severity") == "high")
    medium = sum(1 for f in findings if f.get("severity") == "medium")
    risk_score = min(critical * 30 + high * 15 + medium * 8, 100)

    audit_data["local_hardening"] = {
        "host_info": info,
        "findings": findings,
        "risk_score": risk_score,
        "scan_timestamp": datetime.datetime.now().isoformat(),
        "note": "Local checks only on the machine running FortifyOne. Not a substitute for domain-wide authenticated scanning.",
    }
    print(f"[LOCALHARDENING] Complete on {info['hostname']}: {len(findings)} findings | Risk {risk_score}/100\n")
    return audit_data


if __name__ == "__main__":
    print(run_scan({"local_hardening": {}})["local_hardening"])
