#!/usr/bin/env python3
"""
ReconVision - External Footprint Scanner (Hardened)
TrinTech Digital Defense

Authorized use only. Unauthorized scanning is illegal.
"""

import datetime
import ipaddress
import re
import subprocess
from typing import Dict, Any, Tuple


def validate_target(ip: str, domain: str) -> Tuple[str, str]:
    """Strict validation of IP and domain before any scanning."""
    ip = (ip or "").strip()
    domain = (domain or "").strip().lower()

    try:
        # Accepts IPv4/IPv6, rejects invalid
        ip = str(ipaddress.ip_address(ip))
    except ValueError:
        raise ValueError(f"Invalid IP address: {ip}")

    # Domain: basic RFC-ish + block shell metacharacters
    if not re.match(
        r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*$",
        domain,
    ):
        raise ValueError(f"Invalid domain format: {domain}")

    forbidden = set(";|&$`<>()\n\r\\\"'")
    if any(c in domain for c in forbidden):
        raise ValueError("Domain contains forbidden characters")

    return ip, domain


def run_scan(audit_data: dict) -> dict:
    """Run hardened external scan against validated target."""
    target_ip = audit_data["audit_metadata"].get("public_ip", "")
    domain = audit_data["audit_metadata"].get("domain", "")

    try:
        target_ip, domain = validate_target(target_ip, domain)
    except ValueError as e:
        audit_data["external_scan"] = {
            "open_ports": [],
            "vulnerabilities": [f"[ERROR] Validation failed: {e}"],
            "risk_score": 0,
            "scan_timestamp": datetime.datetime.now().isoformat(),
            "error": str(e),
        }
        print(f"[RECONVISION] Validation failed: {e}")
        return audit_data

    print(f"\n[RECONVISION] Scanning target: {target_ip} ({domain})...")
    open_ports = []
    findings = []

    # Never scan localhost / zero
    if target_ip in ("0.0.0.0", "127.0.0.1", "::1"):
        findings.append("[ERROR] Refusing to scan localhost / zero address")
        audit_data["external_scan"] = {
            "open_ports": [],
            "vulnerabilities": findings,
            "risk_score": 0,
            "scan_timestamp": datetime.datetime.now().isoformat(),
        }
        return audit_data

    try:
        # Strict list-form args only. Never shell=True.
        cmd = [
            "nmap",
            "-sS",
            "-T4",
            "--top-ports",
            "100",
            "-sV",
            "--version-intensity",
            "3",
            "--open",
            "--max-retries",
            "2",
            "--host-timeout",
            "120s",
            target_ip,
        ]
        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )

        if "Nmap scan report" not in res.stdout and res.returncode != 0:
            findings.append(f"[ERROR] nmap failed (rc={res.returncode}): {res.stderr[:200]}")
        else:
            for line in res.stdout.splitlines():
                if "/tcp" in line and "open" in line:
                    parts = line.split()
                    port_id = parts[0].split("/")[0]
                    service = parts[2] if len(parts) > 2 else "unknown"

                    if port_id in ("3389", "445", "135", "139", "5900"):
                        risk = "critical"
                    elif port_id in ("22", "23", "21", "3306", "5432", "1433", "27017"):
                        risk = "high"
                    else:
                        risk = "medium"

                    open_ports.append({
                        "port": port_id,
                        "service": service,
                        "risk_level": risk,
                        "source": "nmap",
                    })
                    findings.append(f"[ACTIVE] Port {port_id} ({service}) OPEN — Risk: {risk}")

    except subprocess.TimeoutExpired:
        findings.append("[ERROR] Scan timed out after 180s")
    except FileNotFoundError:
        findings.append("[ERROR] nmap binary not found. Install with: apt install nmap / pkg install nmap")
    except Exception as e:
        findings.append(f"[ERROR] Scan error: {type(e).__name__}: {e}")

    # Risk scoring
    critical = sum(1 for p in open_ports if p["risk_level"] == "critical")
    high = sum(1 for p in open_ports if p["risk_level"] == "high")
    medium = len(open_ports) - critical - high
    risk_score = min(critical * 35 + high * 20 + medium * 8, 100)

    audit_data["external_scan"] = {
        "open_ports": open_ports,
        "vulnerabilities": findings,
        "risk_score": risk_score,
        "scan_timestamp": datetime.datetime.now().isoformat(),
    }

    print(f"[RECONVISION] Complete: {len(open_ports)} open ports | Risk: {risk_score}/100\n")
    return audit_data
