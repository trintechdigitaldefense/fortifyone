#!/usr/bin/env python3
"""
InternalScan - Basic Internal Network Discovery
TrinTech Digital Defense

Designed to be run FROM INSIDE the client network (on-site or VPN).
Performs host discovery + limited top-port scan.
Does NOT perform aggressive or credentialed scanning.
"""

import datetime
import ipaddress
import subprocess
import socket
from typing import Dict, List, Any


def get_local_network() -> str:
    """Best-effort guess of the local /24 network."""
    try:
        # Create a UDP socket to determine local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        # Assume /24 for simplicity (common on SMB networks)
        network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
        return str(network)
    except Exception:
        return ""


def run_scan(audit_data: dict, target_cidr: str = None) -> dict:
    """
    Run basic internal discovery.

    target_cidr: optional CIDR (e.g. 192.168.1.0/24). If None, tries to auto-detect.
    """
    print("\n[INTERNALSCAN] Starting internal network discovery...")

    if not target_cidr:
        target_cidr = get_local_network()
        if not target_cidr:
            print("[INTERNALSCAN] Could not auto-detect local network. Skipping.")
            audit_data["internal_scan"] = {
                "hosts": [],
                "open_ports": [],
                "risk_score": 0,
                "error": "Could not determine local network",
                "scan_timestamp": datetime.datetime.now().isoformat(),
            }
            return audit_data

    print(f"[INTERNALSCAN] Target range: {target_cidr}")

    hosts = []
    findings = []
    open_ports = []

    try:
        # Host discovery (ping scan)
        cmd_discover = ["nmap", "-sn", "-T4", "--max-retries", "1", target_cidr]
        res = subprocess.run(cmd_discover, capture_output=True, text=True, timeout=120)

        for line in res.stdout.splitlines():
            if "Nmap scan report for" in line:
                # Extract IP
                parts = line.split()
                ip = parts[-1].strip("()")
                if ipaddress.ip_address(ip):
                    hosts.append({"ip": ip, "status": "up"})

        print(f"[INTERNALSCAN] Discovered {len(hosts)} live hosts")

        # Limited top-port scan on discovered hosts (cap at 15 hosts for safety)
        targets = [h["ip"] for h in hosts[:15]]
        if targets:
            target_str = " ".join(targets)
            cmd_ports = [
                "nmap", "-sS", "-T4", "--top-ports", "30",
                "--open", "--max-retries", "1", "--host-timeout", "30s"
            ] + targets

            res2 = subprocess.run(cmd_ports, capture_output=True, text=True, timeout=300)

            current_ip = None
            for line in res2.stdout.splitlines():
                if "Nmap scan report for" in line:
                    parts = line.split()
                    current_ip = parts[-1].strip("()")
                elif "/tcp" in line and "open" in line and current_ip:
                    parts = line.split()
                    port = parts[0].split("/")[0]
                    service = parts[2] if len(parts) > 2 else "unknown"
                    risk = "critical" if port in ("445", "3389", "135", "139") else \
                           "high" if port in ("22", "23", "21", "3306", "5432") else "medium"
                    open_ports.append({
                        "ip": current_ip,
                        "port": port,
                        "service": service,
                        "risk_level": risk,
                        "source": "internal_nmap"
                    })
                    findings.append(f"[INTERNAL] {current_ip}:{port} ({service}) OPEN")

    except subprocess.TimeoutExpired:
        findings.append("[ERROR] Internal scan timed out")
    except FileNotFoundError:
        findings.append("[ERROR] nmap not found")
    except Exception as e:
        findings.append(f"[ERROR] {type(e).__name__}: {e}")

    # Simple risk score
    critical = sum(1 for p in open_ports if p["risk_level"] == "critical")
    high = sum(1 for p in open_ports if p["risk_level"] == "high")
    risk_score = min(critical * 25 + high * 12 + len(open_ports) * 3, 100)

    audit_data["internal_scan"] = {
        "target_cidr": target_cidr,
        "hosts_discovered": len(hosts),
        "hosts": hosts,
        "open_ports": open_ports,
        "findings": findings,
        "risk_score": risk_score,
        "scan_timestamp": datetime.datetime.now().isoformat(),
        "note": "Basic unauthenticated discovery only. Credentialed and deeper scans require additional authorization and tooling."
    }

    print(f"[INTERNALSCAN] Complete: {len(hosts)} hosts, {len(open_ports)} open ports | Risk: {risk_score}/100\n")
    return audit_data


if __name__ == "__main__":
    print("InternalScan standalone test")
    test_data = {"audit_metadata": {}, "internal_scan": {}}
    run_scan(test_data)
